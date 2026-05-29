use std::collections::HashMap;
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use anyhow::{anyhow, Result};

#[derive(Debug, thiserror::Error)]
#[error("TzChainClient: no cached checkpoint for height {0}")]
pub struct TzCacheMissError(pub u64);

#[derive(Clone, Debug)]
pub struct TzBlockInfo {
    pub height: u64,
    pub block_hash: B256,
    pub state_hash: B256,
}

pub struct TzChainClient {
    endpoints: Vec<String>,
    pub(crate) history: std::sync::Mutex<HashMap<u64, TzBlockInfo>>,
    client: reqwest::Client,
}

/// Total deadline for `get_dex_state_snapshot` — covers query + (potentially long) replay + download
/// across all endpoint retries. Sized to comfortably exceed any realistic replay workload while
/// still bounding stuck loops.
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(7200); // 2h

fn snapshot_poll_interval() -> Duration {
    let secs: u64 = std::env::var("TZ_SNAPSHOT_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &u64| n > 0)
        .unwrap_or(5);
    Duration::from_secs(secs)
}

impl TzChainClient {
    pub fn new(endpoints: Vec<String>) -> Self {
        Self {
            endpoints,
            history: std::sync::Mutex::new(HashMap::new()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build reqwest client"),
        }
    }

    pub async fn get_confirmed_block_info(&self) -> Result<TzBlockInfo> {
        #[derive(serde::Deserialize)]
        struct ApiResponse {
            code: i32,
            data: Option<TzBlockInfoRaw>,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct TzBlockInfoRaw {
            height: u64,
            block_hash: B256,
            app_hash: B256,
        }

        let mut last_err = anyhow!("no endpoints configured");
        for endpoint in &self.endpoints {
            let url = format!("{}/chain/confirmed_block_info", endpoint);
            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => { last_err = e.into(); continue; }
            };
            if !resp.status().is_success() {
                last_err = anyhow!("HTTP {}", resp.status());
                continue;
            }
            let api: ApiResponse = match resp.json().await {
                Ok(a) => a,
                Err(e) => { last_err = e.into(); continue; }
            };
            if api.code != 0 {
                last_err = anyhow!("API code {}", api.code);
                continue;
            }
            let raw = api.data.ok_or_else(|| anyhow!("tz chain has no checkpoint yet"))?;
            let info = TzBlockInfo {
                height: raw.height,
                block_hash: raw.block_hash,
                state_hash: raw.app_hash,
            };
            self.history.lock().unwrap().insert(info.height, info.clone());
            return Ok(info);
        }
        Err(last_err)
    }

    pub fn get_confirmed_block_info_at_height(&self, height: u64) -> Result<TzBlockInfo> {
        self.history
            .lock()
            .unwrap()
            .get(&height)
            .cloned()
            .ok_or_else(|| anyhow::Error::new(TzCacheMissError(height)))
    }

    pub fn evict_below(&self, anchor_height: u64) {
        self.history.lock().unwrap().retain(|&h, _| h >= anchor_height);
    }

    /// Fetch a DexState msgpack snapshot at the given height.
    ///
    /// Drives the server's async snapshot-replay protocol end-to-end:
    /// 1. `GET /chain/dex_state_snapshot?height=H` — query availability
    /// 2. If `state_available=false`, server has spawned (or reused) a background replay task.
    ///    Poll the same URL every `TZ_SNAPSHOT_POLL_INTERVAL_SECS` (default 5s) until the
    ///    flag flips, the task fails / is cancelled, or the overall 2h deadline is hit.
    /// 3. `GET /chain/dex_state_snapshot/download?height=H` — fetch raw msgpack bytes.
    ///
    /// Returns the msgpack bytes for `tz_dex::order_preserving_serde::from_msgpack`.
    /// The snapshot's internal `state.context.height` is guaranteed to equal `height` —
    /// the server performs forward-replay from the nearest base snapshot.
    pub async fn get_dex_state_snapshot(&self, height: u64) -> Result<Vec<u8>> {
        let deadline = Instant::now() + SNAPSHOT_DEADLINE;
        let poll_interval = snapshot_poll_interval();

        let mut last_err = anyhow!("no endpoints configured");
        for endpoint in &self.endpoints {
            if Instant::now() >= deadline {
                anyhow::bail!("tz snapshot fetch exhausted overall deadline ({SNAPSHOT_DEADLINE:?})");
            }
            match self.snapshot_flow(endpoint, height, deadline, poll_interval).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    tracing::warn!(
                        endpoint = %endpoint,
                        height,
                        error = %e,
                        "tz: snapshot fetch failed for endpoint, trying next"
                    );
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    async fn snapshot_flow(
        &self,
        endpoint: &str,
        height: u64,
        deadline: Instant,
        poll_interval: Duration,
    ) -> Result<Vec<u8>> {
        loop {
            if Instant::now() >= deadline {
                anyhow::bail!("tz snapshot replay deadline exceeded (2h) for height {height}");
            }

            let url = format!("{endpoint}/chain/dex_state_snapshot?height={height}");
            let resp = self.client.get(&url).send().await?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("HTTP {status} from {url}: {body}");
            }
            let envelope: ApiEnvelope<DexStateSnapshotResponse> = resp.json().await?;
            let data = envelope.data.ok_or_else(|| {
                anyhow!("snapshot query missing data field: code={} message={}",
                    envelope.code, envelope.message)
            })?;

            if data.state_available {
                tracing::info!(
                    requested_height = height,
                    base_snapshot_height = data.base_snapshot_height,
                    "tz: snapshot ready, downloading"
                );
                return self.download_snapshot(endpoint, height).await;
            }

            // state_available=false — expect a running replay task. Log progress and wait.
            match data.task_status.as_ref() {
                Some(ts) => match ts.state {
                    SnapshotReplayState::Running | SnapshotReplayState::Finished => {
                        tracing::info!(
                            task_id = %ts.task_id,
                            requested_height = height,
                            base_snapshot_height = data.base_snapshot_height,
                            current_height = ts.current_height,
                            blocks_processed = ts.blocks_processed,
                            total_blocks = ts.total_blocks,
                            progress_pct = ts.progress_pct,
                            blocks_per_sec = ?ts.blocks_per_sec,
                            state = ?ts.state,
                            "tz: snapshot replay in progress"
                        );
                    }
                    SnapshotReplayState::Failed => {
                        let err = ts.error.clone().unwrap_or_else(|| "<no error>".into());
                        tracing::error!(
                            task_id = %ts.task_id,
                            error = %err,
                            requested_height = height,
                            "tz: snapshot replay task FAILED — bailing"
                        );
                        anyhow::bail!(
                            "tz snapshot replay failed (task {}, height {}): {}",
                            ts.task_id, height, err
                        );
                    }
                    SnapshotReplayState::Cancelled => {
                        tracing::error!(
                            task_id = %ts.task_id,
                            requested_height = height,
                            "tz: snapshot replay task CANCELLED — bailing"
                        );
                        anyhow::bail!(
                            "tz snapshot replay cancelled (task {}, height {})",
                            ts.task_id, height
                        );
                    }
                },
                None => {
                    tracing::warn!(
                        height,
                        "tz: state_available=false but no task_status returned; re-querying"
                    );
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn download_snapshot(&self, endpoint: &str, height: u64) -> Result<Vec<u8>> {
        let url = format!("{endpoint}/chain/dex_state_snapshot/download?height={height}");
        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {status} from {url}: {body}");
        }
        Ok(resp.bytes().await?.to_vec())
    }

    /// `GET /chain/blocks?start=N&end=M` — returns msgpack-encoded Vec<Block> bytes.
    pub async fn get_blocks_range(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        let mut last_err = anyhow!("no endpoints configured");
        for endpoint in &self.endpoints {
            let url = format!("{}/chain/blocks?start={}&end={}", endpoint, start, end);
            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => { last_err = e.into(); continue; }
            };
            if !resp.status().is_success() {
                last_err = anyhow!("HTTP {} from {}", resp.status(), url);
                continue;
            }
            return Ok(resp.bytes().await?.to_vec());
        }
        Err(last_err)
    }
}

// ── server response types (snapshot path) ──────────────────────────────────

#[derive(serde::Deserialize, Debug)]
struct ApiEnvelope<T> {
    #[allow(dead_code)]
    code: i32,
    #[serde(default)]
    message: String,
    data: Option<T>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DexStateSnapshotResponse {
    state_available: bool,
    #[allow(dead_code)]
    #[serde(default)]
    requested_height: u64,
    #[allow(dead_code)]
    #[serde(default)]
    confirmed_height: u64,
    #[serde(default)]
    base_snapshot_height: u64,
    #[allow(dead_code)]
    #[serde(default)]
    task_id: Option<String>,
    #[serde(default)]
    task_status: Option<SnapshotReplayStatus>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum SnapshotReplayState {
    Running,
    Finished,
    Failed,
    Cancelled,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SnapshotReplayStatus {
    task_id: String,
    state: SnapshotReplayState,
    #[allow(dead_code)]
    #[serde(default)]
    requested_height: u64,
    #[allow(dead_code)]
    #[serde(default)]
    base_snapshot_height: u64,
    #[serde(default)]
    current_height: u64,
    #[serde(default)]
    total_blocks: u64,
    #[serde(default)]
    blocks_processed: u64,
    #[serde(default)]
    progress_pct: f64,
    #[serde(default)]
    blocks_per_sec: Option<f64>,
    #[serde(default)]
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    const HASH_A: &str =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str =
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[tokio::test]
    async fn get_confirmed_block_info_parses_ok_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": { "height": 12345u64, "blockHash": HASH_A, "appHash": HASH_B }
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let info = client.get_confirmed_block_info().await.unwrap();
        assert_eq!(info.height, 12345);
        assert_eq!(info.block_hash, HASH_A.parse::<B256>().unwrap());
        assert_eq!(info.state_hash, HASH_B.parse::<B256>().unwrap());
    }

    #[tokio::test]
    async fn get_confirmed_block_info_returns_err_when_data_null() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": null
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        assert!(client.get_confirmed_block_info().await.is_err());
    }

    #[tokio::test]
    async fn get_confirmed_block_info_failover_to_second_endpoint() {
        let good_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": { "height": 999u64, "blockHash": HASH_A, "appHash": HASH_B }
            })))
            .mount(&good_server)
            .await;

        let client = TzChainClient::new(vec![
            "http://127.0.0.1:1".to_string(), // unreachable
            good_server.uri(),
        ]);
        let info = client.get_confirmed_block_info().await.unwrap();
        assert_eq!(info.height, 999);
    }

    #[tokio::test]
    async fn dex_state_snapshot_state_available_downloads_directly() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "OK",
                "data": {
                    "stateAvailable": true,
                    "requestedHeight": 137000u64,
                    "confirmedHeight": 138000u64,
                    "baseSnapshotHeight": 137000u64,
                    "taskId": null,
                    "taskStatus": null
                }
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot/download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/x-msgpack")
                    .set_body_bytes(b"msgpack-bytes".to_vec()),
            )
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let bytes = client.get_dex_state_snapshot(137000).await.unwrap();
        assert_eq!(bytes, b"msgpack-bytes");
    }

    #[tokio::test]
    async fn dex_state_snapshot_failed_task_bails() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 10004,
                "message": "replay required",
                "data": {
                    "stateAvailable": false,
                    "requestedHeight": 137000u64,
                    "confirmedHeight": 138000u64,
                    "baseSnapshotHeight": 130000u64,
                    "taskId": "task-xyz",
                    "taskStatus": {
                        "taskId": "task-xyz",
                        "state": "failed",
                        "requestedHeight": 137000u64,
                        "baseSnapshotHeight": 130000u64,
                        "currentHeight": 132500u64,
                        "totalBlocks": 7000u64,
                        "blocksProcessed": 2500u64,
                        "progressPct": 35.7,
                        "blocksPerSec": 42.0,
                        "error": "process_block panicked at height 132501"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let err = client.get_dex_state_snapshot(137000).await.unwrap_err().to_string();
        assert!(err.contains("task-xyz"), "expected task_id in error: {err}");
        assert!(err.contains("process_block panicked"), "expected upstream error in: {err}");
    }
}
