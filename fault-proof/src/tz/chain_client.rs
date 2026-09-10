use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

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

/// Total deadline for `get_dex_state_snapshot` — covers query + (potentially long) replay +
/// download across all endpoint retries. Sized to comfortably exceed any realistic replay workload
/// while still bounding stuck loops.
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(7200); // 2h

fn snapshot_poll_interval() -> Duration {
    let secs: u64 = std::env::var("TZ_SNAPSHOT_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &u64| n > 0)
        .unwrap_or(5);
    Duration::from_secs(secs)
}

fn bytes_to_mb(bytes: usize) -> f64 {
    bytes as f64 / 1024.0 / 1024.0
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
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
            };
            if !resp.status().is_success() {
                last_err = anyhow!("HTTP {}", resp.status());
                continue;
            }
            let api: ApiResponse = match resp.json().await {
                Ok(a) => a,
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
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
    /// 2. If `state_available=false`, server has spawned (or reused) a background replay task. Poll
    ///    the same URL every `TZ_SNAPSHOT_POLL_INTERVAL_SECS` (default 5s) until the flag flips,
    ///    the task fails / is cancelled, or the overall 2h deadline is hit.
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
                anyhow::bail!(
                    "tz snapshot fetch exhausted overall deadline ({SNAPSHOT_DEADLINE:?})"
                );
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
                anyhow!(
                    "snapshot query missing data field: code={} message={}",
                    envelope.code,
                    envelope.message
                )
            })?;

            if data.state_available {
                tracing::info!(
                    requested_height = height,
                    base_snapshot_height = data.base_snapshot_height,
                    "tz: snapshot ready, downloading"
                );
                return self.download_snapshot(endpoint, height).await;
            }

            // state_available=false — server should have spawned (or reused) a replay task.
            // Fetch detailed state + progress via the poll_path endpoint.
            if let Some(poll_path) = data.poll_path.as_deref() {
                let task_url = format!("{endpoint}{poll_path}");
                let task_resp = self.client.get(&task_url).send().await?;
                let task_status_code = task_resp.status();
                if !task_status_code.is_success() {
                    let body = task_resp.text().await.unwrap_or_default();
                    anyhow::bail!("HTTP {task_status_code} from {task_url}: {body}");
                }
                let task_envelope: ApiEnvelope<ReplayTaskResponse> = task_resp.json().await?;
                let task = task_envelope.data.ok_or_else(|| {
                    anyhow!(
                        "replay task query missing data field: code={} message={}",
                        task_envelope.code,
                        task_envelope.message
                    )
                })?;

                match task.state {
                    SnapshotReplayState::Running | SnapshotReplayState::Finished => {
                        tracing::info!(
                            task_id = %task.task_id,
                            requested_height = height,
                            base_snapshot_height = data.base_snapshot_height,
                            current_height = task.current_height,
                            blocks_processed = task.blocks_processed,
                            total_blocks = task.total_blocks,
                            progress_percent = task.progress_percent,
                            throughput = %task.throughput,
                            state = ?task.state,
                            "tz: snapshot replay in progress"
                        );
                    }
                    SnapshotReplayState::Failed => {
                        let err = task.error.clone().unwrap_or_else(|| "<no error>".into());
                        tracing::error!(
                            task_id = %task.task_id,
                            error = %err,
                            requested_height = height,
                            "tz: snapshot replay task FAILED — bailing"
                        );
                        anyhow::bail!(
                            "tz snapshot replay failed (task {}, height {}): {}",
                            task.task_id,
                            height,
                            err
                        );
                    }
                    SnapshotReplayState::Cancelled => {
                        tracing::error!(
                            task_id = %task.task_id,
                            requested_height = height,
                            "tz: snapshot replay task CANCELLED — bailing"
                        );
                        anyhow::bail!(
                            "tz snapshot replay cancelled (task {}, height {})",
                            task.task_id,
                            height
                        );
                    }
                }
            } else {
                tracing::warn!(
                    height,
                    task_status = ?data.task_status,
                    "tz: state_available=false but no poll_path returned; re-querying"
                );
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn download_snapshot(&self, endpoint: &str, height: u64) -> Result<Vec<u8>> {
        let url = format!("{endpoint}/chain/dex_state_snapshot/download?height={height}");
        let started_at = Instant::now();
        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {status} from {url}: {body}");
        }
        let bytes = resp.bytes().await?.to_vec();
        let elapsed = started_at.elapsed();
        tracing::info!(
            endpoint = %endpoint,
            height,
            elapsed_ms = elapsed.as_millis() as u64,
            bytes = bytes.len(),
            size_mb = bytes_to_mb(bytes.len()),
            "tz: snapshot download complete"
        );
        Ok(bytes)
    }

    /// `GET /chain/blocks?start=N&end=M` — returns msgpack-encoded Vec<Block> bytes.
    pub async fn get_blocks_range(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        let mut last_err = anyhow!("no endpoints configured");
        for endpoint in &self.endpoints {
            let url = format!("{}/chain/blocks?start={}&end={}", endpoint, start, end);
            let started_at = Instant::now();
            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
            };
            if !resp.status().is_success() {
                last_err = anyhow!("HTTP {} from {}", resp.status(), url);
                continue;
            }
            let bytes = resp.bytes().await?.to_vec();
            let elapsed = started_at.elapsed();
            tracing::info!(
                endpoint = %endpoint,
                start,
                end,
                block_count = end.saturating_sub(start).saturating_add(1),
                elapsed_ms = elapsed.as_millis() as u64,
                bytes = bytes.len(),
                size_mb = bytes_to_mb(bytes.len()),
                "tz: blocks range download complete"
            );
            return Ok(bytes);
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

/// Response shape of `GET /chain/dex_state_snapshot?height={u64}` — matches
/// `SnapshotQueryResponse` in tradezone (`crates/chain/src/rpc/handlers/zkvm_snapshot.rs`).
///
/// When `state_available = false`, the server includes `poll_path` pointing at
/// `/chain/dex_state_snapshot/tasks/{task_id}` which we GET separately to
/// inspect detailed replay progress (see [`ReplayTaskResponse`]).
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DexStateSnapshotResponse {
    state_available: bool,
    #[serde(default)]
    base_snapshot_height: u64,
    #[allow(dead_code)]
    #[serde(default)]
    height: u64,
    #[allow(dead_code)]
    #[serde(default)]
    task_id: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    task_status: Option<String>,
    #[serde(default)]
    poll_path: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum SnapshotReplayState {
    Running,
    Finished,
    Failed,
    Cancelled,
}

/// Response shape of `GET /chain/dex_state_snapshot/tasks/{task_id}` — matches
/// tradezone's `ReplayTaskResponse`.
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ReplayTaskResponse {
    task_id: String,
    state: SnapshotReplayState,
    #[serde(default)]
    current_height: u64,
    #[serde(default)]
    total_blocks: u64,
    #[serde(default)]
    blocks_processed: u64,
    #[serde(default)]
    progress_percent: f64,
    #[serde(default)]
    throughput: String,
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

    const HASH_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
                    "baseSnapshotHeight": 137000u64,
                    "height": 137000u64
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
        // Query endpoint reports the task is being driven; client must follow pollPath.
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "OK",
                "data": {
                    "stateAvailable": false,
                    "baseSnapshotHeight": 130000u64,
                    "height": 137000u64,
                    "taskId": "task-xyz",
                    "taskStatus": "failed",
                    "pollPath": "/chain/dex_state_snapshot/tasks/task-xyz"
                }
            })))
            .mount(&mock_server)
            .await;
        // Detail endpoint carries the actual replay state + error message.
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot/tasks/task-xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "OK",
                "data": {
                    "taskId": "task-xyz",
                    "state": "failed",
                    "height": 137000u64,
                    "baseSnapshotHeight": 130000u64,
                    "currentHeight": 132500u64,
                    "totalBlocks": 7000u64,
                    "blocksProcessed": 2500u64,
                    "progressPercent": 35.7,
                    "throughput": "42.0 blocks/s",
                    "error": "process_block panicked at height 132501",
                    "startedAt": 0u64
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
