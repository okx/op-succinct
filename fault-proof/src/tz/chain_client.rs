use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use reqwest::StatusCode;

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
    stream_client: reqwest::Client,
}

/// Total deadline for `get_dex_state_snapshot` — covers query + (potentially long) replay +
/// download across all endpoint retries. Sized to comfortably exceed any realistic replay workload
/// while still bounding stuck loops.
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(7200); // 2h
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCK_STREAM_MAGIC: &[u8; 5] = b"TZBS1";
const BLOCK_STREAM_FRAME_HEADER_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
#[error("tz block stream endpoint unsupported")]
pub struct TzBlockStreamUnsupportedError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TzBlockStreamSegmentResult {
    pub start: u64,
    pub end: u64,
    pub frame_count: u32,
    pub payload_bytes: usize,
}

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
                .timeout(HTTP_TIMEOUT)
                .build()
                .expect("failed to build reqwest client"),
            // Streaming block downloads can run for much longer than a normal RPC request.
            // Do not configure a total request timeout here; retain only the connect timeout.
            stream_client: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
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

    /// `GET /chain/blocks/stream?start=N&end=M&frame=F` — streams msgpack Vec<Block>
    /// frames for a single TradeZone block-store segment into `output_path`.
    ///
    /// The local file format is repeated:
    /// - payload_len u64 BE
    /// - payload bytes
    ///
    /// Payloads are already msgpack Vec<Block>; this method never decodes or re-encodes them.
    pub async fn stream_blocks_segment_to_file(
        &self,
        start: u64,
        end: u64,
        frame_blocks: u64,
        output_path: &Path,
    ) -> Result<TzBlockStreamSegmentResult> {
        anyhow::ensure!(start > 0, "block height 0 is not supported");
        anyhow::ensure!(start <= end, "start must be <= end: start={start}, end={end}");
        anyhow::ensure!(frame_blocks > 0, "frame_blocks must be greater than 0");

        let mut last_err = anyhow!("no endpoints configured");
        let mut saw_unsupported = false;
        for endpoint in &self.endpoints {
            let url = format!(
                "{}/chain/blocks/stream?start={}&end={}&frame={}",
                endpoint, start, end, frame_blocks
            );
            let resp = match self.stream_client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
            };
            let status = resp.status();
            if is_block_stream_unsupported_status(status) {
                saw_unsupported = true;
                last_err = anyhow::Error::new(TzBlockStreamUnsupportedError);
                tracing::warn!(
                    endpoint = %endpoint,
                    start,
                    end,
                    status = %status,
                    "tz: block stream endpoint unsupported on endpoint"
                );
                continue;
            }
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                last_err = anyhow!("HTTP {status} from {url}: {body}");
                continue;
            }

            match self.consume_blocks_stream_response(endpoint, start, end, resp, output_path).await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_err = e;
                    continue;
                }
            }
        }

        if saw_unsupported {
            Err(anyhow::Error::new(TzBlockStreamUnsupportedError))
        } else {
            Err(last_err)
        }
    }

    async fn consume_blocks_stream_response(
        &self,
        endpoint: &str,
        start: u64,
        end: u64,
        resp: reqwest::Response,
        output_path: &Path,
    ) -> Result<TzBlockStreamSegmentResult> {
        let started_at = Instant::now();
        let file = File::create(output_path).with_context(|| {
            format!("failed to create tz block stream temp file {output_path:?}")
        })?;
        let writer = BufWriter::new(file);
        let mut parser = TzBlockStreamParser::new(start, end, writer);
        let mut body = resp.bytes_stream();

        while let Some(chunk) = body.next().await {
            let chunk = chunk.with_context(|| {
                format!("tz block stream body error for segment {start}..{end}")
            })?;
            parser.ingest(&chunk)?;
        }

        let result = parser.finish()?;
        let elapsed = started_at.elapsed();
        tracing::info!(
            endpoint = %endpoint,
            segment_start = start,
            segment_end = end,
            frames = result.frame_count,
            payload_bytes = result.payload_bytes,
            elapsed_ms = elapsed.as_millis() as u64,
            "tz: block stream segment download complete"
        );
        Ok(result)
    }
}

fn is_block_stream_unsupported_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::NOT_IMPLEMENTED | StatusCode::METHOD_NOT_ALLOWED
    )
}

struct PendingBlockStreamFrame {
    start: u64,
    end: u64,
    payload_len: u64,
    payload_written: u64,
}

struct TzBlockStreamParser<W> {
    segment_start: u64,
    segment_end: u64,
    expected_next: u64,
    magic: Vec<u8>,
    header: Vec<u8>,
    current_frame: Option<PendingBlockStreamFrame>,
    writer: W,
    frame_count: u32,
    payload_bytes: usize,
    started_at: Instant,
}

impl<W: Write> TzBlockStreamParser<W> {
    fn new(segment_start: u64, segment_end: u64, writer: W) -> Self {
        Self {
            segment_start,
            segment_end,
            expected_next: segment_start,
            magic: Vec::with_capacity(BLOCK_STREAM_MAGIC.len()),
            header: Vec::with_capacity(BLOCK_STREAM_FRAME_HEADER_LEN),
            current_frame: None,
            writer,
            frame_count: 0,
            payload_bytes: 0,
            started_at: Instant::now(),
        }
    }

    fn ingest(&mut self, mut input: &[u8]) -> Result<()> {
        while !input.is_empty() {
            if self.magic.len() < BLOCK_STREAM_MAGIC.len() {
                let need = BLOCK_STREAM_MAGIC.len() - self.magic.len();
                let take = need.min(input.len());
                self.magic.extend_from_slice(&input[..take]);
                input = &input[take..];
                if self.magic.len() == BLOCK_STREAM_MAGIC.len() {
                    anyhow::ensure!(
                        self.magic.as_slice() == BLOCK_STREAM_MAGIC,
                        "invalid tz block stream magic"
                    );
                }
                continue;
            }

            if self.current_frame.is_none() {
                let need = BLOCK_STREAM_FRAME_HEADER_LEN - self.header.len();
                let take = need.min(input.len());
                self.header.extend_from_slice(&input[..take]);
                input = &input[take..];
                if self.header.len() == BLOCK_STREAM_FRAME_HEADER_LEN {
                    self.start_frame()?;
                }
                continue;
            }

            self.write_payload_bytes(&mut input)?;
        }
        Ok(())
    }

    fn start_frame(&mut self) -> Result<()> {
        debug_assert_eq!(self.header.len(), BLOCK_STREAM_FRAME_HEADER_LEN);
        let frame_start = u64::from_be_bytes(self.header[0..8].try_into().unwrap());
        let frame_end = u64::from_be_bytes(self.header[8..16].try_into().unwrap());
        let payload_len = u64::from_be_bytes(self.header[16..24].try_into().unwrap());
        self.header.clear();

        anyhow::ensure!(
            frame_start == self.expected_next,
            "non-contiguous tz block stream frame: expected_start={}, frame_start={}",
            self.expected_next,
            frame_start
        );
        anyhow::ensure!(
            frame_end >= frame_start,
            "invalid tz block stream frame range: frame_start={frame_start}, frame_end={frame_end}"
        );
        anyhow::ensure!(
            frame_end <= self.segment_end,
            "tz block stream frame exceeds requested segment: frame_end={}, segment_end={}",
            frame_end,
            self.segment_end
        );
        anyhow::ensure!(payload_len > 0, "tz block stream frame has empty payload");
        let payload_len_usize: usize =
            payload_len.try_into().context("tz block stream payload length overflows usize")?;
        self.writer.write_all(&payload_len.to_be_bytes())?;
        self.current_frame = Some(PendingBlockStreamFrame {
            start: frame_start,
            end: frame_end,
            payload_len,
            payload_written: 0,
        });
        self.payload_bytes = self
            .payload_bytes
            .checked_add(payload_len_usize)
            .context("tz block stream payload byte count overflow")?;
        Ok(())
    }

    fn write_payload_bytes(&mut self, input: &mut &[u8]) -> Result<()> {
        let frame = self.current_frame.as_mut().expect("current_frame checked by caller");
        let remaining = frame.payload_len - frame.payload_written;
        let take = usize::try_from(remaining.min(input.len() as u64))
            .context("tz block stream payload chunk length overflows usize")?;
        self.writer.write_all(&input[..take])?;
        frame.payload_written += take as u64;
        *input = &input[take..];

        if frame.payload_written == frame.payload_len {
            let frame = self.current_frame.take().unwrap();
            self.finish_frame(frame)?;
        }
        Ok(())
    }

    fn finish_frame(&mut self, frame: PendingBlockStreamFrame) -> Result<()> {
        self.frame_count =
            self.frame_count.checked_add(1).context("tz block stream frame count overflows u32")?;
        self.expected_next = frame.end.saturating_add(1);
        tracing::info!(
            segment_start = self.segment_start,
            segment_end = self.segment_end,
            frame_start = frame.start,
            frame_end = frame.end,
            payload_bytes = frame.payload_len,
            elapsed_ms = self.started_at.elapsed().as_millis() as u64,
            "tz: block stream frame"
        );
        Ok(())
    }

    fn finish(mut self) -> Result<TzBlockStreamSegmentResult> {
        anyhow::ensure!(
            self.magic.len() == BLOCK_STREAM_MAGIC.len(),
            "incomplete tz block stream magic"
        );
        anyhow::ensure!(self.header.is_empty(), "incomplete tz block stream frame header");
        anyhow::ensure!(self.current_frame.is_none(), "incomplete tz block stream frame payload");
        anyhow::ensure!(
            self.expected_next == self.segment_end.saturating_add(1),
            "tz block stream coverage mismatch: segment_start={}, segment_end={}, next_expected={}",
            self.segment_start,
            self.segment_end,
            self.expected_next
        );
        self.writer.flush()?;
        Ok(TzBlockStreamSegmentResult {
            start: self.segment_start,
            end: self.segment_end,
            frame_count: self.frame_count,
            payload_bytes: self.payload_bytes,
        })
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
        matchers::{method, path, query_param},
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

    fn encoded_stream_frame(start: u64, end: u64, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(BLOCK_STREAM_FRAME_HEADER_LEN + payload.len());
        frame.extend_from_slice(&start.to_be_bytes());
        frame.extend_from_slice(&end.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn encoded_stream_body(frames: &[(u64, u64, &[u8])]) -> Vec<u8> {
        let mut body = BLOCK_STREAM_MAGIC.to_vec();
        for (start, end, payload) in frames {
            body.extend_from_slice(&encoded_stream_frame(*start, *end, payload));
        }
        body
    }

    fn encoded_local_payload_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn block_stream_parser_accepts_arbitrary_chunk_boundaries() {
        let payload_a = b"msgpack-a";
        let payload_b = b"msgpack-b-longer";
        let body = encoded_stream_body(&[(10, 11, payload_a), (12, 13, payload_b)]);

        let mut local = Vec::new();
        let mut parser = TzBlockStreamParser::new(10, 13, &mut local);
        let chunk_sizes = [1usize, 2, 3, 5, 8, 13, 21];
        let mut offset = 0usize;
        let mut chunk_idx = 0usize;
        while offset < body.len() {
            let next = (offset + chunk_sizes[chunk_idx % chunk_sizes.len()]).min(body.len());
            parser.ingest(&body[offset..next]).unwrap();
            offset = next;
            chunk_idx += 1;
        }
        let result = parser.finish().unwrap();

        let mut expected = encoded_local_payload_frame(payload_a);
        expected.extend_from_slice(&encoded_local_payload_frame(payload_b));
        assert_eq!(result.frame_count, 2);
        assert_eq!(result.payload_bytes, payload_a.len() + payload_b.len());
        assert_eq!(local, expected);
    }

    #[test]
    fn block_stream_parser_rejects_non_contiguous_frames() {
        let body = encoded_stream_body(&[(10, 11, b"first"), (13, 13, b"gap")]);
        let mut local = Vec::new();
        let mut parser = TzBlockStreamParser::new(10, 13, &mut local);
        let err = parser.ingest(&body).unwrap_err().to_string();
        assert!(err.contains("non-contiguous"), "expected ordering error, got: {err}");
    }

    #[tokio::test]
    async fn stream_blocks_segment_to_file_writes_local_payload_frames() {
        let mock_server = MockServer::start().await;
        let payload_a = b"frame-a";
        let payload_b = b"frame-b";
        let body = encoded_stream_body(&[(10, 11, payload_a), (12, 13, payload_b)]);
        Mock::given(method("GET"))
            .and(path("/chain/blocks/stream"))
            .and(query_param("start", "10"))
            .and(query_param("end", "13"))
            .and(query_param("frame", "2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/x-tz-block-stream")
                    .set_body_bytes(body),
            )
            .mount(&mock_server)
            .await;

        let temp = tempfile::NamedTempFile::new().unwrap();
        let client = TzChainClient::new(vec![mock_server.uri()]);
        let result = client.stream_blocks_segment_to_file(10, 13, 2, temp.path()).await.unwrap();

        let mut expected = encoded_local_payload_frame(payload_a);
        expected.extend_from_slice(&encoded_local_payload_frame(payload_b));
        assert_eq!(result.frame_count, 2);
        assert_eq!(result.payload_bytes, payload_a.len() + payload_b.len());
        assert_eq!(std::fs::read(temp.path()).unwrap(), expected);
    }

    #[tokio::test]
    async fn stream_blocks_segment_to_file_reports_unsupported_for_404() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/blocks/stream"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let temp = tempfile::NamedTempFile::new().unwrap();
        let client = TzChainClient::new(vec![mock_server.uri()]);
        let err = client.stream_blocks_segment_to_file(10, 13, 2, temp.path()).await.unwrap_err();
        assert!(err.downcast_ref::<TzBlockStreamUnsupportedError>().is_some());
    }
}
