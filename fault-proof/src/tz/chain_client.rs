use alloy_primitives::B256;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
#[error("TzChainClient: no cached checkpoint for height {0}")]
pub struct TzCacheMissError(pub u64);

#[derive(Clone, Debug)]
pub struct TzBlockInfo {
    pub height: u64,
    pub block_hash: B256,
    pub state_hash: B256,
}

/// for tz: Phase 2 — Witness Builder task status returned by `poll_witness_task`.
#[derive(Debug)]
pub enum WitnessStatus {
    Pending,
    Running { last_process_blk_height: u64, process_percentage: u32 },
    Finished { start_dex_state_size: u64, avg_blk_size: u64 },
    Failed { reason: String, last_process_blk_height: u64, process_percentage: u32 },
}

pub struct TzChainClient {
    endpoints: Vec<String>,
    pub(crate) history: std::sync::Mutex<HashMap<u64, TzBlockInfo>>,
    client: reqwest::Client,
}

impl TzChainClient {
    pub fn new(endpoints: Vec<String>) -> Self {
        Self {
            endpoints,
            history: std::sync::Mutex::new(HashMap::new()),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
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

    /// for tz: Phase 2 — Create a Witness Builder task for the given block range.
    ///
    /// POST `/zkp/witness` with `{ "startBlkHeight": start, "endBlkHeight": end }`.
    /// Returns the `artifactId` string on success.
    /// Fails over to the next endpoint on HTTP 5xx or connection errors.
    pub async fn create_witness_task(&self, start: u64, end: u64) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct ApiResponse {
            code: i32,
            message: Option<String>,
            data: Option<CreateResponseData>,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CreateResponseData {
            artifact_id: String,
        }

        let body = serde_json::json!({
            "startBlkHeight": start,
            "endBlkHeight": end,
        });

        let mut last_err = anyhow!("no endpoints configured");
        for endpoint in &self.endpoints {
            let url = format!("{}/zkp/witness", endpoint);
            let resp = match self.client.post(&url).json(&body).send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
            };
            if resp.status().is_server_error() {
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
                let msg = api.message.unwrap_or_else(|| format!("code {}", api.code));
                return Err(anyhow!("Witness Builder create_witness_task failed: {}", msg));
            }
            let data =
                api.data.ok_or_else(|| anyhow!("create_witness_task: missing data in response"))?;
            return Ok(data.artifact_id);
        }
        Err(last_err)
    }

    /// for tz: Phase 2 — Poll the status of a Witness Builder task by artifact ID.
    ///
    /// GET `/zkp/witness/{artifact_id}`.
    /// Application-level statuses (Pending/Running/Finished/Failed) are returned as
    /// `Ok(WitnessStatus::...)` and do NOT trigger failover — they represent definitive answers
    /// from the server. Failover only occurs on transport errors (connection failure, HTTP 5xx).
    pub async fn poll_witness_task(&self, artifact_id: &str) -> Result<WitnessStatus> {
        #[derive(serde::Deserialize)]
        struct ApiResponse {
            code: i32,
            message: Option<String>,
            data: Option<PollResponseData>,
        }
        #[derive(serde::Deserialize)]
        struct PollResponseData {
            status: String,
            detail: Option<serde_json::Value>,
        }

        let mut last_err = anyhow!("no endpoints configured");
        for endpoint in &self.endpoints {
            let url = format!("{}/zkp/witness/{}", endpoint, artifact_id);
            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
            };
            if resp.status().is_server_error() {
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
                // code != 0 with no data means the task was not found or an error occurred.
                let msg = api.message.unwrap_or_else(|| format!("code {}", api.code));
                return Err(anyhow!("Witness Builder poll_witness_task failed: {}", msg));
            }
            let data =
                api.data.ok_or_else(|| anyhow!("poll_witness_task: missing data in response"))?;
            let detail = data.detail.unwrap_or(serde_json::Value::Null);
            let status = match data.status.as_str() {
                "Pending" => WitnessStatus::Pending,
                "Running" => {
                    let last_process_blk_height =
                        detail.get("lastProcessBlkHeight").and_then(|v| v.as_u64()).unwrap_or(0);
                    let process_percentage =
                        detail.get("processPercentage").and_then(|v| v.as_u64()).unwrap_or(0)
                            as u32;
                    WitnessStatus::Running { last_process_blk_height, process_percentage }
                }
                "Finished" => {
                    let start_dex_state_size =
                        detail.get("startDexStateSize").and_then(|v| v.as_u64()).unwrap_or(0);
                    let avg_blk_size =
                        detail.get("avgBlkSize").and_then(|v| v.as_u64()).unwrap_or(0);
                    WitnessStatus::Finished { start_dex_state_size, avg_blk_size }
                }
                "Failed" => {
                    let reason =
                        detail.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let last_process_blk_height =
                        detail.get("lastProcessBlkHeight").and_then(|v| v.as_u64()).unwrap_or(0);
                    let process_percentage =
                        detail.get("processPercentage").and_then(|v| v.as_u64()).unwrap_or(0)
                            as u32;
                    WitnessStatus::Failed { reason, last_process_blk_height, process_percentage }
                }
                other => {
                    return Err(anyhow!("poll_witness_task: unknown status '{}'", other));
                }
            };
            return Ok(status);
        }
        Err(last_err)
    }
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

    #[test]
    fn get_confirmed_block_info_at_height_returns_cache_miss() {
        let client = TzChainClient::new(vec!["http://unused".to_string()]);
        let err = client.get_confirmed_block_info_at_height(42).unwrap_err();
        assert!(err.downcast_ref::<TzCacheMissError>().is_some());
    }

    #[tokio::test]
    async fn get_confirmed_block_info_at_height_returns_cached_entry() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": { "height": 100u64, "blockHash": HASH_A, "appHash": HASH_B }
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        client.get_confirmed_block_info().await.unwrap();
        let info = client.get_confirmed_block_info_at_height(100).unwrap();
        assert_eq!(info.height, 100);
    }

    #[test]
    fn evict_below_removes_entries_below_anchor() {
        let client = TzChainClient::new(vec!["http://unused".to_string()]);
        {
            let mut h = client.history.lock().unwrap();
            for height in [10u64, 20, 30, 40] {
                h.insert(
                    height,
                    TzBlockInfo { height, block_hash: B256::ZERO, state_hash: B256::ZERO },
                );
            }
        }
        client.evict_below(25);
        let h = client.history.lock().unwrap();
        assert!(!h.contains_key(&10));
        assert!(!h.contains_key(&20));
        assert!(h.contains_key(&30));
        assert!(h.contains_key(&40));
    }

    // --- Phase 2: Witness Builder tests ---

    #[tokio::test]
    async fn create_witness_task_returns_artifact_id() {
        let mock_server = MockServer::start().await;
        let artifact_uuid = "550e8400-e29b-41d4-a716-446655440000";
        Mock::given(method("POST"))
            .and(path("/zkp/witness"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": { "artifactId": artifact_uuid }
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let id = client.create_witness_task(100, 200).await.unwrap();
        assert_eq!(id, artifact_uuid);
    }

    #[tokio::test]
    async fn create_witness_task_fails_on_non_zero_code() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/zkp/witness"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 40001,
                "message": "invalid range",
                "data": null
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let err = client.create_witness_task(200, 100).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid range"),
            "error must contain server message, got: {err}"
        );
    }

    #[tokio::test]
    async fn poll_witness_task_finished_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zkp/witness/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": {
                    "status": "Finished",
                    "detail": {
                        "startDexStateSize": 100u64,
                        "avgBlkSize": 50u64
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let status = client.poll_witness_task("abc").await.unwrap();
        match status {
            WitnessStatus::Finished { start_dex_state_size, avg_blk_size } => {
                assert_eq!(start_dex_state_size, 100);
                assert_eq!(avg_blk_size, 50);
            }
            other => panic!("expected Finished, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn poll_witness_task_failed_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zkp/witness/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": {
                    "status": "Failed",
                    "detail": {
                        "reason": "oops",
                        "lastProcessBlkHeight": 100u64,
                        "processPercentage": 50u64
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let status = client.poll_witness_task("abc").await.unwrap();
        match status {
            WitnessStatus::Failed { reason, last_process_blk_height, process_percentage } => {
                assert_eq!(reason, "oops");
                assert_eq!(last_process_blk_height, 100);
                assert_eq!(process_percentage, 50);
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn poll_witness_task_pending_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zkp/witness/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": {
                    "status": "Pending",
                    "detail": null
                }
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let status = client.poll_witness_task("abc").await.unwrap();
        assert!(matches!(status, WitnessStatus::Pending));
    }

    #[tokio::test]
    async fn poll_witness_task_failover_on_http_5xx() {
        let good_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zkp/witness/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": {
                    "status": "Pending",
                    "detail": null
                }
            })))
            .mount(&good_server)
            .await;

        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zkp/witness/abc"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&bad_server)
            .await;

        let client = TzChainClient::new(vec![bad_server.uri(), good_server.uri()]);
        let status = client.poll_witness_task("abc").await.unwrap();
        assert!(matches!(status, WitnessStatus::Pending));
    }

    #[tokio::test]
    async fn poll_witness_task_no_failover_on_application_status() {
        // First endpoint returns a valid Pending application status (code=0).
        // A second endpoint should never be reached.
        let first_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zkp/witness/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": {
                    "status": "Pending",
                    "detail": null
                }
            })))
            .expect(1)
            .mount(&first_server)
            .await;

        // Second server is configured but must not be called.
        let second_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zkp/witness/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "data": { "status": "Finished", "detail": { "startDexStateSize": 1u64, "avgBlkSize": 1u64 } }
            })))
            .expect(0)
            .mount(&second_server)
            .await;

        let client = TzChainClient::new(vec![first_server.uri(), second_server.uri()]);
        let status = client.poll_witness_task("abc").await.unwrap();
        assert!(matches!(status, WitnessStatus::Pending));
        // wiremock verifies mock expectations (expect(1) and expect(0)) on drop.
    }

    #[tokio::test]
    async fn poll_witness_task_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zkp/witness/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 40004,
                "message": "witness task not found",
                "data": null
            })))
            .mount(&mock_server)
            .await;

        let client = TzChainClient::new(vec![mock_server.uri()]);
        let err = client.poll_witness_task("abc").await.unwrap_err();
        assert!(
            err.to_string().contains("witness task not found"),
            "error must contain server message, got: {err}"
        );
    }
}
