use std::collections::HashMap;
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
                h.insert(height, TzBlockInfo {
                    height,
                    block_hash: B256::ZERO,
                    state_hash: B256::ZERO,
                });
            }
        }
        client.evict_below(25);
        let h = client.history.lock().unwrap();
        assert!(!h.contains_key(&10));
        assert!(!h.contains_key(&20));
        assert!(h.contains_key(&30));
        assert!(h.contains_key(&40));
    }
}
