use std::sync::Arc;

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy_rpc_types_eth::Block;
use anyhow::Result;
use async_trait::async_trait;
use op_alloy_rpc_types::Transaction;

use crate::{
    tz_chain_client::{TzCacheMissError, TzChainClient},
    L2ProviderTrait,
};

pub struct TzL2Provider {
    pub tz_client: Arc<TzChainClient>,
}

/// Compute tz rootClaim: keccak256(blockHash ++ stateHash).
pub fn compute_tz_root_claim(block_hash: B256, state_hash: B256) -> FixedBytes<32> {
    keccak256([block_hash.as_slice(), state_hash.as_slice()].concat())
}

#[async_trait]
impl L2ProviderTrait for TzL2Provider {
    async fn get_l2_block_by_number(
        &self,
        _block_number: BlockNumberOrTag,
    ) -> Result<Block<Transaction>> {
        unreachable!("TzL2Provider does not support get_l2_block_by_number")
    }

    async fn get_l2_storage_root(
        &self,
        _address: Address,
        _block_number: BlockNumberOrTag,
    ) -> Result<B256> {
        unreachable!("TzL2Provider does not support get_l2_storage_root")
    }

    async fn compute_output_root_at_block(&self, l2_block_number: U256) -> Result<FixedBytes<32>> {
        let height = l2_block_number.to::<u64>();
        let info = self.tz_client.get_confirmed_block_info_at_height(height)?;
        Ok(compute_tz_root_claim(info.block_hash, info.state_hash))
    }

    async fn get_next_proposal_block(
        &self,
        canonical_head: U256,
        proposal_interval: u64,
    ) -> Result<Option<U256>> {
        let info = match self.tz_client.get_confirmed_block_info().await {
            Ok(i) => i,
            Err(_) => return Ok(None),
        };
        let confirmed = U256::from(info.height);
        if confirmed.saturating_sub(canonical_head) < U256::from(proposal_interval) {
            return Ok(None);
        }
        Ok(Some(confirmed))
    }

    fn evict_cache_below(&self, anchor_height: u64) {
        self.tz_client.evict_below(anchor_height);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz_chain_client::TzBlockInfo;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    const HASH_A: &str =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str =
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn hash_a() -> B256 { HASH_A.parse().unwrap() }
    fn hash_b() -> B256 { HASH_B.parse().unwrap() }

    #[test]
    fn compute_tz_root_claim_matches_manual_keccak() {
        let expected = keccak256(
            [hash_a().as_slice(), hash_b().as_slice()].concat()
        );
        assert_eq!(compute_tz_root_claim(hash_a(), hash_b()), expected);
    }

    #[test]
    fn compute_tz_root_claim_differs_for_swapped_inputs() {
        let ab = compute_tz_root_claim(hash_a(), hash_b());
        let ba = compute_tz_root_claim(hash_b(), hash_a());
        assert_ne!(ab, ba);
    }

    fn make_provider_with_cached(height: u64, block_hash: B256, state_hash: B256) -> TzL2Provider {
        let client = Arc::new(TzChainClient::new(vec!["http://unused".to_string()]));
        {
            let mut h = client.history.lock().unwrap();
            h.insert(height, TzBlockInfo { height, block_hash, state_hash });
        }
        TzL2Provider { tz_client: client }
    }

    #[tokio::test]
    async fn compute_output_root_cache_hit_returns_correct_hash() {
        let provider = make_provider_with_cached(100, hash_a(), hash_b());
        let result = provider.compute_output_root_at_block(U256::from(100u64)).await.unwrap();
        assert_eq!(result, compute_tz_root_claim(hash_a(), hash_b()));
    }

    #[tokio::test]
    async fn compute_output_root_cache_miss_returns_tz_cache_miss_error() {
        let provider = make_provider_with_cached(100, hash_a(), hash_b());
        let err = provider
            .compute_output_root_at_block(U256::from(999u64))
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<TzCacheMissError>().is_some());
        assert_eq!(err.downcast_ref::<TzCacheMissError>().unwrap().0, 999);
    }

    #[tokio::test]
    async fn get_next_proposal_block_returns_none_when_interval_not_met() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0, "message": "ok",
                "data": { "height": 1050u64, "blockHash": HASH_A, "stateHash": HASH_B }
            })))
            .mount(&mock_server)
            .await;

        let client = Arc::new(TzChainClient::new(vec![mock_server.uri()]));
        let provider = TzL2Provider { tz_client: client };
        // canonical_head=1000, interval=100 => need confirmed >= 1100; got 1050 → None
        let result = provider
            .get_next_proposal_block(U256::from(1000u64), 100)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_next_proposal_block_returns_confirmed_when_interval_met() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0, "message": "ok",
                "data": { "height": 1200u64, "blockHash": HASH_A, "stateHash": HASH_B }
            })))
            .mount(&mock_server)
            .await;

        let client = Arc::new(TzChainClient::new(vec![mock_server.uri()]));
        let provider = TzL2Provider { tz_client: client };
        // canonical_head=1000, interval=100 => need confirmed >= 1100; got 1200 → Some(1200)
        let result = provider
            .get_next_proposal_block(U256::from(1000u64), 100)
            .await
            .unwrap();
        assert_eq!(result, Some(U256::from(1200u64)));
    }

    #[tokio::test]
    async fn get_next_proposal_block_returns_none_on_api_error() {
        let client = Arc::new(TzChainClient::new(vec!["http://127.0.0.1:1".to_string()]));
        let provider = TzL2Provider { tz_client: client };
        let result = provider
            .get_next_proposal_block(U256::from(0u64), 100)
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
