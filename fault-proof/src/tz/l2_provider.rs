use std::sync::Arc;

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, FixedBytes, B256, U256};
use alloy_rpc_types_eth::Block;
use anyhow::{bail, Result};
use async_trait::async_trait;
use op_alloy_rpc_types::Transaction;

use super::{
    chain_client::{TzCacheMissError, TzChainClient},
    confirmed_height_tracker::ConfirmedHeightTracker,
    withdraw::{
        claim::claim_root,
        types::{GameCheckpointPreimage, TreeBoundaryWitness},
        wb_client::WbClient,
    },
};
use crate::L2ProviderTrait;

pub struct TzL2Provider {
    pub tz_client: Arc<TzChainClient>,
    /// Confirmed-height stagnation tracker. Shared with the proposer so every clone observes into
    /// one tracker for the process.
    confirmed_height_tracker: Arc<ConfirmedHeightTracker>,
    /// Witness Builder v2 client. Required for the four-field claim path (checkpoint components +
    /// boundary witness); `None` only in isolated unit tests that exercise the chain-client cache.
    pub wb: Option<Arc<WbClient>>,
}

impl TzL2Provider {
    /// Builds a provider that shares its confirmed-height tracker with the caller.
    ///
    /// Sharing the same `Arc` with the proposer keeps a single tracker for the process, so
    /// every clone of the proposer observes into one set of state. Call [`Self::with_wb`] to
    /// enable the four-field claim path.
    pub fn new(tz_client: Arc<TzChainClient>, tracker: Arc<ConfirmedHeightTracker>) -> Self {
        Self { tz_client, confirmed_height_tracker: tracker, wb: None }
    }

    /// Attaches a Witness Builder v2 client, enabling the four-field claim path.
    pub fn with_wb(mut self, wb: Arc<WbClient>) -> Self {
        self.wb = Some(wb);
        self
    }
}

/// Compute the four-field tz `claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖
/// forceRoot)` (spec §4/§7.2). Delegates to the canonical `withdraw::claim::claim_root` codec so
/// there is a single 128-byte-preimage source shared with the challenger and the contract.
pub fn compute_tz_root_claim(
    block_hash: B256,
    app_hash: B256,
    withdrawal_root: B256,
    force_root: B256,
) -> FixedBytes<32> {
    claim_root(block_hash, app_hash, withdrawal_root, force_root)
}

/// Cross-check a boundary witness against the same-height checkpoint (spec §7.2 Range Host): a
/// mismatch means the sub-range must fail + alert.
///
/// R2 #2: `TreeBoundaryWitness` carries NO chainId, so the chainId consistency guard lives solely
/// on the checkpoint top level (the caller passes the checkpoint's `chain_id` and asserts it is a
/// valid non-zero TZ chain). The boundary's own invariant is the popcount wire rule.
pub fn assert_boundary_consistent(
    boundary: &TreeBoundaryWitness,
    checkpoint_chain_id: u64,
) -> Result<()> {
    if checkpoint_chain_id == 0 {
        bail!("tz boundary cross-check: checkpoint chain_id must be non-zero");
    }
    // count == 0 ⇒ active_branches empty; otherwise len == popcount(count) (spec §4 wire).
    if boundary.withdrawal_active_branches.len() != boundary.withdrawal_count.count_ones() as usize ||
        boundary.force_active_branches.len() != boundary.force_count.count_ones() as usize
    {
        bail!("tz boundary cross-check: active_branches length != popcount(count)");
    }
    Ok(())
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
        // Single source: the four validated preimage fields, hashed via the shared claim codec.
        let p = self.fetch_checkpoint_preimage_at_block(l2_block_number).await?;
        Ok(compute_tz_root_claim(p.block_hash, p.app_hash, p.withdrawal_root, p.force_root))
    }

    fn tz_chain_id(&self) -> Option<u64> {
        // The WB client's configured chain id is the single Host source (TzConfig TZ chainId), and
        // is itself the §5.3 chainId guard authority. `None` when built without a WB (unit tests).
        self.wb.as_ref().map(|wb| wb.chain_id())
    }

    async fn fetch_checkpoint_preimage_at_block(
        &self,
        l2_block_number: U256,
    ) -> Result<GameCheckpointPreimage> {
        let height = l2_block_number.to::<u64>();
        let cached_info = match self.tz_client.get_confirmed_block_info_at_height(height) {
            Ok(info) => Some(info),
            Err(err) if self.wb.is_some() && err.downcast_ref::<TzCacheMissError>().is_some() => {
                None
            }
            Err(err) => return Err(err),
        };
        // Four-field claim: blockHash/appHash come from the confirmed block info; withdrawalRoot/
        // forceRoot come from the WB CheckpointV2. Cross-check the shared fields for consistency.
        let Some(wb) = self.wb.as_ref() else {
            bail!(
                "tz: four-field claimRoot requires a witness-builder client; TzL2Provider was \
                 built without one"
            );
        };
        let env = wb
            .get_checkpoint_v2(height)
            .await
            .map_err(|e| anyhow::anyhow!("tz: witness-builder checkpoint at {height}: {e}"))?;
        // R2 #3: chainId is guarded inside `get_checkpoint_v2` against the client's configured
        // chain and carried on the envelope, never inside the checkpoint body.
        let cp = &env.checkpoint;
        if cp.block_height != height {
            bail!(
                "tz: witness-builder checkpoint height mismatch: requested {height}, got {}",
                cp.block_height
            );
        }
        if let Some(info) = cached_info {
            if cp.block_hash != info.block_hash || cp.app_hash != info.state_hash {
                bail!(
                    "tz: checkpoint components at {height} disagree with confirmed block info \
                     (blockHash/appHash mismatch)"
                );
            }
        }
        Ok(GameCheckpointPreimage {
            checkpoint_block_height: height,
            // Unset sentinel — `handle_game_creation` overwrites with the real parent game index
            // before encoding extraData (spec §R3.3).
            parent_index: u32::MAX,
            block_hash: cp.block_hash,
            app_hash: cp.app_hash,
            withdrawal_root: cp.withdrawal_root,
            force_root: cp.force_root,
        })
    }

    async fn fetch_tree_boundary_witness(&self, height: u64) -> Result<TreeBoundaryWitness> {
        let Some(wb) = self.wb.as_ref() else {
            bail!("tz: fetch_tree_boundary_witness requires a witness-builder client");
        };
        wb.get_tree_boundary_witness(height)
            .await
            .map_err(|e| anyhow::anyhow!("tz: witness-builder boundary at {height}: {e}"))
    }

    async fn get_next_proposal_block(
        &self,
        canonical_head: U256,
        proposal_interval: u64,
    ) -> Result<Option<U256>> {
        let info = match self.tz_client.get_confirmed_block_info().await {
            Ok(i) => {
                // Record the height on every successful read, before the interval check, so a
                // height that stops advancing is tracked even while it is still below the
                // proposal interval. A failed read returns early below and records nothing:
                // an error carries no height, and one must never be invented.
                self.confirmed_height_tracker.observe(i.height);
                i
            }
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

    async fn refresh_checkpoint_cache(&self) -> Result<()> {
        self.tz_client.get_confirmed_block_info().await?;
        Ok(())
    }

    async fn fetch_dex_state_snapshot(&self, height: u64) -> Result<Vec<u8>> {
        self.tz_client.get_dex_state_snapshot(height).await
    }

    async fn fetch_blocks_range(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        self.tz_client.get_blocks_range(start, end).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{
        super::{
            chain_client::{TzBlockInfo, TzCacheMissError},
            confirmed_height_tracker::test_support::capture_warns,
        },
        *,
    };
    use tokio::time::Duration;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, Respond, ResponseTemplate,
    };

    const HASH_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn hash_a() -> B256 {
        HASH_A.parse().unwrap()
    }
    fn hash_b() -> B256 {
        HASH_B.parse().unwrap()
    }

    fn wr() -> B256 {
        B256::repeat_byte(0x33)
    }
    fn fr() -> B256 {
        B256::repeat_byte(0x44)
    }

    fn height_response(height: u64) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "height": height, "blockHash": HASH_A, "appHash": HASH_B }
        }))
    }

    /// Replies with a scripted sequence of responses, one per request, so a test can drive a
    /// failed read and a later successful read deterministically.
    struct ScriptedResponses {
        remaining: std::sync::Mutex<VecDeque<ResponseTemplate>>,
    }

    impl Respond for ScriptedResponses {
        fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
            self.remaining
                .lock()
                .unwrap()
                .pop_front()
                .expect("the test scripted more requests than it issued")
        }
    }

    /// Builds a provider backed by a scripted endpoint. The `MockServer` is returned so the
    /// caller keeps it alive for the duration of the test.
    async fn provider_with_script(
        responses: Vec<ResponseTemplate>,
        threshold_secs: u64,
    ) -> (TzL2Provider, Arc<ConfirmedHeightTracker>, MockServer) {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ScriptedResponses { remaining: std::sync::Mutex::new(responses.into()) })
            .mount(&mock_server)
            .await;

        let client = Arc::new(TzChainClient::new(vec![mock_server.uri()]));
        let tracker = Arc::new(ConfirmedHeightTracker::new(threshold_secs));
        let provider = TzL2Provider::new(client, Arc::clone(&tracker));
        (provider, tracker, mock_server)
    }

    /// Reads the elapsed seconds out of a stagnation warning message.
    fn warned_seconds(message: &str) -> u64 {
        message
            .split("unchanged for ")
            .nth(1)
            .and_then(|rest| rest.split('s').next())
            .and_then(|secs| secs.parse().ok())
            .unwrap_or_else(|| panic!("no elapsed seconds in {message}"))
    }

    #[test]
    fn compute_tz_root_claim_matches_four_field_codec() {
        assert_eq!(
            compute_tz_root_claim(hash_a(), hash_b(), wr(), fr()),
            super::super::withdraw::claim::claim_root(hash_a(), hash_b(), wr(), fr())
        );
    }

    #[test]
    fn compute_tz_root_claim_is_order_sensitive() {
        let a = compute_tz_root_claim(hash_a(), hash_b(), wr(), fr());
        let b = compute_tz_root_claim(hash_b(), hash_a(), wr(), fr());
        assert_ne!(a, b);
    }

    #[test]
    fn boundary_consistency_checks_chain_id_and_popcount() {
        // R2 #2: the witness carries NO chain_id; the chain guard is the `checkpoint_chain_id`
        // argument (checkpoint top level), the witness's own invariant is the popcount wire rule.
        let ok = TreeBoundaryWitness {
            schema_version: 2,
            block_height: 50,
            block_hash: B256::repeat_byte(0xbb),
            withdrawal_count: 2, // popcount(2) == 1
            withdrawal_active_branches: vec![B256::repeat_byte(0x11)],
            force_count: 0,
            force_active_branches: vec![],
        };
        assert!(assert_boundary_consistent(&ok, 196).is_ok());
        // checkpoint chain_id == 0 is rejected (guard lives on the checkpoint top level).
        assert!(assert_boundary_consistent(&ok, 0).is_err());
        // popcount mismatch
        let mut bad = ok.clone();
        bad.withdrawal_active_branches.push(B256::repeat_byte(0x22));
        assert!(assert_boundary_consistent(&bad, 196).is_err());
    }

    fn make_provider_with_cached(height: u64, block_hash: B256, state_hash: B256) -> TzL2Provider {
        let client = Arc::new(TzChainClient::new(vec!["http://unused".to_string()]));
        {
            let mut h = client.history.lock().unwrap();
            h.insert(height, TzBlockInfo { height, block_hash, state_hash });
        }
        TzL2Provider::new(client, Arc::new(ConfirmedHeightTracker::new(300)))
    }

    #[tokio::test]
    async fn compute_output_root_builds_from_wb_without_confirmed_cache() {
        // The historical WB checkpoint is sufficient even when latest-only block info is absent.
        let claim = super::super::withdraw::claim::claim_root(hash_a(), hash_b(), wr(), fr());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0, "message": "ok", "data": {
                    "schemaVersion": 2, "chainId": 196, "height": 100, "status": "ready",
                    "claimRoot": claim, "canonicalBlockHash": hash_a(),
                    "appHash": hash_b(), "withdrawalRoot": wr(),
                    "forceRoot": fr()
                }
            })))
            .mount(&server)
            .await;
        let client = Arc::new(TzChainClient::new(vec!["http://unused".to_string()]));
        let wb = Arc::new(WbClient::new(server.uri().parse().unwrap(), 196).unwrap());
        let provider =
            TzL2Provider::new(client, Arc::new(ConfirmedHeightTracker::new(300))).with_wb(wb);
        let result = provider.compute_output_root_at_block(U256::from(100u64)).await.unwrap();
        assert_eq!(result, claim);
    }

    #[tokio::test]
    async fn compute_output_root_rejects_wrong_height_wb_checkpoint_without_cache() {
        let claim = super::super::withdraw::claim::claim_root(hash_a(), hash_b(), wr(), fr());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0, "message": "ok", "data": {
                    "schemaVersion": 2, "chainId": 196, "height": 101, "status": "ready",
                    "claimRoot": claim, "canonicalBlockHash": hash_a(),
                    "appHash": hash_b(), "withdrawalRoot": wr(),
                    "forceRoot": fr()
                }
            })))
            .mount(&server)
            .await;
        let client = Arc::new(TzChainClient::new(vec!["http://unused".to_string()]));
        let wb = Arc::new(WbClient::new(server.uri().parse().unwrap(), 196).unwrap());
        let provider =
            TzL2Provider::new(client, Arc::new(ConfirmedHeightTracker::new(300))).with_wb(wb);
        let err = provider.compute_output_root_at_block(U256::from(100u64)).await.unwrap_err();
        assert!(err.to_string().contains("height"));
    }

    #[tokio::test]
    async fn compute_output_root_without_wb_errors() {
        let provider = make_provider_with_cached(100, hash_a(), hash_b());
        let err = provider.compute_output_root_at_block(U256::from(100u64)).await.unwrap_err();
        assert!(err.to_string().contains("witness-builder"));
    }

    #[tokio::test]
    async fn compute_output_root_cache_miss_returns_tz_cache_miss_error() {
        let provider = make_provider_with_cached(100, hash_a(), hash_b());
        let err = provider.compute_output_root_at_block(U256::from(999u64)).await.unwrap_err();
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
                "data": { "height": 1050u64, "blockHash": HASH_A, "appHash": HASH_B }
            })))
            .mount(&mock_server)
            .await;

        let client = Arc::new(TzChainClient::new(vec![mock_server.uri()]));
        let provider = TzL2Provider::new(client, Arc::new(ConfirmedHeightTracker::new(300)));
        let result = provider.get_next_proposal_block(U256::from(1000u64), 100).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_next_proposal_block_returns_next_interval_when_confirmed_is_ahead() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0, "message": "ok",
                "data": { "height": 1200u64, "blockHash": HASH_A, "appHash": HASH_B }
            })))
            .mount(&mock_server)
            .await;

        let client = Arc::new(TzChainClient::new(vec![mock_server.uri()]));
        let provider = TzL2Provider::new(client, Arc::new(ConfirmedHeightTracker::new(300)));
        let result = provider.get_next_proposal_block(U256::from(1000u64), 100).await.unwrap();
        assert_eq!(result, Some(U256::from(1200u64)));
    }

    #[tokio::test]
    async fn get_next_proposal_block_returns_none_on_api_error() {
        let client = Arc::new(TzChainClient::new(vec!["http://127.0.0.1:1".to_string()]));
        let provider = TzL2Provider::new(client, Arc::new(ConfirmedHeightTracker::new(300)));
        let result = provider.get_next_proposal_block(U256::from(0u64), 100).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn refresh_checkpoint_cache_populates_history() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/confirmed_block_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0, "message": "ok",
                "data": { "height": 500u64, "blockHash": HASH_A, "appHash": HASH_B }
            })))
            .mount(&mock_server)
            .await;

        let client = Arc::new(TzChainClient::new(vec![mock_server.uri()]));
        let provider =
            TzL2Provider::new(Arc::clone(&client), Arc::new(ConfirmedHeightTracker::new(300)));

        provider.refresh_checkpoint_cache().await.unwrap();

        let cached = client.get_confirmed_block_info_at_height(500).unwrap();
        assert_eq!(cached.block_hash, hash_a());
        assert_eq!(cached.state_hash, hash_b());
    }

    #[tokio::test]
    async fn refresh_checkpoint_cache_returns_err_on_api_failure() {
        let client = Arc::new(TzChainClient::new(vec!["http://127.0.0.1:1".to_string()]));
        let provider = TzL2Provider::new(client, Arc::new(ConfirmedHeightTracker::new(300)));
        assert!(provider.refresh_checkpoint_cache().await.is_err());
    }

    // A height that stays below the proposal interval is still observed on every successful
    // read, but no warning is emitted while the elapsed time is under the threshold.
    //
    // These integration tests use the real clock: under a paused clock tokio advances time
    // while the runtime waits on I/O, which trips the request timeout and makes every fetch
    // fail. Staleness is therefore asserted with a threshold far above the (sub-millisecond)
    // real elapsed time for the negative cases, and a short threshold plus a sleep past it for
    // the positive ones.
    #[tokio::test]
    async fn stagnation_below_interval_no_warn_before_threshold() {
        let (capture, _guard) = capture_warns();
        let (provider, tracker, _server) =
            provider_with_script(vec![height_response(950), height_response(950)], 300).await;

        let first = provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap();
        assert_eq!(first, None, "950 is below 900 + 100");
        assert_eq!(tracker.last_observed_height(), Some(950));

        let second = provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap();
        assert_eq!(second, None, "still below the proposal interval");

        assert_eq!(capture.warn_count(), 0, "elapsed time is far under the 300s threshold");
    }

    // Once the unchanged height passes the threshold the warning appears, and it repeats on
    // every later observation instead of being emitted only once.
    #[tokio::test]
    async fn stagnation_below_interval_warns_after_threshold_and_repeats() {
        let (capture, _guard) = capture_warns();
        let (provider, _tracker, _server) =
            provider_with_script(vec![height_response(950); 3], 1).await;

        assert_eq!(provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(), None);

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(), None);
        let messages = capture.messages();
        assert_eq!(messages.len(), 1, "one warning after the threshold is crossed");
        assert!(
            messages[0].contains("confirmed height 950 unchanged for"),
            "unexpected message: {}",
            messages[0]
        );
        assert!(messages[0].contains("(threshold 1s)"), "unexpected message: {}", messages[0]);
        assert!(warned_seconds(&messages[0]) >= 1);

        assert_eq!(provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(), None);
        assert_eq!(capture.warn_count(), 2, "the warning is not suppressed");
    }

    // A failed read must not be treated as an observation: no height is invented, the tracker
    // keeps the last successfully observed height, and the staleness timer keeps running from
    // that success rather than being restarted by the failure.
    #[tokio::test]
    async fn stagnation_failed_read_records_no_observation() {
        let (capture, _guard) = capture_warns();
        let (provider, tracker, _server) = provider_with_script(
            vec![
                ResponseTemplate::new(500),
                height_response(950),
                ResponseTemplate::new(500),
                height_response(950),
            ],
            1,
        )
        .await;

        // A failure on the very first read leaves the tracker empty — nothing was observed.
        assert_eq!(provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(), None);
        assert_eq!(tracker.last_observed_height(), None, "a failed read must not invent a height");

        // First success: the staleness timer starts here.
        assert_eq!(provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(), None);
        assert_eq!(tracker.last_observed_height(), Some(950));

        // Past the threshold, another failure must stay silent: had the failure observed, the
        // unchanged height would have produced a warning here.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(), None);
        assert_eq!(tracker.last_observed_height(), Some(950));
        assert_eq!(capture.warn_count(), 0, "a failed read is not an observation");

        // The next success still measures staleness from the last success, so the failures did
        // not restart the timer either.
        assert_eq!(provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(), None);
        let messages = capture.messages();
        assert_eq!(messages.len(), 1);
        assert!(warned_seconds(&messages[0]) >= 1);
    }

    // A successful read that returns a different height restarts the timer, and staleness is
    // measured from that change onward.
    #[tokio::test]
    async fn stagnation_height_change_resets_then_stagnates() {
        let (capture, _guard) = capture_warns();
        let (provider, tracker, _server) = provider_with_script(
            vec![height_response(950), height_response(1050), height_response(1050)],
            1,
        )
        .await;

        assert_eq!(provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(), None);

        // The height moved past the interval, so a proposal is produced and the timer resets.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            provider.get_next_proposal_block(U256::from(900u64), 100).await.unwrap(),
            Some(U256::from(1050u64))
        );
        assert_eq!(tracker.last_observed_height(), Some(1050));
        assert_eq!(capture.warn_count(), 0, "a changed height resets the timer");

        // The new height then stalls past the threshold.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(provider.get_next_proposal_block(U256::from(1050u64), 100).await.unwrap(), None);
        let messages = capture.messages();
        assert_eq!(messages.len(), 1);
        assert!(
            messages[0].contains("confirmed height 1050 unchanged for"),
            "unexpected message: {}",
            messages[0]
        );
        assert!(warned_seconds(&messages[0]) >= 1);
    }
}
