//! Single-challenge Defender state machine (spec §7.4 / Protocol §6.2).
//!
//! One [`Handler::handle`] call drives one still-responsive `ChallengeOpened` from discovery to
//! either an on-chain `proveChallenge` or a well-defined non-send outcome. Every wait is bounded
//! by the on-chain response deadline; a proof is verified locally before any transaction; a cache
//! hit still re-checks on-chain status + deadline; and no transaction is ever sent when the
//! challenge is closed, the deadline has passed, or the proof fails local verification.

use std::sync::Arc;
use std::sync::Mutex;

use alloy_primitives::{B256, TxHash};
use anyhow::Result;
use async_trait::async_trait;

use crate::tz::withdraw::error::WbError;
use crate::tz::withdraw::types::HistoricalInclusionProof;

use super::cache::ProofCache;
use super::challenge_contract::{ChallengeContract, ChallengeOpened};
use super::rootmanager_client::CoveringRootSource;
use super::verifier::verify_inclusion;

/// Source of Witness Builder facts the handler needs: the canonical record height for a leaf, and
/// a historical inclusion proof bound to an exact `(checkpoint_height, withdrawal_root)`.
#[async_trait]
pub trait WitnessSource: Send + Sync {
    /// Canonical block height at which the record for `leaf_hash` was included (from WB, not the
    /// caller). `WithdrawalNotFound` / `NotReady` mean "not yet" and may be retried before deadline.
    async fn canonical_record_height(&self, leaf_hash: B256) -> Result<u64, WbError>;
    /// Historical inclusion proof for `leaf_hash` at an exact `(checkpoint_height, withdrawal_root)`.
    async fn historical_proof(
        &self,
        leaf_hash: B256,
        checkpoint_height: u64,
        withdrawal_root: B256,
    ) -> Result<HistoricalInclusionProof, WbError>;
}

/// Why the handler did not (yet) submit a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    AlreadyClosed,
    DeadlinePassed,
    OtherResponderWon,
}

/// Why the handler wants to be retried later (still before deadline).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryReason {
    WaitingForRecord,
    WaitingForCoveringRoot,
    TransientWitnessError,
}

/// The result of handling one challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandlerOutcome {
    /// Proof submitted on-chain.
    Proved(TxHash),
    /// No response needed / possible (not an error).
    Skipped(SkipReason),
    /// Retry later; the condition is expected to resolve before the deadline.
    Retry(RetryReason),
    /// Deadline reached with no usable proof — stop responding and alert.
    StoppedNoProof,
    /// Local proof verification failed — never send a transaction; alert (WB/protocol mismatch).
    VerifyFailed,
    /// Submitting the proof transaction failed (revert / lost race at submit time).
    SubmitFailed,
}

/// The Defender's per-challenge handler. Generic over the three seams so it is fully unit-testable
/// with in-memory mocks.
pub struct Handler {
    challenge: Arc<dyn ChallengeContract>,
    witness: Arc<dyn WitnessSource>,
    root_manager: Arc<dyn CoveringRootSource>,
    cache: Mutex<ProofCache>,
    deadline_safety_margin_secs: u64,
}

impl Handler {
    pub fn new(
        challenge: Arc<dyn ChallengeContract>,
        witness: Arc<dyn WitnessSource>,
        root_manager: Arc<dyn CoveringRootSource>,
        cache_capacity: usize,
        deadline_safety_margin_secs: u64,
    ) -> Self {
        Self {
            challenge,
            witness,
            root_manager,
            cache: Mutex::new(ProofCache::new(cache_capacity)),
            deadline_safety_margin_secs,
        }
    }

    /// Whether there is still enough time before `deadline` (with safety margin) to keep working.
    fn has_time(&self, now: u64, deadline: u64) -> bool {
        now.saturating_add(self.deadline_safety_margin_secs) < deadline
    }

    /// Drive one challenge. `now` is the current unix time (injected for deterministic tests).
    pub async fn handle(&self, ev: &ChallengeOpened, now: u64) -> Result<HandlerOutcome> {
        // 1. Is the challenge still open and within its deadline?
        let status = self.challenge.get_challenge(ev.leaf_hash).await?;
        if !status.open {
            return Ok(HandlerOutcome::Skipped(SkipReason::AlreadyClosed));
        }
        if now >= status.deadline {
            return Ok(HandlerOutcome::Skipped(SkipReason::DeadlinePassed));
        }

        // 2. Canonical record height comes from the WB, not the caller.
        let record_height = match self.witness.canonical_record_height(ev.leaf_hash).await {
            Ok(h) => h,
            Err(e) => {
                return Ok(self.classify_wait(e, now, status.deadline, RetryReason::WaitingForRecord));
            }
        };

        // 3. Wait for a finalized RootManager checkpoint that covers the record.
        let (checkpoint_height, withdrawal_root) =
            match self.root_manager.latest_finalized_covering(record_height).await? {
                Some(pair) => pair,
                None => {
                    if self.has_time(now, status.deadline) {
                        return Ok(HandlerOutcome::Retry(RetryReason::WaitingForCoveringRoot));
                    }
                    return Ok(HandlerOutcome::StoppedNoProof);
                }
            };

        // 4. Obtain the proof: LRU cache first, else the WB at that exact root.
        let key = (ev.leaf_hash, withdrawal_root);
        let cached = self.cache.lock().unwrap().get(&key);
        let proof = match cached {
            Some(p) => p,
            None => match self
                .witness
                .historical_proof(ev.leaf_hash, checkpoint_height, withdrawal_root)
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    return Ok(self.classify_wait(
                        e,
                        now,
                        status.deadline,
                        RetryReason::TransientWitnessError,
                    ));
                }
            },
        };

        // 5. Local verification — any failure means NO transaction (alert).
        if verify_inclusion(&proof, withdrawal_root).is_err() {
            return Ok(HandlerOutcome::VerifyFailed);
        }
        // Cache the verified proof (bound to the exact (leaf, root) key).
        self.cache.lock().unwrap().put(key, proof.clone());

        // 6. Re-check on-chain status + deadline before submitting (even on a cache hit).
        let status2 = self.challenge.get_challenge(ev.leaf_hash).await?;
        if !status2.open {
            return Ok(HandlerOutcome::Skipped(SkipReason::OtherResponderWon));
        }
        if now >= status2.deadline {
            return Ok(HandlerOutcome::Skipped(SkipReason::DeadlinePassed));
        }

        // 7. Submit.
        match self
            .challenge
            .prove_challenge(
                ev.leaf_hash,
                checkpoint_height,
                proof.leaf_index,
                proof.count,
                proof.siblings,
            )
            .await
        {
            Ok(tx) => Ok(HandlerOutcome::Proved(tx)),
            Err(_) => Ok(HandlerOutcome::SubmitFailed),
        }
    }

    /// Map a witness error + time budget to a Retry (before deadline) or StoppedNoProof (at/after).
    ///
    /// A "wait" condition means the data may still arrive: `NotReady`, transient transport, and
    /// `WithdrawalNotFound` — the latter because the record may simply not be included yet
    /// (spec §7.4 groups WithdrawalNotFound WITH NotReady for the record wait). A genuinely
    /// permanent protocol error (`RootMismatch` / `WitnessStoreCorrupt` / bad request) is never
    /// waited on: no transaction is sent and the caller alerts.
    fn classify_wait(
        &self,
        err: WbError,
        now: u64,
        deadline: u64,
        retry_reason: RetryReason,
    ) -> HandlerOutcome {
        let is_wait = err.is_retryable() || matches!(err, WbError::WithdrawalNotFound);
        if !is_wait {
            HandlerOutcome::VerifyFailed
        } else if self.has_time(now, deadline) {
            HandlerOutcome::Retry(retry_reason)
        } else {
            HandlerOutcome::StoppedNoProof
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::defender::challenge_contract::{ChallengeStatus, MockChallengeContract};
    use crate::tz::defender::rootmanager_client::MockRootManager;
    use crate::tz::withdraw::tree_adapter::single_leaf_withdrawal_fixture;
    use crate::tz::withdraw::types::WithdrawRecord;
    use alloy_primitives::{Address, B256};
    use std::sync::Mutex as StdMutex;

    const LEAF: [u8; 1] = [0x42];
    const SAFETY: u64 = 100;

    fn record() -> WithdrawRecord {
        WithdrawRecord {
            version: 1,
            chain_id: 196,
            transaction_hash: B256::ZERO,
            token_type: 0,
            token_address: Address::ZERO,
            token_ids: vec![],
            amounts: vec![],
            from: Address::ZERO,
            to: Address::ZERO,
        }
    }

    /// Build a valid count==1 proof for `leaf` and return `(proof, withdrawal_root)`, via the
    /// tz-witness-backed test fixture.
    fn valid_proof(leaf: B256) -> (HistoricalInclusionProof, B256) {
        let (siblings, root) = single_leaf_withdrawal_fixture(leaf);
        let proof = HistoricalInclusionProof {
            record: record(),
            record_hash: leaf,
            leaf_hash: leaf,
            canonical_block_height: 10,
            checkpoint_height: 20,
            withdrawal_root: root,
            leaf_index: 0,
            count: 1,
            siblings,
        };
        (proof, root)
    }

    /// Configurable mock witness.
    struct MockWitness {
        record_height: StdMutex<Result<u64, WbError>>,
        proof: StdMutex<Result<HistoricalInclusionProof, WbError>>,
        proof_calls: StdMutex<u32>,
    }
    impl MockWitness {
        fn new(height: u64, proof: HistoricalInclusionProof) -> Self {
            Self {
                record_height: StdMutex::new(Ok(height)),
                proof: StdMutex::new(Ok(proof)),
                proof_calls: StdMutex::new(0),
            }
        }
        fn set_record_err(&self, e: WbError) {
            *self.record_height.lock().unwrap() = Err(e);
        }
    }
    #[async_trait]
    impl WitnessSource for MockWitness {
        async fn canonical_record_height(&self, _leaf: B256) -> Result<u64, WbError> {
            self.record_height.lock().unwrap().clone()
        }
        async fn historical_proof(
            &self,
            _leaf: B256,
            _cp: u64,
            _root: B256,
        ) -> Result<HistoricalInclusionProof, WbError> {
            *self.proof_calls.lock().unwrap() += 1;
            self.proof.lock().unwrap().clone()
        }
    }

    fn leaf() -> B256 {
        B256::repeat_byte(LEAF[0])
    }

    fn setup(
        deadline: u64,
        rm_height: Option<u64>,
    ) -> (Arc<MockChallengeContract>, Handler, B256) {
        let l = leaf();
        let (proof, root) = valid_proof(l);
        let cc = Arc::new(MockChallengeContract::new());
        cc.set_status(l, ChallengeStatus { open: true, deadline });
        let witness = Arc::new(MockWitness::new(10, proof));
        let rm = Arc::new(MockRootManager::new());
        if let Some(h) = rm_height {
            rm.record(h, root);
        }
        let handler = Handler::new(cc.clone(), witness, rm, 16, SAFETY);
        (cc, handler, root)
    }

    fn ev() -> ChallengeOpened {
        ChallengeOpened {
            chain_id: 196,
            contract: Address::repeat_byte(0x01),
            tx_hash: B256::repeat_byte(0x02),
            log_index: 0,
            leaf_hash: leaf(),
            block_number: 10,
        }
    }

    #[tokio::test]
    async fn happy_path_verifies_and_proves() {
        let (cc, handler, _root) = setup(10_000, Some(20));
        let outcome = handler.handle(&ev(), 0).await.unwrap();
        assert!(matches!(outcome, HandlerOutcome::Proved(_)));
        let calls = cc.prove_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].leaf_index, 0);
        assert_eq!(calls[0].count, 1);
        assert_eq!(calls[0].checkpoint_height, 20);
    }

    #[tokio::test]
    async fn closed_challenge_sends_no_tx() {
        let (cc, handler, _r) = setup(10_000, Some(20));
        cc.set_status(leaf(), ChallengeStatus { open: false, deadline: 10_000 });
        assert_eq!(
            handler.handle(&ev(), 0).await.unwrap(),
            HandlerOutcome::Skipped(SkipReason::AlreadyClosed)
        );
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn deadline_passed_sends_no_tx() {
        let (cc, handler, _r) = setup(100, Some(20));
        assert_eq!(
            handler.handle(&ev(), 200).await.unwrap(),
            HandlerOutcome::Skipped(SkipReason::DeadlinePassed)
        );
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn record_not_found_before_deadline_retries() {
        let (cc, _handler, _r) = setup(10_000, Some(20));
        // Rebuild handler with a witness that reports WithdrawalNotFound.
        let l = leaf();
        let (proof, root) = valid_proof(l);
        let witness = Arc::new(MockWitness::new(10, proof));
        witness.set_record_err(WbError::WithdrawalNotFound);
        let rm = Arc::new(MockRootManager::new());
        rm.record(20, root);
        let h = Handler::new(cc.clone(), witness, rm, 16, SAFETY);
        assert_eq!(
            h.handle(&ev(), 0).await.unwrap(),
            HandlerOutcome::Retry(RetryReason::WaitingForRecord)
        );
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn record_not_found_at_deadline_stops() {
        let (cc, _h, root) = setup(1_000, Some(20));
        let l = leaf();
        let witness = Arc::new(MockWitness::new(10, valid_proof(l).0));
        witness.set_record_err(WbError::NotReady);
        let rm = Arc::new(MockRootManager::new());
        rm.record(20, root);
        let h = Handler::new(cc.clone(), witness, rm, 16, SAFETY);
        // now + SAFETY (100) >= deadline (1000)? now=950 ⇒ 1050 >= 1000 ⇒ out of time.
        assert_eq!(h.handle(&ev(), 950).await.unwrap(), HandlerOutcome::StoppedNoProof);
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn covering_root_absent_retries() {
        // RootManager has nothing covering the record yet.
        let (cc, handler, _r) = setup(10_000, None);
        assert_eq!(
            handler.handle(&ev(), 0).await.unwrap(),
            HandlerOutcome::Retry(RetryReason::WaitingForCoveringRoot)
        );
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn bad_proof_never_sends_tx() {
        let l = leaf();
        let (_good, root) = valid_proof(l);
        // A proof bound to `root` but with a tampered leaf ⇒ verify fails.
        let mut bad = valid_proof(l).0;
        bad.leaf_hash = B256::repeat_byte(0xEE);
        let cc = Arc::new(MockChallengeContract::new());
        cc.set_status(l, ChallengeStatus { open: true, deadline: 10_000 });
        let witness = Arc::new(MockWitness::new(10, bad));
        let rm = Arc::new(MockRootManager::new());
        rm.record(20, root);
        let handler = Handler::new(cc.clone(), witness, rm, 16, SAFETY);
        assert_eq!(handler.handle(&ev(), 0).await.unwrap(), HandlerOutcome::VerifyFailed);
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn other_responder_won_between_verify_and_submit() {
        let l = leaf();
        let (proof, root) = valid_proof(l);
        let cc = Arc::new(MockChallengeContract::new());
        cc.set_status(l, ChallengeStatus { open: true, deadline: 10_000 });
        // A witness that, on the proof call, also closes the challenge (someone else responded).
        struct RacingWitness {
            proof: HistoricalInclusionProof,
            cc: Arc<MockChallengeContract>,
            leaf: B256,
        }
        #[async_trait]
        impl WitnessSource for RacingWitness {
            async fn canonical_record_height(&self, _l: B256) -> Result<u64, WbError> {
                Ok(10)
            }
            async fn historical_proof(
                &self,
                _l: B256,
                _c: u64,
                _r: B256,
            ) -> Result<HistoricalInclusionProof, WbError> {
                // Another defender wins the race right before we submit.
                self.cc.set_status(self.leaf, ChallengeStatus { open: false, deadline: 10_000 });
                Ok(self.proof.clone())
            }
        }
        let witness = Arc::new(RacingWitness { proof, cc: cc.clone(), leaf: l });
        let rm = Arc::new(MockRootManager::new());
        rm.record(20, root);
        let handler = Handler::new(cc.clone(), witness, rm, 16, SAFETY);
        assert_eq!(
            handler.handle(&ev(), 0).await.unwrap(),
            HandlerOutcome::Skipped(SkipReason::OtherResponderWon)
        );
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn submit_failure_is_reported() {
        let (cc, handler, _r) = setup(10_000, Some(20));
        cc.set_fail_prove(true);
        assert_eq!(handler.handle(&ev(), 0).await.unwrap(), HandlerOutcome::SubmitFailed);
    }
}
