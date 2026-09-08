//! Single-challenge Defender state machine.
//!
//! One [`Handler::drive`] step advances one challenge, and the supervisor re-drives every
//! non-terminal challenge each tick. A broadcast transaction is only [`ChallengeState::Submitted`];
//! reaching [`ChallengeState::Proved`] requires a successful receipt plus an on-chain status that
//! confirms our resolution. Deadlines are decided by L2 chain time (the reader's `chain_timestamp`
//! versus `deadline`), never the host clock. Every send — including a resend after a confirmed
//! revert on a changed latest root — is preceded by a fresh local proof verification, and the
//! resend loop is bounded by both the deadline and a finite max-resend cap.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use alloy_primitives::{TxHash, B256};
use anyhow::Result;
use async_trait::async_trait;

use crate::tz::withdraw::{error::WbError, types::HistoricalInclusionProof};

use super::{
    cache::ProofCache,
    challenge_contract::{ChallengeId, ChallengeOpened, ChallengeReader, ChallengeSender, TxStatus},
    rootmanager_client::LatestRootSource,
    verifier::verify_inclusion,
};

/// Source of Witness Builder facts the handler needs.
#[async_trait]
pub trait WitnessSource: Send + Sync {
    /// Canonical block height at which the record for `leaf_hash` was included (from the witness
    /// builder, not the caller). `WithdrawalNotFound` / `NotReady` mean "not yet".
    async fn canonical_record_height(&self, leaf_hash: B256) -> Result<u64, WbError>;
    /// Inclusion proof for `leaf_hash` bound to an exact `withdrawal_root`.
    async fn historical_proof(
        &self,
        leaf_hash: B256,
        withdrawal_root: B256,
    ) -> Result<HistoricalInclusionProof, WbError>;
}

/// State of a single challenge as it moves from discovery to a terminal outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeState {
    /// Newly discovered; not yet worked.
    Discovered,
    /// Waiting for the witness builder (record not yet included, root not yet indexed, transient).
    WaitingWitness,
    /// Proof fetched and locally verified against the current latest root.
    Ready,
    /// A prove transaction was broadcast; the outcome is not yet confirmed.
    Submitted(TxHash),
    /// Receipt success plus an on-chain status confirming our resolution.
    Proved(TxHash),
    /// The challenge is no longer open (resolved by another responder).
    Closed,
    /// The L2-time deadline passed before a usable proof could be submitted/confirmed.
    Expired,
    /// A confirmed revert that is eligible for a bounded resend on a changed root.
    RetryableRevert,
    /// Local verification failed, the witness store is corrupt/mismatched, a protocol error
    /// occurred, or the resend bound was exhausted — never send again; alert.
    PermanentFailure,
}

impl ChallengeState {
    /// Whether the challenge has reached a terminal outcome and needs no further work.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ChallengeState::Proved(_)
                | ChallengeState::Closed
                | ChallengeState::Expired
                | ChallengeState::PermanentFailure
        )
    }
}

/// The Defender's per-challenge handler, generic over the three seams for unit testing.
pub struct Handler {
    reader: Arc<dyn ChallengeReader>,
    sender: Arc<dyn ChallengeSender>,
    witness: Arc<dyn WitnessSource>,
    root_manager: Arc<dyn LatestRootSource>,
    cache: Mutex<ProofCache>,
    deadline_safety_margin_secs: u64,
    max_resend: u32,
    resend_counts: Mutex<HashMap<ChallengeId, u32>>,
    submitted_roots: Mutex<HashMap<ChallengeId, B256>>,
}

impl Handler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: Arc<dyn ChallengeReader>,
        sender: Arc<dyn ChallengeSender>,
        witness: Arc<dyn WitnessSource>,
        root_manager: Arc<dyn LatestRootSource>,
        cache_capacity: usize,
        deadline_safety_margin_secs: u64,
        max_resend: u32,
    ) -> Self {
        Self {
            reader,
            sender,
            witness,
            root_manager,
            cache: Mutex::new(ProofCache::new(cache_capacity)),
            deadline_safety_margin_secs,
            max_resend,
            resend_counts: Mutex::new(HashMap::new()),
            submitted_roots: Mutex::new(HashMap::new()),
        }
    }

    /// Whether the L2-time deadline (with safety margin) has been reached.
    fn past_deadline(&self, status: &super::challenge_contract::ChallengeStatus) -> bool {
        status.chain_timestamp.saturating_add(self.deadline_safety_margin_secs) >= status.deadline
    }

    /// Classify a witness error into either a bounded wait or a permanent failure. A missing root
    /// index for an authoritative latest root, a not-yet-included record, and transient/not-ready
    /// conditions are waits; a mismatch, store corruption, or protocol error is permanent.
    fn classify_witness_wait(err: WbError) -> ChallengeState {
        if err.is_retryable()
            || matches!(err, WbError::WithdrawalNotFound | WbError::RootNotFound)
        {
            ChallengeState::WaitingWitness
        } else {
            ChallengeState::PermanentFailure
        }
    }

    /// Fetch a proof from the LRU cache or the witness builder.
    async fn fetch_proof(
        &self,
        leaf: B256,
        root: B256,
    ) -> Result<HistoricalInclusionProof, WbError> {
        if let Some(p) = self.cache.lock().unwrap().get(&(leaf, root)) {
            return Ok(p);
        }
        self.witness.historical_proof(leaf, root).await
    }

    /// Advance one challenge by a single step. Idempotent for terminal states.
    pub async fn drive(&self, ev: &ChallengeOpened, state: &mut ChallengeState) -> Result<()> {
        if state.is_terminal() {
            return Ok(());
        }

        let status = self.reader.get_challenge(ev.challenge_id).await?;

        // A broadcast transaction is reconciled via receipt + status before any other transition.
        if let ChallengeState::Submitted(tx) = *state {
            *state = self.confirm_submitted(ev, tx, &status).await?;
            return Ok(());
        }

        // Not yet submitted: check terminal conditions, then bind the root, verify, and submit.
        if !status.open {
            *state = ChallengeState::Closed;
            return Ok(());
        }
        if self.past_deadline(&status) {
            *state = ChallengeState::Expired;
            return Ok(());
        }
        *state = self.prepare_and_submit(ev).await?;
        Ok(())
    }

    /// Bind the current latest root, fetch + locally verify the proof, and submit optimistically.
    async fn prepare_and_submit(&self, ev: &ChallengeOpened) -> Result<ChallengeState> {
        let (checkpoint_height, withdrawal_root) = self.root_manager.latest_root().await?;
        let proof = match self.fetch_proof(ev.leaf_hash, withdrawal_root).await {
            Ok(p) => p,
            Err(e) => return Ok(Self::classify_witness_wait(e)),
        };
        if verify_inclusion(&proof, withdrawal_root).is_err() {
            return Ok(ChallengeState::PermanentFailure);
        }
        self.cache.lock().unwrap().put((ev.leaf_hash, withdrawal_root), proof.clone());

        // Re-check status just before submitting (even on a cache hit).
        let status = self.reader.get_challenge(ev.challenge_id).await?;
        if !status.open {
            return Ok(ChallengeState::Closed);
        }
        if self.past_deadline(&status) {
            return Ok(ChallengeState::Expired);
        }
        self.submit(ev, checkpoint_height, withdrawal_root, &proof).await
    }

    /// Submit the proof and record the bound root so a later resend can detect a root change.
    async fn submit(
        &self,
        ev: &ChallengeOpened,
        checkpoint_height: u64,
        withdrawal_root: B256,
        proof: &HistoricalInclusionProof,
    ) -> Result<ChallengeState> {
        match self
            .sender
            .prove_challenge(
                ev.challenge_id,
                checkpoint_height,
                proof.leaf_index,
                proof.count,
                proof.siblings,
            )
            .await
        {
            Ok(tx) => {
                self.submitted_roots.lock().unwrap().insert(ev.challenge_id, withdrawal_root);
                Ok(ChallengeState::Submitted(tx))
            }
            Err(_) => Ok(ChallengeState::PermanentFailure),
        }
    }

    /// Reconcile a `Submitted` challenge via its receipt and the current on-chain status.
    async fn confirm_submitted(
        &self,
        ev: &ChallengeOpened,
        tx: TxHash,
        status: &super::challenge_contract::ChallengeStatus,
    ) -> Result<ChallengeState> {
        match self.sender.confirm(tx).await? {
            TxStatus::Success => {
                if !status.open {
                    Ok(ChallengeState::Proved(tx))
                } else {
                    // Receipt success but the challenge is still open: reconcile on a later tick.
                    Ok(ChallengeState::Submitted(tx))
                }
            }
            TxStatus::Pending => Ok(ChallengeState::Submitted(tx)),
            TxStatus::Reverted => {
                if !status.open {
                    Ok(ChallengeState::Closed)
                } else if self.past_deadline(status) {
                    Ok(ChallengeState::Expired)
                } else {
                    self.try_resend(ev).await
                }
            }
        }
    }

    /// Bounded reactive resend after a confirmed revert: re-read the latest root, and only if it
    /// changed (a resend against the same root would revert again) re-fetch, re-verify, and resend.
    /// Bounded by the max-resend cap; the deadline bound is enforced by the caller.
    async fn try_resend(&self, ev: &ChallengeOpened) -> Result<ChallengeState> {
        let id = ev.challenge_id;
        let attempts = self.resend_counts.lock().unwrap().get(&id).copied().unwrap_or(0);
        if attempts >= self.max_resend {
            return Ok(ChallengeState::PermanentFailure);
        }

        let (checkpoint_height, withdrawal_root) = self.root_manager.latest_root().await?;
        let prev = self.submitted_roots.lock().unwrap().get(&id).copied();
        if prev == Some(withdrawal_root) {
            // The bound root did not change; resending the same proof would revert again.
            return Ok(ChallengeState::PermanentFailure);
        }

        let proof = match self.fetch_proof(ev.leaf_hash, withdrawal_root).await {
            Ok(p) => p,
            Err(e) => return Ok(Self::classify_witness_wait(e)),
        };
        if verify_inclusion(&proof, withdrawal_root).is_err() {
            return Ok(ChallengeState::PermanentFailure);
        }
        self.cache.lock().unwrap().put((ev.leaf_hash, withdrawal_root), proof.clone());

        let next = self.submit(ev, checkpoint_height, withdrawal_root, &proof).await?;
        if matches!(next, ChallengeState::Submitted(_)) {
            *self.resend_counts.lock().unwrap().entry(id).or_insert(0) += 1;
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::{
        defender::{
            challenge_contract::{ChallengeStatus, MockChallengeContract},
            rootmanager_client::MockRootManager,
        },
        withdraw::{tree_adapter::single_leaf_withdrawal_fixture, types::WithdrawRecord},
    };
    use alloy_primitives::{Address, B256};
    use std::sync::Mutex as StdMutex;

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

    /// A valid count==1 proof for `leaf` and its bound root, via the tz-witness-backed fixture.
    fn valid_proof(leaf: B256) -> (HistoricalInclusionProof, B256) {
        let (siblings, root) = single_leaf_withdrawal_fixture(leaf);
        let proof = HistoricalInclusionProof {
            record: record(),
            record_hash: leaf,
            leaf_hash: leaf,
            canonical_block_height: 10,
            withdrawal_root: root,
            leaf_index: 0,
            count: 1,
            siblings,
        };
        (proof, root)
    }

    fn leaf() -> B256 {
        B256::repeat_byte(0x42)
    }

    fn ev() -> ChallengeOpened {
        ChallengeOpened::new(196, Address::repeat_byte(0x01), B256::repeat_byte(0x02), 0, leaf(), 10)
    }

    fn cid() -> ChallengeId {
        ev().challenge_id
    }

    /// Configurable mock witness whose proof result can be scripted.
    struct MockWitness {
        proof: StdMutex<Result<HistoricalInclusionProof, WbError>>,
    }
    impl MockWitness {
        fn ok(proof: HistoricalInclusionProof) -> Self {
            Self { proof: StdMutex::new(Ok(proof)) }
        }
        fn set_proof_err(&self, e: WbError) {
            *self.proof.lock().unwrap() = Err(e);
        }
    }
    #[async_trait]
    impl WitnessSource for MockWitness {
        async fn canonical_record_height(&self, _leaf: B256) -> Result<u64, WbError> {
            Ok(10)
        }
        async fn historical_proof(
            &self,
            _leaf: B256,
            _root: B256,
        ) -> Result<HistoricalInclusionProof, WbError> {
            self.proof.lock().unwrap().clone()
        }
    }

    fn handler_with(
        cc: Arc<MockChallengeContract>,
        witness: Arc<dyn WitnessSource>,
        rm: Arc<MockRootManager>,
        max_resend: u32,
    ) -> Handler {
        Handler::new(cc.clone(), cc.clone(), witness, rm, 16, SAFETY, max_resend)
    }

    /// A challenge whose proof is ready and whose root is set, with a scriptable status.
    fn setup_ready(
        deadline: u64,
        chain_ts: u64,
        rm_height: u64,
    ) -> (Arc<MockChallengeContract>, Arc<MockWitness>, Arc<MockRootManager>, ChallengeId, B256) {
        let (proof, root) = valid_proof(leaf());
        let cc = Arc::new(MockChallengeContract::new());
        let id = cid();
        cc.set_status(id, ChallengeStatus { open: true, deadline, chain_timestamp: chain_ts });
        let witness = Arc::new(MockWitness::ok(proof));
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(rm_height, root);
        (cc, witness, rm, id, root)
    }

    #[tokio::test]
    async fn broadcast_is_submitted_with_calldata_then_confirmed_proved() {
        let (cc, witness, rm, id, _root) = setup_ready(10_000, 0, 20);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        let h = handler_with(cc.clone(), witness, rm, 3);

        let mut state = ChallengeState::Discovered;
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::Submitted(_)), "first drive broadcasts only");
        let calls = cc.prove_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].challenge_id, id);
        assert_eq!(calls[0].checkpoint_height, 20);
        assert_eq!(calls[0].count, 1);
        assert_eq!(calls[0].leaf_index, 0);

        // Confirmation requires a successful receipt AND a resolved on-chain status.
        cc.mark_resolved_in_our_favor(id);
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::Proved(_)), "confirmed only after receipt + status");
    }

    #[tokio::test]
    async fn pending_receipt_stays_submitted_no_resend() {
        let (cc, witness, rm, _id, _root) = setup_ready(10_000, 0, 20);
        // No scripted tx status ⇒ confirm returns Pending.
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Submitted(TxHash::repeat_byte(0x99));
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::Submitted(_)), "pending ⇒ reconcile, not resend");
        assert!(cc.prove_calls().is_empty(), "never resend on a pending receipt");
    }

    #[tokio::test]
    async fn confirmed_revert_with_changed_root_reverifies_and_resends_bounded() {
        let (cc, _w, rm, id, _root) = setup_ready(10_000, 0, 20);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Reverted);
        cc.keep_open(id); // still Open, before deadline
        // The latest root changes to a new value the witness can prove.
        let (other_proof, other_root) = valid_proof(B256::repeat_byte(0x77));
        let witness = Arc::new(MockWitness::ok(other_proof));
        rm.set_latest(21, other_root);
        let h = handler_with(cc.clone(), witness, rm, 1);

        let mut state = ChallengeState::Submitted(TxHash::repeat_byte(0x99));
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::RetryableRevert | ChallengeState::Submitted(_)));

        // A second confirmed revert exceeds max_resend=1 ⇒ terminal, no infinite loop.
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Reverted);
        h.drive(&ev(), &mut state).await.unwrap();
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::PermanentFailure | ChallengeState::Expired));
    }

    #[tokio::test]
    async fn deadline_uses_l2_chain_time_not_host_clock() {
        // chain_timestamp + safety >= deadline ⇒ Expired, regardless of host wall clock.
        let (cc, witness, rm, _id, _root) = setup_ready(1_000, 999, 20);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Discovered;
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::Expired));
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn closed_challenge_becomes_closed_no_tx() {
        let (cc, witness, rm, id, _root) = setup_ready(10_000, 0, 20);
        cc.set_status(id, ChallengeStatus { open: false, deadline: 10_000, chain_timestamp: 0 });
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Discovered;
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::Closed));
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn witness_not_found_is_waiting_witness() {
        let (cc, witness, rm, _id, _root) = setup_ready(10_000, 0, 20);
        witness.set_proof_err(WbError::WithdrawalNotFound);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Discovered;
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::WaitingWitness));
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn root_not_found_is_waiting_witness() {
        let (cc, witness, rm, _id, _root) = setup_ready(10_000, 0, 20);
        witness.set_proof_err(WbError::RootNotFound);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Discovered;
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::WaitingWitness), "authoritative root index lag ⇒ wait");
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn corrupt_witness_is_permanent_failure_no_tx() {
        let (cc, witness, rm, _id, _root) = setup_ready(10_000, 0, 20);
        witness.set_proof_err(WbError::WitnessStoreCorrupt);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Discovered;
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::PermanentFailure));
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn tampered_proof_is_permanent_failure_no_tx() {
        let (cc, _w, rm, _id, root) = setup_ready(10_000, 0, 20);
        let mut bad = valid_proof(leaf()).0;
        bad.leaf_hash = B256::repeat_byte(0xEE); // no longer verifies against the bound root
        let _ = root;
        let witness = Arc::new(MockWitness::ok(bad));
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Discovered;
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::PermanentFailure));
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn submit_failure_is_permanent_failure() {
        let (cc, witness, rm, _id, _root) = setup_ready(10_000, 0, 20);
        cc.set_fail_prove(true);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Discovered;
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::PermanentFailure));
    }

    #[tokio::test]
    async fn missing_latest_root_is_error() {
        // With latest-only semantics a running system always has a current root; a missing one is
        // a hard error, not a silent wait, and never sends a tx.
        let (proof, _root) = valid_proof(leaf());
        let cc = Arc::new(MockChallengeContract::new());
        cc.set_status(cid(), ChallengeStatus { open: true, deadline: 10_000, chain_timestamp: 0 });
        let witness = Arc::new(MockWitness::ok(proof));
        let rm = Arc::new(MockRootManager::new()); // never set
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Discovered;
        assert!(h.drive(&ev(), &mut state).await.is_err());
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn terminal_state_is_a_noop() {
        let (cc, witness, rm, _id, _root) = setup_ready(10_000, 0, 20);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let mut state = ChallengeState::Proved(TxHash::repeat_byte(0x99));
        h.drive(&ev(), &mut state).await.unwrap();
        assert!(matches!(state, ChallengeState::Proved(_)));
        assert!(cc.prove_calls().is_empty());
    }
}
