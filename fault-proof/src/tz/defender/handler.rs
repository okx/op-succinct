//! Single-challenge Defender state machine (design §5).
//!
//! One [`Handler::drive`] step advances one challenge; the supervisor re-drives every non-terminal
//! challenge each tick. The flow per challenge (§4.4) is: covering-root gate → fetch proof →
//! leaf-bound verify → pre-broadcast status/deadline recheck → acquire the global in-flight gate →
//! gated submit → confirm → counted resend. A broadcast transaction is only
//! [`ChallengeState::Submitted`]; reaching [`ChallengeState::Proved`] requires a successful receipt
//! plus an on-chain status that confirms our resolution. Deadlines use L2 chain time (the reader's
//! `chain_timestamp` vs `deadline`), never the host clock.
//!
//! All retry context (`attempts`, the bound `root`, and the wait `reason`) is carried **in the
//! challenge state** — there is no side map — so a witness-builder lag after a confirmed revert
//! retains the resend counter and cannot bypass the `max_resend` cap. At most one transaction is
//! in flight per process, enforced by a shared [`InFlightGate`].

use std::sync::{Arc, Mutex};

use alloy_primitives::{TxHash, B256};
use anyhow::Result;
use async_trait::async_trait;

use crate::tz::withdraw::{error::WbError, types::HistoricalInclusionProof};

use super::{
    cache::ProofCache,
    challenge_contract::{
        ChallengeId, ChallengeOpened, ChallengeReader, ChallengeSender, ChallengeStatus,
        SenderError, SubmitOutcome, TxStatus,
    },
    rootmanager_client::LatestRootSource,
    verifier::verify,
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

/// Why a challenge is waiting (all bounded by the L2-time deadline). Carried in the state so the
/// supervisor can observe progress without a side channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitReason {
    /// The RootManager latest checkpoint does not yet cover the record height (D10).
    RootBehindRecord,
    /// The record is not yet known to the witness builder (WB code 11004).
    WithdrawalNotFound,
    /// The record is not in the latest checkpoint yet — a root/record race (WB code 11005).
    RecordNotInCheckpoint,
    /// The witness data is not ready yet (WB code 11006).
    NotReady,
    /// The (authoritative) latest root has no witness index yet — index lag (WB code 11009).
    RootNotFound,
    /// A transient transport failure (timeout / 5xx).
    Transport,
}

/// State of a single challenge as it moves from discovery to a terminal outcome. Retry context
/// (`attempts`, bound `root`, wait `reason`) lives here (D8) — never in a side map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeState {
    /// Newly discovered; not yet worked.
    Discovered,
    /// Waiting for the witness builder / covering root; `attempts` is the resend count so far.
    WaitingWitness { reason: WaitReason, attempts: u32, last_root: Option<B256> },
    /// Proof was verifiable but the in-flight gate was held by another challenge, so no broadcast
    /// happened this tick; retried next tick.
    Ready { attempts: u32 },
    /// A prove transaction was broadcast (holds the in-flight gate); the outcome is not yet
    /// confirmed. `root` is the withdrawal root it was submitted against; `attempts` the resend
    /// count so far.
    Submitted { tx: TxHash, attempts: u32, root: B256 },
    /// The broadcast outcome is unknown (holds the in-flight gate, R5-1). If `tx_hash` is present
    /// the handler reconciles via status + receipt; with no `tx_hash` and still open it keeps
    /// holding the gate and polling — never inferring "not broadcast", never resending.
    ReconcileUnknown { tx_hash: Option<TxHash>, attempts: u32, root: Option<B256> },
    /// A confirmed revert whose latest root has changed, eligible for a bounded resend on the next
    /// tick; `attempts` already reflects the incremented resend count.
    RetryableRevert { attempts: u32 },
    /// Receipt success plus an on-chain status confirming our resolution.
    Proved(TxHash),
    /// The challenge is no longer open (resolved by another responder).
    Closed,
    /// The L2-time deadline passed before a usable proof could be submitted/confirmed.
    Expired,
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

    /// The resend count carried by a non-terminal, pre-broadcast state.
    fn attempts(&self) -> u32 {
        match self {
            ChallengeState::WaitingWitness { attempts, .. }
            | ChallengeState::Ready { attempts }
            | ChallengeState::RetryableRevert { attempts } => *attempts,
            _ => 0,
        }
    }
}

/// Global single-process in-flight transaction gate (D7): at most one challenge may hold it, so at
/// most one prove transaction is in flight across all `ChallengeId`s. It does NOT survive a restart.
#[derive(Clone, Default)]
pub struct InFlightGate {
    holder: Arc<Mutex<Option<ChallengeId>>>,
}

impl InFlightGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// The challenge currently holding the gate, if any.
    pub fn holder(&self) -> Option<ChallengeId> {
        *self.holder.lock().unwrap()
    }

    /// Acquire the gate for `id` iff it is free or already held by `id`. Returns whether `id` holds
    /// the gate after the call.
    fn try_acquire(&self, id: ChallengeId) -> bool {
        let mut h = self.holder.lock().unwrap();
        match *h {
            Some(cur) if cur != id => false,
            _ => {
                *h = Some(id);
                true
            }
        }
    }

    /// Release the gate iff currently held by `id`.
    fn release(&self, id: ChallengeId) {
        let mut h = self.holder.lock().unwrap();
        if *h == Some(id) {
            *h = None;
        }
    }
}

/// The Defender's per-challenge handler, generic over the three seams for unit testing.
pub struct Handler {
    reader: Arc<dyn ChallengeReader>,
    sender: Arc<dyn ChallengeSender>,
    witness: Arc<dyn WitnessSource>,
    root_manager: Arc<dyn LatestRootSource>,
    chain_id: u64,
    cache: Mutex<ProofCache>,
    deadline_safety_margin_secs: u64,
    max_resend: u32,
}

impl Handler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: Arc<dyn ChallengeReader>,
        sender: Arc<dyn ChallengeSender>,
        witness: Arc<dyn WitnessSource>,
        root_manager: Arc<dyn LatestRootSource>,
        chain_id: u64,
        cache_capacity: usize,
        deadline_safety_margin_secs: u64,
        max_resend: u32,
    ) -> Self {
        Self {
            reader,
            sender,
            witness,
            root_manager,
            chain_id,
            cache: Mutex::new(ProofCache::new(cache_capacity)),
            deadline_safety_margin_secs,
            max_resend,
        }
    }

    /// Whether the L2-time deadline (with safety margin) has been reached.
    fn past_deadline(&self, status: &ChallengeStatus) -> bool {
        status.chain_timestamp.saturating_add(self.deadline_safety_margin_secs) >= status.deadline
    }

    /// Classify a witness error into either a bounded wait (carrying the retry context) or a
    /// permanent failure. Waits: `WithdrawalNotFound` (11004), `RecordNotInCheckpoint` (11005),
    /// `NotReady` (11006), authoritative `RootNotFound` (11009), and transient transport. Everything
    /// else (mismatch, store corruption, protocol, invalid request, permanent transport) is
    /// permanent and fails closed.
    fn classify_witness_wait(err: WbError, attempts: u32, last_root: Option<B256>) -> ChallengeState {
        let reason = match err {
            WbError::WithdrawalNotFound => Some(WaitReason::WithdrawalNotFound),
            WbError::RecordNotInCheckpoint => Some(WaitReason::RecordNotInCheckpoint),
            WbError::NotReady => Some(WaitReason::NotReady),
            WbError::RootNotFound => Some(WaitReason::RootNotFound),
            WbError::Transport { retryable: true, .. } => Some(WaitReason::Transport),
            _ => None,
        };
        match reason {
            Some(reason) => ChallengeState::WaitingWitness { reason, attempts, last_root },
            None => ChallengeState::PermanentFailure,
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

    /// Advance one challenge by a single step. Idempotent for terminal states. `gate` is the shared
    /// process-wide in-flight gate.
    pub async fn drive(
        &self,
        ev: &ChallengeOpened,
        state: &mut ChallengeState,
        gate: &InFlightGate,
    ) -> Result<()> {
        if state.is_terminal() {
            return Ok(());
        }

        let status = self.reader.get_challenge(ev.challenge_id).await?;

        // In-flight states are reconciled first (receipt + status), never re-prepared.
        match state.clone() {
            ChallengeState::Submitted { tx, attempts, root } => {
                *state = self.confirm_submitted(ev, tx, attempts, root, &status, gate).await?;
                return Ok(());
            }
            ChallengeState::ReconcileUnknown { tx_hash, attempts, root } => {
                *state = self.reconcile_unknown(ev, tx_hash, attempts, root, &status, gate).await?;
                return Ok(());
            }
            _ => {}
        }

        // Not in-flight: terminal-condition checks, then the covering gate → verify → gated submit.
        if !status.open {
            *state = ChallengeState::Closed;
            return Ok(());
        }
        if self.past_deadline(&status) {
            *state = ChallengeState::Expired;
            return Ok(());
        }
        let attempts = state.attempts();
        *state = self.prepare_and_submit(ev, attempts, gate).await?;
        Ok(())
    }

    /// Covering gate → fetch → leaf-bound verify → pre-broadcast recheck → gated submit.
    async fn prepare_and_submit(
        &self,
        ev: &ChallengeOpened,
        attempts: u32,
        gate: &InFlightGate,
    ) -> Result<ChallengeState> {
        // 1. Covering-root gate (D10, MR105-2): the record must be covered by the latest checkpoint.
        let record_height = match self.witness.canonical_record_height(ev.leaf_hash).await {
            Ok(h) => h,
            Err(e) => return Ok(Self::classify_witness_wait(e, attempts, None)),
        };
        let (checkpoint_height, withdrawal_root) = self.root_manager.latest_root().await?;
        if checkpoint_height < record_height {
            return Ok(ChallengeState::WaitingWitness {
                reason: WaitReason::RootBehindRecord,
                attempts,
                last_root: Some(withdrawal_root),
            });
        }

        // 2. Obtain the proof (LRU cache, else WB), classifying errors per the wait/permanent split.
        let proof = match self.fetch_proof(ev.leaf_hash, withdrawal_root).await {
            Ok(p) => p,
            Err(e) => return Ok(Self::classify_witness_wait(e, attempts, Some(withdrawal_root))),
        };

        // 3. Local leaf-bound verification (MR105-3) — never send an unverified or mis-bound proof.
        if verify(&proof, ev.leaf_hash, withdrawal_root, self.chain_id).is_err() {
            return Ok(ChallengeState::PermanentFailure);
        }
        self.cache.lock().unwrap().put((ev.leaf_hash, withdrawal_root), proof.clone());

        // 4. Pre-broadcast recheck (MR105-7): fresh status + deadline before EVERY send.
        let status = self.reader.get_challenge(ev.challenge_id).await?;
        if !status.open {
            return Ok(ChallengeState::Closed);
        }
        if self.past_deadline(&status) {
            return Ok(ChallengeState::Expired);
        }

        // 5. Acquire the global in-flight gate (D7). If another challenge holds it, stay Ready.
        if !gate.try_acquire(ev.challenge_id) {
            return Ok(ChallengeState::Ready { attempts });
        }

        // 6. Gated optimistic submit with typed outcome handling.
        self.submit(ev, checkpoint_height, withdrawal_root, &proof, attempts, gate).await
    }

    /// Submit the proof; the in-flight gate is held by `ev` on entry.
    async fn submit(
        &self,
        ev: &ChallengeOpened,
        checkpoint_height: u64,
        withdrawal_root: B256,
        proof: &HistoricalInclusionProof,
        attempts: u32,
        gate: &InFlightGate,
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
            Ok(SubmitOutcome::Submitted(tx)) => {
                Ok(ChallengeState::Submitted { tx, attempts, root: withdrawal_root })
            }
            // Provably never broadcast ⇒ release the gate and retry next tick (the ONLY safe retry).
            Err(SenderError::SafeToRetryPreBroadcast) => {
                gate.release(ev.challenge_id);
                Ok(ChallengeState::Ready { attempts })
            }
            // A confirmed rejection at submit is a confirmed revert ⇒ counted resend / terminal.
            Err(SenderError::ConfirmedRejection) => {
                self.on_confirmed_revert(ev, attempts, withdrawal_root, gate).await
            }
            // Unknown outcome ⇒ hold the gate and reconcile; never infer not-broadcast.
            Err(SenderError::UnknownBroadcastOutcome { tx_hash }) => Ok(
                ChallengeState::ReconcileUnknown { tx_hash, attempts, root: Some(withdrawal_root) },
            ),
        }
    }

    /// Reconcile a `Submitted` challenge via its receipt and the current on-chain status.
    async fn confirm_submitted(
        &self,
        ev: &ChallengeOpened,
        tx: TxHash,
        attempts: u32,
        root: B256,
        status: &ChallengeStatus,
        gate: &InFlightGate,
    ) -> Result<ChallengeState> {
        match self.sender.confirm(tx).await? {
            TxStatus::Success => {
                if !status.open {
                    gate.release(ev.challenge_id);
                    Ok(ChallengeState::Proved(tx))
                } else {
                    // Receipt success but still open: reconcile on a later tick (keep the gate).
                    Ok(ChallengeState::Submitted { tx, attempts, root })
                }
            }
            TxStatus::Pending => Ok(ChallengeState::Submitted { tx, attempts, root }),
            TxStatus::Reverted => {
                if !status.open {
                    gate.release(ev.challenge_id);
                    Ok(ChallengeState::Closed)
                } else if self.past_deadline(status) {
                    gate.release(ev.challenge_id);
                    Ok(ChallengeState::Expired)
                } else {
                    self.on_confirmed_revert(ev, attempts, root, gate).await
                }
            }
        }
    }

    /// Reconcile an unknown broadcast outcome. The gate is held by `ev` (R5-1) and released only on
    /// a confirmed terminal outcome. With no `tx_hash` and still open, keep holding + polling; never
    /// resend, never infer "not broadcast".
    async fn reconcile_unknown(
        &self,
        ev: &ChallengeOpened,
        tx_hash: Option<TxHash>,
        attempts: u32,
        root: Option<B256>,
        status: &ChallengeStatus,
        gate: &InFlightGate,
    ) -> Result<ChallengeState> {
        if let Some(tx) = tx_hash {
            return match self.sender.confirm(tx).await? {
                TxStatus::Success => {
                    if !status.open {
                        gate.release(ev.challenge_id);
                        Ok(ChallengeState::Proved(tx))
                    } else {
                        Ok(ChallengeState::ReconcileUnknown { tx_hash, attempts, root })
                    }
                }
                TxStatus::Pending => {
                    Ok(ChallengeState::ReconcileUnknown { tx_hash, attempts, root })
                }
                TxStatus::Reverted => {
                    if !status.open {
                        gate.release(ev.challenge_id);
                        Ok(ChallengeState::Closed)
                    } else if self.past_deadline(status) {
                        gate.release(ev.challenge_id);
                        Ok(ChallengeState::Expired)
                    } else {
                        self.on_confirmed_revert(ev, attempts, root.unwrap_or_default(), gate).await
                    }
                }
            };
        }
        // No tx hash: never infer not-broadcast, never resend. Hold the gate and poll status.
        if !status.open {
            gate.release(ev.challenge_id);
            return Ok(ChallengeState::Closed);
        }
        if self.past_deadline(status) {
            gate.release(ev.challenge_id);
            return Ok(ChallengeState::Expired);
        }
        Ok(ChallengeState::ReconcileUnknown { tx_hash: None, attempts, root })
    }

    /// Handle a confirmed revert (from a receipt or a `ConfirmedRejection`): the reverted tx is no
    /// longer in flight, so release the gate; then decide a bounded, counted resend. A resend is
    /// attempted only if within `max_resend` AND the latest root changed (resending the same root
    /// would revert again). The incremented counter is carried into `RetryableRevert` (in-state), so
    /// a witness-builder lag on the next tick cannot reset it.
    async fn on_confirmed_revert(
        &self,
        ev: &ChallengeOpened,
        attempts: u32,
        prev_root: B256,
        gate: &InFlightGate,
    ) -> Result<ChallengeState> {
        gate.release(ev.challenge_id);
        let next_attempt = attempts + 1;
        if next_attempt > self.max_resend {
            return Ok(ChallengeState::PermanentFailure);
        }
        let (_checkpoint_height, withdrawal_root) = self.root_manager.latest_root().await?;
        if withdrawal_root == prev_root {
            // The bound root did not change; resending the same proof would revert again.
            return Ok(ChallengeState::PermanentFailure);
        }
        Ok(ChallengeState::RetryableRevert { attempts: next_attempt })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::{
        defender::{
            challenge_contract::{ChallengeStatus, MockChallengeContract},
            rootmanager_client::MockRootManager,
            verifier::record_leaf_hash,
        },
        withdraw::{tree_adapter::single_leaf_withdrawal_fixture, types::WithdrawRecord},
    };
    use alloy_primitives::{Address, B256, U256};
    use std::sync::Mutex as StdMutex;

    const SAFETY: u64 = 100;
    const CHAIN_ID: u64 = 196;

    /// A valid canonical Erc20 record; `seed` varies the tx hash + amount so distinct seeds give
    /// distinct leaves.
    fn valid_record(seed: u8) -> WithdrawRecord {
        WithdrawRecord {
            version: 1,
            chain_id: CHAIN_ID,
            transaction_hash: B256::repeat_byte(seed),
            token_type: 0,
            token_address: Address::repeat_byte(0xAA),
            token_ids: vec![U256::ZERO],
            amounts: vec![U256::from(seed as u64 + 1)],
            from: Address::repeat_byte(0x01),
            to: Address::repeat_byte(0x02),
        }
    }

    /// A valid count==1 proof whose leaf IS the record's tz-witness-recomputed hash.
    fn valid_proof(seed: u8) -> (WithdrawRecord, HistoricalInclusionProof, B256, B256) {
        let record = valid_record(seed);
        let leaf = record_leaf_hash(&record).unwrap();
        let (siblings, root) = single_leaf_withdrawal_fixture(leaf);
        let proof = HistoricalInclusionProof {
            record: record.clone(),
            record_hash: leaf,
            leaf_hash: leaf,
            canonical_block_height: 10,
            withdrawal_root: root,
            leaf_index: 0,
            count: 1,
            siblings,
        };
        (record, proof, leaf, root)
    }

    fn ev_for(leaf: B256) -> ChallengeOpened {
        ChallengeOpened::new(CHAIN_ID, Address::repeat_byte(0x01), B256::repeat_byte(0x02), 0, leaf, 10)
    }

    /// A scriptable witness whose record height, proof result, and a one-shot proof error are all
    /// controllable, with a proof-call counter.
    struct MockWitness {
        record_height: StdMutex<u64>,
        proof: StdMutex<Result<HistoricalInclusionProof, WbError>>,
        err_once: StdMutex<Option<WbError>>,
        proof_calls: StdMutex<u32>,
    }
    impl MockWitness {
        fn ok(proof: HistoricalInclusionProof, record_height: u64) -> Self {
            Self {
                record_height: StdMutex::new(record_height),
                proof: StdMutex::new(Ok(proof)),
                err_once: StdMutex::new(None),
                proof_calls: StdMutex::new(0),
            }
        }
        fn set_proof(&self, proof: HistoricalInclusionProof) {
            *self.proof.lock().unwrap() = Ok(proof);
        }
        fn set_proof_err(&self, e: WbError) {
            *self.proof.lock().unwrap() = Err(e);
        }
        fn set_proof_err_once(&self, e: WbError) {
            *self.err_once.lock().unwrap() = Some(e);
        }
        fn set_record_height(&self, h: u64) {
            *self.record_height.lock().unwrap() = h;
        }
        fn proof_calls(&self) -> u32 {
            *self.proof_calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl WitnessSource for MockWitness {
        async fn canonical_record_height(&self, _leaf: B256) -> Result<u64, WbError> {
            Ok(*self.record_height.lock().unwrap())
        }
        async fn historical_proof(
            &self,
            _leaf: B256,
            _root: B256,
        ) -> Result<HistoricalInclusionProof, WbError> {
            *self.proof_calls.lock().unwrap() += 1;
            if let Some(e) = self.err_once.lock().unwrap().take() {
                return Err(e);
            }
            self.proof.lock().unwrap().clone()
        }
    }

    #[allow(clippy::type_complexity)]
    fn handler_with(
        cc: Arc<MockChallengeContract>,
        witness: Arc<dyn WitnessSource>,
        rm: Arc<MockRootManager>,
        max_resend: u32,
    ) -> Handler {
        Handler::new(cc.clone(), cc.clone(), witness, rm, CHAIN_ID, 16, SAFETY, max_resend)
    }

    /// A ready challenge: valid proof, root set, scriptable status; `record_height` covered by the
    /// RootManager checkpoint height.
    #[allow(clippy::type_complexity)]
    fn setup_ready(
        deadline: u64,
        chain_ts: u64,
        checkpoint_height: u64,
    ) -> (Arc<MockChallengeContract>, Arc<MockWitness>, Arc<MockRootManager>, ChallengeOpened, B256) {
        let (_rec, proof, leaf, root) = valid_proof(0x42);
        let cc = Arc::new(MockChallengeContract::new());
        let ev = ev_for(leaf);
        cc.set_status(ev.challenge_id, ChallengeStatus { open: true, deadline, chain_timestamp: chain_ts });
        let witness = Arc::new(MockWitness::ok(proof, 10));
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(checkpoint_height, root);
        (cc, witness, rm, ev, root)
    }

    #[tokio::test]
    async fn broadcast_gated_and_confirmed_submitted_then_proved() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();

        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Submitted { .. }), "first drive broadcasts only");
        assert_eq!(gate.holder(), Some(ev.challenge_id), "Submitted holds the in-flight gate");
        let calls = cc.prove_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].checkpoint_height, 20);
        assert_eq!(calls[0].count, 1);

        // Confirmation requires a successful receipt AND a resolved on-chain status.
        cc.mark_resolved_in_our_favor(ev.challenge_id);
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Proved(_)), "confirmed only after receipt + status");
        assert_eq!(gate.holder(), None, "gate released on Proved");
    }

    #[tokio::test]
    async fn pending_receipt_stays_submitted_no_resend() {
        let (cc, witness, rm, ev, root) = setup_ready(10_000, 0, 20);
        // No scripted tx status ⇒ confirm returns Pending.
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        gate.try_acquire(ev.challenge_id);
        let mut state = ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root };
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Submitted { .. }), "pending ⇒ reconcile, not resend");
        assert!(cc.prove_calls().is_empty(), "never resend on a pending receipt");
    }

    #[tokio::test]
    async fn covering_gate_waits_until_checkpoint_covers_record() {
        // record_height = 20; latest checkpoint_height = 15 (< 20) ⇒ wait, no proof fetch.
        let (cc, witness, rm, ev, root) = setup_ready(10_000, 0, 15);
        witness.set_record_height(20);
        let h = handler_with(cc.clone(), witness.clone(), rm.clone(), 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::WaitingWitness { reason: WaitReason::RootBehindRecord, .. }),
            "checkpoint behind record ⇒ RootBehindRecord wait, got {state:?}"
        );
        assert_eq!(witness.proof_calls(), 0, "no proof requested while checkpoint behind record");
        assert!(cc.prove_calls().is_empty());

        // Checkpoint catches up ⇒ proof fetched, verified, submitted.
        rm.set_latest(20, root);
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Submitted { .. }));
        assert!(witness.proof_calls() >= 1);
    }

    #[tokio::test]
    async fn record_not_in_checkpoint_11005_is_wait_not_permanent() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        witness.set_proof_err(WbError::RecordNotInCheckpoint); // race between latest_root and WB
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::WaitingWitness { reason: WaitReason::RecordNotInCheckpoint, .. }),
            "11005 = wait-within-deadline, got {state:?}"
        );
        assert!(!state.is_terminal());
    }

    #[tokio::test]
    async fn pre_broadcast_recheck_blocks_send_when_expired() {
        // chain_ts + safety >= deadline ⇒ Expired before any broadcast, regardless of host clock.
        let (cc, witness, rm, ev, _root) = setup_ready(1_000, 999, 20);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Expired));
        assert!(cc.prove_calls().is_empty());
        assert_eq!(gate.holder(), None);
    }

    #[tokio::test]
    async fn unknown_broadcast_outcome_holds_gate_no_resend_without_txhash() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        cc.set_sender_error(ev.challenge_id, SenderError::UnknownBroadcastOutcome { tx_hash: None });
        cc.keep_open(ev.challenge_id);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::ReconcileUnknown { tx_hash: None, .. }));
        assert_eq!(gate.holder(), Some(ev.challenge_id), "unknown outcome HOLDS the gate");
        let before = cc.prove_calls().len();
        h.drive(&ev, &mut state, &gate).await.unwrap(); // still open, no tx hash ⇒ no resend
        assert_eq!(cc.prove_calls().len(), before, "no resend without a confirmed-safe classification");
        assert_eq!(gate.holder(), Some(ev.challenge_id), "gate still held while reconciling");
    }

    #[tokio::test]
    async fn safe_to_retry_pre_broadcast_releases_gate_and_stays_ready() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        cc.set_sender_error(ev.challenge_id, SenderError::SafeToRetryPreBroadcast);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Ready { .. }), "safe-retry ⇒ Ready, got {state:?}");
        assert_eq!(gate.holder(), None, "safe-retry releases the gate");
    }

    /// A valid count==2 proof for the challenged leaf `leaf` under a root that varies with `filler`
    /// (so the SAME leaf is provable under a changing root — the root-staleness resend path).
    fn proof_for(record: &WithdrawRecord, leaf: B256, filler: u8) -> (HistoricalInclusionProof, B256) {
        let ((sib0, idx0), _sib1, root) =
            crate::tz::withdraw::tree_adapter::two_leaf_withdrawal_fixture(
                leaf,
                B256::repeat_byte(filler),
            );
        let proof = HistoricalInclusionProof {
            record: record.clone(),
            record_hash: leaf,
            leaf_hash: leaf,
            canonical_block_height: 10,
            withdrawal_root: root,
            leaf_index: idx0,
            count: 2,
            siblings: sib0,
        };
        (proof, root)
    }

    #[tokio::test]
    async fn resend_counter_lives_in_state_and_caps_even_through_wb_lag() {
        let record = valid_record(0x42);
        let leaf = record_leaf_hash(&record).unwrap();
        let (p0, root0) = proof_for(&record, leaf, 0xF0);
        let cc = Arc::new(MockChallengeContract::new());
        let ev = ev_for(leaf);
        cc.set_status(ev.challenge_id, ChallengeStatus { open: true, deadline: 100_000, chain_timestamp: 0 });
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Reverted);
        cc.keep_open(ev.challenge_id);
        let witness = Arc::new(MockWitness::ok(p0, 10));
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(20, root0);
        let h = handler_with(cc.clone(), witness.clone(), rm.clone(), 3);
        let gate = InFlightGate::new();

        // Start Submitted at attempts 0 against root0; the gate is held by this challenge.
        gate.try_acquire(ev.challenge_id);
        let mut state = ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root: root0 };

        // Each confirmed revert with a changed root increments attempts; a WB-lag between the revert
        // and the re-broadcast retains the counter (cannot reset it).
        for i in 1..=3u8 {
            let (next_proof, next_root) = proof_for(&record, leaf, 0xF0 + i);
            rm.set_latest(20 + i as u64, next_root);
            witness.set_proof(next_proof);
            // Confirmed revert + changed root ⇒ RetryableRevert{attempts=i}.
            h.drive(&ev, &mut state, &gate).await.unwrap();
            assert!(
                matches!(state, ChallengeState::RetryableRevert { attempts } if attempts == i as u32),
                "revert {i} ⇒ RetryableRevert{{attempts={i}}}, got {state:?}"
            );
            // Interpose a WB lag on the resend fetch: it must retain the counter.
            witness.set_proof_err_once(WbError::RootNotFound);
            h.drive(&ev, &mut state, &gate).await.unwrap();
            assert!(
                matches!(state, ChallengeState::WaitingWitness { attempts, .. } if attempts == i as u32),
                "WB-lag retains counter {i}, got {state:?}"
            );
            // WB recovers ⇒ re-broadcast at the SAME attempt count (never reset by the lag).
            h.drive(&ev, &mut state, &gate).await.unwrap();
            assert!(
                matches!(state, ChallengeState::Submitted { attempts, .. } if attempts == i as u32),
                "re-broadcast at attempts={i}, got {state:?}"
            );
        }

        // A 4th confirmed revert would exceed max_resend=3 ⇒ terminal, gate released.
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::PermanentFailure), "capped at max_resend, got {state:?}");
        assert_eq!(gate.holder(), None, "gate released on the terminal cap");
    }

    #[tokio::test]
    async fn closed_challenge_becomes_closed_no_tx() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        cc.set_status(ev.challenge_id, ChallengeStatus { open: false, deadline: 10_000, chain_timestamp: 0 });
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Closed));
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn witness_not_found_and_root_not_found_are_waits() {
        for e in [WbError::WithdrawalNotFound, WbError::RootNotFound] {
            let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
            witness.set_proof_err(e.clone());
            let h = handler_with(cc.clone(), witness, rm, 3);
            let gate = InFlightGate::new();
            let mut state = ChallengeState::Discovered;
            h.drive(&ev, &mut state, &gate).await.unwrap();
            assert!(matches!(state, ChallengeState::WaitingWitness { .. }), "{e:?} ⇒ wait");
            assert!(cc.prove_calls().is_empty());
        }
    }

    #[tokio::test]
    async fn corrupt_and_protocol_witness_are_permanent_no_tx() {
        for e in [WbError::WitnessStoreCorrupt, WbError::Protocol] {
            let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
            witness.set_proof_err(e.clone());
            let h = handler_with(cc.clone(), witness, rm, 3);
            let gate = InFlightGate::new();
            let mut state = ChallengeState::Discovered;
            h.drive(&ev, &mut state, &gate).await.unwrap();
            assert!(matches!(state, ChallengeState::PermanentFailure), "{e:?} ⇒ permanent");
            assert!(cc.prove_calls().is_empty());
        }
    }

    #[tokio::test]
    async fn mis_bound_proof_is_permanent_failure_no_tx() {
        // A valid proof for a DIFFERENT leaf than the challenge's ⇒ leaf-binding fails ⇒ permanent.
        let (_rec, other_proof, _other_leaf, other_root) = valid_proof(0x11);
        let cc = Arc::new(MockChallengeContract::new());
        let ev = ev_for(record_leaf_hash(&valid_record(0x42)).unwrap()); // challenge for leaf 0x42
        cc.set_status(ev.challenge_id, ChallengeStatus { open: true, deadline: 10_000, chain_timestamp: 0 });
        let witness = Arc::new(MockWitness::ok(other_proof, 10));
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(20, other_root);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::PermanentFailure));
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn missing_latest_root_is_error_no_tx() {
        let (_rec, proof, leaf, _root) = valid_proof(0x42);
        let cc = Arc::new(MockChallengeContract::new());
        let ev = ev_for(leaf);
        cc.set_status(ev.challenge_id, ChallengeStatus { open: true, deadline: 10_000, chain_timestamp: 0 });
        let witness = Arc::new(MockWitness::ok(proof, 10));
        let rm = Arc::new(MockRootManager::new()); // never set
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        assert!(h.drive(&ev, &mut state, &gate).await.is_err());
        assert!(cc.prove_calls().is_empty());
    }

    #[tokio::test]
    async fn gate_held_by_another_stays_ready_no_broadcast() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        // Another challenge already holds the gate.
        let other = ChallengeId([0xEE; 32]);
        gate.try_acquire(other);
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Ready { .. }), "gate busy ⇒ Ready, got {state:?}");
        assert!(cc.prove_calls().is_empty(), "no broadcast while the gate is held by another");
        assert_eq!(gate.holder(), Some(other), "the other challenge still holds the gate");
    }

    #[tokio::test]
    async fn terminal_state_is_a_noop() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Proved(TxHash::repeat_byte(0x99));
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Proved(_)));
        assert!(cc.prove_calls().is_empty());
    }
}
