//! Single-challenge Defender state machine.
//!
//! One [`Handler::drive`] step advances one challenge; the supervisor re-drives every non-terminal
//! challenge each tick. The flow per challenge is: covering-root gate → fetch proof →
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

/// Lock a mutex, recovering the guard if a previous holder panicked. The state these mutexes
/// guard (an `Option<ChallengeId>` gate token and an in-memory LRU proof cache) stays structurally
/// valid across a panic, so a poisoned lock must NOT turn into a permanent panic loop on every
/// subsequent tick — recover the inner guard and continue.
fn lock_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
    /// The RootManager latest checkpoint does not yet cover the record height.
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
/// (`attempts`, bound `root`, wait `reason`) lives here — never in a side map.
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
    /// The broadcast outcome is unknown (holds the in-flight gate). If `tx_hash` is present
    /// the handler reconciles via status + receipt; with no `tx_hash` and still open it keeps
    /// holding the gate and polling — never inferring "not broadcast", never resending.
    ReconcileUnknown { tx_hash: Option<TxHash>, attempts: u32, root: Option<B256> },
    /// A confirmed revert eligible for a bounded resend on a later tick; `attempts` already
    /// reflects the incremented resend count and `prev_root` is the withdrawal root that
    /// reverted. Both are persisted here BEFORE the next tick queries the latest root, so a
    /// transient RootManager/WB failure during that query preserves the retry context (no
    /// counter reset) and never resends the same root.
    RetryableRevert { attempts: u32, prev_root: B256 },
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
            ChallengeState::Proved(_) |
                ChallengeState::Closed |
                ChallengeState::Expired |
                ChallengeState::PermanentFailure
        )
    }

    /// The resend count carried by a non-terminal, pre-broadcast state.
    fn attempts(&self) -> u32 {
        match self {
            ChallengeState::WaitingWitness { attempts, .. } |
            ChallengeState::Ready { attempts } |
            ChallengeState::RetryableRevert { attempts, .. } => *attempts,
            _ => 0,
        }
    }
}

/// Global single-process in-flight transaction gate: at most one challenge may hold it, so at
/// most one prove transaction is in flight across all `ChallengeId`s. It does NOT survive a
/// restart.
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
        *lock_recover(&self.holder)
    }

    /// Acquire the gate for `id` iff it is free or already held by `id`. Returns whether `id` holds
    /// the gate after the call.
    fn try_acquire(&self, id: ChallengeId) -> bool {
        let mut h = lock_recover(&self.holder);
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
        let mut h = lock_recover(&self.holder);
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
    /// `NotReady` (11006), authoritative `RootNotFound` (11009), and transient transport.
    /// Everything else (mismatch, store corruption, protocol, invalid request, permanent
    /// transport) is permanent and fails closed.
    fn classify_witness_wait(
        err: WbError,
        attempts: u32,
        last_root: Option<B256>,
    ) -> ChallengeState {
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
        if let Some(p) = lock_recover(&self.cache).get(&(leaf, root)) {
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

        // A confirmed revert eligible for a bounded resend. The incremented `attempts` and the
        // reverted `prev_root` were persisted into this state on the tick that observed the revert,
        // BEFORE this query. So a transient RootManager failure here propagates as an error with
        // the state left untouched — the retry context (counter + reverted root) survives
        // and the same root is never resent. A resend proceeds only once the latest root
        // has actually changed; an unchanged root means resending the same proof would
        // revert again, which is terminal.
        if let ChallengeState::RetryableRevert { attempts, prev_root } = state.clone() {
            let (_checkpoint_height, withdrawal_root) = self.root_manager.latest_root().await?;
            if withdrawal_root == prev_root {
                *state = ChallengeState::PermanentFailure;
                return Ok(());
            }
            *state = self.prepare_and_submit(ev, attempts, gate).await?;
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
        // 1. Covering-root gate: the record must be covered by the latest checkpoint.
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

        // 2. Obtain the proof (LRU cache, else WB), classifying errors per the wait/permanent
        //    split.
        let proof = match self.fetch_proof(ev.leaf_hash, withdrawal_root).await {
            Ok(p) => p,
            Err(e) => return Ok(Self::classify_witness_wait(e, attempts, Some(withdrawal_root))),
        };

        // 3. Local leaf-bound verification — never send an unverified or mis-bound proof.
        if verify(&proof, ev.leaf_hash, withdrawal_root, self.chain_id).is_err() {
            return Ok(ChallengeState::PermanentFailure);
        }
        lock_recover(&self.cache).put((ev.leaf_hash, withdrawal_root), proof.clone());

        // 4. Pre-broadcast recheck: fresh status + deadline before EVERY send.
        let status = self.reader.get_challenge(ev.challenge_id).await?;
        if !status.open {
            return Ok(ChallengeState::Closed);
        }
        if self.past_deadline(&status) {
            return Ok(ChallengeState::Expired);
        }

        // 5. Acquire the global in-flight gate. If another challenge holds it, stay Ready.
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
            // Provably never broadcast ⇒ release the gate and retry next tick (the ONLY safe
            // retry).
            Err(SenderError::SafeToRetryPreBroadcast) => {
                gate.release(ev.challenge_id);
                Ok(ChallengeState::Ready { attempts })
            }
            // A confirmed rejection at submit is a confirmed revert ⇒ counted resend / terminal.
            Err(SenderError::ConfirmedRejection) => {
                self.on_confirmed_revert(ev, attempts, withdrawal_root, gate).await
            }
            // Unknown outcome ⇒ hold the gate and reconcile; never infer not-broadcast.
            Err(SenderError::UnknownBroadcastOutcome { tx_hash }) => {
                Ok(ChallengeState::ReconcileUnknown {
                    tx_hash,
                    attempts,
                    root: Some(withdrawal_root),
                })
            }
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
                    // A successful receipt plus a no-longer-open challenge is terminal, but only
                    // OUR resolution is `Proved` — a challenge closed by
                    // another responder is `Closed`, never credited to us (a
                    // successful receipt alone does not prove we won).
                    gate.release(ev.challenge_id);
                    if status.resolved_by_us {
                        Ok(ChallengeState::Proved(tx))
                    } else {
                        Ok(ChallengeState::Closed)
                    }
                } else if self.past_deadline(status) {
                    // Receipt success but still open past the L2-time deadline: stop holding the
                    // gate on a challenge we can no longer usefully act on.
                    gate.release(ev.challenge_id);
                    Ok(ChallengeState::Expired)
                } else {
                    // Receipt success but still open before the deadline: reconcile on a later tick
                    // (keep the gate).
                    Ok(ChallengeState::Submitted { tx, attempts, root })
                }
            }
            TxStatus::Pending => {
                // A not-yet-mined receipt is NON-TERMINAL: the broadcast tx may still be in the
                // mempool or awaiting inclusion. Releasing the global in-flight gate now — merely
                // because the challenge deadline passed — would let another challenge broadcast a
                // second, concurrent tx from the same signer while this one is still live and
                // untracked. So keep holding the gate and keep reconciling; a reached deadline is
                // recorded but is NOT, on its own, grounds to release the gate. (Unblocking a
                // genuinely stuck tx would require a verifiable cancel/replace/nonce strategy,
                // which is out of scope here.)
                if self.past_deadline(status) {
                    tracing::warn!(
                        challenge_id = ?ev.challenge_id,
                        "prove tx still pending past the L2-time deadline; holding the in-flight \
                         gate and continuing to reconcile (a non-terminal receipt is not treated \
                         as terminal)"
                    );
                }
                Ok(ChallengeState::Submitted { tx, attempts, root })
            }
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

    /// Reconcile an unknown broadcast outcome. The gate is held by `ev` and released only on
    /// a confirmed terminal outcome. With no `tx_hash` and still open, keep holding + polling;
    /// never resend, never infer "not broadcast".
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
                        // Only OUR resolution is `Proved`; a challenge closed by another responder
                        // is `Closed` even with a successful receipt for our tx.
                        gate.release(ev.challenge_id);
                        if status.resolved_by_us {
                            Ok(ChallengeState::Proved(tx))
                        } else {
                            Ok(ChallengeState::Closed)
                        }
                    } else if self.past_deadline(status) {
                        gate.release(ev.challenge_id);
                        Ok(ChallengeState::Expired)
                    } else {
                        Ok(ChallengeState::ReconcileUnknown { tx_hash, attempts, root })
                    }
                }
                TxStatus::Pending => {
                    // Non-terminal receipt for a tx that may have broadcast: keep holding the gate
                    // and keep reconciling. A reached deadline is recorded but does NOT release the
                    // gate, because the tx may still be live in the mempool and releasing it would
                    // risk a second, concurrent broadcast.
                    if self.past_deadline(status) {
                        tracing::warn!(
                            challenge_id = ?ev.challenge_id,
                            "unknown-outcome prove tx still pending past the L2-time deadline; \
                             holding the in-flight gate and continuing to reconcile"
                        );
                    }
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
    /// longer in flight, so release the gate; then, if still within `max_resend`, persist the
    /// INCREMENTED counter and the reverted root into `RetryableRevert` (in-state). The latest-root
    /// read and the "root must have changed to resend" decision happen on the NEXT tick (in
    /// [`Handler::drive`]) from that persisted state, so a transient RootManager/WB failure during
    /// that read preserves the retry context (no counter reset) and never resends the same root. A
    /// witness-builder lag after the revert likewise cannot reset the counter.
    async fn on_confirmed_revert(
        &self,
        ev: &ChallengeOpened,
        attempts: u32,
        prev_root: B256,
        gate: &InFlightGate,
    ) -> Result<ChallengeState> {
        // The reverted tx is terminal (a confirmed on-chain revert / confirmed rejection), so it is
        // no longer in flight: release the gate.
        gate.release(ev.challenge_id);
        let next_attempt = attempts + 1;
        if next_attempt > self.max_resend {
            return Ok(ChallengeState::PermanentFailure);
        }
        // Persist the confirmed revert, the incremented attempt count, and the reverted root BEFORE
        // any fallible RootManager/WB query. The latest root is read next tick from this state; if
        // that read fails transiently the context is retained (counter not reset, same root not
        // resent). A resend proceeds only once the latest root has changed.
        Ok(ChallengeState::RetryableRevert { attempts: next_attempt, prev_root })
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
        ChallengeOpened::new(
            CHAIN_ID,
            Address::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            0,
            leaf,
            10,
        )
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
    ) -> (Arc<MockChallengeContract>, Arc<MockWitness>, Arc<MockRootManager>, ChallengeOpened, B256)
    {
        let (_rec, proof, leaf, root) = valid_proof(0x42);
        let cc = Arc::new(MockChallengeContract::new());
        let ev = ev_for(leaf);
        cc.set_status(
            ev.challenge_id,
            ChallengeStatus {
                open: true,
                deadline,
                chain_timestamp: chain_ts,
                resolved_by_us: false,
            },
        );
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
        assert!(
            matches!(state, ChallengeState::Proved(_)),
            "confirmed only after receipt + status"
        );
        assert_eq!(gate.holder(), None, "gate released on Proved");
    }

    #[tokio::test]
    async fn pending_receipt_stays_submitted_no_resend() {
        let (cc, witness, rm, ev, root) = setup_ready(10_000, 0, 20);
        // No scripted tx status ⇒ confirm returns Pending.
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        gate.try_acquire(ev.challenge_id);
        let mut state =
            ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root };
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::Submitted { .. }),
            "pending ⇒ reconcile, not resend"
        );
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
            matches!(
                state,
                ChallengeState::WaitingWitness { reason: WaitReason::RootBehindRecord, .. }
            ),
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
            matches!(
                state,
                ChallengeState::WaitingWitness { reason: WaitReason::RecordNotInCheckpoint, .. }
            ),
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
        cc.set_sender_error(
            ev.challenge_id,
            SenderError::UnknownBroadcastOutcome { tx_hash: None },
        );
        cc.keep_open(ev.challenge_id);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::ReconcileUnknown { tx_hash: None, .. }));
        assert_eq!(gate.holder(), Some(ev.challenge_id), "unknown outcome HOLDS the gate");
        let before = cc.prove_calls().len();
        h.drive(&ev, &mut state, &gate).await.unwrap(); // still open, no tx hash ⇒ no resend
        assert_eq!(
            cc.prove_calls().len(),
            before,
            "no resend without a confirmed-safe classification"
        );
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
    fn proof_for(
        record: &WithdrawRecord,
        leaf: B256,
        filler: u8,
    ) -> (HistoricalInclusionProof, B256) {
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
        cc.set_status(
            ev.challenge_id,
            ChallengeStatus {
                open: true,
                deadline: 100_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
        );
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Reverted);
        cc.keep_open(ev.challenge_id);
        let witness = Arc::new(MockWitness::ok(p0, 10));
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(20, root0);
        let h = handler_with(cc.clone(), witness.clone(), rm.clone(), 3);
        let gate = InFlightGate::new();

        // Start Submitted at attempts 0 against root0; the gate is held by this challenge.
        gate.try_acquire(ev.challenge_id);
        let mut state =
            ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root: root0 };

        // Each confirmed revert with a changed root increments attempts; a WB-lag between the
        // revert and the re-broadcast retains the counter (cannot reset it).
        for i in 1..=3u8 {
            let (next_proof, next_root) = proof_for(&record, leaf, 0xF0 + i);
            rm.set_latest(20 + i as u64, next_root);
            witness.set_proof(next_proof);
            // Confirmed revert + changed root ⇒ RetryableRevert{attempts=i}.
            h.drive(&ev, &mut state, &gate).await.unwrap();
            assert!(
                matches!(state, ChallengeState::RetryableRevert { attempts, .. } if attempts == i as u32),
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
        assert!(
            matches!(state, ChallengeState::PermanentFailure),
            "capped at max_resend, got {state:?}"
        );
        assert_eq!(gate.holder(), None, "gate released on the terminal cap");
    }

    #[tokio::test]
    async fn closed_challenge_becomes_closed_no_tx() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        cc.set_status(
            ev.challenge_id,
            ChallengeStatus {
                open: false,
                deadline: 10_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
        );
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
        cc.set_status(
            ev.challenge_id,
            ChallengeStatus {
                open: true,
                deadline: 10_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
        );
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
        cc.set_status(
            ev.challenge_id,
            ChallengeStatus {
                open: true,
                deadline: 10_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
        );
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

    // ── Resolution ownership (a successful receipt on a no-longer-open challenge is only OUR win
    //    when the on-chain status attributes the resolution to us) ──

    #[tokio::test]
    async fn receipt_success_closed_by_other_is_closed_not_proved() {
        // Our tx receipt succeeded and the challenge is no longer open, but the on-chain status
        // says it was NOT resolved by us ⇒ Closed, never Proved.
        let (cc, witness, rm, ev, root) = setup_ready(10_000, 0, 20);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        cc.mark_closed_by_other(ev.challenge_id);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        gate.try_acquire(ev.challenge_id);
        let mut state =
            ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root };
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::Closed),
            "closed by another responder ⇒ Closed, not Proved, got {state:?}"
        );
        assert_eq!(gate.holder(), None, "gate released on the terminal outcome");
    }

    #[tokio::test]
    async fn unknown_then_success_closed_by_other_is_closed_not_proved() {
        // The reconcile-unknown path must apply the same ownership rule.
        let (cc, witness, rm, ev, root) = setup_ready(10_000, 0, 20);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        cc.mark_closed_by_other(ev.challenge_id);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        gate.try_acquire(ev.challenge_id);
        let mut state = ChallengeState::ReconcileUnknown {
            tx_hash: Some(TxHash::repeat_byte(0x99)),
            attempts: 0,
            root: Some(root),
        };
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Closed), "closed-by-other ⇒ Closed, got {state:?}");
        assert_eq!(gate.holder(), None);
    }

    // ── Terminal-receipt gate release honours the L2-time deadline; a NON-terminal (Pending)
    //    receipt does NOT — a pending tx may still be in the mempool, so it keeps holding the gate
    //    and is kept tracked rather than being treated as terminal on the deadline alone. ──

    #[tokio::test]
    async fn submitted_pending_past_deadline_holds_gate_and_keeps_tracking() {
        // The receipt is still Pending while chain_ts + safety >= deadline. The tx may still be in
        // the mempool, so the challenge must STAY Submitted (kept tracked) and KEEP holding the
        // in-flight gate — it must NOT be treated as Expired / released on the deadline alone
        // (releasing would let a second, concurrent tx broadcast against the untracked pending
        // one).
        let (cc, witness, rm, ev, root) = setup_ready(1_000, 999, 20);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        gate.try_acquire(ev.challenge_id);
        let mut state =
            ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root };
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::Submitted { .. }),
            "pending past deadline stays Submitted (a non-terminal receipt is not terminal), got {state:?}"
        );
        assert_eq!(
            gate.holder(),
            Some(ev.challenge_id),
            "the pending tx keeps holding the in-flight gate"
        );
        assert!(cc.prove_calls().is_empty(), "no new broadcast while reconciling a pending tx");

        // Once the receipt reaches a terminal state (success + our on-chain resolution), the gate
        // is released normally — the pending hold is not permanent, it just waits for a
        // real outcome.
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        cc.mark_resolved_in_our_favor(ev.challenge_id);
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::Proved(_)),
            "a terminal receipt resolves the challenge, got {state:?}"
        );
        assert_eq!(gate.holder(), None, "gate released on the terminal outcome");
    }

    #[tokio::test]
    async fn pending_past_deadline_holds_gate_and_blocks_a_second_broadcast() {
        // A prove tx still Pending past its deadline must not free the gate, so a DIFFERENT ready
        // challenge cannot broadcast a second, concurrent tx while the first is still live.
        let gate = InFlightGate::new();

        // Challenge A: Submitted, receipt Pending, past its L2-time deadline ⇒ stays Submitted and
        // keeps holding the gate.
        let (cc_a, wit_a, rm_a, ev_a, root_a) = setup_ready(1_000, 999, 20);
        let h_a = handler_with(cc_a.clone(), wit_a, rm_a, 3);
        gate.try_acquire(ev_a.challenge_id);
        let mut state_a =
            ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root: root_a };
        h_a.drive(&ev_a, &mut state_a, &gate).await.unwrap();
        assert!(matches!(state_a, ChallengeState::Submitted { .. }), "A stays Submitted");
        assert_eq!(
            gate.holder(),
            Some(ev_a.challenge_id),
            "A keeps holding the gate past deadline"
        );

        // Challenge B: a distinct, fully-ready challenge sharing the same gate. It must NOT
        // broadcast while A holds the gate ⇒ it stays Ready and issues no tx (no second
        // concurrent broadcast).
        let (_r2, proof_b, leaf_b, root_b) = valid_proof(0x55);
        let cc_b = Arc::new(MockChallengeContract::new());
        // The ChallengeId derives from (chain_id, contract, tx_hash, log_index) — NOT the leaf — so
        // B must use a distinct tx_hash (0x03 vs A's 0x02) to be a genuinely different challenge.
        let ev_b = ChallengeOpened::new(
            CHAIN_ID,
            Address::repeat_byte(0x01),
            B256::repeat_byte(0x03),
            0,
            leaf_b,
            10,
        );
        assert_ne!(ev_a.challenge_id, ev_b.challenge_id, "A and B are distinct challenges");
        cc_b.set_status(
            ev_b.challenge_id,
            ChallengeStatus {
                open: true,
                deadline: 10_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
        );
        let wit_b = Arc::new(MockWitness::ok(proof_b, 10));
        let rm_b = Arc::new(MockRootManager::new());
        rm_b.set_latest(20, root_b);
        let h_b = handler_with(cc_b.clone(), wit_b, rm_b, 3);
        let mut state_b = ChallengeState::Discovered;
        h_b.drive(&ev_b, &mut state_b, &gate).await.unwrap();
        assert!(
            matches!(state_b, ChallengeState::Ready { .. }),
            "B blocked behind A's held gate, got {state_b:?}"
        );
        assert!(
            cc_b.prove_calls().is_empty(),
            "no second concurrent tx while A's pending tx holds the gate"
        );
        assert_eq!(gate.holder(), Some(ev_a.challenge_id), "the gate is still A's");
    }

    #[tokio::test]
    async fn submitted_success_still_open_past_deadline_expires_and_releases_gate() {
        // Receipt succeeded but the challenge is still open and past its deadline ⇒ Expired.
        let (cc, witness, rm, ev, root) = setup_ready(1_000, 999, 20);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        cc.keep_open(ev.challenge_id);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        gate.try_acquire(ev.challenge_id);
        let mut state =
            ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root };
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::Expired),
            "success+open past deadline ⇒ Expired, got {state:?}"
        );
        assert_eq!(gate.holder(), None);
    }

    #[tokio::test]
    async fn unknown_pending_past_deadline_holds_gate_and_keeps_reconciling() {
        // Unknown broadcast outcome with a tx hash whose receipt is still Pending past the
        // deadline: the tx may still be in the mempool, so the challenge KEEPS reconciling
        // (stays ReconcileUnknown) and KEEPS holding the gate — it is not treated as
        // Expired on the deadline alone.
        let (cc, witness, rm, ev, root) = setup_ready(1_000, 999, 20);
        let h = handler_with(cc.clone(), witness, rm, 3);
        let gate = InFlightGate::new();
        gate.try_acquire(ev.challenge_id);
        let mut state = ChallengeState::ReconcileUnknown {
            tx_hash: Some(TxHash::repeat_byte(0x99)),
            attempts: 0,
            root: Some(root),
        };
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::ReconcileUnknown { tx_hash: Some(_), .. }),
            "unknown+pending past deadline keeps reconciling, got {state:?}"
        );
        assert_eq!(
            gate.holder(),
            Some(ev.challenge_id),
            "a pending unknown-outcome tx keeps holding the gate"
        );
        assert!(cc.prove_calls().is_empty(), "no broadcast while reconciling a pending unknown tx");
    }

    // ── Confirmed-rejection resend context survives a transient RootManager failure: the
    //    incremented counter + reverted root are persisted BEFORE the fallible latest-root query,
    // so    a transient RPC blip neither resets the counter nor resends the same root ──

    #[tokio::test]
    async fn confirmed_rejection_transient_root_failure_preserves_resend_context() {
        let (cc, witness, rm, ev, root0) = setup_ready(100_000, 0, 20);
        // The submit is confirmed-rejected on-chain.
        cc.set_sender_error(ev.challenge_id, SenderError::ConfirmedRejection);
        cc.keep_open(ev.challenge_id);
        let h = handler_with(cc.clone(), witness, rm.clone(), 3);
        let gate = InFlightGate::new();

        // Drive 1: Discovered → prepare/submit → ConfirmedRejection. The incremented counter and
        // the reverted root are persisted into RetryableRevert WITHOUT querying the latest
        // root.
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::RetryableRevert { attempts: 1, prev_root } if prev_root == root0),
            "confirmed rejection ⇒ RetryableRevert{{attempts:1, prev_root:root0}}, got {state:?}"
        );
        assert_eq!(gate.holder(), None, "the reverted tx released the gate");
        assert!(cc.prove_calls().is_empty(), "a confirmed rejection records no broadcast");

        // Drive 2: the RootManager RPC blips (transient). The drive surfaces the error and LEAVES
        // THE STATE UNTOUCHED — the retry context survives (attempts stays 1, prev_root stays
        // root0).
        rm.fail_latest_once();
        assert!(
            h.drive(&ev, &mut state, &gate).await.is_err(),
            "a transient RootManager failure surfaces as an error"
        );
        assert!(
            matches!(state, ChallengeState::RetryableRevert { attempts: 1, prev_root } if prev_root == root0),
            "transient failure must NOT reset attempts or lose the reverted root, got {state:?}"
        );

        // Drive 3: the RootManager recovers but the latest root is UNCHANGED (still root0).
        // Resending the same root would revert again, so the challenge terminates — it
        // never resends the same root, and the counter was never reset behind our back.
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(
            matches!(state, ChallengeState::PermanentFailure),
            "unchanged root after recovery ⇒ no same-root resend, terminal, got {state:?}"
        );
        assert!(cc.prove_calls().is_empty(), "the same reverted root is never rebroadcast");
    }

    // ── Lock-poison resilience: a panic while a production state lock is held must not turn every
    //    subsequent tick into a panic loop ──

    #[test]
    fn lock_recover_recovers_a_poisoned_mutex() {
        let m = Arc::new(Mutex::new(5u32));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("poison the mutex while holding the guard");
        })
        .join();
        // `.lock().unwrap()` would panic on the poisoned mutex; lock_recover must not.
        assert_eq!(*lock_recover(&m), 5, "state recovered after poison");
        *lock_recover(&m) = 7;
        assert_eq!(*lock_recover(&m), 7);
    }

    #[test]
    fn in_flight_gate_survives_a_poisoned_lock() {
        let gate = InFlightGate::new();
        let holder = gate.holder.clone();
        let _ = std::thread::spawn(move || {
            let _g = holder.lock().unwrap();
            panic!("poison the in-flight gate mutex");
        })
        .join();
        // The gate must stay usable rather than panic on every access after a poisoning panic.
        assert_eq!(gate.holder(), None, "gate state recovered after poison");
        assert!(gate.try_acquire(ChallengeId([0x01; 32])));
        assert_eq!(gate.holder(), Some(ChallengeId([0x01; 32])));
        gate.release(ChallengeId([0x01; 32]));
        assert_eq!(gate.holder(), None);
    }

    #[tokio::test]
    async fn proof_cache_survives_a_poisoned_lock() {
        let (cc, witness, rm, ev, _root) = setup_ready(10_000, 0, 20);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        let h = handler_with(cc.clone(), witness, rm, 3);
        // Poison the proof-cache mutex: its guard's Drop marks it poisoned as the panic unwinds.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = h.cache.lock().unwrap();
            panic!("poison the proof cache mutex");
        }));
        // A drive that reads and writes the cache must still succeed rather than panic on the
        // poison.
        let gate = InFlightGate::new();
        let mut state = ChallengeState::Discovered;
        h.drive(&ev, &mut state, &gate).await.unwrap();
        assert!(matches!(state, ChallengeState::Submitted { .. }), "recovered: {state:?}");
    }
}
