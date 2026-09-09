//! Event-driven supervisor loop.
//!
//! Each tick reads the L2 latest head `H`, computes `actionable_to = H - finality_blocks` **once**
//! (Model A, R5-3), scans an explicit [`ScanWindow`] (`[startup_lookback, actionable_to]` on the
//! first tick, a reorg-safe cursor for `from_block` afterwards, `to_block` always `actionable_to`),
//! merges newly-discovered challenges (deduplicated by [`ChallengeId`]) into a pending map, and
//! re-drives every non-terminal challenge one step. Discovery (dedup) and pending work (retry) are
//! decoupled, so a challenge that is waiting for the witness, awaiting confirmation, or eligible
//! for a bounded resend is re-driven on subsequent ticks rather than dropped once its event is
//! seen.
//!
//! Two invariants the reviewed version violated are restored here:
//! - **Per-challenge failure isolation** (MR105-4): a transient status/RootManager/receipt error
//!   for one challenge is caught and the challenge is **preserved** in `pending` (never
//!   removed-then-`?`); the tick keeps driving the others.
//! - **Single in-flight broadcast, nearest-deadline-first** (MR105-5/D7): broadcasting is gated by
//!   a shared [`InFlightGate`]; challenges are driven nearest-deadline-first so the free gate is
//!   granted to the most urgent challenge.
//!
//! Restart recovery keeps no persistence: a prior transaction hash and the in-flight gate are lost
//! across a restart, so on startup the supervisor rescans a bounded window and, for each
//! rediscovered challenge, queries only the current on-chain status. A closed challenge is not
//! re-enqueued; a still-open one is re-enqueued for best-effort recovery and may resend. A hard
//! cross-restart no-double-submit guarantee is deferred to a future contract with idempotent
//! per-challenge transitions.

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;

use super::{
    challenge_contract::{ChallengeId, ChallengeOpened, ChallengeReader, ScanWindow},
    handler::{ChallengeState, Handler, InFlightGate},
    watcher::Watcher,
};

/// Drives discovery and the pending/retry queue.
pub struct Supervisor {
    watcher: Watcher,
    handler: Handler,
    reader: Arc<dyn ChallengeReader>,
    gate: InFlightGate,
    finality_blocks: u64,
    startup_lookback: u64,
    /// Reorg-safe steady-state cursor for `from_block`; `None` until the first tick (which uses
    /// the explicit startup lookback window).
    cursor: Option<u64>,
    pending: HashMap<ChallengeId, (ChallengeOpened, ChallengeState)>,
}

impl Supervisor {
    pub fn new(
        watcher: Watcher,
        handler: Handler,
        reader: Arc<dyn ChallengeReader>,
        gate: InFlightGate,
        finality_blocks: u64,
        startup_lookback: u64,
    ) -> Self {
        Self {
            watcher,
            handler,
            reader,
            gate,
            finality_blocks,
            startup_lookback,
            cursor: None,
            pending: HashMap::new(),
        }
    }

    /// The scan window for this tick: startup uses the explicit `[actionable_to - startup_lookback,
    /// actionable_to]`; steady-state uses the reorg-safe cursor for `from_block`. `to_block` is
    /// always `actionable_to` (finality applied exactly once by the caller of this helper).
    fn scan_window(&self, actionable_to: u64) -> ScanWindow {
        let from_block =
            self.cursor.unwrap_or_else(|| actionable_to.saturating_sub(self.startup_lookback));
        ScanWindow { from_block, to_block: actionable_to }
    }

    /// One supervisor iteration. `l2_head` is the L2 latest head `H`; finality is applied here
    /// exactly once as `actionable_to = H - finality_blocks`.
    pub async fn tick(&mut self, l2_head: u64) -> Result<()> {
        let actionable_to = l2_head.saturating_sub(self.finality_blocks);
        let window = self.scan_window(actionable_to);
        for ev in self.watcher.poll(window).await? {
            self.pending.entry(ev.challenge_id).or_insert((ev, ChallengeState::Discovered));
        }
        // Advance the reorg-safe cursor so the next tick continues just past this window.
        self.cursor = Some(actionable_to.saturating_add(1));

        // Order pending challenges nearest-deadline-first so the single in-flight gate is granted
        // to the most urgent challenge. A status-read error while ordering does NOT drop
        // the challenge: it is ordered last (u64::MAX) and still driven (its own drive
        // re-reads + handles it).
        let mut ids: Vec<ChallengeId> = self.pending.keys().copied().collect();
        let mut deadlines: HashMap<ChallengeId, u64> = HashMap::new();
        for id in &ids {
            let deadline =
                self.reader.get_challenge(*id).await.map(|s| s.deadline).unwrap_or(u64::MAX);
            deadlines.insert(*id, deadline);
        }
        ids.sort_by(|a, b| {
            let (da, db) = (
                deadlines.get(a).copied().unwrap_or(u64::MAX),
                deadlines.get(b).copied().unwrap_or(u64::MAX),
            );
            da.cmp(&db).then_with(|| a.0.cmp(&b.0))
        });

        for id in ids {
            if let Some((ev, mut state)) = self.pending.remove(&id) {
                let before = state.clone();
                if !state.is_terminal() {
                    if let Err(e) = self.handler.drive(&ev, &mut state, &self.gate).await {
                        tracing::warn!(
                            error = %e,
                            "challenge drive failed this tick; preserving it for retry \
                             (per-challenge failure isolation)"
                        );
                        // Failure isolation: restore the pre-drive state and keep the challenge.
                        state = before;
                    }
                }
                if !state.is_terminal() {
                    self.pending.insert(id, (ev, state));
                }
            }
        }
        Ok(())
    }

    /// Best-effort restart reconciliation using current on-chain status only. A closed challenge is
    /// skipped; a still-open one is re-enqueued (may resend). No prior transaction receipt is
    /// queried — the tx hash is lost across a restart.
    pub async fn reconcile_on_startup(&mut self, rediscovered: &[ChallengeOpened]) -> Result<()> {
        for ev in rediscovered {
            let status = self.reader.get_challenge(ev.challenge_id).await?;
            if status.open {
                self.pending
                    .entry(ev.challenge_id)
                    .or_insert((ev.clone(), ChallengeState::Discovered));
                tracing::warn!(
                    "re-enqueued a still-open challenge on startup for best-effort recovery; a hard \
                     cross-restart no-double-submit guarantee depends on future contract idempotency"
                );
            }
        }
        Ok(())
    }

    /// Number of pending (non-terminal) challenges.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether a challenge is currently pending.
    pub fn is_pending(&self, id: ChallengeId) -> bool {
        self.pending.contains_key(&id)
    }

    /// The current pending state of a challenge, if any.
    pub fn pending_state(&self, id: ChallengeId) -> Option<ChallengeState> {
        self.pending.get(&id).map(|(_, s)| s.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::{
        defender::{
            challenge_contract::{ChallengeStatus, MockChallengeContract, ScanWindow, TxStatus},
            handler::WitnessSource,
            rootmanager_client::MockRootManager,
            verifier::record_leaf_hash,
        },
        withdraw::{
            error::WbError,
            tree_adapter::{single_leaf_withdrawal_fixture, two_leaf_withdrawal_fixture},
            types::{HistoricalInclusionProof, WithdrawRecord},
        },
    };
    use alloy_primitives::{Address, TxHash, B256, U256};
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    const SAFETY: u64 = 100;
    const CHAIN_ID: u64 = 196;

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

    fn valid_proof(seed: u8) -> (HistoricalInclusionProof, B256, B256) {
        let record = valid_record(seed);
        let leaf = record_leaf_hash(&record).unwrap();
        let (siblings, root) = single_leaf_withdrawal_fixture(leaf);
        let proof = HistoricalInclusionProof {
            record,
            record_hash: leaf,
            leaf_hash: leaf,
            canonical_block_height: 10,
            withdrawal_root: root,
            leaf_index: 0,
            count: 1,
            siblings,
        };
        (proof, leaf, root)
    }

    /// A witness whose proof result can be switched between not-ready and ready.
    struct SwitchWitness {
        proof: StdMutex<Result<HistoricalInclusionProof, WbError>>,
    }
    impl SwitchWitness {
        fn not_ready() -> Self {
            Self { proof: StdMutex::new(Err(WbError::WithdrawalNotFound)) }
        }
        fn make_ready(&self, proof: HistoricalInclusionProof) {
            *self.proof.lock().unwrap() = Ok(proof);
        }
    }
    #[async_trait]
    impl WitnessSource for SwitchWitness {
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

    fn contract() -> Address {
        Address::repeat_byte(0x01)
    }

    fn handler_with(
        cc: Arc<MockChallengeContract>,
        witness: Arc<dyn WitnessSource>,
        rm: Arc<MockRootManager>,
    ) -> Handler {
        Handler::new(cc.clone(), cc.clone(), witness, rm, CHAIN_ID, 16, SAFETY, 3)
    }

    #[tokio::test]
    async fn pending_challenge_is_redriven_until_terminal() {
        let (proof, leaf, root) = valid_proof(0x42);
        let cc = Arc::new(MockChallengeContract::new());
        let ev = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x02), 0, leaf, 100);
        let id = ev.challenge_id;
        cc.inject_opened(ev, 10_000);
        cc.set_status(id, ChallengeStatus { open: true, deadline: 10_000, chain_timestamp: 0 });
        let witness = Arc::new(SwitchWitness::not_ready());
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(20, root);
        let handler = handler_with(cc.clone(), witness.clone(), rm);
        let mut sup = Supervisor::new(
            Watcher::new(cc.clone()),
            handler,
            cc.clone(),
            InFlightGate::new(),
            0,
            1_000,
        );

        // Tick 1: witness not ready ⇒ the challenge stays pending (not dropped).
        sup.tick(200).await.unwrap();
        assert_eq!(sup.pending_len(), 1, "non-terminal challenge stays pending");

        // Make the witness ready and prime a successful receipt; keep the challenge open so the
        // first re-drive broadcasts.
        witness.make_ready(proof);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        sup.tick(200).await.unwrap(); // Submitted
        assert_eq!(sup.pending_len(), 1);

        // The prove resolves the challenge on-chain; the next tick confirms and terminates it.
        cc.mark_resolved_in_our_favor(id);
        sup.tick(200).await.unwrap(); // Submitted → Proved (terminal)
        assert_eq!(sup.pending_len(), 0, "terminal challenge is removed");
    }

    /// Two challenges (`seed_a`, `seed_b`) sharing ONE two-leaf tree root, each with its own
    /// per-index bound proof. Returns `(leaf_a, proof_a, leaf_b, proof_b, root)`.
    #[allow(clippy::type_complexity)]
    fn two_challenge_tree(
        seed_a: u8,
        seed_b: u8,
    ) -> (B256, HistoricalInclusionProof, B256, HistoricalInclusionProof, B256) {
        let ra = valid_record(seed_a);
        let rb = valid_record(seed_b);
        let la = record_leaf_hash(&ra).unwrap();
        let lb = record_leaf_hash(&rb).unwrap();
        let ((sib_a, idx_a), (sib_b, idx_b), root) = two_leaf_withdrawal_fixture(la, lb);
        let pa = HistoricalInclusionProof {
            record: ra,
            record_hash: la,
            leaf_hash: la,
            canonical_block_height: 10,
            withdrawal_root: root,
            leaf_index: idx_a,
            count: 2,
            siblings: sib_a,
        };
        let pb = HistoricalInclusionProof {
            record: rb,
            record_hash: lb,
            leaf_hash: lb,
            canonical_block_height: 10,
            withdrawal_root: root,
            leaf_index: idx_b,
            count: 2,
            siblings: sib_b,
        };
        (la, pa, lb, pb, root)
    }

    fn leaf_witness(entries: Vec<(B256, HistoricalInclusionProof)>) -> Arc<LeafWitness> {
        let mut m = std::collections::HashMap::new();
        for (leaf, proof) in entries {
            m.insert(leaf, proof);
        }
        Arc::new(LeafWitness { by_leaf: StdMutex::new(m) })
    }

    #[tokio::test]
    async fn transient_error_preserves_challenge_and_isolates_failure() {
        let (leaf_a, proof_a, leaf_b, proof_b, root) = two_challenge_tree(0x0A, 0x0B);
        let cc = Arc::new(MockChallengeContract::new());
        let a = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x0A), 0, leaf_a, 100);
        let b = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x0B), 0, leaf_b, 100);
        cc.inject_opened(a.clone(), 10_000);
        cc.inject_opened(b.clone(), 10_000);
        cc.set_status(
            a.challenge_id,
            ChallengeStatus { open: true, deadline: 10_000, chain_timestamp: 0 },
        );
        cc.set_status(
            b.challenge_id,
            ChallengeStatus { open: true, deadline: 10_000, chain_timestamp: 0 },
        );
        let witness = leaf_witness(vec![(leaf_a, proof_a), (leaf_b, proof_b)]);
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(20, root);
        let handler = handler_with(cc.clone(), witness, rm);
        let mut sup = Supervisor::new(
            Watcher::new(cc.clone()),
            handler,
            cc.clone(),
            InFlightGate::new(),
            0,
            1_000,
        );

        // A's status RPC fails this whole tick; B must still be driven, and A must be preserved
        // (never removed-then-`?`).
        cc.set_status_failure(a.challenge_id);
        sup.tick(200).await.unwrap();
        assert!(sup.is_pending(a.challenge_id), "A preserved despite its transient status error");
        assert!(
            matches!(sup.pending_state(a.challenge_id), Some(ChallengeState::Discovered)),
            "A did not advance while its RPC was failing: {:?}",
            sup.pending_state(a.challenge_id)
        );
        assert!(
            matches!(sup.pending_state(b.challenge_id), Some(ChallengeState::Submitted { .. })),
            "B advanced (broadcast) this tick despite A's failure: {:?}",
            sup.pending_state(b.challenge_id)
        );

        // A recovers on the next tick once its RPC succeeds (gate held by B ⇒ Ready, i.e.
        // advanced).
        cc.clear_status_failure(a.challenge_id);
        sup.tick(200).await.unwrap();
        assert!(
            !matches!(sup.pending_state(a.challenge_id), Some(ChallengeState::Discovered)),
            "A advanced after its RPC recovered: {:?}",
            sup.pending_state(a.challenge_id)
        );
    }

    #[tokio::test]
    async fn finality_applied_once_and_startup_window_explicit() {
        let cc = Arc::new(MockChallengeContract::new());
        let witness = Arc::new(SwitchWitness::not_ready());
        let rm = Arc::new(MockRootManager::new());
        let handler = handler_with(cc.clone(), witness, rm);
        // finality_blocks = 32, startup_lookback = 1000.
        let mut sup = Supervisor::new(
            Watcher::new(cc.clone()),
            handler,
            cc.clone(),
            InFlightGate::new(),
            32,
            1_000,
        );
        sup.tick(10_000).await.unwrap();
        let w = cc.last_scan_window().expect("watch_opened received an explicit window");
        assert_eq!(
            w.to_block,
            10_000 - 32,
            "actionable_to = H - finality_blocks (subtracted ONCE)"
        );
        assert_eq!(
            w.from_block,
            (10_000 - 32) - 1_000,
            "explicit startup [actionable_to - lookback, .]"
        );
    }

    #[tokio::test]
    async fn single_in_flight_nearest_deadline_first() {
        // A deadline 9000, B deadline 5000 (nearer). Both ready in the same tree/root. Only one
        // broadcasts this tick, and it is the nearest-deadline challenge (B).
        let (leaf_a, proof_a, leaf_b, proof_b, root) = two_challenge_tree(0x0A, 0x0B);
        let cc = Arc::new(MockChallengeContract::new());
        let a = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x0A), 0, leaf_a, 100);
        let b = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x0B), 0, leaf_b, 100);
        cc.inject_opened(a.clone(), 9_000);
        cc.inject_opened(b.clone(), 5_000);
        cc.set_status(
            a.challenge_id,
            ChallengeStatus { open: true, deadline: 9_000, chain_timestamp: 0 },
        );
        cc.set_status(
            b.challenge_id,
            ChallengeStatus { open: true, deadline: 5_000, chain_timestamp: 0 },
        );
        let witness = leaf_witness(vec![(leaf_a, proof_a), (leaf_b, proof_b)]);
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(20, root);
        let handler = handler_with(cc.clone(), witness, rm);
        let mut sup = Supervisor::new(
            Watcher::new(cc.clone()),
            handler,
            cc.clone(),
            InFlightGate::new(),
            0,
            1_000,
        );

        sup.tick(500).await.unwrap();
        let calls = cc.prove_calls();
        assert_eq!(calls.len(), 1, "at most one in-flight tx per tick");
        assert_eq!(calls[0].challenge_id, b.challenge_id, "nearest-deadline (B) broadcasts first");
    }

    /// A witness that returns a per-leaf bound proof (so leaf-bound verify passes for each).
    struct LeafWitness {
        by_leaf: StdMutex<std::collections::HashMap<B256, HistoricalInclusionProof>>,
    }
    #[async_trait]
    impl WitnessSource for LeafWitness {
        async fn canonical_record_height(&self, _leaf: B256) -> Result<u64, WbError> {
            Ok(10)
        }
        async fn historical_proof(
            &self,
            leaf: B256,
            _root: B256,
        ) -> Result<HistoricalInclusionProof, WbError> {
            self.by_leaf.lock().unwrap().get(&leaf).cloned().ok_or(WbError::WithdrawalNotFound)
        }
    }

    #[tokio::test]
    async fn restart_reconcile_status_only_open_redriven_closed_skipped() {
        let (_p, leaf_o, _r) = valid_proof(0x10);
        let (_p2, leaf_c, _r2) = valid_proof(0x11);
        let cc = Arc::new(MockChallengeContract::new());
        let open =
            ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x10), 0, leaf_o, 100);
        let closed =
            ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x11), 0, leaf_c, 100);
        cc.inject_opened(open.clone(), 10_000);
        cc.inject_opened(closed.clone(), 10_000);
        cc.set_status(
            closed.challenge_id,
            ChallengeStatus { open: false, deadline: 10_000, chain_timestamp: 0 },
        );

        let witness = Arc::new(SwitchWitness::not_ready());
        let rm = Arc::new(MockRootManager::new());
        let handler = handler_with(cc.clone(), witness, rm);
        let mut sup = Supervisor::new(
            Watcher::new(cc.clone()),
            handler,
            cc.clone(),
            InFlightGate::new(),
            0,
            1_000,
        );

        let rediscovered =
            crate::tz::defender::challenge_contract::ChallengeEventSource::watch_opened(
                &*cc,
                ScanWindow { from_block: 0, to_block: 10_000 },
            )
            .await
            .unwrap();
        sup.reconcile_on_startup(&rediscovered).await.unwrap();
        assert!(sup.is_pending(open.challenge_id), "still-open ⇒ best-effort re-drive");
        assert!(
            !sup.is_pending(closed.challenge_id),
            "closed ⇒ not enqueued (no old-receipt lookup)"
        );
    }
}
