//! Event-driven supervisor loop.
//!
//! Each tick reads the L2 latest head `H`, computes `actionable_to = H - finality_blocks` **once**
//! (Model A), scans an explicit [`ScanWindow`] (`[startup_lookback, actionable_to]` on the
//! first tick, a reorg-safe cursor for `from_block` afterwards, `to_block` always `actionable_to`),
//! merges newly-discovered challenges (deduplicated by [`ChallengeId`]) into a pending map, and
//! re-drives every non-terminal challenge one step. Discovery (dedup) and pending work (retry) are
//! decoupled, so a challenge that is waiting for the witness, awaiting confirmation, or eligible
//! for a bounded resend is re-driven on subsequent ticks rather than dropped once its event is
//! seen.
//!
//! Two invariants the reviewed version violated are restored here:
//! - **Per-challenge failure isolation**: a transient status/RootManager/receipt error for one
//!   challenge is caught and the challenge is **preserved** in `pending` (never removed-then-`?`);
//!   the tick keeps driving the others.
//! - **Single in-flight broadcast, nearest-deadline-first**: broadcasting is gated by a shared
//!   [`InFlightGate`]; challenges are driven nearest-deadline-first so the free gate is granted to
//!   the most urgent challenge.
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
    /// Reorg overlap: how many blocks below the previous finalized frontier to re-scan so a reorg
    /// that replaced an event there (a new [`ChallengeId`]) is re-observed.
    reorg_safety_margin: u64,
    /// Highest finalized `to_block` scanned so far; `None` until the first tick (which uses the
    /// explicit startup lookback window). Discovery only advances when the frontier grows.
    frontier: Option<u64>,
    /// Monotonic discovery counter and per-challenge discovery sequence. Assigned once, at first
    /// discovery, so equal-deadline challenges break ties by discovery order (a `HashMap` does not
    /// preserve insertion order). A reorg-overlap re-scan of an already-known challenge does not
    /// reach the assignment (the watcher dedups by `ChallengeId`), so its sequence stays stable.
    next_discovery_seq: u64,
    discovery_seq: HashMap<ChallengeId, u64>,
    pending: HashMap<ChallengeId, (ChallengeOpened, ChallengeState)>,
}

impl Supervisor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watcher: Watcher,
        handler: Handler,
        reader: Arc<dyn ChallengeReader>,
        gate: InFlightGate,
        finality_blocks: u64,
        startup_lookback: u64,
        reorg_safety_margin: u64,
    ) -> Self {
        Self {
            watcher,
            handler,
            reader,
            gate,
            finality_blocks,
            startup_lookback,
            reorg_safety_margin,
            frontier: None,
            next_discovery_seq: 0,
            discovery_seq: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// One supervisor iteration. `l2_head` is the L2 latest head `H`; finality is applied here
    /// exactly once as `actionable_to = H - finality_blocks`.
    ///
    /// Discovery and pending work are decoupled: discovery runs only when the finalized frontier
    /// advances (so a static or regressed head never produces a reversed `[from > to]` window), and
    /// a discovery RPC failure is isolated (logged, cursor left intact) rather than aborting the
    /// tick — either way every non-terminal pending challenge is still driven so confirmations,
    /// deadlines, and bounded resends keep progressing.
    pub async fn tick(&mut self, l2_head: u64) -> Result<()> {
        let actionable_to = l2_head.saturating_sub(self.finality_blocks);

        // Run discovery only when the finalized frontier has advanced. On a static or regressed
        // head there is no new finalized block, so discovery is skipped this tick (no reversed
        // window) while the pending queue below is still driven.
        let advanced = self.frontier.is_none_or(|f| actionable_to > f);
        if advanced {
            // Reorg-safe overlap: re-scan the last `reorg_safety_margin` blocks below the previous
            // frontier so a reorg replacement (a new ChallengeId) there is re-observed; dedup by
            // ChallengeId makes the overlap idempotent. The first tick uses the explicit startup
            // lookback window. `from_block <= actionable_to` holds because the frontier advanced.
            let from_block = match self.frontier {
                Some(f) => f.saturating_add(1).saturating_sub(self.reorg_safety_margin),
                None => actionable_to.saturating_sub(self.startup_lookback),
            };
            let window = ScanWindow { from_block, to_block: actionable_to };
            // Isolate discovery failures: a transient event-source RPC error must not abort the
            // tick and starve every already-pending challenge of its confirmation / deadline /
            // resend progress. Log it, leave the frontier unchanged (retry next tick), and fall
            // through to drive the pending queue.
            match self.watcher.poll(window).await {
                Ok(discovered) => {
                    for ev in discovered {
                        let id = ev.challenge_id;
                        if !self.discovery_seq.contains_key(&id) {
                            self.discovery_seq.insert(id, self.next_discovery_seq);
                            self.next_discovery_seq += 1;
                        }
                        self.pending.entry(id).or_insert((ev, ChallengeState::Discovered));
                    }
                    self.frontier = Some(actionable_to);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "challenge event scan failed this tick; isolating the discovery failure \
                         and still driving pending challenges (frontier unchanged, retry next tick)"
                    );
                }
            }
        }

        // Order pending challenges nearest-deadline-first so the single in-flight gate is granted
        // to the most urgent challenge; equal deadlines break ties by discovery order (never by
        // opaque ChallengeId bytes). A status-read error while ordering does NOT drop the
        // challenge: it is ordered last (u64::MAX) and still driven (its own drive re-reads it).
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
            let (sa, sb) = (
                self.discovery_seq.get(a).copied().unwrap_or(u64::MAX),
                self.discovery_seq.get(b).copied().unwrap_or(u64::MAX),
            );
            da.cmp(&db).then_with(|| sa.cmp(&sb))
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
                if state.is_terminal() {
                    // Terminal: drop the challenge and its discovery sequence.
                    self.discovery_seq.remove(&id);
                } else {
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
        cc.set_status(
            id,
            ChallengeStatus {
                open: true,
                deadline: 10_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
        );
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
            16,
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
            ChallengeStatus {
                open: true,
                deadline: 10_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
        );
        cc.set_status(
            b.challenge_id,
            ChallengeStatus {
                open: true,
                deadline: 10_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
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
            16,
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
            16,
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
            ChallengeStatus {
                open: true,
                deadline: 9_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
        );
        cc.set_status(
            b.challenge_id,
            ChallengeStatus {
                open: true,
                deadline: 5_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
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
            16,
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
            ChallengeStatus {
                open: false,
                deadline: 10_000,
                chain_timestamp: 0,
                resolved_by_us: false,
            },
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
            16,
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

    fn open_status() -> ChallengeStatus {
        ChallengeStatus { open: true, deadline: 10_000, chain_timestamp: 0, resolved_by_us: false }
    }

    #[tokio::test]
    async fn same_head_skips_discovery_but_still_drives_pending() {
        // finality 0 ⇒ actionable_to == l2_head. C1 is discovered on tick 1; a second challenge is
        // injected afterwards within the same window. A tick at the SAME head must NOT discover the
        // newcomer (no new finalized block) yet must still drive C1 to its next state.
        let (proof, leaf, root) = valid_proof(0x42);
        let cc = Arc::new(MockChallengeContract::new());
        let c1 = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x01), 0, leaf, 100);
        cc.inject_opened(c1.clone(), 10_000);
        cc.set_status(c1.challenge_id, open_status());
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
            16,
        );

        sup.tick(200).await.unwrap();
        assert!(
            matches!(
                sup.pending_state(c1.challenge_id),
                Some(ChallengeState::WaitingWitness { .. })
            ),
            "tick 1 discovers C1 and (witness not ready) leaves it waiting"
        );

        // A newcomer appears within the window and the witness becomes ready.
        let c2 = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x02), 0, leaf, 150);
        cc.inject_opened(c2.clone(), 10_000);
        cc.set_status(c2.challenge_id, open_status());
        witness.make_ready(proof);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);

        sup.tick(200).await.unwrap(); // SAME head ⇒ discovery skipped
        assert!(
            !sup.is_pending(c2.challenge_id),
            "same head ⇒ no new finalized block ⇒ C2 not discovered"
        );
        assert!(
            matches!(sup.pending_state(c1.challenge_id), Some(ChallengeState::Submitted { .. })),
            "C1 still driven despite skipped discovery: {:?}",
            sup.pending_state(c1.challenge_id)
        );
    }

    #[tokio::test]
    async fn head_regression_skips_discovery_and_preserves_frontier() {
        let (proof, leaf, root) = valid_proof(0x42);
        let cc = Arc::new(MockChallengeContract::new());
        let c1 = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x01), 0, leaf, 100);
        cc.inject_opened(c1.clone(), 10_000);
        cc.set_status(c1.challenge_id, open_status());
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
            16,
        );

        sup.tick(500).await.unwrap();
        assert_eq!(cc.last_scan_window().unwrap().to_block, 500, "tick 1 scans up to head 500");
        assert!(sup.is_pending(c1.challenge_id));

        // Head regresses; the witness becomes ready. The regressed tick must not produce a reversed
        // window (no scan), must preserve the frontier, and must still drive C1.
        witness.make_ready(proof);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        sup.tick(300).await.unwrap();
        assert_eq!(
            cc.last_scan_window().unwrap().to_block,
            500,
            "regressed head ⇒ discovery skipped (no scan at to_block 300)"
        );
        assert!(
            matches!(sup.pending_state(c1.challenge_id), Some(ChallengeState::Submitted { .. })),
            "C1 still driven on a regressed head: {:?}",
            sup.pending_state(c1.challenge_id)
        );
    }

    #[tokio::test]
    async fn reorg_overlap_rediscovers_replacement_below_previous_frontier() {
        // margin = 16. Tick 1 at head 100 sets frontier = 100. A reorg then introduces a
        // replacement event (a NEW ChallengeId) at block 95 — below the old frontier but
        // within the reorg margin. Tick 2 at head 110 must re-scan [100 + 1 - 16 = 85, 110]
        // and rediscover it; a forward-only scan from 101 would have missed block 95.
        let (_p, leaf, root) = valid_proof(0x42);
        let cc = Arc::new(MockChallengeContract::new());
        let c1 = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x01), 0, leaf, 50);
        cc.inject_opened(c1.clone(), 10_000);
        cc.set_status(c1.challenge_id, open_status());
        let witness = Arc::new(SwitchWitness::not_ready());
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
            16,
        );

        sup.tick(100).await.unwrap();
        assert!(sup.is_pending(c1.challenge_id));

        let replacement = ChallengeOpened::new(
            CHAIN_ID,
            contract(),
            B256::repeat_byte(0x02),
            0,
            B256::repeat_byte(0x77),
            95,
        );
        cc.inject_opened(replacement.clone(), 10_000);
        cc.set_status(replacement.challenge_id, open_status());

        sup.tick(110).await.unwrap();
        let w = cc.last_scan_window().unwrap();
        assert_eq!(
            w.from_block, 85,
            "reorg overlap re-scans the margin below the previous frontier"
        );
        assert_eq!(w.to_block, 110);
        assert!(
            sup.is_pending(replacement.challenge_id),
            "reorg replacement below the old frontier is rediscovered via the overlap"
        );
    }

    #[tokio::test]
    async fn event_scan_failure_is_isolated_and_pending_still_driven() {
        // A pending challenge must keep progressing even when the event-scan RPC fails this tick,
        // and a failed scan must not advance the frontier (so recovery re-scans the missed range).
        let (proof, leaf, root) = valid_proof(0x42);
        let cc = Arc::new(MockChallengeContract::new());
        let c1 = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x01), 0, leaf, 100);
        cc.inject_opened(c1.clone(), 10_000);
        cc.set_status(c1.challenge_id, open_status());
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
            16,
        );

        sup.tick(200).await.unwrap();
        assert!(matches!(
            sup.pending_state(c1.challenge_id),
            Some(ChallengeState::WaitingWitness { .. })
        ));

        // The event RPC fails while the witness becomes ready; C1 must still advance to Submitted.
        witness.make_ready(proof);
        cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
        cc.set_watch_failure();
        sup.tick(300).await.unwrap();
        assert!(
            matches!(sup.pending_state(c1.challenge_id), Some(ChallengeState::Submitted { .. })),
            "pending driven despite the event-scan RPC failure: {:?}",
            sup.pending_state(c1.challenge_id)
        );

        // The frontier did not advance during the failure, so a recovered scan still finds new
        // events (a newcomer sharing C1's leaf so it verifies; it stays Ready behind the gate).
        cc.clear_watch_failure();
        let c2 = ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x02), 0, leaf, 250);
        cc.inject_opened(c2.clone(), 10_000);
        cc.set_status(c2.challenge_id, open_status());
        sup.tick(300).await.unwrap();
        assert!(
            sup.is_pending(c2.challenge_id),
            "cursor not advanced during the failure ⇒ the recovered scan discovers the newcomer"
        );
    }

    #[tokio::test]
    async fn equal_deadline_breaks_tie_by_discovery_order_not_challenge_id() {
        // Two challenges share the SAME deadline. The one discovered FIRST must broadcast first
        // under the single in-flight gate — even when its ChallengeId sorts AFTER the other's by
        // bytes (the old, incorrect tiebreak). Both are provable under one shared two-leaf tree.
        let (leaf_a, proof_a, leaf_b, proof_b, root) = two_challenge_tree(0x0A, 0x0B);
        let e1 =
            ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x01), 0, leaf_a, 100);
        let e2 =
            ChallengeOpened::new(CHAIN_ID, contract(), B256::repeat_byte(0x02), 0, leaf_b, 100);
        // Discover the LARGER-ChallengeId event first, so a byte-order tiebreak would (wrongly)
        // pick the other one.
        let (first, second) =
            if e1.challenge_id.0 > e2.challenge_id.0 { (e1, e2) } else { (e2, e1) };
        assert!(first.challenge_id.0 > second.challenge_id.0, "arranged: first has the larger id");

        let cc = Arc::new(MockChallengeContract::new());
        cc.inject_opened(first.clone(), 5_000);
        cc.inject_opened(second.clone(), 5_000);
        let st = ChallengeStatus {
            open: true,
            deadline: 5_000,
            chain_timestamp: 0,
            resolved_by_us: false,
        };
        cc.set_status(first.challenge_id, st);
        cc.set_status(second.challenge_id, st);
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
            16,
        );

        sup.tick(500).await.unwrap();
        let calls = cc.prove_calls();
        assert_eq!(calls.len(), 1, "single in-flight tx per tick");
        assert_eq!(
            calls[0].challenge_id, first.challenge_id,
            "equal deadline ⇒ the first-discovered challenge broadcasts, not the ChallengeId-byte winner"
        );
    }
}
