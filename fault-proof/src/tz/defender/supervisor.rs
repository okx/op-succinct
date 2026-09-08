//! Event-driven supervisor loop.
//!
//! Each tick reads the L2 finalized tip, discovers newly-finalized challenges (deduplicated by
//! [`ChallengeId`]), and re-drives every non-terminal challenge through the handler state machine
//! until it terminates. Discovery (dedup) and pending work (retry) are decoupled, so a challenge
//! that is waiting for the witness, awaiting confirmation, or eligible for a bounded resend is
//! re-driven on subsequent ticks rather than dropped once the watcher has marked its event seen.
//!
//! Restart recovery keeps no persistence: a prior transaction hash is lost across a restart, so on
//! startup the supervisor rescans a bounded window and, for each rediscovered challenge, queries
//! only the current on-chain status. A closed challenge is not re-enqueued; a still-open one is
//! re-enqueued for best-effort recovery and may resend. A hard cross-restart no-double-submit
//! guarantee is deferred to a future contract that provides idempotent per-challenge transitions.

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;

use super::{
    challenge_contract::{ChallengeId, ChallengeOpened, ChallengeReader},
    handler::{ChallengeState, Handler},
    watcher::Watcher,
};

/// Drives discovery and the pending/retry queue.
pub struct Supervisor {
    watcher: Watcher,
    handler: Handler,
    reader: Arc<dyn ChallengeReader>,
    pending: HashMap<ChallengeId, (ChallengeOpened, ChallengeState)>,
}

impl Supervisor {
    pub fn new(watcher: Watcher, handler: Handler, reader: Arc<dyn ChallengeReader>) -> Self {
        Self { watcher, handler, reader, pending: HashMap::new() }
    }

    /// One supervisor iteration: discover newly-finalized challenges, then re-drive every
    /// non-terminal pending challenge one step and drop the terminal ones.
    pub async fn tick(&mut self, l2_finalized_tip: u64) -> Result<()> {
        for ev in self.watcher.poll(l2_finalized_tip).await? {
            self.pending.entry(ev.challenge_id).or_insert((ev, ChallengeState::Discovered));
        }

        let ids: Vec<ChallengeId> = self.pending.keys().copied().collect();
        for id in ids {
            // Remove-drive-reinsert avoids holding a borrow of `pending` across the handler call
            // and naturally drops terminal entries by not reinserting them.
            if let Some((ev, mut state)) = self.pending.remove(&id) {
                if !state.is_terminal() {
                    self.handler.drive(&ev, &mut state).await?;
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
            challenge_contract::{ChallengeStatus, MockChallengeContract, TxStatus},
            handler::WitnessSource,
            rootmanager_client::MockRootManager,
        },
        withdraw::{
            error::WbError, tree_adapter::single_leaf_withdrawal_fixture,
            types::{HistoricalInclusionProof, WithdrawRecord},
        },
    };
    use alloy_primitives::{Address, B256, TxHash};
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    const SAFETY: u64 = 100;

    fn leaf() -> B256 {
        B256::repeat_byte(0x42)
    }

    fn valid_proof(leaf: B256) -> (HistoricalInclusionProof, B256) {
        let (siblings, root) = single_leaf_withdrawal_fixture(leaf);
        let proof = HistoricalInclusionProof {
            record: WithdrawRecord {
                version: 1,
                chain_id: 196,
                transaction_hash: B256::ZERO,
                token_type: 0,
                token_address: Address::ZERO,
                token_ids: vec![],
                amounts: vec![],
                from: Address::ZERO,
                to: Address::ZERO,
            },
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

    #[tokio::test]
    async fn pending_challenge_is_redriven_until_terminal() {
        let (proof, root) = valid_proof(leaf());
        let cc = Arc::new(MockChallengeContract::new());
        let id = cc.inject_opened_from(
            196,
            contract(),
            B256::repeat_byte(0x02),
            0,
            leaf(),
            100,
            10_000,
        );
        cc.set_status(id, ChallengeStatus { open: true, deadline: 10_000, chain_timestamp: 0 });
        let witness = Arc::new(SwitchWitness::not_ready());
        let rm = Arc::new(MockRootManager::new());
        rm.set_latest(20, root);
        let handler =
            Handler::new(cc.clone(), cc.clone(), witness.clone(), rm, 16, SAFETY, 3);
        let mut sup = Supervisor::new(Watcher::new(cc.clone(), 0), handler, cc.clone());

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

    #[tokio::test]
    async fn restart_reconcile_status_only_open_redriven_closed_skipped() {
        let cc = Arc::new(MockChallengeContract::new());
        let open_id = cc.inject_opened_from(
            196,
            contract(),
            B256::repeat_byte(0x10),
            0,
            leaf(),
            100,
            10_000,
        );
        let closed_id = cc.inject_opened_from(
            196,
            contract(),
            B256::repeat_byte(0x11),
            0,
            leaf(),
            100,
            10_000,
        );
        cc.set_status(closed_id, ChallengeStatus { open: false, deadline: 10_000, chain_timestamp: 0 });

        let witness = Arc::new(SwitchWitness::not_ready());
        let rm = Arc::new(MockRootManager::new());
        let handler = Handler::new(cc.clone(), cc.clone(), witness, rm, 16, SAFETY, 3);
        let mut sup = Supervisor::new(Watcher::new(cc.clone(), 0), handler, cc.clone());

        let rediscovered = crate::tz::defender::challenge_contract::ChallengeEventSource::watch_opened(&*cc)
            .await
            .unwrap();
        sup.reconcile_on_startup(&rediscovered).await.unwrap();
        assert!(sup.is_pending(open_id), "still-open ⇒ best-effort re-drive");
        assert!(!sup.is_pending(closed_id), "closed ⇒ not enqueued (no old-receipt lookup)");
    }
}
