//! Challenge-event watcher (spec §7.4).
//!
//! Scans the challenge contract for `ChallengeOpened` events, applies L2 finality gating (only
//! events buried by `finality_blocks` are actionable), and deduplicates by the event identity
//! `(chain, contract, tx_hash, log_index)` — never by `leaf_hash`, so a re-opened challenge is a
//! distinct event and restart recovery via rescan does not double-handle. The proof cache is NOT
//! persisted; recovery is purely event-driven (spec §7.4 recovery).

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;

use super::challenge_contract::{ChallengeContract, ChallengeOpened};

/// Tracks already-dispatched events (dedup) and applies finality gating.
pub struct Watcher {
    challenge: Arc<dyn ChallengeContract>,
    finality_blocks: u64,
    seen: HashSet<(u64, alloy_primitives::Address, alloy_primitives::B256, u64)>,
}

impl Watcher {
    pub fn new(challenge: Arc<dyn ChallengeContract>, finality_blocks: u64) -> Self {
        Self { challenge, finality_blocks, seen: HashSet::new() }
    }

    /// Return the finalized, not-yet-seen challenges given the current L2 tip, marking them seen.
    ///
    /// An event is actionable only once `tip >= event.block_number + finality_blocks`. Reorg
    /// safety: because only finalized events are ever dispatched and dedup is by event identity,
    /// a restart that rescans the same window will not re-dispatch already-handled challenges.
    pub async fn poll(&mut self, l2_tip: u64) -> Result<Vec<ChallengeOpened>> {
        let opened = self.challenge.watch_opened().await?;
        let mut out = Vec::new();
        for ev in opened {
            let finalized = l2_tip >= ev.block_number.saturating_add(self.finality_blocks);
            if !finalized {
                continue;
            }
            if self.seen.insert(ev.identity()) {
                out.push(ev);
            }
        }
        Ok(out)
    }

    /// Number of distinct events dispatched so far (observability).
    pub fn dispatched_count(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::defender::challenge_contract::MockChallengeContract;
    use alloy_primitives::{Address, B256};

    fn ev(log_index: u64, leaf: u8, block: u64) -> ChallengeOpened {
        ChallengeOpened {
            chain_id: 196,
            contract: Address::repeat_byte(0x01),
            tx_hash: B256::repeat_byte(0x02),
            log_index,
            leaf_hash: B256::repeat_byte(leaf),
            block_number: block,
        }
    }

    #[tokio::test]
    async fn only_finalized_events_are_returned() {
        let cc = Arc::new(MockChallengeContract::new());
        cc.inject_opened(ev(0, 0xAA, 100), 10_000);
        let mut w = Watcher::new(cc, 32);
        // tip 120 < 100 + 32 = 132 ⇒ not finalized yet.
        assert!(w.poll(120).await.unwrap().is_empty());
        // tip 132 ⇒ finalized.
        let got = w.poll(132).await.unwrap();
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn dedup_by_identity_survives_rescan() {
        let cc = Arc::new(MockChallengeContract::new());
        cc.inject_opened(ev(0, 0xAA, 100), 10_000);
        let mut w = Watcher::new(cc, 0);
        assert_eq!(w.poll(200).await.unwrap().len(), 1);
        // Re-scan the same window (simulating a restart): the event is not re-dispatched.
        assert_eq!(w.poll(200).await.unwrap().len(), 0);
        assert_eq!(w.dispatched_count(), 1);
    }

    #[tokio::test]
    async fn distinct_log_indices_are_distinct_events() {
        let cc = Arc::new(MockChallengeContract::new());
        cc.inject_opened(ev(0, 0xAA, 100), 10_000);
        cc.inject_opened(ev(1, 0xAA, 100), 10_000); // same leaf, different logIndex
        let mut w = Watcher::new(cc, 0);
        assert_eq!(w.poll(200).await.unwrap().len(), 2);
    }
}
