//! Challenge-event watcher.
//!
//! Scans the challenge event source for `ChallengeOpened` events, applies L2 finality gating (only
//! events buried by `finality_blocks` are actionable), and deduplicates by the opaque
//! [`ChallengeId`] — never by `leaf_hash`, so a re-opened challenge is a distinct event and restart
//! recovery via rescan does not double-handle. The proof cache is not persisted; recovery is purely
//! event-driven.

use std::{collections::HashSet, sync::Arc};

use anyhow::Result;

use super::challenge_contract::{ChallengeEventSource, ChallengeId, ChallengeOpened};

/// Tracks already-dispatched challenges (dedup) and applies finality gating.
pub struct Watcher {
    source: Arc<dyn ChallengeEventSource>,
    finality_blocks: u64,
    seen: HashSet<ChallengeId>,
}

impl Watcher {
    pub fn new(source: Arc<dyn ChallengeEventSource>, finality_blocks: u64) -> Self {
        Self { source, finality_blocks, seen: HashSet::new() }
    }

    /// Return the finalized, not-yet-seen challenges given the current L2 tip, marking them seen.
    ///
    /// An event is actionable only once `tip >= event.block_number + finality_blocks`. Reorg
    /// safety: because only finalized events are ever dispatched and dedup is by `ChallengeId`, a
    /// restart that rescans the same window will not re-dispatch already-handled challenges.
    pub async fn poll(&mut self, l2_tip: u64) -> Result<Vec<ChallengeOpened>> {
        let opened = self.source.watch_opened().await?;
        let mut out = Vec::new();
        for ev in opened {
            let finalized = l2_tip >= ev.block_number.saturating_add(self.finality_blocks);
            if !finalized {
                continue;
            }
            if self.seen.insert(ev.challenge_id) {
                out.push(ev);
            }
        }
        Ok(out)
    }

    /// Number of distinct challenges dispatched so far (observability).
    pub fn dispatched_count(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::defender::challenge_contract::MockChallengeContract;
    use alloy_primitives::{Address, B256};

    fn inject(cc: &MockChallengeContract, log_index: u64, leaf: u8, block: u64) -> ChallengeId {
        cc.inject_opened_from(
            196,
            Address::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            log_index,
            B256::repeat_byte(leaf),
            block,
            10_000,
        )
    }

    #[tokio::test]
    async fn only_finalized_events_are_returned() {
        let cc = Arc::new(MockChallengeContract::new());
        inject(&cc, 0, 0xAA, 100);
        let mut w = Watcher::new(cc, 32);
        // tip 120 < 100 + 32 = 132 ⇒ not finalized yet.
        assert!(w.poll(120).await.unwrap().is_empty());
        // tip 132 ⇒ finalized.
        let got = w.poll(132).await.unwrap();
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn dedup_by_challenge_id_survives_rescan() {
        let cc = Arc::new(MockChallengeContract::new());
        inject(&cc, 0, 0xAA, 100);
        let mut w = Watcher::new(cc, 0);
        assert_eq!(w.poll(200).await.unwrap().len(), 1);
        // Re-scan the same window (simulating a restart): the challenge is not re-dispatched.
        assert_eq!(w.poll(200).await.unwrap().len(), 0);
        assert_eq!(w.dispatched_count(), 1);
    }

    #[tokio::test]
    async fn distinct_log_indices_are_distinct_events() {
        let cc = Arc::new(MockChallengeContract::new());
        inject(&cc, 0, 0xAA, 100);
        inject(&cc, 1, 0xAA, 100); // same leaf, different logIndex ⇒ distinct ChallengeId
        let mut w = Watcher::new(cc, 0);
        assert_eq!(w.poll(200).await.unwrap().len(), 2);
    }
}
