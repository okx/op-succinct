//! Challenge-event watcher.
//!
//! Scans the challenge event source over an explicit finality-bounded [`ScanWindow`] and
//! deduplicates by the opaque [`ChallengeId`] — never by `leaf_hash`, so a re-opened challenge is a
//! distinct event and restart recovery via rescan does not double-handle. Finality is applied
//! exactly once by the supervisor (which sets `window.to_block = actionable_to = H -
//! finality_blocks`, Model A); the watcher does NOT re-subtract `finality_blocks`. The proof cache
//! is not persisted; recovery is purely event-driven.

use std::{collections::HashSet, sync::Arc};

use anyhow::Result;

use super::challenge_contract::{ChallengeEventSource, ChallengeId, ChallengeOpened, ScanWindow};

/// Tracks already-dispatched challenges (dedup) over successive scan windows.
pub struct Watcher {
    source: Arc<dyn ChallengeEventSource>,
    seen: HashSet<ChallengeId>,
}

impl Watcher {
    pub fn new(source: Arc<dyn ChallengeEventSource>) -> Self {
        Self { source, seen: HashSet::new() }
    }

    /// Scan `window` and return the not-yet-seen challenges, marking them seen.
    ///
    /// The window's `to_block` already encodes finality (`actionable_to = H - finality_blocks`,
    /// computed once by the supervisor); the watcher does not re-apply finality. Reorg safety:
    /// because dedup is by `ChallengeId`, a restart that rescans the same window will not
    /// re-dispatch already-handled challenges.
    pub async fn poll(&mut self, window: ScanWindow) -> Result<Vec<ChallengeOpened>> {
        let opened = self.source.watch_opened(window).await?;
        let mut out = Vec::new();
        for ev in opened {
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
    async fn only_events_within_the_window_are_returned() {
        let cc = Arc::new(MockChallengeContract::new());
        inject(&cc, 0, 0xAA, 100);
        let mut w = Watcher::new(cc);
        // to_block = 99 (< 100) ⇒ the event is above the actionable window.
        assert!(w.poll(ScanWindow { from_block: 0, to_block: 99 }).await.unwrap().is_empty());
        // to_block = 132 ⇒ within the window (finality already encoded by the caller).
        let got = w.poll(ScanWindow { from_block: 0, to_block: 132 }).await.unwrap();
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn dedup_by_challenge_id_survives_rescan() {
        let cc = Arc::new(MockChallengeContract::new());
        inject(&cc, 0, 0xAA, 100);
        let mut w = Watcher::new(cc);
        let window = ScanWindow { from_block: 0, to_block: 200 };
        assert_eq!(w.poll(window).await.unwrap().len(), 1);
        // Re-scan the same window (simulating a restart): the challenge is not re-dispatched.
        assert_eq!(w.poll(window).await.unwrap().len(), 0);
        assert_eq!(w.dispatched_count(), 1);
    }

    #[tokio::test]
    async fn distinct_log_indices_are_distinct_events() {
        let cc = Arc::new(MockChallengeContract::new());
        inject(&cc, 0, 0xAA, 100);
        inject(&cc, 1, 0xAA, 100); // same leaf, different logIndex ⇒ distinct ChallengeId
        let mut w = Watcher::new(cc);
        assert_eq!(w.poll(ScanWindow { from_block: 0, to_block: 200 }).await.unwrap().len(), 2);
    }
}
