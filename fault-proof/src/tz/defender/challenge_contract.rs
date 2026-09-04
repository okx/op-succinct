//! X Layer Withdraw-challenge contract seam (spec §5 decision 1, §7.4).
//!
//! The real ABI is not yet finalized, so the Defender depends only on the
//! [`ChallengeContract`] trait. [`MockChallengeContract`] is an in-memory implementation for
//! unit/integration tests: it can inject `ChallengeOpened` events, script per-leaf challenge
//! status/deadline, and record every `prove_challenge` calldata. The Withdraw tag `0x02` is
//! fixed inside the contract and never travels in calldata.

use std::sync::Mutex;

use alloy_primitives::{Address, TxHash, B256};
use anyhow::Result;
use async_trait::async_trait;

/// A challenge-opened event. Identity is `(chain_id, contract, tx_hash, log_index)` — NOT
/// `leaf_hash` — so restarts/rescans dedup correctly and a re-opened challenge for the same leaf
/// is a distinct event (spec §7.4 recovery).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeOpened {
    pub chain_id: u64,
    pub contract: Address,
    pub tx_hash: B256,
    pub log_index: u64,
    pub leaf_hash: B256,
    /// L2 block at which the event was emitted (used for finality gating by the watcher).
    pub block_number: u64,
}

impl ChallengeOpened {
    /// The dedup identity of this event.
    pub fn identity(&self) -> (u64, Address, B256, u64) {
        (self.chain_id, self.contract, self.tx_hash, self.log_index)
    }
}

/// On-chain status of a challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeStatus {
    /// Whether the challenge is still open and can be responded to.
    pub open: bool,
    /// The response deadline (unix seconds).
    pub deadline: u64,
}

/// The Defender's view of the X Layer challenge contract.
#[async_trait]
pub trait ChallengeContract: Send + Sync {
    /// Return challenges opened since the last scan (watcher applies finality + dedup).
    async fn watch_opened(&self) -> Result<Vec<ChallengeOpened>>;
    /// Read the current status/deadline of a challenge, keyed by its leaf hash.
    async fn get_challenge(&self, leaf_hash: B256) -> Result<ChallengeStatus>;
    /// Submit a proof for a challenge. The Withdraw tag is fixed in the contract, not passed here.
    async fn prove_challenge(
        &self,
        leaf_hash: B256,
        checkpoint_height: u64,
        leaf_index: u32,
        count: u32,
        siblings: [B256; 32],
    ) -> Result<TxHash>;
}

/// Recorded `prove_challenge` calldata (for test assertions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProveCall {
    pub leaf_hash: B256,
    pub checkpoint_height: u64,
    pub leaf_index: u32,
    pub count: u32,
    pub siblings: [B256; 32],
}

/// In-memory mock challenge contract (spec §5 decision 1).
pub struct MockChallengeContract {
    inner: Mutex<MockState>,
}

struct MockState {
    opened: Vec<ChallengeOpened>,
    status: std::collections::HashMap<B256, ChallengeStatus>,
    prove_calls: Vec<ProveCall>,
    /// When set, `prove_challenge` fails to simulate a lost race / revert.
    fail_prove: bool,
}

impl Default for MockChallengeContract {
    fn default() -> Self {
        Self::new()
    }
}

impl MockChallengeContract {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MockState {
                opened: Vec::new(),
                status: std::collections::HashMap::new(),
                prove_calls: Vec::new(),
                fail_prove: false,
            }),
        }
    }

    /// Inject an opened challenge that `watch_opened` will return, and default its status to open.
    pub fn inject_opened(&self, ev: ChallengeOpened, deadline: u64) {
        let mut s = self.inner.lock().unwrap();
        s.status.insert(ev.leaf_hash, ChallengeStatus { open: true, deadline });
        s.opened.push(ev);
    }

    /// Script the status/deadline returned for a leaf.
    pub fn set_status(&self, leaf_hash: B256, status: ChallengeStatus) {
        self.inner.lock().unwrap().status.insert(leaf_hash, status);
    }

    /// Make the next `prove_challenge` calls fail (simulate revert / lost race at submit time).
    pub fn set_fail_prove(&self, fail: bool) {
        self.inner.lock().unwrap().fail_prove = fail;
    }

    /// All recorded `prove_challenge` calldata.
    pub fn prove_calls(&self) -> Vec<ProveCall> {
        self.inner.lock().unwrap().prove_calls.clone()
    }
}

#[async_trait]
impl ChallengeContract for MockChallengeContract {
    async fn watch_opened(&self) -> Result<Vec<ChallengeOpened>> {
        Ok(self.inner.lock().unwrap().opened.clone())
    }

    async fn get_challenge(&self, leaf_hash: B256) -> Result<ChallengeStatus> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .status
            .get(&leaf_hash)
            .copied()
            .unwrap_or(ChallengeStatus { open: false, deadline: 0 }))
    }

    async fn prove_challenge(
        &self,
        leaf_hash: B256,
        checkpoint_height: u64,
        leaf_index: u32,
        count: u32,
        siblings: [B256; 32],
    ) -> Result<TxHash> {
        let mut s = self.inner.lock().unwrap();
        if s.fail_prove {
            anyhow::bail!("mock prove_challenge failed (simulated revert)");
        }
        s.prove_calls.push(ProveCall { leaf_hash, checkpoint_height, leaf_index, count, siblings });
        Ok(TxHash::repeat_byte(0x99))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened(leaf: B256) -> ChallengeOpened {
        ChallengeOpened {
            chain_id: 196,
            contract: Address::repeat_byte(0x01),
            tx_hash: B256::repeat_byte(0x02),
            log_index: 0,
            leaf_hash: leaf,
            block_number: 10,
        }
    }

    #[tokio::test]
    async fn watch_returns_injected_and_records_prove_calldata() {
        let mock = MockChallengeContract::new();
        let leaf = B256::repeat_byte(0xAB);
        mock.inject_opened(opened(leaf), 5_000);

        let evs = mock.watch_opened().await.unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].leaf_hash, leaf);
        assert!(mock.get_challenge(leaf).await.unwrap().open);

        let sibs = [B256::repeat_byte(0x07); 32];
        mock.prove_challenge(leaf, 20, 3, 5, sibs).await.unwrap();
        let calls = mock.prove_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            ProveCall {
                leaf_hash: leaf,
                checkpoint_height: 20,
                leaf_index: 3,
                count: 5,
                siblings: sibs
            }
        );
    }

    #[test]
    fn identity_excludes_leaf_hash() {
        let a = opened(B256::repeat_byte(0x01));
        let mut b = a.clone();
        b.leaf_hash = B256::repeat_byte(0xFF); // different leaf, same event coordinates
        assert_eq!(a.identity(), b.identity());
    }

    #[tokio::test]
    async fn unknown_leaf_is_closed() {
        let mock = MockChallengeContract::new();
        assert!(!mock.get_challenge(B256::repeat_byte(0x01)).await.unwrap().open);
    }
}
