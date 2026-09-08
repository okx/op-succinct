//! X Layer Withdraw-challenge contract seam.
//!
//! The real challenge/prove ABI is not yet finalized, so the Defender depends only on three
//! minimal, mockable traits — [`ChallengeEventSource`], [`ChallengeReader`], and
//! [`ChallengeSender`] — all keyed by an opaque, adapter-owned [`ChallengeId`].
//! [`MockChallengeContract`] is an in-memory implementation of all three for unit/integration
//! tests: it injects `ChallengeOpened` events, scripts per-challenge status/deadline/chain-time,
//! and records every `prove_challenge` calldata. When the real ABI lands it replaces the mock
//! behind these traits without touching the watcher, handler, or verifier. The Withdraw tag is
//! fixed inside the contract and never travels in calldata.

use std::sync::Mutex;

use alloy_primitives::{keccak256, Address, TxHash, B256};
use anyhow::Result;
use async_trait::async_trait;

/// Opaque, adapter-owned challenge identity. A leaf may be challenged more than once, so the leaf
/// hash cannot identify a challenge; the adapter derives a stable id from the event coordinates.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ChallengeId(pub [u8; 32]);

/// Derive a stable [`ChallengeId`] from an event's coordinates without assuming the real ABI.
pub fn derive_challenge_id(
    chain_id: u64,
    contract: Address,
    tx_hash: B256,
    log_index: u64,
) -> ChallengeId {
    let mut buf = Vec::with_capacity(8 + 20 + 32 + 8);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(contract.as_slice());
    buf.extend_from_slice(tx_hash.as_slice());
    buf.extend_from_slice(&log_index.to_be_bytes());
    ChallengeId(keccak256(&buf).0)
}

/// A challenge-opened event. Identity is the opaque [`ChallengeId`] — never `leaf_hash` — so a
/// re-opened challenge for the same leaf is a distinct event and rescans dedup correctly. The
/// event coordinates are retained for the mock's id derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeOpened {
    pub challenge_id: ChallengeId,
    pub leaf_hash: B256,
    /// L2 block at which the event was emitted (used for finality gating by the watcher).
    pub block_number: u64,
    pub chain_id: u64,
    pub contract: Address,
    pub tx_hash: B256,
    pub log_index: u64,
}

impl ChallengeOpened {
    /// Build an event, deriving its opaque [`ChallengeId`] from the coordinates.
    pub fn new(
        chain_id: u64,
        contract: Address,
        tx_hash: B256,
        log_index: u64,
        leaf_hash: B256,
        block_number: u64,
    ) -> Self {
        Self {
            challenge_id: derive_challenge_id(chain_id, contract, tx_hash, log_index),
            leaf_hash,
            block_number,
            chain_id,
            contract,
            tx_hash,
            log_index,
        }
    }
}

/// On-chain status of a challenge, read at a single L2 view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeStatus {
    /// Whether the challenge is still open and can be responded to.
    pub open: bool,
    /// The response deadline, expressed in L2 chain time (seconds).
    pub deadline: u64,
    /// The L2 chain timestamp observed in the same read, used for deadline decisions.
    pub chain_timestamp: u64,
}

/// Source of `ChallengeOpened` events; owns a reorg-safe from-block cursor internally.
#[async_trait]
pub trait ChallengeEventSource: Send + Sync {
    /// Return challenges opened since the last scan (the watcher applies finality + dedup).
    async fn watch_opened(&self) -> Result<Vec<ChallengeOpened>>;
}

/// Reader of a challenge's current on-chain status, keyed by [`ChallengeId`].
#[async_trait]
pub trait ChallengeReader: Send + Sync {
    async fn get_challenge(&self, id: ChallengeId) -> Result<ChallengeStatus>;
}

/// The confirmation status of a broadcast transaction. A broadcast tx is only `Submitted`; the
/// outcome requires a receipt (`Success`/`Reverted`) plus the challenge's on-chain status, and an
/// ambiguous/not-yet-mined receipt (`Pending`) is reconciled on a later tick, never blind-resent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    Success,
    Reverted,
    Pending,
}

/// Sender of a proof for a challenge, keyed by [`ChallengeId`].
#[async_trait]
pub trait ChallengeSender: Send + Sync {
    /// Submit a proof for a challenge. The Withdraw tag is fixed in the contract, not passed here.
    async fn prove_challenge(
        &self,
        id: ChallengeId,
        checkpoint_height: u64,
        leaf_index: u32,
        count: u32,
        siblings: [B256; 32],
    ) -> Result<TxHash>;

    /// Confirm a previously-broadcast transaction via its receipt.
    async fn confirm(&self, tx: TxHash) -> Result<TxStatus>;
}

/// Recorded `prove_challenge` calldata (for test assertions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProveCall {
    pub challenge_id: ChallengeId,
    pub checkpoint_height: u64,
    pub leaf_index: u32,
    pub count: u32,
    pub siblings: [B256; 32],
}

/// In-memory mock challenge contract implementing all three seams.
pub struct MockChallengeContract {
    inner: Mutex<MockState>,
}

struct MockState {
    opened: Vec<ChallengeOpened>,
    status: std::collections::HashMap<ChallengeId, ChallengeStatus>,
    prove_calls: Vec<ProveCall>,
    /// Scripted transaction receipt statuses, keyed by tx hash.
    tx_status: std::collections::HashMap<TxHash, TxStatus>,
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
                tx_status: std::collections::HashMap::new(),
                fail_prove: false,
            }),
        }
    }

    /// Inject an already-built opened challenge and default its status to open (by its id).
    pub fn inject_opened(&self, ev: ChallengeOpened, deadline: u64) {
        let mut s = self.inner.lock().unwrap();
        s.status.insert(
            ev.challenge_id,
            ChallengeStatus { open: true, deadline, chain_timestamp: 0 },
        );
        s.opened.push(ev);
    }

    /// Build + inject an opened challenge from its coordinates, returning the derived id.
    #[allow(clippy::too_many_arguments)]
    pub fn inject_opened_from(
        &self,
        chain_id: u64,
        contract: Address,
        tx_hash: B256,
        log_index: u64,
        leaf_hash: B256,
        block_number: u64,
        deadline: u64,
    ) -> ChallengeId {
        let ev = ChallengeOpened::new(chain_id, contract, tx_hash, log_index, leaf_hash, block_number);
        let id = ev.challenge_id;
        self.inject_opened(ev, deadline);
        id
    }

    /// Script the status returned for a challenge id.
    pub fn set_status(&self, id: ChallengeId, status: ChallengeStatus) {
        self.inner.lock().unwrap().status.insert(id, status);
    }

    /// Make the next `prove_challenge` calls fail (simulate revert / lost race at submit time).
    pub fn set_fail_prove(&self, fail: bool) {
        self.inner.lock().unwrap().fail_prove = fail;
    }

    /// Script the receipt status returned by `confirm` for a transaction hash.
    pub fn set_tx_status(&self, tx: TxHash, status: TxStatus) {
        self.inner.lock().unwrap().tx_status.insert(tx, status);
    }

    /// Mark a challenge resolved (no longer open) — used to model our prove resolving it.
    pub fn mark_resolved_in_our_favor(&self, id: ChallengeId) {
        if let Some(st) = self.inner.lock().unwrap().status.get_mut(&id) {
            st.open = false;
        }
    }

    /// Keep a challenge open (used to model a still-contested challenge after a revert).
    pub fn keep_open(&self, id: ChallengeId) {
        if let Some(st) = self.inner.lock().unwrap().status.get_mut(&id) {
            st.open = true;
        }
    }

    /// All recorded `prove_challenge` calldata.
    pub fn prove_calls(&self) -> Vec<ProveCall> {
        self.inner.lock().unwrap().prove_calls.clone()
    }
}

#[async_trait]
impl ChallengeEventSource for MockChallengeContract {
    async fn watch_opened(&self) -> Result<Vec<ChallengeOpened>> {
        Ok(self.inner.lock().unwrap().opened.clone())
    }
}

#[async_trait]
impl ChallengeReader for MockChallengeContract {
    async fn get_challenge(&self, id: ChallengeId) -> Result<ChallengeStatus> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .status
            .get(&id)
            .copied()
            .unwrap_or(ChallengeStatus { open: false, deadline: 0, chain_timestamp: 0 }))
    }
}

#[async_trait]
impl ChallengeSender for MockChallengeContract {
    async fn prove_challenge(
        &self,
        id: ChallengeId,
        checkpoint_height: u64,
        leaf_index: u32,
        count: u32,
        siblings: [B256; 32],
    ) -> Result<TxHash> {
        let mut s = self.inner.lock().unwrap();
        if s.fail_prove {
            anyhow::bail!("mock prove_challenge failed (simulated revert)");
        }
        s.prove_calls.push(ProveCall {
            challenge_id: id,
            checkpoint_height,
            leaf_index,
            count,
            siblings,
        });
        Ok(TxHash::repeat_byte(0x99))
    }

    async fn confirm(&self, tx: TxHash) -> Result<TxStatus> {
        // Default to Pending (not yet mined / ambiguous) so callers reconcile rather than resend.
        Ok(self.inner.lock().unwrap().tx_status.get(&tx).copied().unwrap_or(TxStatus::Pending))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn same_leaf_two_events_are_distinct_challenge_ids() {
        let mock = MockChallengeContract::new();
        let leaf = B256::repeat_byte(0xAB);
        // Two opens for the same leaf differ by (tx_hash, log_index) ⇒ distinct ChallengeId.
        let a = mock.inject_opened_from(
            196,
            Address::repeat_byte(1),
            B256::repeat_byte(0x10),
            0,
            leaf,
            10,
            5_000,
        );
        let b = mock.inject_opened_from(
            196,
            Address::repeat_byte(1),
            B256::repeat_byte(0x11),
            0,
            leaf,
            10,
            5_000,
        );
        assert_ne!(a, b, "same leaf, different event coords ⇒ distinct ChallengeId");
        let evs = mock.watch_opened().await.unwrap();
        assert_eq!(evs.len(), 2);
        assert!(mock.get_challenge(a).await.unwrap().open);
        assert!(mock.get_challenge(b).await.unwrap().open);
    }

    #[tokio::test]
    async fn reader_reports_chain_timestamp() {
        let mock = MockChallengeContract::new();
        let id = mock.inject_opened_from(
            196,
            Address::repeat_byte(1),
            B256::repeat_byte(0x10),
            0,
            B256::repeat_byte(0xAB),
            10,
            5_000,
        );
        mock.set_status(id, ChallengeStatus { open: true, deadline: 5_000, chain_timestamp: 4_200 });
        assert_eq!(mock.get_challenge(id).await.unwrap().chain_timestamp, 4_200);
    }

    #[tokio::test]
    async fn records_prove_calldata_by_challenge_id() {
        let mock = MockChallengeContract::new();
        let id = mock.inject_opened_from(
            196,
            Address::repeat_byte(1),
            B256::repeat_byte(0x10),
            0,
            B256::repeat_byte(0xAB),
            10,
            5_000,
        );
        let sibs = [B256::repeat_byte(0x07); 32];
        mock.prove_challenge(id, 20, 3, 5, sibs).await.unwrap();
        let calls = mock.prove_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            ProveCall { challenge_id: id, checkpoint_height: 20, leaf_index: 3, count: 5, siblings: sibs }
        );
    }

    #[test]
    fn id_is_stable_and_coordinate_sensitive() {
        let base = derive_challenge_id(196, Address::repeat_byte(1), B256::repeat_byte(0x10), 0);
        assert_eq!(
            base,
            derive_challenge_id(196, Address::repeat_byte(1), B256::repeat_byte(0x10), 0),
            "same coordinates ⇒ same id"
        );
        assert_ne!(
            base,
            derive_challenge_id(196, Address::repeat_byte(1), B256::repeat_byte(0x10), 1),
            "different log index ⇒ different id"
        );
    }

    #[tokio::test]
    async fn unknown_challenge_is_closed() {
        let mock = MockChallengeContract::new();
        let id = derive_challenge_id(1, Address::ZERO, B256::ZERO, 0);
        assert!(!mock.get_challenge(id).await.unwrap().open);
    }
}
