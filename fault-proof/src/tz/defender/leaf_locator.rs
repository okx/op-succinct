//! Isolated, replaceable component: challenge event → Witness-Builder leaf key.
//!
//! [`LeafLocator`] is the single seam whose only job is turning what a decoded challenge event
//! provides into the leaf hash the state machine consumes (via `ChallengeOpened.leaf_hash`). The
//! "how do we get the leaf from the event" assumption lives ONLY here, never in the watcher,
//! handler, verifier, or supervisor. When the event schema changes (e.g. it starts carrying the
//! leaf key directly), only the locator wired into the adapter changes — nothing else.

use std::sync::Arc;

use alloy_primitives::B256;
use async_trait::async_trait;

use crate::tz::withdraw::{error::WbError, wb_client::TzTxToLeaf};

use super::challenge_manager::RawChallengeEvent;

/// Turns a decoded challenge event into the Witness-Builder leaf key (a `bytes32` leaf hash).
#[async_trait]
pub trait LeafLocator: Send + Sync {
    /// Resolve the leaf hash for `ev`. A not-found / ambiguous condition surfaces as a [`WbError`]
    /// (the adapter maps it to a witness-wait); it must never panic.
    async fn locate(&self, ev: &RawChallengeEvent) -> Result<B256, WbError>;
}

/// The event already carries the leaf hash in its identifier slot; return it verbatim. This is the
/// implementation used once the event schema exposes the leaf key directly.
pub struct DirectLeafLocator;

#[async_trait]
impl LeafLocator for DirectLeafLocator {
    async fn locate(&self, ev: &RawChallengeEvent) -> Result<B256, WbError> {
        Ok(ev.identifier)
    }
}

/// The event carries a transaction-scoped identifier; resolve it to the leaf key via a
/// [`TzTxToLeaf`] reverse lookup. Not-found / ambiguous errors from the lookup propagate unchanged
/// (the adapter maps them to a witness-wait, never a panic). This is the implementation used while
/// the event exposes only the identifier and not the leaf key.
pub struct ReverseLookupLeafLocator<W: TzTxToLeaf> {
    wb: Arc<W>,
}

impl<W: TzTxToLeaf> ReverseLookupLeafLocator<W> {
    pub fn new(wb: Arc<W>) -> Self {
        Self { wb }
    }
}

#[async_trait]
impl<W: TzTxToLeaf> LeafLocator for ReverseLookupLeafLocator<W> {
    async fn locate(&self, ev: &RawChallengeEvent) -> Result<B256, WbError> {
        self.wb.record_hash_by_tz_tx(ev.identifier).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::defender::challenge_manager::ChallengeType;
    use alloy_primitives::{Address, U256};

    /// A `RawChallengeEvent` whose identifier slot is `identifier`.
    fn raw_event_with_identifier(identifier: B256) -> RawChallengeEvent {
        RawChallengeEvent {
            onchain_challenge_id: U256::from(1u64),
            challenge_type: ChallengeType::WithdrawNotInRoot,
            identifier,
            response_deadline: 1_000,
            block_number: 10,
            chain_id: 196,
            contract: Address::repeat_byte(0x01),
            tx_hash: B256::repeat_byte(0x02),
            log_index: 0,
        }
    }

    #[tokio::test]
    async fn direct_locator_returns_event_identifier_as_leaf() {
        let ev = raw_event_with_identifier(B256::repeat_byte(0xab));
        let leaf = DirectLeafLocator.locate(&ev).await.unwrap();
        assert_eq!(leaf, B256::repeat_byte(0xab));
    }

    #[tokio::test]
    async fn reverse_locator_maps_tz_tx_to_leaf_via_wb() {
        use crate::tz::withdraw::wb_client::test_doubles::MockTzTxToLeaf;
        let mut m = std::collections::HashMap::new();
        m.insert(B256::repeat_byte(0x11), B256::repeat_byte(0x99));
        let loc = ReverseLookupLeafLocator::new(Arc::new(MockTzTxToLeaf(m)));
        let ev = raw_event_with_identifier(B256::repeat_byte(0x11));
        assert_eq!(loc.locate(&ev).await.unwrap(), B256::repeat_byte(0x99));
    }

    #[tokio::test]
    async fn reverse_locator_propagates_not_found() {
        use crate::tz::withdraw::wb_client::test_doubles::MockTzTxToLeaf;
        let loc = ReverseLookupLeafLocator::new(Arc::new(MockTzTxToLeaf(Default::default())));
        let ev = raw_event_with_identifier(B256::repeat_byte(0x11));
        assert!(matches!(loc.locate(&ev).await, Err(WbError::WithdrawalNotFound)));
    }
}
