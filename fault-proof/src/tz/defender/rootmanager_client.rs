//! TZRootManager access for the Defender (spec §7.4).
//!
//! The handler binds `(checkpointHeight, withdrawalRoot)` to a **finalized** RootManager
//! checkpoint that covers the record height. This is abstracted behind [`CoveringRootSource`] so
//! the state machine is unit-testable with [`MockRootManager`]; the on-chain
//! [`RootManagerClient`] reads `getLatestRoots()` from `TZRootManager` at a finalized block.

use alloy_primitives::B256;
use alloy_provider::Provider;
use alloy_sol_types::sol;
use anyhow::{Context, Result};
use async_trait::async_trait;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ITZRootManager {
        function getLatestRoots() external view returns (uint256 height, bytes32 withdrawalRoot, bytes32 forceTxRoot);
        function getRoots(uint256 height) external view returns (bytes32 withdrawalRoot, bytes32 forceTxRoot);
    }
}

/// Source of the finalized covering `(checkpointHeight, withdrawalRoot)` for a record height.
#[async_trait]
pub trait CoveringRootSource: Send + Sync {
    /// Return the latest finalized RootManager checkpoint whose height `>= record_height`, with
    /// its `withdrawalRoot`; `None` if no finalized checkpoint covers the record yet.
    async fn latest_finalized_covering(&self, record_height: u64) -> Result<Option<(u64, B256)>>;
}

/// On-chain TZRootManager client reading `getLatestRoots()`. The "finalized" guarantee is
/// provided by the caller reading against a finalized L1 view; this client returns the latest
/// recorded covering root or `None`.
pub struct RootManagerClient<P: Provider + Clone> {
    inner: ITZRootManager::ITZRootManagerInstance<P>,
}

impl<P: Provider + Clone> RootManagerClient<P> {
    pub fn new(address: alloy_primitives::Address, provider: P) -> Self {
        Self { inner: ITZRootManager::new(address, provider) }
    }
}

#[async_trait]
impl<P: Provider + Clone + Send + Sync + 'static> CoveringRootSource for RootManagerClient<P> {
    async fn latest_finalized_covering(&self, record_height: u64) -> Result<Option<(u64, B256)>> {
        let latest = self
            .inner
            .getLatestRoots()
            .call()
            .await
            .context("failed to read TZRootManager.getLatestRoots")?;
        let height = crate::checked_l2_block_number(latest.height)
            .context("RootManager latest height exceeds u64")?;
        if height >= record_height {
            Ok(Some((height, latest.withdrawalRoot)))
        } else {
            Ok(None)
        }
    }
}

/// In-memory covering-root source for tests: a sorted list of `(height, withdrawalRoot)`.
#[derive(Default)]
pub struct MockRootManager {
    checkpoints: std::sync::Mutex<Vec<(u64, B256)>>,
}

impl MockRootManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a finalized checkpoint.
    pub fn record(&self, height: u64, withdrawal_root: B256) {
        let mut c = self.checkpoints.lock().unwrap();
        c.push((height, withdrawal_root));
        c.sort_by_key(|(h, _)| *h);
    }
}

#[async_trait]
impl CoveringRootSource for MockRootManager {
    async fn latest_finalized_covering(&self, record_height: u64) -> Result<Option<(u64, B256)>> {
        let c = self.checkpoints.lock().unwrap();
        // The latest checkpoint covers the record iff its height >= record_height.
        Ok(c.last().filter(|(h, _)| *h >= record_height).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn covering_requires_latest_height_ge_record() {
        let rm = MockRootManager::new();
        assert!(rm.latest_finalized_covering(100).await.unwrap().is_none());
        rm.record(90, B256::repeat_byte(0x01));
        // 90 < 100 ⇒ not covered yet.
        assert!(rm.latest_finalized_covering(100).await.unwrap().is_none());
        rm.record(120, B256::repeat_byte(0x02));
        // latest (120) >= 100 ⇒ covered, bind its withdrawalRoot.
        assert_eq!(
            rm.latest_finalized_covering(100).await.unwrap(),
            Some((120, B256::repeat_byte(0x02)))
        );
    }
}
