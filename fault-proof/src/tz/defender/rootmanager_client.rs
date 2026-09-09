//! TZRootManager access for the Defender.
//!
//! The handler binds `(checkpointHeight, withdrawalRoot)` to the RootManager's current latest
//! checkpoint. This is abstracted behind [`LatestRootSource`] so the state machine is
//! unit-testable with [`MockRootManager`]; the on-chain [`RootManagerClient`] reads
//! `getLatestRoots()` from `TZRootManager` at the current/latest state.

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
    }
}

/// Source of the current latest RootManager checkpoint.
#[async_trait]
pub trait LatestRootSource: Send + Sync {
    /// The current latest RootManager checkpoint `(checkpoint_height, withdrawal_root)`, read at
    /// the L2 current/latest state — NOT a finalized/lagging view. A prove transaction is
    /// verified against the contract's then-current root, so a finalized root would be stale
    /// and rejected.
    async fn latest_root(&self) -> Result<(u64, B256)>;
}

/// On-chain TZRootManager client reading `getLatestRoots()` at the current/latest state.
pub struct RootManagerClient<P: Provider + Clone> {
    inner: ITZRootManager::ITZRootManagerInstance<P>,
}

impl<P: Provider + Clone> RootManagerClient<P> {
    pub fn new(address: alloy_primitives::Address, provider: P) -> Self {
        Self { inner: ITZRootManager::new(address, provider) }
    }
}

#[async_trait]
impl<P: Provider + Clone + Send + Sync + 'static> LatestRootSource for RootManagerClient<P> {
    async fn latest_root(&self) -> Result<(u64, B256)> {
        let latest = self
            .inner
            .getLatestRoots()
            .call()
            .await
            .context("failed to read TZRootManager.getLatestRoots")?;
        let height = crate::checked_l2_block_number(latest.height)
            .context("RootManager latest height exceeds u64")?;
        Ok((height, latest.withdrawalRoot))
    }
}

/// In-memory latest-root source for tests: holds the current latest `(height, withdrawalRoot)`.
#[derive(Default)]
pub struct MockRootManager {
    latest: std::sync::Mutex<Option<(u64, B256)>>,
}

impl MockRootManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current latest checkpoint (latest-only semantics: replaces any prior value).
    pub fn set_latest(&self, height: u64, withdrawal_root: B256) {
        *self.latest.lock().unwrap() = Some((height, withdrawal_root));
    }
}

#[async_trait]
impl LatestRootSource for MockRootManager {
    async fn latest_root(&self) -> Result<(u64, B256)> {
        self.latest.lock().unwrap().ok_or_else(|| anyhow::anyhow!("no latest root set"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn latest_root_returns_current_latest_pair() {
        let rm = MockRootManager::new();
        // No root set yet ⇒ error (no latest available).
        assert!(rm.latest_root().await.is_err());
        rm.set_latest(90, B256::repeat_byte(0x01));
        assert_eq!(rm.latest_root().await.unwrap(), (90, B256::repeat_byte(0x01)));
        // A newer root replaces the latest (latest-only semantics).
        rm.set_latest(120, B256::repeat_byte(0x02));
        assert_eq!(rm.latest_root().await.unwrap(), (120, B256::repeat_byte(0x02)));
    }
}
