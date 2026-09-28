//! Adapter implementing [`WitnessSource`] over the real [`WbClient`].
//!
//! The challenge event's `leaf_hash` is passed to the Witness Builder as the record-hash key for
//! its lookups. Whether the contract's event leaf actually equals the Witness Builder record hash
//! is an open cross-repo question governed by the leaf-encoding compatibility gate: while the two
//! encodings are not declared compatible for a deployment, the proof flow is blocked upstream and
//! this adapter is never reached. There is no local re-encoding here — masking any mismatch is
//! deliberately avoided.

use std::sync::Arc;

use alloy_primitives::B256;
use anyhow::Result;
use async_trait::async_trait;

use crate::tz::withdraw::{error::WbError, types::HistoricalInclusionProof, wb_client::WbClient};

use super::handler::WitnessSource;

/// [`WitnessSource`] backed by the Witness Builder v2 client.
pub struct WbWitnessSource {
    wb: Arc<WbClient>,
}

impl WbWitnessSource {
    pub fn new(wb: Arc<WbClient>) -> Self {
        Self { wb }
    }
}

#[async_trait]
impl WitnessSource for WbWitnessSource {
    async fn canonical_record_height(&self, leaf_hash: B256) -> Result<u64, WbError> {
        self.wb.get_canonical_record_height(leaf_hash).await
    }

    async fn historical_proof(
        &self,
        leaf_hash: B256,
        withdrawal_root: B256,
    ) -> Result<HistoricalInclusionProof, WbError> {
        self.wb.get_inclusion_proof(leaf_hash, withdrawal_root).await
    }
}
