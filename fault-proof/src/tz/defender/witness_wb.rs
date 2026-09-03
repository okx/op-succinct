//! Adapter implementing [`WitnessSource`] over the real [`WbClient`] (spec §7.1/§7.4).
//!
//! For V1 records `recordHash == leafHash` (spec §4), so the challenge's `leaf_hash` is used
//! directly as the record hash for the WB lookups.

use std::sync::Arc;

use alloy_primitives::B256;
use anyhow::Result;
use async_trait::async_trait;

use crate::tz::withdraw::error::WbError;
use crate::tz::withdraw::types::HistoricalInclusionProof;
use crate::tz::withdraw::wb_client::WbClient;

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
        checkpoint_height: u64,
        withdrawal_root: B256,
    ) -> Result<HistoricalInclusionProof, WbError> {
        self.wb
            .get_historical_inclusion_proof(leaf_hash, checkpoint_height, withdrawal_root)
            .await
    }
}
