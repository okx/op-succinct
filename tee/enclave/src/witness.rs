//! Witness wire type — alias for `op-succinct-client-utils::DefaultWitnessData`.
//!
//! The handler accepts [`Witness`] over HTTP as a rkyv-serialized body.
//! BootInfo (and all journal-relevant range parameters) is encoded inside
//! `witness.preimage_store` as `PreimageKey::Local` entries; the enclave
//! extracts via [`kona_proof::BootInfo::load`].
//!
//! Bounds-checking against extracted BootInfo lives in [`check_bounds`].

pub use op_succinct_client_utils::witness::DefaultWitnessData as Witness;

use crate::error::{Error, Result};
use kona_proof::BootInfo;

/// Validate the boot info range is sane.
///
/// We require `claimed_l2_block_number > 0` — if claimed == 0, there is no
/// "previous" block to compare against. Other invariants (e.g. claimed >
/// safe head) are enforced by `get_inputs_for_pipeline` later.
pub fn check_bounds(boot: &BootInfo) -> Result<()> {
    if boot.claimed_l2_block_number == 0 {
        return Err(Error::InvalidRangeBounds(0, 0));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kona_genesis::{L1ChainConfig, RollupConfig};

    fn synth_boot(claimed: u64) -> BootInfo {
        BootInfo {
            l1_head: Default::default(),
            agreed_l2_output_root: Default::default(),
            claimed_l2_output_root: Default::default(),
            claimed_l2_block_number: claimed,
            chain_id: 0,
            rollup_config: RollupConfig::default(),
            l1_config: L1ChainConfig::default(),
        }
    }

    #[test]
    fn check_bounds_rejects_zero_claimed() {
        let err = check_bounds(&synth_boot(0)).expect_err("should reject");
        assert!(matches!(err, Error::InvalidRangeBounds(0, 0)));
    }

    #[test]
    fn check_bounds_accepts_positive_claimed() {
        assert!(check_bounds(&synth_boot(1800)).is_ok());
    }
}
