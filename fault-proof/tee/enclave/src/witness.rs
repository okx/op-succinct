use kona_proof::BootInfo;

use crate::error::Error;

pub fn check_bounds(boot: &BootInfo) -> Result<(), Error> {
    if boot.claimed_l2_block_number == 0 {
        return Err(Error::InvalidRangeBounds);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use kona_genesis::{L1ChainConfig, RollupConfig};

    fn make_boot_info(claimed_l2_block_number: u64) -> BootInfo {
        BootInfo {
            l1_head: B256::ZERO,
            agreed_l2_output_root: B256::ZERO,
            claimed_l2_output_root: B256::ZERO,
            claimed_l2_block_number,
            chain_id: 1,
            rollup_config: RollupConfig::default(),
            l1_config: L1ChainConfig::default(),
        }
    }

    #[test]
    fn check_bounds_rejects_zero_block_number() {
        let boot = make_boot_info(0);
        let result = check_bounds(&boot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::InvalidRangeBounds),
            "expected InvalidRangeBounds, got: {err}"
        );
    }

    #[test]
    fn check_bounds_accepts_nonzero_block_number() {
        let cases = [1u64, 100, u64::MAX];
        for block_num in cases {
            let boot = make_boot_info(block_num);
            assert!(check_bounds(&boot).is_ok(), "block_number={block_num} should be valid");
        }
    }
}
