//! Four-field `claimRoot` codec and `OPSuccinctFaultDisputeGame` `extraData` decode (spec §4, §7.2).
//!
//! `claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)`, preimage exactly
//! 128 bytes (`abi.encodePacked` semantics). This is byte-identical to the on-chain
//! `_checkRootClaimCommitment` (`contracts/src/fp/OPSuccinctFaultDisputeGame.sol:695`) and to the
//! existing `game_validator::compute_v3_claim_root` — the same 4×32-byte concat + keccak256.

use alloy_primitives::{keccak256, B256};
use anyhow::{bail, Result};

use super::types::GameCheckpointPreimage;

/// Length of the four-preimage `extraData()` blob (CWIA args from offset `0x54`):
/// `l2BlockNumber(uint256,32) ‖ parentIndex(u32,4) ‖ blockHash(32) ‖ appHash(32) ‖
/// withdrawalRoot(32) ‖ forceRoot(32)` = 164 bytes.
pub const FOUR_PREIMAGE_EXTRA_DATA_LEN: usize = 164;

/// Compute the four-field `claimRoot` from its 128-byte `abi.encodePacked` preimage.
///
/// Byte-identical to the contract's `_checkRootClaimCommitment` and to
/// `game_validator::compute_v3_claim_root`.
pub fn claim_root(block_hash: B256, app_hash: B256, withdrawal_root: B256, force_root: B256) -> B256 {
    let mut preimage = [0u8; 128];
    preimage[..32].copy_from_slice(block_hash.as_slice());
    preimage[32..64].copy_from_slice(app_hash.as_slice());
    preimage[64..96].copy_from_slice(withdrawal_root.as_slice());
    preimage[96..].copy_from_slice(force_root.as_slice());
    keccak256(preimage)
}

/// Encode a [`GameCheckpointPreimage`] into the 164-byte four-preimage `extraData()` blob.
///
/// Byte-exact inverse of [`decode_four_preimage_extra_data`] and the SOLE production encoder of the
/// CWIA layout (spec §R3.3), so `handle_game_creation` never hand-rolls the byte offsets:
/// `l2BlockNumber(uint256 BE, right-aligned)@[0,32) ‖ parentIndex(u32 BE)@[32,36) ‖
/// blockHash@[36,68) ‖ appHash@[68,100) ‖ withdrawalRoot@[100,132) ‖ forceRoot@[132,164)`. The
/// height is a `u64` so it always fits the low 8 bytes (top 24 stay zero, matching decode's guard).
pub fn encode_four_preimage_extra_data(
    pre: &GameCheckpointPreimage,
) -> [u8; FOUR_PREIMAGE_EXTRA_DATA_LEN] {
    let mut e = [0u8; FOUR_PREIMAGE_EXTRA_DATA_LEN];
    e[24..32].copy_from_slice(&pre.checkpoint_block_height.to_be_bytes());
    e[32..36].copy_from_slice(&pre.parent_index.to_be_bytes());
    e[36..68].copy_from_slice(pre.block_hash.as_slice());
    e[68..100].copy_from_slice(pre.app_hash.as_slice());
    e[100..132].copy_from_slice(pre.withdrawal_root.as_slice());
    e[132..164].copy_from_slice(pre.force_root.as_slice());
    e
}

/// Decode the 164-byte four-preimage `extraData()` blob into its fields.
///
/// The first 32 bytes are a big-endian `uint256` L2 block number; a value that does not fit in
/// `u64` (any of the top 24 bytes non-zero) is rejected, matching `checked_l2_block_number`.
pub fn decode_four_preimage_extra_data(extra: &[u8]) -> Result<GameCheckpointPreimage> {
    if extra.len() != FOUR_PREIMAGE_EXTRA_DATA_LEN {
        bail!(
            "four-preimage extraData must be {FOUR_PREIMAGE_EXTRA_DATA_LEN} bytes, got {}",
            extra.len()
        );
    }
    // l2BlockNumber: uint256 big-endian at [0, 32); reject if it exceeds u64::MAX.
    if extra[..24].iter().any(|&b| b != 0) {
        bail!("four-preimage extraData l2BlockNumber exceeds u64::MAX");
    }
    let mut h = [0u8; 8];
    h.copy_from_slice(&extra[24..32]);
    let checkpoint_block_height = u64::from_be_bytes(h);

    let mut p = [0u8; 4];
    p.copy_from_slice(&extra[32..36]);
    let parent_index = u32::from_be_bytes(p);

    Ok(GameCheckpointPreimage {
        checkpoint_block_height,
        parent_index,
        block_hash: B256::from_slice(&extra[36..68]),
        app_hash: B256::from_slice(&extra[68..100]),
        withdrawal_root: B256::from_slice(&extra[100..132]),
        force_root: B256::from_slice(&extra[132..164]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, B256};

    #[test]
    fn claim_root_matches_packed_keccak_128_bytes() {
        let bh = B256::repeat_byte(0x11);
        let ah = B256::repeat_byte(0x22);
        let wr = B256::repeat_byte(0x33);
        let fr = B256::repeat_byte(0x44);
        let mut pre = [0u8; 128];
        pre[..32].copy_from_slice(bh.as_slice());
        pre[32..64].copy_from_slice(ah.as_slice());
        pre[64..96].copy_from_slice(wr.as_slice());
        pre[96..].copy_from_slice(fr.as_slice());
        assert_eq!(claim_root(bh, ah, wr, fr), keccak256(pre));
    }

    #[test]
    fn claim_root_is_order_sensitive() {
        let a = claim_root(
            B256::repeat_byte(1),
            B256::repeat_byte(2),
            B256::repeat_byte(3),
            B256::repeat_byte(4),
        );
        let b = claim_root(
            B256::repeat_byte(2),
            B256::repeat_byte(1),
            B256::repeat_byte(3),
            B256::repeat_byte(4),
        );
        assert_ne!(a, b);
    }

    /// Build a valid 164-byte extraData blob from fields (test helper mirroring the CWIA layout).
    fn encode_extra(
        height: u64,
        parent_index: u32,
        bh: B256,
        ah: B256,
        wr: B256,
        fr: B256,
    ) -> [u8; 164] {
        let mut e = [0u8; 164];
        e[24..32].copy_from_slice(&height.to_be_bytes());
        e[32..36].copy_from_slice(&parent_index.to_be_bytes());
        e[36..68].copy_from_slice(bh.as_slice());
        e[68..100].copy_from_slice(ah.as_slice());
        e[100..132].copy_from_slice(wr.as_slice());
        e[132..164].copy_from_slice(fr.as_slice());
        e
    }

    #[test]
    fn decode_extra_data_roundtrips_fields() {
        let bh = B256::repeat_byte(0xa1);
        let ah = B256::repeat_byte(0xb2);
        let wr = B256::repeat_byte(0xc3);
        let fr = B256::repeat_byte(0xd4);
        let e = encode_extra(36_000, u32::MAX, bh, ah, wr, fr);
        let d = decode_four_preimage_extra_data(&e).unwrap();
        assert_eq!(d.checkpoint_block_height, 36_000);
        assert_eq!(d.parent_index, u32::MAX);
        assert_eq!(d.block_hash, bh);
        assert_eq!(d.app_hash, ah);
        assert_eq!(d.withdrawal_root, wr);
        assert_eq!(d.force_root, fr);
        // The decoded four-preimage must reproduce the same claimRoot the contract commits to.
        assert_eq!(claim_root(d.block_hash, d.app_hash, d.withdrawal_root, d.force_root), claim_root(bh, ah, wr, fr));
    }

    #[test]
    fn encode_four_preimage_extra_data_roundtrips_and_matches_test_layout() {
        let pre = GameCheckpointPreimage {
            checkpoint_block_height: 36_000,
            parent_index: 7,
            block_hash: B256::repeat_byte(0xa1),
            app_hash: B256::repeat_byte(0xb2),
            withdrawal_root: B256::repeat_byte(0xc3),
            force_root: B256::repeat_byte(0xd4),
        };
        let e = encode_four_preimage_extra_data(&pre);
        assert_eq!(e.len(), FOUR_PREIMAGE_EXTRA_DATA_LEN);
        // byte-identical to the independent test helper layout above.
        assert_eq!(
            e,
            encode_extra(36_000, 7, pre.block_hash, pre.app_hash, pre.withdrawal_root, pre.force_root)
        );
        // and it round-trips through the production decoder.
        assert_eq!(decode_four_preimage_extra_data(&e).unwrap(), pre);
    }

    #[test]
    fn decode_extra_data_rejects_wrong_length() {
        assert!(decode_four_preimage_extra_data(&[0u8; 36]).is_err());
        assert!(decode_four_preimage_extra_data(&[0u8; 163]).is_err());
        assert!(decode_four_preimage_extra_data(&[0u8; 165]).is_err());
    }

    #[test]
    fn decode_extra_data_rejects_height_over_u64() {
        let mut extra = [0u8; 164];
        extra[0] = 0x01; // top byte of uint256 set ⇒ > u64::MAX
        assert!(decode_four_preimage_extra_data(&extra).is_err());
    }
}
