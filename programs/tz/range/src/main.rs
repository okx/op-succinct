//! tz range guest: replay blocks over a DexState snapshot and commit a
//! BootInfoStruct.

#![cfg_attr(target_os = "zkvm", no_main)]

#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{B256, keccak256};
use alloy_sol_types::SolValue;
use op_succinct_client_utils::boot::BootInfoStruct;
use tz_block_processor::{Block, compute_app_hash, process_block, verify_next_block};
use tz_dex::DexState;

pub fn main() {
    let snapshot_bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let chunk_count: u32 = sp1_zkvm::io::read();

    // Order-preserving decode so Slab free-list is recovered exactly; the
    // default rmp_serde path reshuffles slot indices.
    //
    // Bring our own `rmp_serde::Deserializer` so this guest doesn't depend on
    // tz-dex shipping a `from_msgpack` convenience wrapper — the underlying
    // `order_preserving_serde::deserialize` lives in tz-dex on every branch.
    let mut state: DexState = {
        let mut de = rmp_serde::Deserializer::new(&snapshot_bytes[..]);
        tz_dex::order_preserving_serde::deserialize(&mut de)
            .unwrap_or_else(|e| panic!("failed to deserialize DexState snapshot: {}", e))
    };

    let start_block_hash = state.context.block_hash;
    let start_state_hash = blake3_hash_state(&state);

    for chunk_idx in 0..chunk_count {
        let chunk_bytes: Vec<u8> = sp1_zkvm::io::read_vec();
        let chunk: Vec<Block> = rmp_serde::from_slice(&chunk_bytes).unwrap_or_else(|e| {
            panic!("failed to deserialize Vec<Block> chunk {}: {}", chunk_idx, e)
        });
        for block in &chunk {
            verify_next_block(&state, block).unwrap_or_else(|e| {
                panic!("verify_next_block failed at height {}: {}", block.header.height, e)
            });
            // verify_pool = None: zkVM has no parallel runtime.
            process_block(&mut state, block, None).unwrap_or_else(|e| {
                panic!("process_block failed at height {}: {}", block.header.height, e)
            });
        }
    }

    let end_block_hash = state.context.block_hash;
    let end_state_hash = blake3_hash_state(&state);

    // l1Head / rollupConfigHash are forced to ZERO — tradezone is not an
    // Optimism rollup, those upstream fields carry no meaning here.
    let boot_info = BootInfoStruct {
        l1Head: B256::ZERO,
        l2PreRoot: keccak_join(start_block_hash, B256::from(start_state_hash)),
        l2PostRoot: keccak_join(end_block_hash, B256::from(end_state_hash)),
        l2BlockNumber: state.context.height,
        rollupConfigHash: B256::ZERO,
    };
    sp1_zkvm::io::commit_slice(&SolValue::abi_encode(&boot_info));
}

/// `keccak256(abi.encode(a, b))` for two `bytes32` values. `abi_encode_sequence`
/// on `(B256, B256)` emits exactly 64 bytes — each element padded to 32, no
/// offset header — matching Solidity `abi.encode` for all-static tuples.
fn keccak_join(b1: B256, b2: B256) -> B256 {
    let encoded = <(B256, B256) as SolValue>::abi_encode_sequence(&(b1, b2));
    debug_assert_eq!(encoded.len(), 64);
    keccak256(&encoded)
}

/// Use `compute_app_hash` (default rmp_serde + blake3, same path the
/// sequencer uses for PublishedAppHash) so the guest's state hashes
/// byte-match the sequencer's ground truth.
fn blake3_hash_state(state: &DexState) -> [u8; 32] {
    compute_app_hash(state)
        .expect("compute_app_hash: rmp_serde must serialize DexState")
        .app_hash
        .0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tz_dex::DexContext;

    #[test]
    fn blake3_hash_state_is_deterministic() {
        let state = DexState::default();
        let h1 = blake3_hash_state(&state);
        let h2 = blake3_hash_state(&state);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn blake3_hash_state_differs_for_different_states() {
        let a = DexState::default();
        let b = DexState {
            context: DexContext { height: 1, ..Default::default() },
            ..DexState::default()
        };
        assert_ne!(blake3_hash_state(&a), blake3_hash_state(&b));
    }

    #[test]
    fn boot_info_abi_encodes_to_160_bytes() {
        let bi = BootInfoStruct {
            l1Head: B256::ZERO,
            l2PreRoot: [0x11; 32].into(),
            l2PostRoot: [0x22; 32].into(),
            l2BlockNumber: 36000,
            rollupConfigHash: B256::ZERO,
        };
        assert_eq!(SolValue::abi_encode(&bi).len(), 160);
    }

    #[test]
    fn keccak_join_matches_raw_concat_hash() {
        let b1 = B256::from([0x11u8; 32]);
        let b2 = B256::from([0x22u8; 32]);
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(b1.as_slice());
        concat[32..].copy_from_slice(b2.as_slice());
        assert_eq!(keccak_join(b1, b2), keccak256(concat));
    }
}
