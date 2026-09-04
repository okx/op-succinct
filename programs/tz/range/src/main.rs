//! tz range guest: replay blocks over a DexState snapshot and commit a four-field claimRoot
//! BootInfoStruct (TRDZN-1339 R2 #5).
//!
//! R2 #5 integrates `tz-witness` so `l2PreRoot`/`l2PostRoot` are the 128-byte four-field
//! `claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)` instead of the old
//! two-field `keccak_join(blockHash, appHash)`. The tree/root math is `tz-witness` (single source):
//!  - pre roots: re-expand each sub-range-start boundary `(count, active_branches)` into a full
//!    `TreeFrontier`, `tz_witness::merkle::inner_root` → `business_root(namespace, count, inner)`;
//!  - post roots: replay `(S,E]`, and for each block
//!    `tz_block_processor::withdrawal::extract_withdrawals` feeds `tz_witness::merkle::append`; the
//!    guest NEVER trusts host-supplied leaves/post roots.
//!
//! ⚠️ SP1-verification NOTEs (this environment has no `cargo-prove`, so the guest could not be
//! compiled/built here — see implementation-report.md "Blockers"). The creator must confirm on the
//! SP1 guest target:
//!   [N1] `process_block` returns the `BlockResult` (captured below) that `extract_withdrawals`
//!        consumes; the exact return type/signature at rev e56881eb must be linked, not guessed.
//!   [N2] the stdin input ORDER for the two boundaries + `tz_chain_id` must match what the proposer
//!        writes (`fault_proof::tz::proposer::boundary_stdin_fields`); align the two together.
//!   [N3] `tz_chain_id` is read only to tag extracted records for `extract_withdrawals`; it is NOT
//!        part of any root (spec §6 keeps chainId out of the claim), only a replay input.
//!   [N4] ForceTx has no in-range extractor here, so the force frontier stays at its boundary
//!        count (empty ⇒ `empty_force_root`); wire a force extractor if/when one exists.

#![cfg_attr(target_os = "zkvm", no_main)]

#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use alloy_sol_types::SolValue;
use op_succinct_client_utils::boot::BootInfoStruct;
use tz_block_processor::{
    compute_app_hash, process_block, verify_next_block, withdrawal::extract_withdrawals, Block,
};
use tz_dex::DexState;
use tz_witness::{
    checkpoint::checkpoint_v2_claim_root,
    merkle::{append, business_root, inner_root, TreeFrontier, TreeNamespace, TREE_DEPTH},
};

pub fn main() {
    let snapshot_bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let chunk_count: u32 = sp1_zkvm::io::read();

    // [N2] Sub-range-start boundary block written by the proposer right after `chunk_count`, in the
    // §R4.3 canonical order: tz_chain_id (③), block_hash (④, R4), then the two trees (⑤–⑧). Order
    // must match `fault_proof::tz::proposer::boundary_stdin_fields`.
    let tz_chain_id: u64 = sp1_zkvm::io::read();
    let boundary_block_hash: B256 = sp1_zkvm::io::read(); // ④ (R4)
    let w_count: u32 = sp1_zkvm::io::read();
    let w_active: Vec<B256> = sp1_zkvm::io::read();
    let f_count: u32 = sp1_zkvm::io::read();
    let f_active: Vec<B256> = sp1_zkvm::io::read();

    let mut state: DexState = {
        let mut de = rmp_serde::Deserializer::new(&snapshot_bytes[..]);
        tz_dex::order_preserving_serde::deserialize(&mut de)
            .unwrap_or_else(|e| panic!("failed to deserialize DexState snapshot: {}", e))
    };

    let start_block_hash = state.context.block_hash;
    // R4 §R4.2-3: the boundary MUST fall on the snapshot's start block. This re-enforces the Host's
    // pre-proving `assert_boundary_consistent` inside the zkVM — a boundary for a different block
    // (e.g. a reorged block at the right height) cannot produce a passing proof. Mismatch ⇒ panic.
    assert_eq!(
        boundary_block_hash, start_block_hash,
        "boundary block hash != snapshot start block hash"
    );
    let start_app_hash = B256::from(blake3_hash_state(&state));

    // Pre roots: rebuild each tree's frontier from its compact boundary, then wrap with count+tag.
    let mut w_frontier = frontier_from_boundary(w_count, &w_active);
    let f_frontier = frontier_from_boundary(f_count, &f_active);
    let pre_withdrawal_root =
        business_root(TreeNamespace::Withdrawal, w_frontier.count, inner_root(&w_frontier));
    let pre_force_root =
        business_root(TreeNamespace::ForceTx, f_frontier.count, inner_root(&f_frontier));
    let l2_pre_root = checkpoint_v2_claim_root(
        start_block_hash,
        start_app_hash,
        pre_withdrawal_root,
        pre_force_root,
    );

    for chunk_idx in 0..chunk_count {
        let chunk_bytes: Vec<u8> = sp1_zkvm::io::read_vec();
        let chunk: Vec<Block> = rmp_serde::from_slice(&chunk_bytes).unwrap_or_else(|e| {
            panic!("failed to deserialize Vec<Block> chunk {}: {}", chunk_idx, e)
        });
        for block in &chunk {
            verify_next_block(&state, block).unwrap_or_else(|e| {
                panic!("verify_next_block failed at height {}: {}", block.header.height, e)
            });
            // [N1] Capture the BlockResult so extracted withdrawals can be appended. verify_pool =
            // None: zkVM has no parallel runtime.
            let block_result = process_block(&mut state, block, None).unwrap_or_else(|e| {
                panic!("process_block failed at height {}: {}", block.header.height, e)
            });
            // The guest self-derives leaves from the canonical replay (never trusts the host).
            let withdrawals = extract_withdrawals(tz_chain_id, &block_result).unwrap_or_else(|e| {
                panic!("extract_withdrawals failed at height {}: {}", block.header.height, e)
            });
            for cw in &withdrawals {
                let appended = append(&w_frontier, cw.record_hash).unwrap_or_else(|e| {
                    panic!("tz-witness append failed at height {}: {}", block.header.height, e)
                });
                w_frontier = appended.frontier;
            }
        }
    }

    let end_block_hash = state.context.block_hash;
    let end_app_hash = B256::from(blake3_hash_state(&state));

    // Post roots: withdrawal frontier advanced by the replay; force frontier unchanged ([N4]).
    let post_withdrawal_root =
        business_root(TreeNamespace::Withdrawal, w_frontier.count, inner_root(&w_frontier));
    let post_force_root =
        business_root(TreeNamespace::ForceTx, f_frontier.count, inner_root(&f_frontier));
    let l2_post_root = checkpoint_v2_claim_root(
        end_block_hash,
        end_app_hash,
        post_withdrawal_root,
        post_force_root,
    );

    // l1Head / rollupConfigHash are forced to ZERO — tradezone is not an Optimism rollup.
    let boot_info = BootInfoStruct {
        l1Head: B256::ZERO,
        l2PreRoot: l2_pre_root,
        l2PostRoot: l2_post_root,
        l2BlockNumber: state.context.height,
        rollupConfigHash: B256::ZERO,
    };
    sp1_zkvm::io::commit_slice(&SolValue::abi_encode(&boot_info));
}

/// Re-expand a compact boundary `(count, active_branches)` into a full `TreeFrontier` (place each
/// active branch at its set-bit level of `count`). `tz-witness` exposes `active_branches()` but no
/// inverse, so the guest owns this expansion; the root math stays in `tz_witness::merkle`.
fn frontier_from_boundary(count: u32, active_branches: &[B256]) -> TreeFrontier {
    assert_eq!(
        active_branches.len(),
        count.count_ones() as usize,
        "boundary active_branches length must equal popcount(count)"
    );
    let mut branch = [B256::ZERO; TREE_DEPTH];
    let mut next = 0usize;
    for (h, slot) in branch.iter_mut().enumerate() {
        if (count >> h) & 1 == 1 {
            *slot = active_branches[next];
            next += 1;
        }
    }
    TreeFrontier { count, branch }
}

/// Use `compute_app_hash` (default rmp_serde + blake3) so the guest's app hash byte-matches the
/// sequencer's PublishedAppHash.
fn blake3_hash_state(state: &DexState) -> [u8; 32] {
    compute_app_hash(state).expect("compute_app_hash: rmp_serde must serialize DexState").app_hash.0
}
