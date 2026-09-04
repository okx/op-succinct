//! Thin adapter over `tz_witness::merkle` (R2 #4, spec §5 "single computation source").
//!
//! op-succinct owns **no** tree/root/proof algorithm. Every root, inner-root and proof computation
//! here delegates to `tz_witness::merkle` (fixed rev `e56881eb…`). The only op-succinct-owned glue
//! is:
//!   1. mapping our convenience `tag: u8` (0x02 Withdrawal / 0x01 ForceTx) to `TreeNamespace`;
//!   2. re-expanding a compact boundary `(count, active_branches)` into a full `TreeFrontier`
//!      (`tz-witness` exposes `TreeFrontier::active_branches()` but no inverse), then calling
//!      `tz_witness::merkle::inner_root`;
//!   3. enforcing the structural proof hard rules (`count > 0`, `leaf_index < count`,
//!      `siblings.len() == 32`) at the boundary and mapping `MerkleError` → [`WbError`].
//!
//! The previous version of this file copied the incremental tree + proof-path recomputation
//! locally because the build environment could not fetch the private tradezone crate; R2 removes
//! that copy entirely — the algorithm now has a single byte-source in `tz-witness`.

use alloy_primitives::B256;
use tz_witness::merkle::{
    self, ClaimProof, MerkleError, TreeFrontier, TreeNamespace, FORCE_ROOT_TAG,
    TREE_DEPTH as TZW_TREE_DEPTH, WITHDRAWAL_ROOT_TAG,
};

use super::error::WbError;

/// Incremental Merkle tree depth (from `tz_witness::merkle`).
pub const TREE_DEPTH: usize = TZW_TREE_DEPTH;
/// Outer wrapper tag for the Withdrawal tree (`tz_witness::merkle::WITHDRAWAL_ROOT_TAG`).
pub const WITHDRAWAL_TAG: u8 = WITHDRAWAL_ROOT_TAG;
/// Outer wrapper tag for the ForceTx tree (`tz_witness::merkle::FORCE_ROOT_TAG`).
pub const FORCE_TAG: u8 = FORCE_ROOT_TAG;

/// Map op-succinct's convenience `tag` byte to a `tz_witness` namespace.
fn namespace_for_tag(tag: u8) -> Result<TreeNamespace, WbError> {
    match tag {
        WITHDRAWAL_ROOT_TAG => Ok(TreeNamespace::Withdrawal),
        FORCE_ROOT_TAG => Ok(TreeNamespace::ForceTx),
        _ => Err(WbError::WitnessStoreCorrupt),
    }
}

/// The empty-subtree hash vector `z[0..=32]` (delegated to `tz_witness::merkle::zero_hashes`).
pub fn zero_hashes() -> [B256; TREE_DEPTH + 1] {
    merkle::zero_hashes()
}

/// The empty inner root `z[32]` (delegated).
pub fn empty_inner_root() -> B256 {
    merkle::zero_hashes()[TREE_DEPTH]
}

/// The empty ForceTx root (`tz_witness::merkle::empty_force_root`).
pub fn empty_force_root() -> B256 {
    merkle::empty_force_root()
}

/// The empty Withdrawal root. `tz-witness` exposes only `empty_force_root`, so build the withdrawal
/// variant from the same primitives: `business_root(Withdrawal, 0, inner_root(empty frontier))`.
pub fn empty_withdrawal_root() -> B256 {
    merkle::business_root(TreeNamespace::Withdrawal, 0, merkle::inner_root(&TreeFrontier::default()))
}

/// Outer `count + tag` wrapper, delegated to `tz_witness::merkle::business_root`. `tag` selects the
/// namespace; callers pass only the two module constants (`WITHDRAWAL_TAG` / `FORCE_TAG`).
pub fn business_root(inner_root_value: B256, count: u32, tag: u8) -> B256 {
    let namespace =
        if tag == FORCE_ROOT_TAG { TreeNamespace::ForceTx } else { TreeNamespace::Withdrawal };
    merkle::business_root(namespace, count, inner_root_value)
}

/// Rebuild the inner root of a tree with `count` leaves from its compact boundary frontier
/// (`active_branches` = branch nodes at the set-bit levels of `count`, low→high). Validates
/// `active_branches.len() == popcount(count)`, re-expands into a full `[B256; 32]` branch array,
/// then delegates the actual root computation to `tz_witness::merkle::inner_root`.
pub fn root_from_frontier(active_branches: &[B256], count: u32) -> Result<B256, WbError> {
    if active_branches.len() != count.count_ones() as usize {
        return Err(WbError::WitnessStoreCorrupt);
    }
    let mut branch = [B256::ZERO; TREE_DEPTH];
    let mut next_branch = 0usize;
    for (h, slot) in branch.iter_mut().enumerate() {
        if (count >> h) & 1 == 1 {
            *slot = active_branches[next_branch];
            next_branch += 1;
        }
    }
    Ok(merkle::inner_root(&TreeFrontier { count, branch }))
}

/// Verify a Withdrawal/ForceTx inclusion proof against a bound business root, delegating the tree
/// math to `tz_witness::merkle::verify_proof`.
///
/// The structural hard rules (spec §4: `count > 0`, `leaf_index < count`, `siblings.len() == 32`)
/// are enforced at the op-succinct boundary and surface as [`WbError::WitnessStoreCorrupt`]; a
/// value mismatch (rebuilt root ≠ `expected_root`) surfaces as [`WbError::RootMismatch`]. The inner
/// root rebuild + outer wrap + comparison are entirely `tz_witness`'s.
pub fn verify_proof(
    leaf: B256,
    leaf_index: u32,
    count: u32,
    siblings: &[B256],
    expected_root: B256,
    tag: u8,
) -> Result<(), WbError> {
    if count == 0 || leaf_index >= count || siblings.len() != TREE_DEPTH {
        return Err(WbError::WitnessStoreCorrupt);
    }
    let mut sibs = [B256::ZERO; TREE_DEPTH];
    sibs.copy_from_slice(siblings);
    let namespace = namespace_for_tag(tag)?;
    let proof = ClaimProof { namespace, leaf, leaf_index, count, siblings: sibs, expected_root };
    merkle::verify_proof(&proof).map_err(|e| match e {
        // Structural cases are pre-checked above; a surviving InvalidProof is a value mismatch.
        MerkleError::InvalidProof => WbError::RootMismatch,
        MerkleError::TreeFull => WbError::WitnessStoreCorrupt,
        _ => WbError::WitnessStoreCorrupt,
    })
}

/// Build a valid single-leaf (`count == 1`) proof's `(siblings, expected_root)` for the Withdrawal
/// namespace — TEST-FIXTURE SUPPORT ONLY (production never constructs proofs, it only verifies them
/// via [`verify_proof`]). Uses `tz_witness::merkle` primitives so the fixture is byte-consistent
/// with the verifier: a `count == 1` tree places the leaf at index 0 with all-empty siblings.
#[cfg(test)]
pub fn single_leaf_withdrawal_fixture(leaf: B256) -> ([B256; TREE_DEPTH], B256) {
    let z = merkle::zero_hashes();
    let mut siblings = [B256::ZERO; TREE_DEPTH];
    siblings.copy_from_slice(&z[..TREE_DEPTH]);
    let appended = merkle::append(&TreeFrontier::default(), leaf).expect("append single leaf");
    let root = merkle::business_root(TreeNamespace::Withdrawal, 1, appended.inner_root);
    (siblings, root)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The frozen empty-tree vectors are asserted against tz-witness' computation (spec §2: each
    // language asserts independently, never copies a literal across).
    #[test]
    fn empty_vectors_match_spec_published_values() {
        let force = format!("{:#x}", empty_force_root());
        let withdrawal = format!("{:#x}", empty_withdrawal_root());
        let inner = format!("{:#x}", empty_inner_root());
        assert!(inner.starts_with("0x27ae5ba0") && inner.ends_with("d757"), "inner={inner}");
        assert!(force.starts_with("0x2ce29f3b") && force.ends_with("2a56"), "force={force}");
        assert!(
            withdrawal.starts_with("0x6b7dbdc9") && withdrawal.ends_with("76d7"),
            "withdrawal={withdrawal}"
        );
        assert_ne!(empty_withdrawal_root(), empty_force_root());
    }

    #[test]
    fn business_root_tag_and_count_matter() {
        let inner = B256::repeat_byte(0xab);
        assert_ne!(business_root(inner, 5, WITHDRAWAL_TAG), business_root(inner, 5, FORCE_TAG));
        assert_ne!(business_root(inner, 5, WITHDRAWAL_TAG), business_root(inner, 6, WITHDRAWAL_TAG));
    }

    #[test]
    fn verify_proof_rejects_bad_bounds() {
        let sibs = [B256::ZERO; TREE_DEPTH];
        assert!(matches!(
            verify_proof(B256::ZERO, 0, 0, &sibs, B256::ZERO, WITHDRAWAL_TAG),
            Err(WbError::WitnessStoreCorrupt)
        ));
        assert!(matches!(
            verify_proof(B256::ZERO, 5, 5, &sibs, B256::ZERO, WITHDRAWAL_TAG),
            Err(WbError::WitnessStoreCorrupt)
        ));
        let short = vec![B256::ZERO; TREE_DEPTH - 1];
        assert!(matches!(
            verify_proof(B256::ZERO, 0, 1, &short, B256::ZERO, WITHDRAWAL_TAG),
            Err(WbError::WitnessStoreCorrupt)
        ));
    }

    #[test]
    fn verify_proof_roundtrips_single_leaf_tree() {
        let leaf = B256::repeat_byte(0x42);
        let (sibs, root) = single_leaf_withdrawal_fixture(leaf);
        assert!(verify_proof(leaf, 0, 1, &sibs, root, WITHDRAWAL_TAG).is_ok());
        assert!(matches!(
            verify_proof(leaf, 0, 1, &sibs, root, FORCE_TAG),
            Err(WbError::RootMismatch)
        ));
        assert!(matches!(
            verify_proof(B256::repeat_byte(0x43), 0, 1, &sibs, root, WITHDRAWAL_TAG),
            Err(WbError::RootMismatch)
        ));
    }

    #[test]
    fn root_from_frontier_rejects_bad_popcount() {
        let bad = vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)];
        assert!(matches!(root_from_frontier(&bad, 2), Err(WbError::WitnessStoreCorrupt)));
        assert_eq!(root_from_frontier(&[], 0).unwrap(), empty_inner_root());
    }
}
