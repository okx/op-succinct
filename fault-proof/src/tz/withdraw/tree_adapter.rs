//! Outer `count + tag` tree wrapper, fixed empty-tree vectors, and inclusion-proof
//! verification for the Withdrawal/ForceTx trees (spec §4, §7.1).
//!
//! # Single source of truth for the *inner* tree
//!
//! The subtle *incremental* tree construction (frontier/branch append as leaves are added
//! during a canonical replay) is owned by the TradeZone Claim Tree Core
//! (`tradezone:crates/chain/src/witness/`, agglayer `unified-bridge 0.18.0` LocalExitTree
//! lineage). The SP1 range guest reuses that crate directly; op-succinct does **not**
//! re-implement the incremental builder (spec §10 non-goal, §14 criterion 5).
//!
//! This adapter implements only what op-succinct legitimately owns and what the Defender's
//! *local proof verification* needs (spec §7.4): the outermost `count + tag` wrapper, the
//! fixed empty-tree vectors, and standard Merkle **proof-path** recomputation. Each of these
//! is fully specified in spec §4 and is byte-equivalent to the Protocol §3.3.2 Rust reference
//! — it is a verification-side recomputation, not a copy of the incremental builder.
//!
//! ## Claim Tree Core integration seam
//!
//! When the `tradezone` Claim Tree Core crate is fetchable in the build environment, a
//! future `tz-claim-tree` feature can re-point [`calculate_inner_root`] / [`verify_proof`] to
//! delegate to the core so there is a single byte-source; the native implementation here then
//! becomes the cross-check oracle (spec §5: "行为必须逐字节等价"). The current environment cannot
//! fetch that private crate (see the ELF/vkey/access hand-off note), so the spec-faithful
//! native implementation is used and unit-tested against the spec's published empty vectors.

use alloy_primitives::{keccak256, B256};

use super::error::WbError;

/// Incremental Merkle tree depth (spec §4).
pub const TREE_DEPTH: usize = 32;
/// Outer wrapper tag for the Withdrawal tree (spec §4).
pub const WITHDRAWAL_TAG: u8 = 0x02;
/// Outer wrapper tag for the ForceTx tree (spec §4).
pub const FORCE_TAG: u8 = 0x01;

/// The empty-subtree hash at every level: `z[0] = bytes32(0)`, `z[h+1] = keccak256(z[h] ‖ z[h])`.
/// `z[TREE_DEPTH]` is the empty inner root. Computed independently (spec §9 item 11), never copied.
fn empty_subtree_hashes() -> [B256; TREE_DEPTH + 1] {
    let mut z = [B256::ZERO; TREE_DEPTH + 1];
    for h in 0..TREE_DEPTH {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(z[h].as_slice());
        buf[32..].copy_from_slice(z[h].as_slice());
        z[h + 1] = keccak256(buf);
    }
    z
}

/// The empty inner root (`z[TREE_DEPTH]`).
pub fn empty_inner_root() -> B256 {
    empty_subtree_hashes()[TREE_DEPTH]
}

/// The full empty-subtree hash vector `z[0..=TREE_DEPTH]` (spec §4). Exposed so callers building
/// inclusion proofs / boundary frontiers reuse the same independently-computed zero hashes.
pub fn zero_hashes() -> [B256; TREE_DEPTH + 1] {
    empty_subtree_hashes()
}

/// The empty Withdrawal root: `business_root(empty_inner_root, 0, WITHDRAWAL_TAG)`.
pub fn empty_withdrawal_root() -> B256 {
    business_root(empty_inner_root(), 0, WITHDRAWAL_TAG)
}

/// The empty ForceTx root: `business_root(empty_inner_root, 0, FORCE_TAG)`. ForceTx currently has
/// no leaves ⇒ this is always the ForceTx root (spec §4 — MUST NOT be `NotReady`).
pub fn empty_force_root() -> B256 {
    business_root(empty_inner_root(), 0, FORCE_TAG)
}

/// Outer wrapper: `keccak256(inner_root ‖ uint256(count) ‖ tag)`, preimage exactly 65 bytes,
/// `count` big-endian right-aligned in a `uint256` (spec §4).
pub fn business_root(inner_root: B256, count: u32, tag: u8) -> B256 {
    let mut preimage = [0u8; 65];
    preimage[..32].copy_from_slice(inner_root.as_slice());
    // uint256(count), big-endian right-aligned: low 4 bytes at [61, 65) of the count word.
    preimage[60..64].copy_from_slice(&count.to_be_bytes());
    preimage[64] = tag;
    keccak256(preimage)
}

/// Rebuild the inner root of a tree with `count` leaves from its boundary frontier
/// (`active_branches` = the branch nodes at the levels set in `count`'s binary, low→high;
/// spec §4). This is the decoder cross-check op-succinct owns: it validates
/// `active_branches.len() == popcount(count)` and reconstructs the declared pre-root without
/// re-implementing the incremental *builder*. Empty trees (`count == 0`) rebuild to
/// [`empty_inner_root`].
pub fn root_from_frontier(active_branches: &[B256], count: u32) -> Result<B256, WbError> {
    if active_branches.len() != count.count_ones() as usize {
        return Err(WbError::WitnessStoreCorrupt);
    }
    let z = empty_subtree_hashes();
    let mut node = B256::ZERO;
    let mut next_branch = 0usize;
    for (h, z_h) in z.iter().enumerate().take(TREE_DEPTH) {
        let mut buf = [0u8; 64];
        if (count >> h) & 1 == 1 {
            // A stored frontier node sits on the left at this level.
            let branch = active_branches[next_branch];
            next_branch += 1;
            buf[..32].copy_from_slice(branch.as_slice());
            buf[32..].copy_from_slice(node.as_slice());
        } else {
            // Empty subtree on the right.
            buf[..32].copy_from_slice(node.as_slice());
            buf[32..].copy_from_slice(z_h.as_slice());
        }
        node = keccak256(buf);
    }
    Ok(node)
}

/// Recompute the inner root from a leaf and its 32-sibling Merkle path.
///
/// Parent = `keccak256(left ‖ right)` (unsorted); the position at each level is the corresponding
/// bit of `leaf_index` (bit 0 = level 0). This is the verification-side recomputation of spec §4.
pub fn calculate_inner_root(leaf: B256, leaf_index: u32, siblings: &[B256; TREE_DEPTH]) -> B256 {
    let mut node = leaf;
    for (h, sibling) in siblings.iter().enumerate() {
        let mut buf = [0u8; 64];
        if (leaf_index >> h) & 1 == 0 {
            // node is the left child.
            buf[..32].copy_from_slice(node.as_slice());
            buf[32..].copy_from_slice(sibling.as_slice());
        } else {
            // node is the right child.
            buf[..32].copy_from_slice(sibling.as_slice());
            buf[32..].copy_from_slice(node.as_slice());
        }
        node = keccak256(buf);
    }
    node
}

/// Verify a Withdrawal/ForceTx inclusion proof against a bound business root.
///
/// Enforces the structural preconditions (spec §4): `count > 0`, `leaf_index < count`,
/// `siblings.len() == 32`; then rebuilds the inner root, wraps it with `count + tag`, and
/// compares to `expected_root`. Structural violations return [`WbError::WitnessStoreCorrupt`];
/// a value mismatch returns [`WbError::RootMismatch`].
pub fn verify_proof(
    leaf: B256,
    leaf_index: u32,
    count: u32,
    siblings: &[B256],
    expected_root: B256,
    tag: u8,
) -> Result<(), WbError> {
    if count == 0 {
        return Err(WbError::WitnessStoreCorrupt);
    }
    if leaf_index >= count {
        return Err(WbError::WitnessStoreCorrupt);
    }
    if siblings.len() != TREE_DEPTH {
        return Err(WbError::WitnessStoreCorrupt);
    }
    let mut sibs = [B256::ZERO; TREE_DEPTH];
    sibs.copy_from_slice(siblings);
    let inner = calculate_inner_root(leaf, leaf_index, &sibs);
    let root = business_root(inner, count, tag);
    if root == expected_root {
        Ok(())
    } else {
        Err(WbError::RootMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Spec §4 publishes (truncated) the fixed empty vectors. We compute them independently via
    // the z-recurrence + outer wrapper and assert they match the published prefixes/suffixes and
    // are mutually distinct (spec §9 item 11 — computed, not copied from one another).
    #[test]
    fn empty_vectors_match_spec_published_values() {
        let inner = format!("{:#x}", empty_inner_root());
        let force = format!("{:#x}", empty_force_root());
        let withdrawal = format!("{:#x}", empty_withdrawal_root());

        // emptyInnerRoot = 0x27ae5ba0…d757
        assert!(inner.starts_with("0x27ae5ba0"), "inner={inner}");
        assert!(inner.ends_with("d757"), "inner={inner}");
        // EMPTY_FORCE_ROOT = 0x2ce29f3b…2a56
        assert!(force.starts_with("0x2ce29f3b"), "force={force}");
        assert!(force.ends_with("2a56"), "force={force}");
        // EMPTY_WITHDRAWAL_ROOT = 0x6b7dbdc9…76d7
        assert!(withdrawal.starts_with("0x6b7dbdc9"), "withdrawal={withdrawal}");
        assert!(withdrawal.ends_with("76d7"), "withdrawal={withdrawal}");

        // Distinct — each computed for its own tag, not copied.
        assert_ne!(empty_withdrawal_root(), empty_force_root());
        assert_ne!(empty_inner_root(), empty_withdrawal_root());
    }

    #[test]
    fn business_root_is_65_byte_tagged_keccak() {
        let inner = B256::repeat_byte(0xab);
        let mut pre = [0u8; 65];
        pre[..32].copy_from_slice(inner.as_slice());
        pre[60..64].copy_from_slice(&5u32.to_be_bytes());
        pre[64] = WITHDRAWAL_TAG;
        assert_eq!(business_root(inner, 5, WITHDRAWAL_TAG), keccak256(pre));
        // tag must matter: withdrawal vs force differ for the same inner+count.
        assert_ne!(
            business_root(inner, 5, WITHDRAWAL_TAG),
            business_root(inner, 5, FORCE_TAG)
        );
        // count must matter.
        assert_ne!(
            business_root(inner, 5, WITHDRAWAL_TAG),
            business_root(inner, 6, WITHDRAWAL_TAG)
        );
    }

    #[test]
    fn verify_proof_rejects_bad_bounds() {
        let sibs = [B256::ZERO; 32];
        // count == 0
        assert!(matches!(
            verify_proof(B256::ZERO, 0, 0, &sibs, B256::ZERO, WITHDRAWAL_TAG),
            Err(WbError::WitnessStoreCorrupt)
        ));
        // leaf_index == count
        assert!(matches!(
            verify_proof(B256::ZERO, 5, 5, &sibs, B256::ZERO, WITHDRAWAL_TAG),
            Err(WbError::WitnessStoreCorrupt)
        ));
        // wrong siblings length
        let short = vec![B256::ZERO; 31];
        assert!(matches!(
            verify_proof(B256::ZERO, 0, 1, &short, B256::ZERO, WITHDRAWAL_TAG),
            Err(WbError::WitnessStoreCorrupt)
        ));
    }

    #[test]
    fn verify_proof_roundtrips_single_leaf_tree() {
        // A count==1 tree: the leaf sits at index 0, siblings are all empty-subtree hashes.
        let leaf = B256::repeat_byte(0x42);
        let z = super::empty_subtree_hashes();
        let mut sibs = [B256::ZERO; 32];
        sibs[..].copy_from_slice(&z[..32]);
        let inner = calculate_inner_root(leaf, 0, &sibs);
        let root = business_root(inner, 1, WITHDRAWAL_TAG);
        // Correct proof verifies.
        assert!(verify_proof(leaf, 0, 1, &sibs, root, WITHDRAWAL_TAG).is_ok());
        // Wrong tag ⇒ root mismatch.
        assert!(matches!(
            verify_proof(leaf, 0, 1, &sibs, root, FORCE_TAG),
            Err(WbError::RootMismatch)
        ));
        // Tampered leaf ⇒ root mismatch.
        assert!(matches!(
            verify_proof(B256::repeat_byte(0x43), 0, 1, &sibs, root, WITHDRAWAL_TAG),
            Err(WbError::RootMismatch)
        ));
    }

    /// Independent reference incremental builder used ONLY as a test oracle (spec §9 item 11 —
    /// computed independently). Appends leaves and tracks the frontier `branch[h]` + root, so we
    /// can assert `root_from_frontier` recovers the same pre-root for counts 0/1/2/3/5.
    struct RefTree {
        branch: [B256; TREE_DEPTH],
        z: [B256; TREE_DEPTH + 1],
        count: u32,
    }
    impl RefTree {
        fn new() -> Self {
            RefTree { branch: [B256::ZERO; TREE_DEPTH], z: super::empty_subtree_hashes(), count: 0 }
        }
        fn append(&mut self, leaf: B256) {
            let mut node = leaf;
            let mut size = self.count;
            for h in 0..TREE_DEPTH {
                if size & 1 == 1 {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(self.branch[h].as_slice());
                    buf[32..].copy_from_slice(node.as_slice());
                    node = keccak256(buf);
                } else {
                    self.branch[h] = node;
                    break;
                }
                size >>= 1;
            }
            self.count += 1;
        }
        fn root(&self) -> B256 {
            let mut node = B256::ZERO;
            let mut size = self.count;
            for h in 0..TREE_DEPTH {
                let mut buf = [0u8; 64];
                if size & 1 == 1 {
                    buf[..32].copy_from_slice(self.branch[h].as_slice());
                    buf[32..].copy_from_slice(node.as_slice());
                } else {
                    buf[..32].copy_from_slice(node.as_slice());
                    buf[32..].copy_from_slice(self.z[h].as_slice());
                }
                node = keccak256(buf);
                size >>= 1;
            }
            node
        }
        /// The active branches at the set-bit levels of `count`, low→high (the boundary wire).
        fn active_branches(&self) -> Vec<B256> {
            let mut out = Vec::new();
            for h in 0..TREE_DEPTH {
                if (self.count >> h) & 1 == 1 {
                    out.push(self.branch[h]);
                }
            }
            out
        }
    }

    #[test]
    fn root_from_frontier_matches_reference_for_counts_0_1_2_3_5() {
        // count == 0 rebuilds to the empty inner root.
        assert_eq!(root_from_frontier(&[], 0).unwrap(), empty_inner_root());

        for &n in &[1u32, 2, 3, 5] {
            let mut t = RefTree::new();
            for i in 0..n {
                t.append(B256::repeat_byte(0x10 + i as u8));
            }
            let ab = t.active_branches();
            assert_eq!(ab.len(), n.count_ones() as usize, "popcount for count={n}");
            let rebuilt = root_from_frontier(&ab, n).unwrap();
            assert_eq!(rebuilt, t.root(), "frontier rebuild must match reference root for count={n}");
            // Wrong length ⇒ rejected.
            let mut bad = ab.clone();
            bad.push(B256::ZERO);
            assert!(matches!(root_from_frontier(&bad, n), Err(WbError::WitnessStoreCorrupt)));
        }
    }

    #[test]
    fn inner_root_position_depends_on_leaf_index_bits() {
        let leaf = B256::repeat_byte(0x11);
        let mut sibs = [B256::ZERO; 32];
        sibs[0] = B256::repeat_byte(0x22);
        // index 0 (left) vs index 1 (right) at level 0 must differ.
        assert_ne!(calculate_inner_root(leaf, 0, &sibs), calculate_inner_root(leaf, 1, &sibs));
    }
}
