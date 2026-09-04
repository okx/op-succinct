//! Local inclusion-proof verification for the Defender (spec §7.4).
//!
//! Before submitting `proveChallenge`, the Defender rebuilds the inner root from the leaf +
//! Merkle path and checks the outer `count + Withdraw-tag` wrapper equals the exact bound
//! `withdrawalRoot`, enforcing `count > 0`, `leaf_index < count`, `siblings.len() == 32`, and that
//! the proof is actually bound to the root it claims. Any failure means no transaction is sent
//! (the caller alerts). Tree math delegates to [`super::super::withdraw::tree_adapter`].

use alloy_primitives::B256;

use crate::tz::withdraw::error::WbError;
use crate::tz::withdraw::tree_adapter::{verify_proof, WITHDRAWAL_TAG};
use crate::tz::withdraw::types::HistoricalInclusionProof;

/// Verify a historical inclusion proof against the exact `withdrawalRoot` the Defender bound
/// (the finalized RootManager covering root). Returns `Ok(())` only when the proof is internally
/// consistent AND anchored to `bound_withdrawal_root`.
pub fn verify_inclusion(
    proof: &HistoricalInclusionProof,
    bound_withdrawal_root: B256,
) -> Result<(), WbError> {
    // The proof must be bound to the exact root the Defender committed to.
    if proof.withdrawal_root != bound_withdrawal_root {
        return Err(WbError::RootMismatch);
    }
    // Rebuild inner root + wrap with count + Withdraw tag, comparing to the bound root. This also
    // enforces count > 0, leaf_index < count, siblings.len() == 32.
    verify_proof(
        proof.leaf_hash,
        proof.leaf_index,
        proof.count,
        &proof.siblings,
        bound_withdrawal_root,
        WITHDRAWAL_TAG,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::withdraw::tree_adapter::single_leaf_withdrawal_fixture;
    use crate::tz::withdraw::types::WithdrawRecord;
    use alloy_primitives::{Address, B256};

    fn record() -> WithdrawRecord {
        WithdrawRecord {
            version: 1,
            chain_id: 196,
            transaction_hash: B256::repeat_byte(0x01),
            token_type: 0,
            token_address: Address::ZERO,
            token_ids: vec![],
            amounts: vec![],
            from: Address::ZERO,
            to: Address::ZERO,
        }
    }

    /// A valid single-leaf (count == 1) proof and its correct bound root, built via the
    /// tz-witness-backed test fixture (no local tree algorithm).
    fn valid_proof() -> (HistoricalInclusionProof, B256) {
        let leaf = B256::repeat_byte(0x42);
        let (siblings, root) = single_leaf_withdrawal_fixture(leaf);
        let proof = HistoricalInclusionProof {
            record: record(),
            record_hash: leaf,
            leaf_hash: leaf,
            canonical_block_height: 10,
            checkpoint_height: 20,
            withdrawal_root: root,
            leaf_index: 0,
            count: 1,
            siblings,
        };
        (proof, root)
    }

    #[test]
    fn valid_proof_verifies() {
        let (proof, root) = valid_proof();
        assert!(verify_inclusion(&proof, root).is_ok());
    }

    #[test]
    fn proof_bound_to_wrong_root_is_rejected() {
        let (proof, _root) = valid_proof();
        assert!(matches!(
            verify_inclusion(&proof, B256::repeat_byte(0xFE)),
            Err(WbError::RootMismatch)
        ));
    }

    #[test]
    fn count_zero_is_rejected() {
        let (mut proof, root) = valid_proof();
        proof.count = 0;
        assert!(matches!(verify_inclusion(&proof, root), Err(WbError::WitnessStoreCorrupt)));
    }

    #[test]
    fn leaf_index_equal_count_is_rejected() {
        let (mut proof, root) = valid_proof();
        proof.leaf_index = proof.count; // leaf_index == count
        assert!(verify_inclusion(&proof, root).is_err());
    }

    #[test]
    fn tampered_leaf_is_rejected() {
        let (mut proof, root) = valid_proof();
        proof.leaf_hash = B256::repeat_byte(0x43);
        assert!(matches!(verify_inclusion(&proof, root), Err(WbError::RootMismatch)));
    }
}
