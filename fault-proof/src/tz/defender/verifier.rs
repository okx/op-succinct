//! Local inclusion-proof verification for the Defender (spec §7.4).
//!
//! Before submitting `proveChallenge`, the Defender rebuilds the inner root from the leaf +
//! Merkle path and checks the outer `count + Withdraw-tag` wrapper equals the exact bound
//! `withdrawalRoot`, enforcing `count > 0`, `leaf_index < count`, `siblings.len() == 32`, and that
//! the proof is actually bound to the root it claims. Any failure means no transaction is sent
//! (the caller alerts). Tree math delegates to [`super::super::withdraw::tree_adapter`].

use alloy_primitives::B256;

use crate::tz::withdraw::{
    error::WbError,
    tree_adapter::{verify_proof, WITHDRAWAL_TAG},
    types::{HistoricalInclusionProof, WithdrawRecord},
};

/// Recompute the canonical V1 leaf hash of a withdrawal record via `tz-witness` (no local hash
/// algorithm). Fails closed as [`WbError::WitnessStoreCorrupt`] when the record is malformed or its
/// token arrays are inconsistent — the same validation `tz-witness` applies before hashing a leaf.
pub fn record_leaf_hash(record: &WithdrawRecord) -> Result<B256, WbError> {
    use tz_witness::withdrawal::{
        RawTradezoneWithdrawal as TzRaw, TokenType as TzTokenType, WithdrawRecord as TzRecord,
    };
    let token_type =
        TzTokenType::try_from(record.token_type).map_err(|_| WbError::WitnessStoreCorrupt)?;
    let tz = TzRecord {
        version: record.version,
        chain_id: record.chain_id,
        transaction_hash: record.transaction_hash,
        raw_tradezone_withdrawal: TzRaw {
            token_type,
            token_address: record.token_address,
            token_ids: record.token_ids.clone(),
            amounts: record.amounts.clone(),
            from: record.from,
            to: record.to,
        },
    };
    tz.record_hash().map_err(|_| WbError::WitnessStoreCorrupt)
}

/// Leaf-bound proof verification: verify a historical inclusion proof is bound to exactly the
/// challenged leaf, the exact requested root, and the configured chain. Fails closed unless ALL of:
/// `record_hash == requested_leaf`, `leaf_hash == requested_leaf`, `withdrawal_root ==
/// requested_root`, `record.chain_id == chain_id`, the `tz-witness`-recomputed record hash equals
/// `requested_leaf`, AND the Merkle inclusion of `leaf_hash` under `requested_root` verifies. A
/// valid Merkle proof of a *different* leaf under the same root is therefore rejected.
pub fn verify(
    proof: &HistoricalInclusionProof,
    requested_leaf: B256,
    requested_root: B256,
    chain_id: u64,
) -> Result<(), WbError> {
    // Bind the proof to the exact challenged leaf, the exact requested root, and our chain.
    if proof.record_hash != requested_leaf ||
        proof.leaf_hash != requested_leaf ||
        proof.withdrawal_root != requested_root ||
        proof.record.chain_id != chain_id
    {
        return Err(WbError::RootMismatch);
    }
    // The record's own fields must recompute (via tz-witness) to the challenged leaf.
    if record_leaf_hash(&proof.record)? != requested_leaf {
        return Err(WbError::RootMismatch);
    }
    // Merkle inclusion of the leaf under the exact bound root (also enforces the structural rules).
    verify_inclusion(proof, requested_root)
}

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
    use crate::tz::withdraw::{
        tree_adapter::single_leaf_withdrawal_fixture, types::WithdrawRecord,
    };
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

    // --- Leaf-bound verification ---

    /// A valid Erc20 record; `amount` seeds the transaction hash + amount so distinct seeds give
    /// distinct leaves.
    fn valid_record(chain_id: u64, seed: u8) -> WithdrawRecord {
        WithdrawRecord {
            version: 1,
            chain_id,
            transaction_hash: B256::repeat_byte(seed),
            token_type: 0, // Erc20
            token_address: Address::repeat_byte(0xAA),
            token_ids: vec![alloy_primitives::U256::ZERO],
            amounts: vec![alloy_primitives::U256::from(seed as u64 + 1)],
            from: Address::repeat_byte(0x01),
            to: Address::repeat_byte(0x02),
        }
    }

    /// A valid count==1 proof whose leaf IS the record's tz-witness-recomputed hash.
    fn valid_bound_proof(record: &WithdrawRecord) -> (HistoricalInclusionProof, B256) {
        let leaf = record_leaf_hash(record).unwrap();
        let (siblings, root) = single_leaf_withdrawal_fixture(leaf);
        let proof = HistoricalInclusionProof {
            record: record.clone(),
            record_hash: leaf,
            leaf_hash: leaf,
            canonical_block_height: 10,
            withdrawal_root: root,
            leaf_index: 0,
            count: 1,
            siblings,
        };
        (proof, root)
    }

    #[test]
    fn leaf_bound_verify_accepts_matching_leaf() {
        let rec = valid_record(196, 0x42);
        let (proof, root) = valid_bound_proof(&rec);
        assert!(verify(&proof, proof.leaf_hash, root, 196).is_ok());
    }

    #[test]
    fn valid_proof_of_different_leaf_is_rejected() {
        // A genuinely valid Merkle proof for leaf B, requested for a different leaf A.
        let (proof_b, root_b) = valid_bound_proof(&valid_record(196, 0x0B));
        let leaf_a = record_leaf_hash(&valid_record(196, 0x0A)).unwrap();
        assert_ne!(leaf_a, proof_b.leaf_hash);
        assert!(
            verify(&proof_b, leaf_a, root_b, 196).is_err(),
            "leaf binding must reject proof of B"
        );
    }

    #[test]
    fn root_and_chainid_mismatch_rejected() {
        let rec = valid_record(196, 0x42);
        let (proof, root) = valid_bound_proof(&rec);
        // Wrong requested root.
        assert!(verify(&proof, proof.leaf_hash, B256::repeat_byte(0xFE), 196).is_err());
        // Wrong configured chain id (record.chain_id == 196 != 999).
        assert!(verify(&proof, proof.leaf_hash, root, 999).is_err());
    }

    #[test]
    fn malformed_record_fails_closed_on_recompute() {
        // Empty token arrays are not a valid canonical Erc20 record ⇒ record_leaf_hash fails
        // closed.
        let rec = WithdrawRecord {
            version: 1,
            chain_id: 196,
            transaction_hash: B256::ZERO,
            token_type: 0,
            token_address: Address::ZERO,
            token_ids: vec![],
            amounts: vec![],
            from: Address::ZERO,
            to: Address::ZERO,
        };
        assert!(matches!(record_leaf_hash(&rec), Err(WbError::WitnessStoreCorrupt)));
    }
}
