//! Protocol types for the four-field TradeZone checkpoint claim, mirroring the Witness
//! Builder v2 / Protocol wire structures field-for-field (spec §7.1).
//!
//! These are host-side domain types. Wire (de)serialization DTOs live in [`super::wb_client`]
//! so that the JSON shape can evolve without changing the domain types the proposer /
//! challenger / defender reason about — the same split the existing `game_validator`
//! `RootResponse`/`RootComponents` uses.

use alloy_primitives::{Address, B256, U256};

/// Four-field checkpoint returned by the Witness Builder v2 `root` endpoint.
///
/// Mirrors `tz_witness::checkpoint::CheckpointV2` field-for-field (7 fields, **no `chain_id`**;
/// R2 #3). `chain_id` and `block_height` are NOT part of `claim_root` (spec §4). The chainId that
/// the WB advertises for cross-chain guarding lives ONLY at the flat top level of the checkpoint
/// RPC response and is carried host-side in [`CheckpointV2Envelope`], never inside this struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointV2 {
    pub schema_version: u16,
    pub block_height: u64,
    pub block_hash: B256,
    pub app_hash: B256,
    pub withdrawal_root: B256,
    pub force_root: B256,
    pub claim_root: B256,
}

/// Host-side envelope pairing a [`CheckpointV2`] with the top-level `chainId` from the flat
/// `SnapshotQueryResponse` (R2 #3: chainId is a bare top-level `u64`, populated only for v2, used
/// for host/challenger "correct TZ chain" cross-checks — NOT part of the checkpoint body or
/// `claim_root`). Assembled by [`super::wb_client`] from the flat response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointV2Envelope {
    pub checkpoint: CheckpointV2,
    pub chain_id: u64,
}

/// The incremental-tree boundary at a canonical height: for each of the two trees, the leaf
/// `count` and the active frontier branches.
///
/// Wire invariant (spec §4): `count == 0 ⇒ active_branches == []`; otherwise
/// `active_branches.len() == count.count_ones()` (popcount), ordered low→high level, bare
/// `bytes32` with no level field and no zero padding. The decoder validates this and rebuilds
/// the declared root (see [`super::wb_client`]).
///
/// R2 #2: `TreeBoundaryResponse` carries **no `chainId`** — chainId consistency is enforced only
/// on the checkpoint top level (see [`CheckpointV2Envelope`]). This struct therefore has no
/// `chain_id` field.
///
/// R4 (MR102-R3-3): the upstream `TreeBoundaryResponse` **does** carry `block_hash` (the canonical
/// block hash at the same height H), positioned between `block_height` and `withdrawal_count`; the
/// R2 mirror dropped it, which made the boundary↔snapshot same-height blockHash consistency check
/// impossible. It is restored here in the same position so the mirror is field-for-field complete
/// and the Host/guest cross-checks have a field to bind to (spec §R4.2-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeBoundaryWitness {
    pub schema_version: u16,
    pub block_height: u64,
    pub block_hash: B256,
    pub withdrawal_count: u32,
    pub withdrawal_active_branches: Vec<B256>,
    pub force_count: u32,
    pub force_active_branches: Vec<B256>,
}

/// A V1 Withdraw record. `leaf_hash == record_hash` for V1 (spec §4). The leaf hash is
/// `keccak256(abi.encode(version, chain_id, transaction_hash, token_type, token_address,
/// token_ids, amounts, from, to))` — Solidity `abi.encode` semantics, computed by the Witness
/// Builder / Claim Tree Core, not re-implemented here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawRecord {
    pub version: u16,
    pub chain_id: u64,
    pub transaction_hash: B256,
    pub token_type: u8,
    pub token_address: Address,
    pub token_ids: Vec<U256>,
    pub amounts: Vec<U256>,
    pub from: Address,
    pub to: Address,
}

/// A historical Withdraw inclusion proof, bound to an exact `(checkpoint_height,
/// withdrawal_root)` pair. Verified locally before the Defender submits `proveChallenge`
/// (spec §7.4): the verifier enforces `count > 0`, `leaf_index < count`, `siblings.len() == 32`,
/// rebuilds the inner root, and checks the outer `count + tag` wrapper equals `withdrawal_root`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalInclusionProof {
    pub record: WithdrawRecord,
    pub record_hash: B256,
    pub leaf_hash: B256,
    pub canonical_block_height: u64,
    pub checkpoint_height: u64,
    pub withdrawal_root: B256,
    pub leaf_index: u32,
    pub count: u32,
    pub siblings: [B256; 32],
}

/// The four-preimage decoded from an `OPSuccinctFaultDisputeGame` `extraData()` blob
/// (164-byte four-preimage mode). See [`super::claim::decode_four_preimage_extra_data`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameCheckpointPreimage {
    pub checkpoint_block_height: u64,
    pub parent_index: u32,
    pub block_hash: B256,
    pub app_hash: B256,
    pub withdrawal_root: B256,
    pub force_root: B256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn boundary_witness_roundtrips_via_clone_eq() {
        let w = TreeBoundaryWitness {
            schema_version: 2,
            block_height: 36_000,
            block_hash: B256::repeat_byte(0xbb),
            withdrawal_count: 5,
            withdrawal_active_branches: vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
            force_count: 0,
            force_active_branches: vec![],
        };
        assert_eq!(w.clone(), w);
        // count == 0 ⇒ empty branches (spec §4 wire invariant, asserted structurally here).
        assert!(w.force_active_branches.is_empty());
    }

    #[test]
    fn checkpoint_and_preimage_are_value_types() {
        let cp = CheckpointV2 {
            schema_version: 2,
            block_height: 100,
            block_hash: B256::repeat_byte(0x11),
            app_hash: B256::repeat_byte(0x22),
            withdrawal_root: B256::repeat_byte(0x33),
            force_root: B256::repeat_byte(0x44),
            claim_root: B256::repeat_byte(0x55),
        };
        assert_eq!(cp.clone(), cp);
        // chainId lives only in the host envelope, never in the checkpoint body (R2 #3).
        let env = CheckpointV2Envelope { checkpoint: cp.clone(), chain_id: 196 };
        assert_eq!(env.chain_id, 196);
        assert_eq!(env.checkpoint, cp);

        let pre = GameCheckpointPreimage {
            checkpoint_block_height: 100,
            parent_index: u32::MAX,
            block_hash: cp.block_hash,
            app_hash: cp.app_hash,
            withdrawal_root: cp.withdrawal_root,
            force_root: cp.force_root,
        };
        assert_eq!(pre.clone(), pre);
        assert_eq!(pre.checkpoint_block_height, cp.block_height);
    }
}
