//! `RangeJournal` — the EIP712 typed-data structure signed by the enclave for
//! each Range proof.
//!
//! Two flavors:
//! - `RangeJournal`: `sol!`-generated, used for **EIP712 hashing** and
//!   Solidity ABI compatibility (`alloy_sol_types::SolStruct`).
//! - `RangeJournalWire`: rkyv-friendly mirror, used as the journal portion
//!   of [`crate::response::RangeTaskResponse`] over the HTTP wire.
//!
//! ## Field selection
//!
//! Fields chosen to be 1:1 derivable from
//! [`kona_proof::BootInfo`] (with one enclave-supplied field `pcr0`):
//!
//! | journal field        | source                                       |
//! |----------------------|----------------------------------------------|
//! | `pcr0`               | enclave (Nitro NSM measurement)              |
//! | `config_hash`        | `hash_rollup_config(&boot.rollup_config)`    |
//! | `l1_origin_hash`     | `boot.l1_head`                               |
//! | `l2_block_number`    | `boot.claimed_l2_block_number`               |
//! | `prev_output_root`   | `boot.agreed_l2_output_root`                 |
//! | `output_root`        | computed by `kona_client::run` and compared against `boot.claimed_l2_output_root` |
//!
//! Aligns with `op-succinct/utils/client/src/boot.rs` `BootInfoStruct`.
//!
//! ## ⚠️ Field order is locked at v0.1
//!
//! EIP712 type hashes depend on field order. Reordering after the verifier
//! contract is deployed breaks all existing signatures.

use alloy_primitives::FixedBytes;
use alloy_sol_types::sol;
use rkyv::{Archive, Deserialize, Serialize};

sol! {
    /// Journal signed by the enclave for a single Range proof.
    ///
    /// Solidity type:
    /// ```solidity
    /// struct RangeJournal {
    ///     bytes32 pcr0;
    ///     bytes32 configHash;
    ///     bytes32 l1OriginHash;
    ///     uint64  l2BlockNumber;
    ///     bytes32 prevOutputRoot;
    ///     bytes32 outputRoot;
    /// }
    /// ```
    #[derive(Debug, PartialEq, Eq)]
    struct RangeJournal {
        bytes32 pcr0;
        bytes32 configHash;
        bytes32 l1OriginHash;
        uint64  l2BlockNumber;
        bytes32 prevOutputRoot;
        bytes32 outputRoot;
    }
}

/// rkyv-friendly mirror of [`RangeJournal`] for HTTP wire transmission.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct RangeJournalWire {
    pub pcr0: [u8; 32],
    pub config_hash: [u8; 32],
    pub l1_origin_hash: [u8; 32],
    pub l2_block_number: u64,
    pub prev_output_root: [u8; 32],
    pub output_root: [u8; 32],
}

impl From<&RangeJournal> for RangeJournalWire {
    fn from(j: &RangeJournal) -> Self {
        Self {
            pcr0: j.pcr0.0,
            config_hash: j.configHash.0,
            l1_origin_hash: j.l1OriginHash.0,
            l2_block_number: j.l2BlockNumber,
            prev_output_root: j.prevOutputRoot.0,
            output_root: j.outputRoot.0,
        }
    }
}

impl From<&RangeJournalWire> for RangeJournal {
    fn from(w: &RangeJournalWire) -> Self {
        Self {
            pcr0: FixedBytes(w.pcr0),
            configHash: FixedBytes(w.config_hash),
            l1OriginHash: FixedBytes(w.l1_origin_hash),
            l2BlockNumber: w.l2_block_number,
            prevOutputRoot: FixedBytes(w.prev_output_root),
            outputRoot: FixedBytes(w.output_root),
        }
    }
}
