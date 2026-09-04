//! Host-side shared library for the four-field TradeZone checkpoint claim and the
//! Withdraw/ForceTx inclusion-proof plumbing (spec §7.1).
//!
//! This module is shared by three binaries — `tz-proposer`, `tz-challenger`, and the new
//! `tz-defender` — and carries:
//! - [`types`]: protocol types (`CheckpointV2`, `TreeBoundaryWitness`, `WithdrawRecord`,
//!   `HistoricalInclusionProof`, `GameCheckpointPreimage`).
//! - [`claim`]: the 128-byte `claimRoot` codec + 164-byte Game `extraData` decode.
//! - [`error`]: the stable [`error::WbError`] enum + `is_retryable` classification.
//! - [`tree_adapter`]: the outer `count + tag` wrapper, empty-tree vectors, and inclusion-proof
//!   verification. The inner incremental-tree algorithm is owned by the TradeZone Claim Tree Core
//!   (tradezone `crates/chain/src/witness/`); see the module docs for the integration seam.
//! - [`wb_client`]: the Witness Builder v2 client (checkpointV2, boundary witness, canonical
//!   record, historical inclusion proof).
//!
//! All code here is host-side and gated behind the `tz` Cargo feature. Nothing in this module is
//! compiled into the SP1 zkVM guest (the guest reuses the Claim Tree Core directly).

pub mod claim;
pub mod error;
pub mod tree_adapter;
pub mod types;
pub mod wb_client;

pub use error::WbError;
pub use types::{
    CheckpointV2, GameCheckpointPreimage, HistoricalInclusionProof, TreeBoundaryWitness,
    WithdrawRecord,
};
