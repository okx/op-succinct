//! Shared interface types between enclave, host, proposer, and on-chain verifier.
//!
//! Three consumers depend on this crate at the same git commit:
//! - Enclave: signs `RangeJournal` with `secp256k1` over `keccak256(packed)`.
//! - Host / proposer: encodes `RangeJournal + signature` into the `prove(bytes)`
//!   payload via `abi_encode_params`.
//! - On-chain verifier: ABI-decodes `proofBytes` back into `(RangeJournal, bytes)`
//!   and reconstructs the packed-bytes digest to recover the signer.
//!
//! Any breaking change requires synchronized updates on all sides.
//!
//! ## Stability
//!
//! Field order and types in `RangeJournal` are part of the wire contract —
//! the packed-bytes signing layout depends on them, so a silent reorder
//! invalidates every existing signature.

pub mod wire;
pub mod journal;
pub mod error;
pub mod task;

pub use error::{ErrorKind, ErrorResponse};
pub use journal::{RangeJournal, RangeJournalWire, RangeTaskResponse};
pub use task::{
    CreateTaskResponse, DeleteTaskResponse, TaskId, TaskListResponse, TaskPhase, TaskStateView,
    TaskStatusView, TaskSummary,
};
