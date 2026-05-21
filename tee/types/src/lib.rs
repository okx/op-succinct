//! Shared interface types between `xlayer-tee-prover` (enclave) and the proposer.
//!
//! This crate is the **interface contract** between three teams:
//! - Enclave team: implements the `xlayer-tee-prover` ELF (HTTP server inside Nitro Enclave)
//! - Host/proposer team: implements the proposer (forked op-succinct validity)
//! - Contract team: implements `KonaTeeVerifier.sol` on L1
//!
//! All three depend on this crate at the same git commit. Any breaking change here
//! requires synchronized updates across all three sides.
//!
//! ## Stability
//!
//! Once tagged v0.1 and aligned, **do not change field orders, names, or types**
//! without explicit cross-team review. EIP712 type hashes are computed from field
//! orderings; a silent reorder breaks signature compatibility on-chain.

pub mod paths;
pub mod limits;
pub mod content_type;
pub mod eip712;
pub mod journal;
pub mod response;
pub mod error;
pub mod task;

pub use error::{ErrorKind, ErrorResponse};
pub use journal::{RangeJournal, RangeJournalWire};
pub use response::RangeTaskResponse;
pub use task::{
    CreateTaskResponse, DeleteTaskResponse, TaskId, TaskListResponse, TaskPhase, TaskStateView,
    TaskStatusView, TaskSummary,
};
