//! Internal enclave errors with mapping into the wire-level
//! [`xlayer_tee_types::ErrorKind`].

use thiserror::Error;
use xlayer_tee_types::{ErrorKind, TaskPhase};

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to deserialize witness body via rkyv: {0}")]
    DeserializeWitness(String),

    #[error("witness preimage_store is missing required BootInfo Local key")]
    MissingBootInfo,

    #[error("witness is malformed: {0}")]
    MalformedWitness(String),

    #[error("range bounds in journal request are invalid: starting={0}, ending={1}")]
    InvalidRangeBounds(u64, u64),

    #[error("attestation request is invalid: {0}")]
    InvalidAttestationRequest(&'static str),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("kona replay reported claim mismatch: computed {computed:?} != claim {claim:?}")]
    ClaimMismatch { computed: [u8; 32], claim: [u8; 32] },

    #[error("internal enclave error: {0}")]
    Internal(String),

    // -------------------- Async task model -------------------------------------
    /// `x-task-id` header is missing or not a UUID-shaped string.
    #[error("invalid task id: {0}")]
    InvalidTaskId(String),

    /// `task_id` not present in the manager.
    #[error("task {0} not found")]
    TaskUnknown(String),

    /// `max_inflight_tasks` is full; tell the proposer to back off.
    #[error("too many in-flight tasks ({inflight}/{cap}); back off")]
    TooManyTasks { inflight: usize, cap: usize },

    /// Task was DELETE'd while running (`oneshot::Sender` fired).
    #[error("task {task_id} was cancelled at phase {at_phase:?}")]
    Cancelled { task_id: String, at_phase: TaskPhase },

}

impl Error {
    /// Map an internal error to the public `xlayer_tee_types::ErrorKind`
    /// that gets serialized into the JSON error response body.
    pub fn to_wire_kind(&self) -> ErrorKind {
        match self {
            Self::DeserializeWitness(_) => ErrorKind::DeserializeRkyv,
            Self::MissingBootInfo | Self::MalformedWitness(_) | Self::InvalidRangeBounds(..) => {
                ErrorKind::InvalidWitness
            }
            Self::InvalidAttestationRequest(_) => ErrorKind::InternalEnclave,
            Self::Signing(_) => ErrorKind::InternalEnclave,
            Self::ClaimMismatch { .. } => ErrorKind::ClaimMismatch,
            Self::Internal(_) => ErrorKind::InternalEnclave,
            Self::InvalidTaskId(_) => ErrorKind::InvalidTaskId,
            Self::TaskUnknown(_) => ErrorKind::TaskUnknown,
            Self::TooManyTasks { .. } => ErrorKind::TooManyTasks,
            Self::Cancelled { .. } => ErrorKind::Cancelled,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
