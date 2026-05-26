//! Host error type and proposer-facing numeric error codes.

use thiserror::Error;
use xlayer_tee_types::ErrorKind;

pub const CODE_OK: i32 = 0;
pub const CODE_INVALID_ARGUMENT: i32 = 10001;
pub const CODE_RESOURCE_NOT_FOUND: i32 = 10004;
pub const CODE_INTERNAL_ERROR: i32 = 20001;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("enclave {kind:?}: {message}")]
    Enclave { kind: ErrorKind, message: String },
}

impl Error {
    pub fn code(&self) -> i32 {
        match self {
            Self::InvalidArgument(_) => CODE_INVALID_ARGUMENT,
            Self::NotFound(_) => CODE_RESOURCE_NOT_FOUND,
            Self::Internal(_) => CODE_INTERNAL_ERROR,
            Self::Enclave { kind, .. } => map_enclave_kind(*kind),
        }
    }
}

/// Collapse the enclave's 14-variant `ErrorKind` into the 3 numeric codes
/// the proposer expects:
///
/// | bucket             | code  | ErrorKind                                        |
/// |--------------------|-------|--------------------------------------------------|
/// | `INVALID_ARGUMENT` | 10001 | bad client input (witness / claim / range / hdr) |
/// | `RESOURCE_NOT_FOUND` | 10004 | `TaskUnknown` only                             |
/// | `INTERNAL_ERROR`   | 20001 | server-side transient (kona panic, timeout, OOM) |
///
/// `DeserializeRkyv` belongs to `INVALID_ARGUMENT`: a body that fails rkyv
/// decode is bad client input — retrying the same bytes never helps.
/// `TooManyTasks` is `INTERNAL_ERROR` because the proposer should back off
/// and retry the same `task_id` later (server-side capacity issue).
fn map_enclave_kind(kind: ErrorKind) -> i32 {
    match kind {
        ErrorKind::TaskUnknown => CODE_RESOURCE_NOT_FOUND,
        ErrorKind::ClaimMismatch
        | ErrorKind::InvalidWitness
        | ErrorKind::InvalidRangeSig
        | ErrorKind::ChainBreak
        | ErrorKind::Inconsistent
        | ErrorKind::DeserializeRkyv
        | ErrorKind::Cancelled
        | ErrorKind::InvalidTaskId
        | ErrorKind::InvalidChainIdHeader => CODE_INVALID_ARGUMENT,
        ErrorKind::KonaExec
        | ErrorKind::InternalEnclave
        | ErrorKind::Timeout
        | ErrorKind::TooManyTasks => CODE_INTERNAL_ERROR,
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_argument_maps_to_10001() {
        assert_eq!(Error::InvalidArgument("x".into()).code(), CODE_INVALID_ARGUMENT);
    }

    #[test]
    fn not_found_maps_to_10004() {
        assert_eq!(Error::NotFound("x".into()).code(), CODE_RESOURCE_NOT_FOUND);
    }

    #[test]
    fn internal_maps_to_20001() {
        assert_eq!(Error::Internal("x".into()).code(), CODE_INTERNAL_ERROR);
    }

    #[test]
    fn enclave_terminal_kinds_map_to_10001() {
        for kind in [
            ErrorKind::ClaimMismatch,
            ErrorKind::InvalidWitness,
            ErrorKind::InvalidRangeSig,
            ErrorKind::ChainBreak,
            ErrorKind::Inconsistent,
            ErrorKind::DeserializeRkyv,
            ErrorKind::InvalidChainIdHeader,
        ] {
            let e = Error::Enclave { kind, message: "x".into() };
            assert_eq!(e.code(), CODE_INVALID_ARGUMENT, "kind {kind:?}");
        }
    }

    #[test]
    fn enclave_retryable_kinds_map_to_20001() {
        for kind in [ErrorKind::KonaExec, ErrorKind::InternalEnclave, ErrorKind::Timeout] {
            let e = Error::Enclave { kind, message: "x".into() };
            assert_eq!(e.code(), CODE_INTERNAL_ERROR, "kind {kind:?}");
        }
    }
}
