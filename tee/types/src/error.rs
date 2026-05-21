//! Error protocol between enclave and proposer.
//!
//! On failure the enclave returns:
//! - HTTP status code (400 for terminal, 500 for retryable) — see [`ErrorKind::status_code`]
//! - JSON body of type [`ErrorResponse`]
//!
//! Proposer dispatches on `error_kind` to decide retry vs abort.

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// Enumerates every well-known failure mode the enclave can report.
///
/// **Retryable (HTTP 500)** — transient errors; proposer should re-submit
/// the same task. Counted against `retry_max` budget.
///
/// **Terminal (HTTP 400)** — semantic errors that re-submitting will not fix.
/// Proposer aborts the current tick and surfaces a P1 alert.
///
/// Serialized as the PascalCase variant name, e.g. `{"error_kind": "ClaimMismatch"}`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub enum ErrorKind {
    // -------------------- Retryable (HTTP 500) --------------------
    /// kona-driver execution failed (panic, oracle error, etc.).
    KonaExec,
    /// rkyv deserialization of the request body failed (truncation,
    /// version mismatch, schema drift).
    DeserializeRkyv,
    /// Other unexpected enclave-internal error.
    InternalEnclave,
    /// Enclave-side deadline exceeded.
    Timeout,

    // -------------------- Terminal (HTTP 400) ---------------------
    /// Enclave-computed `output_root` does not match the claim embedded
    /// in the witness `BootInfo.claimed_l2_output_root`.
    ClaimMismatch,
    /// Witness preimage integrity check failed, or a required `Local`
    /// preimage key is missing (BootInfo / RollupConfig).
    InvalidWitness,
    /// (Aggregation only) At least one of the supplied range proof
    /// signatures fails ECDSA recovery against the enclave's pubkey.
    InvalidRangeSig,
    /// (Aggregation only) `range[i].prev_output_root != range[i-1].output_root`.
    ChainBreak,
    /// (Aggregation only) `config_hash` / `pcr0` / `l1_origin_*` differ
    /// across the supplied range proofs.
    Inconsistent,

    // -------------------- Async task model --------------------
    /// `max_inflight_tasks` cap is reached; proposer should back off and
    /// retry the same `task_id` later. Retryable. HTTP `429 Too Many Requests`.
    TooManyTasks,
    /// `task_id` not found in the manager — either never created or evicted by
    /// TTL GC. Retryable: proposer should re-`POST` with a fresh `task_id`.
    /// HTTP `404 Not Found`.
    TaskUnknown,
    /// Task was `DELETE`'d by the proposer before it could finish. Terminal:
    /// resubmission requires a new `task_id`. HTTP `409 Conflict`.
    Cancelled,
    /// The `x-task-id` header is missing or not a well-formed UUID. Terminal.
    /// HTTP `400 Bad Request`.
    InvalidTaskId,
    /// The `x-eip712-chain-id` or `x-eip712-verifying-contract` header is
    /// missing, malformed, or out of range. Terminal. HTTP `400 Bad Request`.
    /// Per-task EIP712 domain headers — see `paths::HEADER_CHAIN_ID` and
    /// `paths::HEADER_VERIFYING_CONTRACT`.
    InvalidEip712Header,
}

impl ErrorKind {
    /// HTTP status code that the enclave server returns for this error.
    pub const fn status_code(self) -> u16 {
        match self {
            Self::KonaExec
            | Self::DeserializeRkyv
            | Self::InternalEnclave
            | Self::Timeout => 500,
            Self::ClaimMismatch
            | Self::InvalidWitness
            | Self::InvalidRangeSig
            | Self::ChainBreak
            | Self::Inconsistent
            | Self::InvalidTaskId
            | Self::InvalidEip712Header => 400,
            Self::TooManyTasks => 429,
            Self::TaskUnknown => 404,
            Self::Cancelled => 409,
        }
    }

    /// `true` if the proposer should re-submit this task on encountering
    /// this error. `false` if the task should be considered terminally failed.
    pub const fn is_retryable(self) -> bool {
        match self {
            Self::KonaExec
            | Self::DeserializeRkyv
            | Self::InternalEnclave
            | Self::Timeout
            | Self::TooManyTasks
            | Self::TaskUnknown => true,
            Self::ClaimMismatch
            | Self::InvalidWitness
            | Self::InvalidRangeSig
            | Self::ChainBreak
            | Self::Inconsistent
            | Self::Cancelled
            | Self::InvalidTaskId
            | Self::InvalidEip712Header => false,
        }
    }
}

/// JSON body returned in HTTP 400 / 500 responses.
///
/// Wire shape:
/// ```json
/// {
///   "error_kind": "ClaimMismatch",
///   "message": "computed output_root 0x… != claim 0x…"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error_kind: ErrorKind,
    pub message: String,
}

impl ErrorResponse {
    pub fn new(error_kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { error_kind, message: message.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_partition_correctly() {
        assert_eq!(ErrorKind::KonaExec.status_code(), 500);
        assert_eq!(ErrorKind::ClaimMismatch.status_code(), 400);
        assert!(ErrorKind::Timeout.is_retryable());
        assert!(!ErrorKind::InvalidWitness.is_retryable());
    }

    #[test]
    fn error_response_serializes_pascal_case() {
        let resp = ErrorResponse::new(ErrorKind::ClaimMismatch, "bad");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ClaimMismatch\""));
        assert!(json.contains("\"bad\""));
    }
}
