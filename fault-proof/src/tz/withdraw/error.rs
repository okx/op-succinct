//! Stable Witness Builder error taxonomy (spec §7.1, §7.3).
//!
//! Callers (L1 Challenger, Defender) branch on [`WbError::is_retryable`]: `NotReady` and
//! transient transport/5xx failures are retried with backoff; every other variant is a
//! permanent condition that must alert rather than silently retry forever — and, crucially,
//! a permanent error must never cause a silent miss (spec §7.3, §9 item 7).

use thiserror::Error;

/// A classified Witness Builder v2 client error.
#[derive(Clone, Debug, Error)]
pub enum WbError {
    /// The request itself was malformed (4xx that is not one of the specific cases below).
    #[error("witness-builder rejected the request as invalid")]
    InvalidRequest,
    /// The response advertised a schema version this client does not support.
    #[error("witness-builder response uses an unsupported schema version")]
    UnsupportedVersion,
    /// No checkpoint exists at the requested height.
    #[error("witness-builder has no checkpoint at the requested height")]
    CheckpointNotFound,
    /// The requested withdrawal record is unknown to the witness builder.
    #[error("witness-builder has no record for the requested withdrawal")]
    WithdrawalNotFound,
    /// The record exists but is not included in the requested checkpoint.
    #[error("record is not included in the requested checkpoint")]
    RecordNotInCheckpoint,
    /// The data is not yet available but is expected to become available (retryable).
    #[error("witness-builder data is not ready yet")]
    NotReady,
    /// A returned root/proof did not match the locally recomputed value (permanent, alert).
    #[error("witness-builder root/proof did not match the locally recomputed value")]
    RootMismatch,
    /// The boundary/witness wire was internally inconsistent (e.g. `len != popcount(count)` or
    /// a declared root that does not rebuild) — permanent, alert (spec §4).
    #[error("witness-builder boundary/witness store is corrupt or inconsistent")]
    WitnessStoreCorrupt,
    /// A transport-level failure. `retryable` distinguishes transient (timeout / 5xx / connect)
    /// from permanent transport problems.
    #[error("witness-builder transport error ({}): {message}", if *.retryable { "retryable" } else { "permanent" })]
    Transport { message: String, retryable: bool },
}

impl WbError {
    /// A transient transport error (timeout, connection reset, HTTP 5xx).
    pub fn transient_transport(message: impl Into<String>) -> Self {
        WbError::Transport { message: message.into(), retryable: true }
    }

    /// A permanent transport error (malformed URL, unexpected non-retryable protocol failure).
    pub fn permanent_transport(message: impl Into<String>) -> Self {
        WbError::Transport { message: message.into(), retryable: false }
    }

    /// Whether the caller should retry with backoff (`NotReady` and transient transport) rather
    /// than treat the condition as permanent.
    pub fn is_retryable(&self) -> bool {
        match self {
            WbError::NotReady => true,
            WbError::Transport { retryable, .. } => *retryable,
            WbError::InvalidRequest
            | WbError::UnsupportedVersion
            | WbError::CheckpointNotFound
            | WbError::WithdrawalNotFound
            | WbError::RecordNotInCheckpoint
            | WbError::RootMismatch
            | WbError::WitnessStoreCorrupt => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification() {
        assert!(WbError::NotReady.is_retryable());
        assert!(WbError::transient_transport("502 bad gateway").is_retryable());
        assert!(!WbError::permanent_transport("invalid url").is_retryable());
        assert!(!WbError::RootMismatch.is_retryable());
        assert!(!WbError::WithdrawalNotFound.is_retryable());
        assert!(!WbError::WitnessStoreCorrupt.is_retryable());
        assert!(!WbError::CheckpointNotFound.is_retryable());
        assert!(!WbError::RecordNotInCheckpoint.is_retryable());
        assert!(!WbError::InvalidRequest.is_retryable());
        assert!(!WbError::UnsupportedVersion.is_retryable());
    }

    #[test]
    fn transport_message_is_preserved() {
        let e = WbError::transient_transport("connect timeout");
        assert!(e.to_string().contains("connect timeout"));
        assert!(e.to_string().contains("retryable"));
    }
}
