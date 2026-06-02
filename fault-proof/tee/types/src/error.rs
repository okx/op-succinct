use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

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
    KonaExec,
    InternalEnclave,
    Timeout,
    DeserializeRkyv,
    ClaimMismatch,
    InvalidWitness,
    InvalidRangeSig,
    ChainBreak,
    Inconsistent,
    InvalidTaskId,
    TooManyTasks,
    TaskUnknown,
    Cancelled,
}

impl ErrorKind {
    pub fn status_code(self) -> u16 {
        match self {
            Self::KonaExec | Self::InternalEnclave | Self::Timeout => 500,
            Self::DeserializeRkyv |
            Self::ClaimMismatch |
            Self::InvalidWitness |
            Self::InvalidRangeSig |
            Self::ChainBreak |
            Self::Inconsistent |
            Self::InvalidTaskId => 400,
            Self::TooManyTasks => 429,
            Self::TaskUnknown => 404,
            Self::Cancelled => 409,
        }
    }

    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::KonaExec |
                Self::InternalEnclave |
                Self::Timeout |
                Self::TooManyTasks |
                Self::TaskUnknown
        )
    }
}

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
    fn status_code_classification() {
        let cases: &[(ErrorKind, u16)] = &[
            (ErrorKind::KonaExec, 500),
            (ErrorKind::InternalEnclave, 500),
            (ErrorKind::Timeout, 500),
            (ErrorKind::DeserializeRkyv, 400),
            (ErrorKind::ClaimMismatch, 400),
            (ErrorKind::InvalidWitness, 400),
            (ErrorKind::InvalidRangeSig, 400),
            (ErrorKind::ChainBreak, 400),
            (ErrorKind::Inconsistent, 400),
            (ErrorKind::InvalidTaskId, 400),
            (ErrorKind::TooManyTasks, 429),
            (ErrorKind::TaskUnknown, 404),
            (ErrorKind::Cancelled, 409),
        ];
        for &(kind, expected) in cases {
            assert_eq!(kind.status_code(), expected, "{kind:?} should return {expected}");
        }
    }

    #[test]
    fn is_retryable_classification() {
        let retryable = [
            ErrorKind::KonaExec,
            ErrorKind::InternalEnclave,
            ErrorKind::Timeout,
            ErrorKind::TooManyTasks,
            ErrorKind::TaskUnknown,
        ];
        let non_retryable = [
            ErrorKind::DeserializeRkyv,
            ErrorKind::ClaimMismatch,
            ErrorKind::InvalidWitness,
            ErrorKind::InvalidRangeSig,
            ErrorKind::ChainBreak,
            ErrorKind::Inconsistent,
            ErrorKind::InvalidTaskId,
            ErrorKind::Cancelled,
        ];
        for kind in retryable {
            assert!(kind.is_retryable(), "{kind:?} should be retryable");
        }
        for kind in non_retryable {
            assert!(!kind.is_retryable(), "{kind:?} should NOT be retryable");
        }
    }

    #[test]
    fn error_response_json_pascal_case() {
        let resp =
            ErrorResponse::new(ErrorKind::ClaimMismatch, "pcr0 does not match expected value");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"error_kind\":\"ClaimMismatch\""),
            "JSON should use PascalCase variant: {json}"
        );
        assert!(
            json.contains("\"message\":\"pcr0 does not match expected value\""),
            "JSON should contain message: {json}"
        );
    }

    #[test]
    fn error_response_new_constructor() {
        let resp = ErrorResponse::new(ErrorKind::Timeout, "enclave response timed out");
        assert_eq!(resp.error_kind, ErrorKind::Timeout);
        assert_eq!(resp.message, "enclave response timed out");
    }
}
