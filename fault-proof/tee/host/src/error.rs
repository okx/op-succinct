use std::fmt;

use xlayer_tee_types::ErrorKind;

#[derive(Debug)]
pub enum HostError {
    EmptyBody,
    BodyTooLarge { actual: usize, limit: usize },
    TaskNotFound(String),
    EnclaveError { kind: ErrorKind, message: String },
    EnclaveUnreachable(String),
    ConfigError(String),
    Internal(String),
}

impl HostError {
    pub fn code(&self) -> i32 {
        match self {
            Self::EmptyBody | Self::BodyTooLarge { .. } => 10001,
            Self::TaskNotFound(_) => 10004,
            Self::EnclaveError { kind, .. } => match kind {
                ErrorKind::TaskUnknown => 10004,
                ErrorKind::ClaimMismatch |
                ErrorKind::InvalidWitness |
                ErrorKind::InvalidRangeSig |
                ErrorKind::ChainBreak |
                ErrorKind::Inconsistent |
                ErrorKind::DeserializeRkyv |
                ErrorKind::Cancelled |
                ErrorKind::InvalidTaskId => 10001,
                ErrorKind::KonaExec |
                ErrorKind::InternalEnclave |
                ErrorKind::Timeout |
                ErrorKind::TooManyTasks => 20001,
            },
            Self::EnclaveUnreachable(_) => 20001,
            Self::ConfigError(_) => 10001,
            Self::Internal(_) => 20001,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::EmptyBody => "empty witness body".to_string(),
            Self::BodyTooLarge { actual, limit } => {
                format!("witness body {actual} bytes > limit {limit}")
            }
            Self::TaskNotFound(id) => format!("task not found: {id}"),
            Self::EnclaveError { message, .. } => message.clone(),
            Self::EnclaveUnreachable(msg) => msg.clone(),
            Self::ConfigError(msg) => msg.clone(),
            Self::Internal(msg) => msg.clone(),
        }
    }

    pub fn is_too_many_tasks(&self) -> bool {
        matches!(self, Self::EnclaveError { kind: ErrorKind::TooManyTasks, .. })
    }

    pub fn is_task_unknown(&self) -> bool {
        matches!(self, Self::EnclaveError { kind: ErrorKind::TaskUnknown, .. })
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code(), self.message())
    }
}

impl std::error::Error for HostError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_maps_correctly_for_all_variants() {
        let cases: Vec<(HostError, i32)> = vec![
            (HostError::EmptyBody, 10001),
            (HostError::BodyTooLarge { actual: 300, limit: 256 }, 10001),
            (HostError::TaskNotFound("abc".into()), 10004),
            (HostError::EnclaveUnreachable("down".into()), 20001),
            (HostError::ConfigError("bad".into()), 10001),
            (HostError::Internal("oops".into()), 20001),
        ];
        for (err, expected_code) in cases {
            assert_eq!(err.code(), expected_code, "{err:?} should map to {expected_code}");
        }
    }

    #[test]
    fn code_maps_correctly_for_all_error_kind_variants() {
        let cases: &[(ErrorKind, i32)] = &[
            (ErrorKind::TaskUnknown, 10004),
            (ErrorKind::ClaimMismatch, 10001),
            (ErrorKind::InvalidWitness, 10001),
            (ErrorKind::InvalidRangeSig, 10001),
            (ErrorKind::ChainBreak, 10001),
            (ErrorKind::Inconsistent, 10001),
            (ErrorKind::DeserializeRkyv, 10001),
            (ErrorKind::Cancelled, 10001),
            (ErrorKind::InvalidTaskId, 10001),
            (ErrorKind::KonaExec, 20001),
            (ErrorKind::InternalEnclave, 20001),
            (ErrorKind::Timeout, 20001),
            (ErrorKind::TooManyTasks, 20001),
        ];
        for &(kind, expected_code) in cases {
            let err = HostError::EnclaveError { kind, message: "test".into() };
            assert_eq!(err.code(), expected_code, "{kind:?} should map to {expected_code}");
        }
    }

    #[test]
    fn message_formats_correctly() {
        assert_eq!(HostError::EmptyBody.message(), "empty witness body");
        assert_eq!(
            HostError::BodyTooLarge { actual: 300000000, limit: 268435456 }.message(),
            "witness body 300000000 bytes > limit 268435456"
        );
        assert!(HostError::TaskNotFound("abc".into()).message().contains("abc"));
    }

    #[test]
    fn is_too_many_tasks_classification() {
        assert!(HostError::EnclaveError { kind: ErrorKind::TooManyTasks, message: "full".into() }
            .is_too_many_tasks());
        assert!(!HostError::EnclaveError { kind: ErrorKind::Timeout, message: "slow".into() }
            .is_too_many_tasks());
        assert!(!HostError::Internal("x".into()).is_too_many_tasks());
    }

    #[test]
    fn is_task_unknown_classification() {
        assert!(HostError::EnclaveError { kind: ErrorKind::TaskUnknown, message: "gone".into() }
            .is_task_unknown());
        assert!(!HostError::EnclaveError { kind: ErrorKind::KonaExec, message: "fail".into() }
            .is_task_unknown());
    }

    #[test]
    fn display_includes_code_and_message() {
        let err = HostError::EmptyBody;
        let display = format!("{err}");
        assert!(display.contains("10001"));
        assert!(display.contains("empty witness body"));
    }
}
