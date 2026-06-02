use xlayer_tee_types::ErrorKind;

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("empty witness body")]
    EmptyBody,
    #[error("witness body {actual} bytes > limit {limit}")]
    BodyTooLarge { actual: usize, limit: usize },
    #[error("task {0} not found")]
    TaskNotFound(String),
    #[error("enclave error ({kind:?}): {message}")]
    EnclaveError { kind: ErrorKind, message: String },
    #[error("enclave unreachable: {0}")]
    EnclaveUnreachable(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl HostError {
    pub fn code(&self) -> i32 {
        match self {
            Self::TaskNotFound(_) => 10004,
            Self::EmptyBody | Self::BodyTooLarge { .. } => 10001,
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
            Self::EnclaveUnreachable(_) | Self::Internal(_) => 20001,
        }
    }

    pub fn is_too_many_tasks(&self) -> bool {
        matches!(self, Self::EnclaveError { kind: ErrorKind::TooManyTasks, .. })
    }

    pub fn is_task_unknown(&self) -> bool {
        matches!(self, Self::EnclaveError { kind: ErrorKind::TaskUnknown, .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_mapping_covers_all_variants() {
        let cases: &[(HostError, i32)] = &[
            (HostError::EmptyBody, 10001),
            (HostError::BodyTooLarge { actual: 100, limit: 50 }, 10001),
            (HostError::TaskNotFound("x".into()), 10004),
            (
                HostError::EnclaveError { kind: ErrorKind::TaskUnknown, message: String::new() },
                10004,
            ),
            (
                HostError::EnclaveError { kind: ErrorKind::ClaimMismatch, message: String::new() },
                10001,
            ),
            (
                HostError::EnclaveError { kind: ErrorKind::InvalidWitness, message: String::new() },
                10001,
            ),
            (
                HostError::EnclaveError {
                    kind: ErrorKind::InvalidRangeSig,
                    message: String::new(),
                },
                10001,
            ),
            (
                HostError::EnclaveError { kind: ErrorKind::ChainBreak, message: String::new() },
                10001,
            ),
            (
                HostError::EnclaveError { kind: ErrorKind::Inconsistent, message: String::new() },
                10001,
            ),
            (
                HostError::EnclaveError {
                    kind: ErrorKind::DeserializeRkyv,
                    message: String::new(),
                },
                10001,
            ),
            (HostError::EnclaveError { kind: ErrorKind::Cancelled, message: String::new() }, 10001),
            (
                HostError::EnclaveError { kind: ErrorKind::InvalidTaskId, message: String::new() },
                10001,
            ),
            (HostError::EnclaveError { kind: ErrorKind::KonaExec, message: String::new() }, 20001),
            (
                HostError::EnclaveError {
                    kind: ErrorKind::InternalEnclave,
                    message: String::new(),
                },
                20001,
            ),
            (HostError::EnclaveError { kind: ErrorKind::Timeout, message: String::new() }, 20001),
            (
                HostError::EnclaveError { kind: ErrorKind::TooManyTasks, message: String::new() },
                20001,
            ),
            (HostError::EnclaveUnreachable(String::new()), 20001),
            (HostError::Internal(String::new()), 20001),
        ];
        for (error, expected_code) in cases {
            assert_eq!(
                error.code(),
                *expected_code,
                "{error:?} should map to code {expected_code}"
            );
        }
    }

    #[test]
    fn is_too_many_tasks_predicate() {
        assert!(HostError::EnclaveError { kind: ErrorKind::TooManyTasks, message: String::new() }
            .is_too_many_tasks());
        assert!(!HostError::EmptyBody.is_too_many_tasks());
    }

    #[test]
    fn is_task_unknown_predicate() {
        assert!(HostError::EnclaveError { kind: ErrorKind::TaskUnknown, message: String::new() }
            .is_task_unknown());
        assert!(!HostError::TaskNotFound("x".into()).is_task_unknown());
    }
}
