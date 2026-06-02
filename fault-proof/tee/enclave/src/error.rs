use xlayer_tee_types::ErrorKind;

/// Sentinel string used to detect claim mismatch errors from upstream kona executor.
/// Coupling point: this must match the error message in
/// `utils/client/src/witness/executor.rs:163`.
pub const CLAIM_MISMATCH_SENTINEL: &str = "Failed to validate L2 block";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to deserialize witness: {0}")]
    DeserializeWitness(String),

    #[error("malformed witness data: {0}")]
    MalformedWitness(String),

    #[error("missing boot info")]
    MissingBootInfo,

    #[error("invalid range bounds: claimed_l2_block_number must be > 0")]
    InvalidRangeBounds,

    #[error("claim mismatch: claim={}", hex::encode(.claim))]
    ClaimMismatch { claim: [u8; 32] },

    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("invalid attestation request: {0}")]
    InvalidAttestationRequest(String),

    #[error("too many tasks")]
    TooManyTasks,

    #[error("task not found: {0}")]
    TaskUnknown(String),

    #[error("invalid task id: {0}")]
    InvalidTaskId(String),
}

impl Error {
    pub fn to_wire_kind(&self) -> ErrorKind {
        match self {
            Self::DeserializeWitness(_) => ErrorKind::DeserializeRkyv,
            Self::MalformedWitness(_) | Self::MissingBootInfo | Self::InvalidRangeBounds => {
                ErrorKind::InvalidWitness
            }
            Self::ClaimMismatch { .. } => ErrorKind::ClaimMismatch,
            Self::Internal(_) | Self::InvalidAttestationRequest(_) => ErrorKind::InternalEnclave,
            Self::TooManyTasks => ErrorKind::TooManyTasks,
            Self::TaskUnknown(_) => ErrorKind::TaskUnknown,
            Self::InvalidTaskId(_) => ErrorKind::InvalidTaskId,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_wire_kind_mapping() {
        let cases: &[(&dyn Fn() -> Error, ErrorKind)] = &[
            (&|| Error::DeserializeWitness("bad bytes".into()), ErrorKind::DeserializeRkyv),
            (&|| Error::MalformedWitness("missing field".into()), ErrorKind::InvalidWitness),
            (&|| Error::MissingBootInfo, ErrorKind::InvalidWitness),
            (&|| Error::InvalidRangeBounds, ErrorKind::InvalidWitness),
            (&|| Error::ClaimMismatch { claim: [0xAA; 32] }, ErrorKind::ClaimMismatch),
            (&|| Error::Internal(anyhow::anyhow!("something failed")), ErrorKind::InternalEnclave),
            (&|| Error::InvalidAttestationRequest("bad nonce".into()), ErrorKind::InternalEnclave),
            (&|| Error::TooManyTasks, ErrorKind::TooManyTasks),
            (&|| Error::TaskUnknown("abc".into()), ErrorKind::TaskUnknown),
            (&|| Error::InvalidTaskId("not-uuid".into()), ErrorKind::InvalidTaskId),
        ];

        for (make_err, expected_kind) in cases {
            let err = make_err();
            assert_eq!(
                err.to_wire_kind(),
                *expected_kind,
                "Error `{err}` should map to {expected_kind:?}"
            );
        }
    }

    #[test]
    fn claim_mismatch_sentinel_matches_upstream() {
        let upstream_msg =
            "Failed to validate L2 block #42 with claimed output root 0xabc. Got 0xdef instead";
        assert!(
            upstream_msg.contains(CLAIM_MISMATCH_SENTINEL),
            "Sentinel must match upstream executor error format"
        );
    }
}
