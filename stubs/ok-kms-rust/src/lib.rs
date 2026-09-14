//! In-tree stub of the OKG-internal `ok-kms-rust` SDK.
//!
//! Mirrors exactly the public surface that `op-succinct-signer-utils`
//! (`utils/signer/src/kms.rs`) compiles against, so a workspace path
//! dependency substitutes for the real SDK without touching the committed
//! manifest. `KmsClient::new` succeeds so the existing `OnceLock` init path
//! stays exercised; every secret lookup fails at runtime with a plain error
//! directing the operator to `just kms-crate`. Bare-minimum: no grep marker.

use std::fmt;

#[derive(Debug)]
pub enum KmsError {
    /// Named by an `init_kms_client` match arm in utils/signer/src/kms.rs; kept for source compat.
    Disabled,
    /// Carries the plain stub failure message returned by `get_all_secrets`.
    Backend(String),
}

impl fmt::Display for KmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KmsError::Disabled => write!(f, "ok-kms-rust stub: KMS disabled"),
            KmsError::Backend(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for KmsError {}

pub struct KmsClient {}

impl KmsClient {
    /// Constructs successfully so the existing OnceLock init path stays exercised.
    pub fn new() -> Result<KmsClient, KmsError> {
        Ok(KmsClient {})
    }

    /// Bare-minimum stub: always fails at runtime with a plain error directing the
    /// operator to run `just kms-crate` for a real build. (No grep-able marker.)
    pub fn get_all_secrets(&self) -> Result<String, KmsError> {
        Err(KmsError::Backend(
            "ok-kms-rust stub in use — run `just kms-crate` to link the real SDK for a KMS build"
                .to_string(),
        ))
    }
}
