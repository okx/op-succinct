//! Offline KMS stub supporting both signer and startup configuration consumers.
//! Every secret lookup fails; the marker prevents shipping the stub in production.

#[used]
static OK_KMS_STUB_MARKER: [u8; 11] = *b"OK_KMS_STUB";

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
    /// Always fails: the offline stub cannot provide secrets.
    pub fn get_secret_value(&self, _key: &str) -> Result<String, KmsError> {
        Err(KmsError::Backend("OK_KMS_STUB: offline stub cannot resolve secrets".to_string()))
    }

    /// Constructs successfully so the existing OnceLock init path stays exercised.
    pub fn new() -> Result<KmsClient, KmsError> {
        Ok(KmsClient {})
    }

    /// Always fails: the offline stub cannot provide secrets.
    pub fn get_all_secrets(&self) -> Result<String, KmsError> {
        Err(KmsError::Backend(
            "OK_KMS_STUB: ok-kms-rust stub in use — run `just kms-crate` to link the real SDK for a KMS build"
                .to_string(),
        ))
    }
}
