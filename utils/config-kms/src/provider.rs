//! Secret-backend access boundary.
//!
//! [`KmsSecretProvider`] is the single, mockable seam through which the resolver
//! obtains plaintext for a reference. [`OkKmsProvider`] is the real adapter over
//! `ok-kms-rust` v1.0.1; tests substitute an in-memory mock.

use crate::error::KmsConfigError;

/// Payload-free provider error. Intentionally carries no message so that no
/// underlying/backend text can flow into a diagnostic (redaction invariant).
#[derive(Debug)]
pub enum KmsProviderError {
    /// The requested key was not present in the backend.
    NotFound,
    /// Any other failure while fetching the secret (transport, backend, decode).
    Fetch,
}

/// The single access boundary used by the resolver to fetch a secret by key.
/// Mockable for tests; the production implementation is [`OkKmsProvider`].
pub trait KmsSecretProvider {
    fn get_secret_value(&self, key: &str) -> Result<String, KmsProviderError>;
}

/// Production provider backed by `ok-kms-rust` v1.0.1.
pub struct OkKmsProvider {
    client: ok_kms_rust::KmsClient,
}

impl KmsSecretProvider for OkKmsProvider {
    fn get_secret_value(&self, key: &str) -> Result<String, KmsProviderError> {
        // Map every backend error to a payload-free class: the raw backend error
        // text must never reach a diagnostic.
        self.client
            .get_secret_value(key)
            .map_err(|_| KmsProviderError::Fetch)
    }
}

/// A protected-set env var is considered "present" only if it holds a
/// non-whitespace value.
fn present(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// On-demand backend initialization. Validates the runtime preconditions and
/// constructs the real provider. Returns a redacted [`KmsConfigError::KmsInitError`]
/// on any problem — no value, key, or backend text is included.
///
/// Preconditions (mirrors the backend's own contract, checked up-front so a
/// misconfiguration yields a deterministic, redacted class before any FFI call):
/// `KMS_ENABLED` must equal exactly `"true"`; `KMS_PROVIDER` is required; and
/// `KMS_SECRET_NAME` is required, with `KMS_REGION` additionally required for the
/// AWS provider. The backend additionally validates the dynamic library, region,
/// secret name, and cloud access during construction.
pub fn init_provider() -> Result<OkKmsProvider, KmsConfigError> {
    if std::env::var("KMS_ENABLED").as_deref() != Ok("true") {
        return Err(KmsConfigError::KmsInitError);
    }
    let provider = std::env::var("KMS_PROVIDER").unwrap_or_default();
    let provider = provider.trim().to_lowercase();
    if provider.is_empty() {
        return Err(KmsConfigError::KmsInitError);
    }
    if !present("KMS_SECRET_NAME") {
        return Err(KmsConfigError::KmsInitError);
    }
    if provider == "aws" && !present("KMS_REGION") {
        return Err(KmsConfigError::KmsInitError);
    }
    let client = ok_kms_rust::KmsClient::new().map_err(|_| KmsConfigError::KmsInitError)?;
    Ok(OkKmsProvider { client })
}
