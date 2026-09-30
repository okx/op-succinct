//! Real `ok-kms-rust`-backed provider and the process-wide KMS client singleton.
//!
//! This whole module is compiled only under `#[cfg(feature = "kms")]` — the gate
//! lives on its `mod real;` declaration in the parent, so no per-item `#[cfg]` is
//! needed here. The boundary types ([`KmsProviderError`], [`KmsSecretProvider`])
//! live in the always-compiled parent module. Every SDK error is mapped to a
//! payload-free class at the boundary so no backend text can be cached or surfaced
//! (redaction invariant).

use super::{KmsProviderError, KmsSecretProvider};
use crate::error::KmsConfigError;
use std::sync::OnceLock;

/// Payload-free marker that backend initialization failed. Carries no message so
/// that no backend/SDK error text can ever be cached or surfaced (redaction
/// invariant). It is what the process-wide cache stores on the failure path.
#[derive(Clone, Copy)]
pub(crate) struct KmsInitFailed;

/// Process-wide, initialized-at-most-once cache of the real backend client.
///
/// The client is constructed lazily on first need and then **never dropped** for
/// the life of the process; an initialization failure is cached as the
/// payload-free [`KmsInitFailed`] so every later access fails closed without
/// re-invoking the backend. `KmsClient` is already `Send + Sync`, so the
/// `OnceLock` is stored directly with no newtype and no `unsafe impl`.
static KMS_CLIENT: OnceLock<Result<ok_kms_rust::KmsClient, KmsInitFailed>> = OnceLock::new();

/// Generic init-once seam: initialize `cell` at most once via `ctor`, cache the
/// outcome for the process lifetime, and map a cached failure to the redacted
/// [`KmsConfigError::KmsInitError`]. Generic over the stored value so the singleton
/// can be exercised in tests without the SDK (e.g. `T = u32`).
pub(crate) fn init_once<T>(
    cell: &OnceLock<Result<T, KmsInitFailed>>,
    ctor: impl FnOnce() -> Result<T, KmsInitFailed>,
) -> Result<&T, KmsConfigError> {
    cell.get_or_init(ctor).as_ref().map_err(|_| KmsConfigError::KmsInitError)
}

/// The process-wide real backend client, constructed at most once. The SDK
/// `KmsError` is mapped to the payload-free [`KmsInitFailed`] **at this boundary**
/// so its text is dropped before it can be cached.
fn process_kms_client() -> Result<&'static ok_kms_rust::KmsClient, KmsConfigError> {
    init_once(&KMS_CLIENT, || ok_kms_rust::KmsClient::new().map_err(|_| KmsInitFailed))
}

/// Production provider backed by `ok-kms-rust` v1.0.1. Holds a shared reference to
/// the never-dropped process-wide client rather than owning it, so every provider
/// instance shares one client.
pub struct OkKmsProvider {
    client: &'static ok_kms_rust::KmsClient,
}

impl OkKmsProvider {
    /// Wrap the process-wide client borrowed from the singleton.
    fn from_static(client: &'static ok_kms_rust::KmsClient) -> Self {
        Self { client }
    }
}

impl KmsSecretProvider for OkKmsProvider {
    fn get_secret_value(&self, key: &str) -> Result<String, KmsProviderError> {
        // Map every backend error to a payload-free class: the raw backend error
        // text must never reach a diagnostic.
        self.client.get_secret_value(key).map_err(|_| KmsProviderError::Fetch)
    }
}

/// A protected-set env var is considered "present" only if it holds a
/// non-whitespace value.
fn present(name: &str) -> bool {
    std::env::var(name).map(|v| !v.trim().is_empty()).unwrap_or(false)
}

/// On-demand backend initialization. Validates the runtime preconditions and
/// returns a provider backed by the process-wide client. Returns a redacted
/// [`KmsConfigError::KmsInitError`] on any problem — no value, key, or backend
/// text is included.
///
/// Preconditions: `KMS_ENABLED` must equal exactly `"true"`; `KMS_PROVIDER` is
/// required; `KMS_SECRET_NAME` is required, with `KMS_REGION` additionally required
/// for the AWS provider. The backend additionally validates the dynamic library,
/// region, secret name, and cloud access during construction.
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
    Ok(OkKmsProvider::from_static(process_kms_client()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_once_constructs_at_most_once() {
        static C: OnceLock<Result<u32, KmsInitFailed>> = OnceLock::new();
        let calls = std::cell::Cell::new(0);
        let mk = || {
            calls.set(calls.get() + 1);
            Ok(7u32)
        };
        assert_eq!(*init_once(&C, mk).unwrap(), 7);
        assert_eq!(*init_once(&C, mk).unwrap(), 7); // cached
        assert_eq!(calls.get(), 1); // ctor ran once
    }

    #[test]
    fn init_once_caches_failure_and_maps_redacted() {
        static C: OnceLock<Result<u32, KmsInitFailed>> = OnceLock::new();
        let calls = std::cell::Cell::new(0);
        let mk = || {
            calls.set(calls.get() + 1);
            Err(KmsInitFailed)
        };
        assert!(matches!(init_once(&C, mk), Err(KmsConfigError::KmsInitError)));
        assert!(matches!(init_once(&C, mk), Err(KmsConfigError::KmsInitError))); // cached, ctor not re-run
        assert_eq!(calls.get(), 1);
    }
}
