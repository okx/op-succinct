//! Secret-backend access boundary.
//!
//! [`KmsSecretProvider`] and [`KmsProviderError`] are always compiled — the pure
//! resolver, the injectable seam, and the test mock use them in every build. The
//! real `ok-kms-rust`-backed provider ([`OkKmsProvider`] / [`init_provider`]) lives
//! in the [`real`] submodule, compiled only under a single `#[cfg(feature = "kms")]
//! mod real;` gate; with the feature off there is no internal SDK in the build
//! graph at all, and a `kms:<key>` reference fails closed at the resolver's factory.

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
/// Mockable for tests; the production implementation is [`OkKmsProvider`], compiled
/// only under the `kms` feature.
pub trait KmsSecretProvider {
    fn get_secret_value(&self, key: &str) -> Result<String, KmsProviderError>;
}

// The real ok-kms-rust-backed adapter (provider + process-wide singleton) is
// compiled behind exactly one module-level feature gate. With `kms` off, no SDK
// enters the build graph and none of `real`'s items exist.
#[cfg(feature = "kms")]
mod real;
#[cfg(feature = "kms")]
pub use real::{init_provider, OkKmsProvider};
