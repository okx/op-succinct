//! Fail-fast offline stub for the `ok-kms-rust` v1.0.1 SDK.
//!
//! It mirrors exactly the surface the resolver depends on — `KmsClient::new()` and
//! `KmsClient::get_secret_value(&self, &str)` — so the workspace compiles and links
//! offline, without the private SDK. Construction succeeds (linking and startup are
//! exercised) but every secret lookup ALWAYS fails: a misbuilt node fails at first
//! access rather than running on a bogus value. This stub NEVER returns a (fake)
//! secret. An `OK_KMS_STUB` marker is embedded so an accidental production link is
//! detectable and can be rejected by the production image build.

use std::fmt;

/// Marker embedded in any binary that links this stub. `#[used]` keeps it through
/// optimization and stripping, so `grep -qa OK_KMS_STUB <binary>` detects an
/// accidental inclusion even if no code path formats [`StubError`].
#[used]
#[allow(dead_code)]
static OK_KMS_STUB_MARKER: [u8; 11] = *b"OK_KMS_STUB";

/// Concrete error type for the stub. Its message also carries the `OK_KMS_STUB`
/// marker. `provider.rs` discards the error payload, so only the shape matters.
#[derive(Debug)]
pub struct StubError;

impl fmt::Display for StubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OK_KMS_STUB: offline ok-kms-rust stub cannot resolve secrets")
    }
}

impl std::error::Error for StubError {}

/// Stub KMS client mirroring the v1.0.1 surface used in production.
pub struct KmsClient;

impl KmsClient {
    /// Succeeds, so linking and startup paths are exercised offline.
    pub fn new() -> Result<KmsClient, StubError> {
        Ok(KmsClient)
    }

    /// Always fails — the offline stub never returns a secret value.
    pub fn get_secret_value(&self, _key: &str) -> Result<String, StubError> {
        Err(StubError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_succeeds() {
        assert!(KmsClient::new().is_ok());
    }

    #[test]
    fn get_secret_value_always_errs() {
        assert!(KmsClient::new().unwrap().get_secret_value("anything").is_err());
    }

    #[test]
    fn error_carries_marker() {
        let e = KmsClient::new().unwrap().get_secret_value("k").unwrap_err();
        assert!(format!("{e}").contains("OK_KMS_STUB"));
    }
}
