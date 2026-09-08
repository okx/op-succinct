//! KMS reference-resolution helper.
//!
//! A secret value of the form `kms:<name>` is resolved via the OKG-internal
//! `ok-kms-rust` SDK at load time; any value WITHOUT the `kms:` prefix passes
//! through byte-for-byte unchanged. The SDK is reachable only in some build
//! environments, so it is gated behind the `kms` feature. Default builds
//! compile against the in-tree stub (`stubs/ok-kms-rust`) and resolve offline.
//!
//! # Singleton note (kms feature on)
//! `ok-kms-rust` loads a Go CGO `.so` at init. Dropping `KmsClient` would call
//! `dlclose` and SIGBUS (Go GC goroutines keep running), so the client lives in
//! a process-global `OnceLock` and is never dropped.

use thiserror::Error;

/// Prefix that marks a value as a KMS reference.
pub const KMS_REF_PREFIX: &str = "kms:";

/// True iff `value` begins with `KMS_REF_PREFIX` (case-sensitive, no trimming).
pub fn is_kms_ref(value: &str) -> bool {
    value.starts_with(KMS_REF_PREFIX)
}

/// Errors from KMS reference resolution. Messages never carry the resolved
/// secret value (only the reference name or SDK error text) — see
/// `context-kg/technical/pitfalls/signer.md` "Sensitive Data in Logs".
#[derive(Debug, Error)]
pub enum KmsError {
    /// A `kms:` reference was seen but the `kms` feature is not compiled in.
    #[error(
        "KMS reference seen but this binary was built without the `kms` feature; \
         rebuild with `--features kms` (e.g. `just build-kms proposer`) or supply a literal secret"
    )]
    Disabled,
    /// The reference name after `kms:` is empty, or the resolved secret is empty.
    #[error("KMS reference name or resolved secret value is empty")]
    Empty,
    /// The SDK lookup failed (SDK disabled, backend/network error, or key absent).
    #[error("KMS backend error: {0}")]
    Backend(String),
}

/// If `value` is a `kms:<name>` reference, resolve `<name>` via the SDK and
/// return the secret. Otherwise return `value` unchanged (byte-for-byte).
pub fn maybe_resolve(value: &str) -> Result<String, KmsError> {
    if !is_kms_ref(value) {
        return Ok(value.to_string());
    }
    let name = &value[KMS_REF_PREFIX.len()..];
    if name.is_empty() {
        return Err(KmsError::Empty);
    }
    imp::resolve(name)
}

#[cfg(feature = "kms")]
mod imp {
    use std::sync::OnceLock;

    use ok_kms_rust::{KmsClient, KmsError as SdkError};

    use super::KmsError;

    // Constructed at most once; never dropped (CGO `.so` lifetime). GC8.
    static KMS_CLIENT: OnceLock<Result<KmsClient, String>> = OnceLock::new();

    fn client() -> Result<&'static KmsClient, KmsError> {
        KMS_CLIENT
            .get_or_init(|| match KmsClient::new() {
                Ok(c) => {
                    tracing::info!("KMS client initialized");
                    Ok(c)
                }
                Err(SdkError::Disabled) => {
                    Err("ok-kms-rust SDK reported Disabled — check its activation env vars".to_string())
                }
                Err(e) => Err(format!("KMS init failed: {e}")),
            })
            .as_ref()
            .map_err(|e| KmsError::Backend(e.clone()))
    }

    pub fn resolve(name: &str) -> Result<String, KmsError> {
        let client = client()?;
        let json = client
            .get_all_secrets()
            .map_err(|e| KmsError::Backend(e.to_string()))?;
        let secrets: std::collections::HashMap<String, String> =
            serde_json::from_str(&json).map_err(|e| KmsError::Backend(format!("parse KMS JSON: {e}")))?;
        match secrets.get(name) {
            Some(v) if !v.is_empty() => Ok(v.clone()),
            Some(_) => Err(KmsError::Empty),
            None => Err(KmsError::Backend(format!("KMS key '{name}' not found"))),
        }
    }
}

#[cfg(not(feature = "kms"))]
mod imp {
    use super::KmsError;

    pub fn resolve(_name: &str) -> Result<String, KmsError> {
        Err(KmsError::Disabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_kms_ref_detects_only_exact_prefix() {
        assert!(is_kms_ref("kms:foo"));
        assert!(!is_kms_ref("foo"));
        assert!(!is_kms_ref("KMS:foo")); // case-sensitive
        assert!(!is_kms_ref(" kms:foo")); // leading space is not a prefix
        assert!(!is_kms_ref(""));
    }

    #[test]
    fn passthrough_is_byte_for_byte() {
        // trailing whitespace and 0x-prefixed literals must round-trip unchanged
        let v = "0xabc123   ";
        assert_eq!(maybe_resolve(v).unwrap(), v);
        assert_eq!(maybe_resolve("plain-secret").unwrap(), "plain-secret");
    }

    #[test]
    fn empty_reference_name_is_empty_error() {
        assert!(matches!(maybe_resolve("kms:"), Err(KmsError::Empty)));
    }

    #[cfg(not(feature = "kms"))]
    #[test]
    fn reference_without_feature_is_disabled_with_guidance() {
        match maybe_resolve("kms:foo") {
            Err(KmsError::Disabled) => {
                let msg = KmsError::Disabled.to_string();
                assert!(msg.contains("--features kms"), "message must include rebuild guidance");
            }
            other => panic!("expected Disabled, got {other:?}"),
        }
    }

    #[cfg(feature = "kms")]
    #[test]
    fn reference_with_feature_and_stub_fails_loudly_and_reuses_client() {
        // Two lookups both fail carrying the stub marker; the OnceLock client
        // is constructed at most once (second call reuses it — no panic/second init).
        let e1 = maybe_resolve("kms:x").unwrap_err();
        let e2 = maybe_resolve("kms:y").unwrap_err();
        assert!(e1.to_string().contains("OK_KMS_STUB"), "got: {e1}");
        assert!(e2.to_string().contains("OK_KMS_STUB"), "got: {e2}");
    }
}
