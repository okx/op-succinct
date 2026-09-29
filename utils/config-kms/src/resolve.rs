//! Resolution core.
//!
//! [`resolve_values`] is a pure function over the protected items' current values:
//! it never touches global process state, lazily initializes the backend only when
//! a reference is actually present, and fails closed on any problem. The public
//! entry point that wires it to the process environment is added on top of this
//! core.

use crate::classify::{classify, Classification};
use crate::error::KmsConfigError;
use crate::provider::{KmsProviderError, KmsSecretProvider};
use crate::PROTECTED_KEYS;

/// Resolve the protected items' values without touching global state.
///
/// `reads` supplies each item's current raw value (name → optional value).
/// `provider_factory` is invoked at most once, lazily, on the first reference.
/// Returns the `(name, plaintext)` pairs that must be written back; plaintext,
/// absent, and empty items are omitted (left untouched). Any error aborts the
/// whole resolution (fail-closed) and mutates nothing (this function owns no state).
pub(crate) fn resolve_values(
    reads: &[(&'static str, Option<String>)],
    provider_factory: &mut dyn FnMut() -> Result<Box<dyn KmsSecretProvider>, KmsConfigError>,
) -> Result<Vec<(&'static str, String)>, KmsConfigError> {
    let mut provider: Option<Box<dyn KmsSecretProvider>> = None;
    let mut resolved: Vec<(&'static str, String)> = Vec::new();

    for name in PROTECTED_KEYS {
        let raw = reads
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| v.as_deref());
        // Absent or empty: not processed by this feature (existing validation applies).
        let value = match raw {
            Some(v) if !v.is_empty() => v,
            _ => continue,
        };
        match classify(value) {
            Classification::Plaintext => continue,
            Classification::InvalidFormat => {
                return Err(KmsConfigError::InvalidReferenceFormat { item: name });
            }
            Classification::KmsRef { key } => {
                if provider.is_none() {
                    provider = Some(provider_factory()?); // lazy init; fail-closed
                }
                let provider = provider.as_ref().expect("provider set above");
                let plaintext = provider.get_secret_value(&key).map_err(|e| match e {
                    KmsProviderError::NotFound => KmsConfigError::SecretNotFound { item: name },
                    KmsProviderError::Fetch => KmsConfigError::SecretFetchError { item: name },
                })?;
                if plaintext.is_empty() {
                    return Err(KmsConfigError::EmptySecretValue { item: name });
                }
                resolved.push((name, plaintext));
            }
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashMap;

    /// In-memory provider: maps keys to secrets, or fails every fetch.
    struct MockProvider {
        secrets: HashMap<String, String>,
        fail_fetch: bool,
    }

    impl MockProvider {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self {
                secrets: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                fail_fetch: false,
            }
        }
        fn failing() -> Self {
            Self { secrets: HashMap::new(), fail_fetch: true }
        }
    }

    impl KmsSecretProvider for MockProvider {
        fn get_secret_value(&self, key: &str) -> Result<String, KmsProviderError> {
            if self.fail_fetch {
                return Err(KmsProviderError::Fetch);
            }
            match self.secrets.get(key) {
                Some(v) => Ok(v.clone()),
                None => Err(KmsProviderError::NotFound),
            }
        }
    }

    fn reads(pairs: &[(&'static str, Option<&str>)]) -> Vec<(&'static str, Option<String>)> {
        pairs.iter().map(|(n, v)| (*n, v.map(|s| s.to_string()))).collect()
    }

    #[test]
    fn resolves_multiple_refs_and_leaves_others() {
        let r = reads(&[
            ("NETWORK_PRIVATE_KEY", Some("kms:k-net")),
            ("XLAYER_ACCESS_KEY", Some("kms:k-acc")),
            ("XLAYER_SECRET_KEY", Some("0xplain")), // plaintext -> omitted
            ("SP1_GATEWAY_TOKEN", None),            // absent -> omitted
        ]);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(MockProvider::new(&[("k-net", "p1"), ("k-acc", "p2")])))
        };
        let out = resolve_values(&r, &mut factory).unwrap();
        assert_eq!(
            out,
            vec![("NETWORK_PRIVATE_KEY", "p1".to_string()), ("XLAYER_ACCESS_KEY", "p2".to_string())]
        );
    }

    #[test]
    fn all_plaintext_never_inits_kms() {
        let r = reads(&[
            ("NETWORK_PRIVATE_KEY", Some("0xraw")),
            ("XLAYER_ACCESS_KEY", None),
            ("CLI_REDIS_NODES", Some("")), // empty -> omitted
        ]);
        let init_count = Cell::new(0usize);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            init_count.set(init_count.get() + 1);
            Ok(Box::new(MockProvider::new(&[])))
        };
        let out = resolve_values(&r, &mut factory).unwrap();
        assert_eq!(init_count.get(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn inits_provider_at_most_once() {
        let r = reads(&[
            ("NETWORK_PRIVATE_KEY", Some("kms:a")),
            ("XLAYER_ACCESS_KEY", Some("kms:b")),
            ("XLAYER_SECRET_KEY", Some("kms:c")),
        ]);
        let init_count = Cell::new(0usize);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            init_count.set(init_count.get() + 1);
            Ok(Box::new(MockProvider::new(&[("a", "1"), ("b", "2"), ("c", "3")])))
        };
        let out = resolve_values(&r, &mut factory).unwrap();
        assert_eq!(init_count.get(), 1);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn empty_key_fails_invalid_format() {
        let r = reads(&[("NETWORK_PRIVATE_KEY", Some("kms:"))]);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(MockProvider::new(&[])))
        };
        let err = resolve_values(&r, &mut factory).unwrap_err();
        assert!(matches!(
            err,
            KmsConfigError::InvalidReferenceFormat { item } if item == "NETWORK_PRIVATE_KEY"
        ));
    }

    #[test]
    fn init_failure_fails_closed() {
        let r = reads(&[("NETWORK_PRIVATE_KEY", Some("kms:k"))]);
        let mut factory =
            || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> { Err(KmsConfigError::KmsInitError) };
        let err = resolve_values(&r, &mut factory).unwrap_err();
        assert!(matches!(err, KmsConfigError::KmsInitError));
    }

    #[test]
    fn fetch_failure_fails_closed() {
        let r = reads(&[("XLAYER_ACCESS_KEY", Some("kms:k"))]);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(MockProvider::failing()))
        };
        let err = resolve_values(&r, &mut factory).unwrap_err();
        assert!(matches!(
            err,
            KmsConfigError::SecretFetchError { item } if item == "XLAYER_ACCESS_KEY"
        ));
    }

    #[test]
    fn key_not_found_fails_closed() {
        let r = reads(&[("SP1_GATEWAY_TOKEN", Some("kms:missing"))]);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(MockProvider::new(&[("present", "v")])))
        };
        let err = resolve_values(&r, &mut factory).unwrap_err();
        assert!(matches!(
            err,
            KmsConfigError::SecretNotFound { item } if item == "SP1_GATEWAY_TOKEN"
        ));
    }

    #[test]
    fn empty_value_fails_closed() {
        let r = reads(&[("SP1_GATEWAY_S3_TOKEN", Some("kms:k"))]);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(MockProvider::new(&[("k", "")]))) // provider returns empty
        };
        let err = resolve_values(&r, &mut factory).unwrap_err();
        assert!(matches!(
            err,
            KmsConfigError::EmptySecretValue { item } if item == "SP1_GATEWAY_S3_TOKEN"
        ));
    }

    #[test]
    fn redis_nodes_multinode_string_verbatim() {
        let nodes = "redis-1:6379,redis-2:6379,redis-3:6379";
        let r = reads(&[("CLI_REDIS_NODES", Some("kms:redis"))]);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(MockProvider::new(&[("redis", nodes)])))
        };
        let out = resolve_values(&r, &mut factory).unwrap();
        assert_eq!(out, vec![("CLI_REDIS_NODES", nodes.to_string())]);
    }

    #[test]
    fn error_display_is_redacted() {
        // A fetch failure for a reference whose key/plaintext are sensitive.
        let r = reads(&[("XLAYER_SECRET_KEY", Some("kms:prod/xlayer-secret"))]);
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(MockProvider::failing()))
        };
        let err = resolve_values(&r, &mut factory).unwrap_err();
        let shown = format!("{err}");
        assert!(shown.contains("XLAYER_SECRET_KEY"), "must name the item: {shown}");
        for leak in ["topsecret", "kms:", "prod/xlayer-secret"] {
            assert!(!shown.contains(leak), "must not leak {leak:?}: {shown}");
        }
    }
}
