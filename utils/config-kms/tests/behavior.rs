//! Behavioral tests over the real process environment. No network and no KMS SDK
//! are required: the plaintext/invalid paths use the default entry point, and the
//! full success + fail-closed matrix drives the public injectable entry point
//! `resolve_protected_config_env_with` with a test-local mock provider.
//!
//! These mutate global process env, so they are serialized behind a mutex and each
//! snapshots/restores the protected vars (and the runtime KMS vars).

use op_succinct_config_kms::{
    resolve_protected_config_env, resolve_protected_config_env_with, KmsConfigError,
    KmsProviderError, KmsSecretProvider,
};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

const PROTECTED: [&str; 6] = [
    "NETWORK_PRIVATE_KEY",
    "XLAYER_ACCESS_KEY",
    "XLAYER_SECRET_KEY",
    "SP1_GATEWAY_TOKEN",
    "SP1_GATEWAY_S3_TOKEN",
    "CLI_REDIS_NODES",
];

const KMS_RUNTIME: [&str; 4] = ["KMS_ENABLED", "KMS_PROVIDER", "KMS_SECRET_NAME", "KMS_REGION"];

fn snapshot() -> Vec<(&'static str, Option<String>)> {
    PROTECTED
        .iter()
        .chain(KMS_RUNTIME.iter())
        .map(|k| (*k, std::env::var(k).ok()))
        .collect()
}

fn restore(snap: &[(&'static str, Option<String>)]) {
    for (k, v) in snap {
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
}

fn clear_all() {
    for k in PROTECTED.iter().chain(KMS_RUNTIME.iter()) {
        std::env::remove_var(k);
    }
}

// ── Test-local configurable mock (implements the public trait; zero SDK dependency) ──
//
// Interior-mutable because the trait method takes `&self`. Shared via `Rc` so the
// test keeps a handle to inspect `get_hits` / `get_args` after the boxed clone is
// consumed by the resolver's factory.
struct MockProvider {
    values: HashMap<String, String>,
    get_err: Option<KmsProviderError>,
    get_hits: Cell<usize>,
    get_args: RefCell<Vec<String>>,
}

impl MockProvider {
    fn new(pairs: &[(&str, &str)]) -> Rc<Self> {
        Rc::new(Self {
            values: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            get_err: None,
            get_hits: Cell::new(0),
            get_args: RefCell::new(Vec::new()),
        })
    }
    fn failing(err: KmsProviderError) -> Rc<Self> {
        Rc::new(Self {
            values: HashMap::new(),
            get_err: Some(err),
            get_hits: Cell::new(0),
            get_args: RefCell::new(Vec::new()),
        })
    }
}

impl KmsSecretProvider for MockProvider {
    fn get_secret_value(&self, key: &str) -> Result<String, KmsProviderError> {
        self.get_hits.set(self.get_hits.get() + 1);
        self.get_args.borrow_mut().push(key.to_string());
        if let Some(err) = &self.get_err {
            // KmsProviderError is payload-free; reconstruct the same variant.
            return Err(match err {
                KmsProviderError::NotFound => KmsProviderError::NotFound,
                KmsProviderError::Fetch => KmsProviderError::Fetch,
            });
        }
        match self.values.get(key) {
            Some(v) => Ok(v.clone()),
            None => Err(KmsProviderError::NotFound),
        }
    }
}

/// Boxable shared handle: the resolver's factory hands out `Box<dyn KmsSecretProvider>`
/// while the test keeps its own `Rc` clone to inspect `get_hits` / `get_args`.
/// (A local newtype is needed because the orphan rule forbids implementing the
/// external trait directly for `Rc<MockProvider>`.)
struct SharedMock(Rc<MockProvider>);

impl KmsSecretProvider for SharedMock {
    fn get_secret_value(&self, key: &str) -> Result<String, KmsProviderError> {
        self.0.get_secret_value(key)
    }
}

// ── Baseline behavior tests (default entry point; no provider needed) ──

#[test]
fn all_plaintext_starts_and_leaves_values_untouched() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("XLAYER_ACCESS_KEY", "0xraw");

    let result = resolve_protected_config_env();
    let value_after = std::env::var("XLAYER_ACCESS_KEY").ok();
    restore(&snap);

    assert!(result.is_ok(), "all-plaintext mode must start: {result:?}");
    assert_eq!(value_after.as_deref(), Some("0xraw"), "plaintext must be byte-identical");
}

#[test]
fn invalid_reference_fails_closed_without_kms_env() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("NETWORK_PRIVATE_KEY", "kms:"); // empty key

    let result = resolve_protected_config_env();
    restore(&snap);

    assert!(
        matches!(result, Err(KmsConfigError::InvalidReferenceFormat { .. })),
        "empty-key reference must fail closed as InvalidReferenceFormat: {result:?}"
    );
}

// ── Integration matrix via the public injectable entry point + mock ──

#[test]
fn full_success_write_back() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("NETWORK_PRIVATE_KEY", "kms:k1");
    std::env::set_var("XLAYER_ACCESS_KEY", "kms:k2");
    std::env::set_var("XLAYER_SECRET_KEY", "0xraw"); // plaintext -> untouched
    // SP1_GATEWAY_TOKEN, SP1_GATEWAY_S3_TOKEN, CLI_REDIS_NODES absent -> untouched

    let mock = MockProvider::new(&[("k1", "p1"), ("k2", "p2")]);
    let init_count = Cell::new(0usize);
    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            init_count.set(init_count.get() + 1);
            Ok(Box::new(SharedMock(Rc::clone(&mock))))
        };
        resolve_protected_config_env_with(&mut factory)
    };
    let net = std::env::var("NETWORK_PRIVATE_KEY").ok();
    let acc = std::env::var("XLAYER_ACCESS_KEY").ok();
    let sec = std::env::var("XLAYER_SECRET_KEY").ok();
    let s3_absent = std::env::var("SP1_GATEWAY_S3_TOKEN").is_err();
    restore(&snap);

    assert!(result.is_ok(), "success path must return Ok: {result:?}");
    assert_eq!(net.as_deref(), Some("p1"), "reference resolved and written back");
    assert_eq!(acc.as_deref(), Some("p2"), "reference resolved and written back");
    assert_eq!(sec.as_deref(), Some("0xraw"), "plaintext byte-identical");
    assert!(s3_absent, "absent item stays absent");
}

#[test]
fn lazy_init_never_constructs_provider() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("XLAYER_ACCESS_KEY", "0xraw"); // plaintext only, no reference

    let init_count = Cell::new(0usize);
    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            init_count.set(init_count.get() + 1);
            Ok(Box::new(SharedMock(MockProvider::new(&[]))))
        };
        resolve_protected_config_env_with(&mut factory)
    };
    restore(&snap);

    assert!(result.is_ok());
    assert_eq!(init_count.get(), 0, "no reference -> provider never constructed");
}

#[test]
fn init_called_at_most_once() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("NETWORK_PRIVATE_KEY", "kms:a");
    std::env::set_var("XLAYER_ACCESS_KEY", "kms:b");
    std::env::set_var("XLAYER_SECRET_KEY", "kms:c");

    let mock = MockProvider::new(&[("a", "1"), ("b", "2"), ("c", "3")]);
    let init_count = Cell::new(0usize);
    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            init_count.set(init_count.get() + 1);
            Ok(Box::new(SharedMock(Rc::clone(&mock))))
        };
        resolve_protected_config_env_with(&mut factory)
    };
    restore(&snap);

    assert!(result.is_ok());
    assert_eq!(init_count.get(), 1, "provider constructed exactly once for multiple references");
    assert_eq!(mock.get_hits.get(), 3, "each reference fetched once");
}

#[test]
fn init_failure_is_atomic() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("NETWORK_PRIVATE_KEY", "kms:k1");
    std::env::set_var("XLAYER_ACCESS_KEY", "0xplain");

    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Err(KmsConfigError::KmsInitError)
        };
        resolve_protected_config_env_with(&mut factory)
    };
    let net = std::env::var("NETWORK_PRIVATE_KEY").ok();
    let acc = std::env::var("XLAYER_ACCESS_KEY").ok();
    restore(&snap);

    assert!(matches!(result, Err(KmsConfigError::KmsInitError)), "init failure fails closed: {result:?}");
    assert_eq!(net.as_deref(), Some("kms:k1"), "no env mutation on failure (reference item)");
    assert_eq!(acc.as_deref(), Some("0xplain"), "no env mutation on failure (plaintext item)");
}

#[test]
fn fetch_failure_fails_closed_atomic() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("XLAYER_ACCESS_KEY", "kms:k1");

    let mock = MockProvider::failing(KmsProviderError::Fetch);
    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(SharedMock(Rc::clone(&mock))))
        };
        resolve_protected_config_env_with(&mut factory)
    };
    let acc = std::env::var("XLAYER_ACCESS_KEY").ok();
    restore(&snap);

    assert!(
        matches!(result, Err(KmsConfigError::SecretFetchError { item }) if item == "XLAYER_ACCESS_KEY"),
        "fetch failure fails closed: {result:?}"
    );
    assert_eq!(acc.as_deref(), Some("kms:k1"), "no env mutation on failure");
}

#[test]
fn not_found_fails_closed_atomic() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("SP1_GATEWAY_TOKEN", "kms:missing");

    let mock = MockProvider::new(&[("present", "v")]); // "missing" absent -> NotFound
    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(SharedMock(Rc::clone(&mock))))
        };
        resolve_protected_config_env_with(&mut factory)
    };
    let tok = std::env::var("SP1_GATEWAY_TOKEN").ok();
    restore(&snap);

    assert!(
        matches!(result, Err(KmsConfigError::SecretNotFound { item }) if item == "SP1_GATEWAY_TOKEN"),
        "missing key fails closed: {result:?}"
    );
    assert_eq!(tok.as_deref(), Some("kms:missing"), "no env mutation on failure");
}

#[test]
fn empty_value_fails_closed_atomic() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("SP1_GATEWAY_S3_TOKEN", "kms:k1");

    let mock = MockProvider::new(&[("k1", "")]); // provider returns empty
    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(SharedMock(Rc::clone(&mock))))
        };
        resolve_protected_config_env_with(&mut factory)
    };
    let tok = std::env::var("SP1_GATEWAY_S3_TOKEN").ok();
    restore(&snap);

    assert!(
        matches!(result, Err(KmsConfigError::EmptySecretValue { item }) if item == "SP1_GATEWAY_S3_TOKEN"),
        "empty value fails closed: {result:?}"
    );
    assert_eq!(tok.as_deref(), Some("kms:k1"), "no env mutation on failure");
}

#[test]
fn error_display_redacted_via_public_entry() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("XLAYER_SECRET_KEY", "kms:prod/xlayer-secret");

    let mock = MockProvider::failing(KmsProviderError::Fetch);
    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(SharedMock(Rc::clone(&mock))))
        };
        resolve_protected_config_env_with(&mut factory)
    };
    restore(&snap);

    let err = result.unwrap_err();
    let shown = format!("{err}");
    assert!(shown.contains("XLAYER_SECRET_KEY"), "must name the item: {shown}");
    for leak in ["kms:", "prod/xlayer-secret", "topsecret"] {
        assert!(!shown.contains(leak), "must not leak {leak:?}: {shown}");
    }
}

#[test]
fn provider_receives_key_verbatim() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let snap = snapshot();
    clear_all();
    std::env::set_var("SP1_GATEWAY_TOKEN", "kms:svc/token");

    let mock = MockProvider::new(&[("svc/token", "resolved")]);
    let result = {
        let mut factory = || -> Result<Box<dyn KmsSecretProvider>, KmsConfigError> {
            Ok(Box::new(SharedMock(Rc::clone(&mock))))
        };
        resolve_protected_config_env_with(&mut factory)
    };
    let args = mock.get_args.borrow().clone();
    restore(&snap);

    assert!(result.is_ok(), "success: {result:?}");
    assert_eq!(args, vec!["svc/token".to_string()], "key passed to provider verbatim");
}
