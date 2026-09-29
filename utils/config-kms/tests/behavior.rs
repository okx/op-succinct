//! Behavioral tests over the real process environment. No network is required:
//! they exercise only the all-plaintext no-op path and the invalid-format
//! fail-closed path (which short-circuits before any backend init).
//!
//! These mutate global process env, so they are serialized behind a mutex and
//! each snapshots/restores the protected vars (and the runtime KMS vars).

use op_succinct_config_kms::{resolve_protected_config_env, KmsConfigError};
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
    // No KMS runtime env is set: a format error must short-circuit before any init.
    std::env::set_var("NETWORK_PRIVATE_KEY", "kms:"); // empty key

    let result = resolve_protected_config_env();
    restore(&snap);

    assert!(
        matches!(result, Err(KmsConfigError::InvalidReferenceFormat { .. })),
        "empty-key reference must fail closed as InvalidReferenceFormat: {result:?}"
    );
}
