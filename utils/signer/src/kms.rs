//! KMS helper for fetching secrets from OKG Aliyun KMS via `ok-kms-rust`.
//!
//! # Environment variables
//! - `ENABLE_KMS`         – set to `"true"` to fetch `secret_key` from KMS instead of env var.
//! - `KMS_SECRET_KEY_NAME` – KMS key name for `secret_key`; defaults to `"XLAYER_SECRET_KEY"`.
//!
//! # Singleton note
//! `ok-kms-rust` loads a Go CGO `.so` at init time. Dropping `KmsClient` would trigger
//! `dlclose` and cause SIGBUS because Go's GC goroutines keep running. The client is therefore
//! stored in a process-global `OnceLock` and never dropped.

use std::sync::OnceLock;

use anyhow::{Context, Result};
use ok_kms_rust::{KmsClient, KmsError};

static KMS_CLIENT: OnceLock<Result<Option<KmsClient>, String>> = OnceLock::new();

fn init_kms_client() -> Result<&'static Option<KmsClient>> {
    KMS_CLIENT
        .get_or_init(|| match KmsClient::new() {
            Ok(client) => {
                tracing::info!("KMS client initialized");
                Ok(Some(client))
            }
            Err(KmsError::Disabled) => Ok(None),
            Err(e) => Err(format!("KMS init failed: {e}")),
        })
        .as_ref()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Returns `true` when `ENABLE_KMS` is set to `"true"` (case-insensitive).
pub fn is_kms_enabled() -> bool {
    std::env::var("ENABLE_KMS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Fetches a single secret value from KMS.
///
/// `key_name` is the exact key stored in KMS (e.g. `"XLAYER_SECRET_KEY"`).
///
/// Errors if:
/// - KMS client init fails or is disabled (caller set `ENABLE_KMS=true` explicitly)
/// - the key is absent from the KMS response
pub fn fetch_secret(key_name: &str) -> Result<String> {
    let client_opt = init_kms_client()?;

    let client = client_opt.as_ref().with_context(|| {
        "ENABLE_KMS=true but KMS client is disabled (KMS_ENABLED not set or KMS unreachable)"
    })?;

    let json = client
        .get_all_secrets()
        .context("failed to fetch secrets from KMS")?;

    let secrets: std::collections::HashMap<String, String> =
        serde_json::from_str(&json).context("failed to parse KMS secrets JSON")?;

    secrets
        .get(key_name)
        .cloned()
        .with_context(|| format!("KMS key '{key_name}' not found in KMS response"))
}
