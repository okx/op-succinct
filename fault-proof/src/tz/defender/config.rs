//! Independent Defender configuration (spec §7.5).
//!
//! All secrets are read from the environment (KB rule: never hardcode) and redacted in `Debug`
//! output as `***REDACTED***` (KB rule). The Defender has its OWN config and signer, separate
//! from the Proposer / L1 Challenger.

use std::time::Duration;

use alloy_primitives::Address;
use anyhow::{bail, Context, Result};
use reqwest::Url;

/// A secret string that never prints its contents.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted(String);

impl Redacted {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***REDACTED***")
    }
}

/// Independent Defender configuration.
#[derive(Clone, Debug)]
pub struct DefenderConfig {
    /// X Layer Withdraw-challenge contract address.
    pub challenge_contract: Address,
    /// TZRootManager address (finalized covering roots).
    pub root_manager: Address,
    /// Witness Builder v2 endpoint.
    pub wb_endpoint: Url,
    /// TZ chain id (non-zero) — guards WB checkpoint responses.
    pub chain_id: u64,
    /// L2 finality depth (blocks) before an event/root is actionable.
    pub finality_blocks: u64,
    /// Startup lookback (blocks) to rescan for still-open challenges.
    pub startup_lookback: u64,
    /// Backoff between retries when waiting for WB record / covering root.
    pub retry_backoff: Duration,
    /// Safety margin before the on-chain response deadline (stop responding within it).
    pub deadline_safety_margin: Duration,
    /// LRU proof-cache capacity.
    pub cache_capacity: usize,
    /// Signer secret (KMS resource / key ref). Redacted in Debug.
    pub signer_secret: Redacted,
}

impl DefenderConfig {
    pub fn from_env() -> Result<Self> {
        Self::parse_from(|k| std::env::var(k).ok())
    }

    /// Parse from a generic env reader (tests inject a pure-function reader instead of mutating
    /// process env — Rust 2024 `set_var` is `unsafe`; mirrors `tz::config::TzConfig::parse_from`).
    pub fn parse_from<F>(read: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let req = |k: &str| -> Result<String> {
            read(k).filter(|v| !v.trim().is_empty()).with_context(|| format!("{k} must be set"))
        };
        let parse_addr = |k: &str| -> Result<Address> {
            req(k)?.parse::<Address>().with_context(|| format!("{k} must be a 20-byte address"))
        };

        let chain_id: u64 = req("DEFENDER_TZ_CHAIN_ID")?
            .parse()
            .context("DEFENDER_TZ_CHAIN_ID must be an integer")?;
        if chain_id == 0 {
            bail!("DEFENDER_TZ_CHAIN_ID must be non-zero");
        }

        let opt_u64 = |k: &str, default: u64| -> Result<u64> {
            match read(k) {
                Some(v) if !v.trim().is_empty() => {
                    v.trim().parse().with_context(|| format!("{k} must be an integer"))
                }
                _ => Ok(default),
            }
        };

        Ok(Self {
            challenge_contract: parse_addr("DEFENDER_CHALLENGE_CONTRACT")?,
            root_manager: parse_addr("DEFENDER_ROOT_MANAGER")?,
            wb_endpoint: req("DEFENDER_WB_ENDPOINT")?
                .parse::<Url>()
                .context("DEFENDER_WB_ENDPOINT must be a URL")?,
            chain_id,
            finality_blocks: opt_u64("DEFENDER_FINALITY_BLOCKS", 32)?,
            startup_lookback: opt_u64("DEFENDER_STARTUP_LOOKBACK", 10_000)?,
            retry_backoff: Duration::from_secs(opt_u64("DEFENDER_RETRY_BACKOFF_SECS", 15)?),
            deadline_safety_margin: Duration::from_secs(opt_u64(
                "DEFENDER_DEADLINE_SAFETY_MARGIN_SECS",
                3600,
            )?),
            cache_capacity: opt_u64("DEFENDER_CACHE_CAPACITY", 1024)? as usize,
            signer_secret: Redacted(req("DEFENDER_SIGNER_SECRET")?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn full_env() -> HashMap<&'static str, String> {
        let mut m = HashMap::new();
        m.insert("DEFENDER_CHALLENGE_CONTRACT", format!("{:#x}", Address::repeat_byte(0x01)));
        m.insert("DEFENDER_ROOT_MANAGER", format!("{:#x}", Address::repeat_byte(0x02)));
        m.insert("DEFENDER_WB_ENDPOINT", "http://wb:8545".to_string());
        m.insert("DEFENDER_TZ_CHAIN_ID", "196".to_string());
        m.insert("DEFENDER_SIGNER_SECRET", "super-secret-kms-ref".to_string());
        m
    }

    fn reader(m: HashMap<&'static str, String>) -> impl Fn(&str) -> Option<String> {
        move |k| m.get(k).cloned()
    }

    #[test]
    fn parses_full_env_with_defaults() {
        let cfg = DefenderConfig::parse_from(reader(full_env())).unwrap();
        assert_eq!(cfg.chain_id, 196);
        assert_eq!(cfg.finality_blocks, 32); // default
        assert_eq!(cfg.cache_capacity, 1024); // default
        assert_eq!(cfg.deadline_safety_margin, Duration::from_secs(3600));
    }

    #[test]
    fn missing_required_var_errors() {
        let mut m = full_env();
        m.remove("DEFENDER_WB_ENDPOINT");
        let err = DefenderConfig::parse_from(reader(m)).unwrap_err();
        assert!(err.to_string().contains("DEFENDER_WB_ENDPOINT"));
    }

    #[test]
    fn zero_chain_id_errors() {
        let mut m = full_env();
        m.insert("DEFENDER_TZ_CHAIN_ID", "0".to_string());
        assert!(DefenderConfig::parse_from(reader(m)).is_err());
    }

    #[test]
    fn debug_redacts_signer_secret() {
        let cfg = DefenderConfig::parse_from(reader(full_env())).unwrap();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("***REDACTED***"), "debug must redact: {dbg}");
        assert!(!dbg.contains("super-secret-kms-ref"), "secret leaked: {dbg}");
        // The value is still usable programmatically.
        assert_eq!(cfg.signer_secret.expose(), "super-secret-kms-ref");
    }
}
