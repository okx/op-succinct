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
    /// Extra L2-block margin beyond finality when computing the startup rescan window.
    pub reorg_safety_margin: u64,
    /// Startup lookback (L2 blocks) to rescan for still-open challenges.
    pub startup_lookback: u64,
    /// Maximum number of bounded resends for a single challenge before it terminates.
    pub max_resend: u32,
    /// Backoff between retries when waiting for the witness record or the latest root.
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

        // The resend cap is a u32; reject an out-of-range configuration rather than silently
        // truncating it (a bare `as u32` maps e.g. 2^32 to 0, disabling all resends).
        let max_resend_raw = opt_u64("DEFENDER_MAX_RESEND", 3)?;
        let max_resend = u32::try_from(max_resend_raw).ok().with_context(|| {
            format!(
                "DEFENDER_MAX_RESEND ({max_resend_raw}) exceeds the maximum supported value ({})",
                u32::MAX
            )
        })?;

        let cfg = Self {
            challenge_contract: parse_addr("DEFENDER_CHALLENGE_CONTRACT")?,
            root_manager: parse_addr("DEFENDER_ROOT_MANAGER")?,
            wb_endpoint: req("DEFENDER_WB_ENDPOINT")?
                .parse::<Url>()
                .context("DEFENDER_WB_ENDPOINT must be a URL")?,
            chain_id,
            finality_blocks: opt_u64("DEFENDER_FINALITY_BLOCKS", 32)?,
            reorg_safety_margin: opt_u64("DEFENDER_REORG_SAFETY_MARGIN", 16)?,
            startup_lookback: opt_u64("DEFENDER_STARTUP_LOOKBACK", 10_000)?,
            max_resend,
            retry_backoff: Duration::from_secs(opt_u64("DEFENDER_RETRY_BACKOFF_SECS", 15)?),
            deadline_safety_margin: Duration::from_secs(opt_u64(
                "DEFENDER_DEADLINE_SAFETY_MARGIN_SECS",
                3600,
            )?),
            cache_capacity: opt_u64("DEFENDER_CACHE_CAPACITY", 1024)? as usize,
            signer_secret: Redacted(req("DEFENDER_SIGNER_SECRET")?),
        };

        // When both the challenge response period and a conservative minimum L2 block interval are
        // configured, the startup rescan window must be at least the derived block-count lower
        // bound so a challenge still open after downtime stays inside the window.
        if let (Some(period), Some(interval)) = (
            read("DEFENDER_MAX_CHALLENGE_RESPONSE_SECS")
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().parse::<u64>())
                .transpose()
                .context("DEFENDER_MAX_CHALLENGE_RESPONSE_SECS must be an integer")?,
            read("DEFENDER_MIN_L2_BLOCK_INTERVAL_SECS")
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().parse::<u64>())
                .transpose()
                .context("DEFENDER_MIN_L2_BLOCK_INTERVAL_SECS must be an integer")?,
        ) {
            let lower_bound = cfg.startup_lookback_blocks(period, interval);
            if cfg.startup_lookback < lower_bound {
                bail!(
                    "DEFENDER_STARTUP_LOOKBACK ({}) is below the required block lower bound ({})",
                    cfg.startup_lookback,
                    lower_bound
                );
            }
        }

        Ok(cfg)
    }

    /// Lower bound, in L2 BLOCKS, for how far back to rescan on startup so a challenge still open
    /// after downtime is inside the window. All terms are block counts; seconds and block counts
    /// are never added directly — the response period is converted to blocks via the conservative
    /// minimum L2 block interval first.
    pub fn startup_lookback_blocks(
        &self,
        max_challenge_response_secs: u64,
        min_l2_block_interval_secs: u64,
    ) -> u64 {
        let interval = min_l2_block_interval_secs.max(1);
        let period_blocks = max_challenge_response_secs.div_ceil(interval);
        // Saturating: these are block counts summed from independently-configured values, so an
        // extreme configuration must clamp at the u64 ceiling rather than wrap around.
        period_blocks.saturating_add(self.finality_blocks).saturating_add(self.reorg_safety_margin)
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
    fn startup_lookback_lower_bound_is_blocks_not_seconds() {
        let cfg = DefenderConfig::parse_from(reader(full_env())).unwrap();
        // period=7200s, min L2 block interval=2s ⇒ ceil(3600) blocks; + finality + reorg margin.
        let lb = cfg.startup_lookback_blocks(7200, 2);
        assert!(lb >= 3600 + cfg.finality_blocks, "must add finality depth in BLOCKS");
        // Seconds and blocks are never added directly.
        assert_ne!(lb, 7200 + 32);
    }

    #[test]
    fn too_small_startup_lookback_is_rejected() {
        let mut m = full_env();
        m.insert("DEFENDER_STARTUP_LOOKBACK", "1".to_string());
        m.insert("DEFENDER_MAX_CHALLENGE_RESPONSE_SECS", "7200".to_string());
        m.insert("DEFENDER_MIN_L2_BLOCK_INTERVAL_SECS", "2".to_string());
        assert!(DefenderConfig::parse_from(reader(m)).is_err());
    }

    #[test]
    fn max_resend_defaults_and_parses() {
        let cfg = DefenderConfig::parse_from(reader(full_env())).unwrap();
        assert_eq!(cfg.max_resend, 3); // default
    }

    #[test]
    fn max_resend_above_u32_range_is_rejected_not_truncated() {
        // 2^32 would silently become 0 under a bare `as u32`, disabling every resend. It must be
        // rejected with a clear error instead.
        let mut m = full_env();
        m.insert("DEFENDER_MAX_RESEND", (u32::MAX as u64 + 1).to_string());
        let err = DefenderConfig::parse_from(reader(m)).unwrap_err();
        assert!(err.to_string().contains("DEFENDER_MAX_RESEND"), "unexpected error: {err}");
    }

    #[test]
    fn max_resend_at_u32_ceiling_is_accepted() {
        let mut m = full_env();
        m.insert("DEFENDER_MAX_RESEND", u32::MAX.to_string());
        assert_eq!(DefenderConfig::parse_from(reader(m)).unwrap().max_resend, u32::MAX);
    }

    #[test]
    fn startup_lookback_blocks_saturates_instead_of_overflowing() {
        // With finality_blocks at the u64 ceiling, summing the block-count terms must saturate at
        // u64::MAX rather than wrap around (a debug-build overflow panic / release wraparound).
        let mut m = full_env();
        m.insert("DEFENDER_FINALITY_BLOCKS", u64::MAX.to_string());
        let cfg = DefenderConfig::parse_from(reader(m)).unwrap();
        assert_eq!(cfg.startup_lookback_blocks(10, 1), u64::MAX);
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
