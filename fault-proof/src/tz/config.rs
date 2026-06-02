//! tz-specific environment-based configuration.
//!
//! - `L2_RPC` (required): comma-separated REST endpoint list. After split/trim/filter, must be
//!   non-empty.
//! - `GAME_TYPE` (optional, default `1961`): the registered tz `TeeDisputeGame` type. Non-numeric
//!   or absent values silently fall back to the default.
//!
//! `rollup_config_hash` is intentionally NOT a field — the proposer reads it from L1 via
//! `factory.game_impl(game_type).rollupConfigHash()` at construction.

use std::env;

use anyhow::{anyhow, bail, Result};

pub const DEFAULT_TZ_GAME_TYPE: u32 = 1961;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TzConfig {
    pub rpc_urls: Vec<String>,
    pub game_type: u32,
}

impl TzConfig {
    pub fn from_env() -> Result<Self> {
        Self::parse_from(|k| env::var(k).ok())
    }

    /// Same impl as `from_env` (PRD §FR-10): tz challenger reads identical env vars.
    /// Parity is enforced structurally — both methods delegate to `parse_from` with the same
    /// `std::env::var` reader, so they cannot diverge without an obvious diff.
    pub fn challenger_from_env() -> Result<Self> {
        Self::parse_from(|k| env::var(k).ok())
    }

    /// Parses TzConfig from a generic env-like reader. Production callers use `from_env` /
    /// `challenger_from_env` which inject `std::env::var`; tests inject a pure-function reader
    /// to avoid mutating process env. Process env mutation is `unsafe` under Rust 2024 because
    /// libc `getenv`/`setenv` in concurrent code can cause use-after-free in some libc impls
    /// (notably macOS Apple libc) — see Rust RFC 3458.
    fn parse_from<F>(read: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let raw = read("L2_RPC").ok_or_else(|| {
            anyhow!("L2_RPC must be set for tz services (comma-separated endpoint list)")
        })?;
        let rpc_urls: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if rpc_urls.is_empty() {
            bail!("L2_RPC must contain at least one non-empty URL");
        }
        let game_type =
            read("GAME_TYPE").and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_TZ_GAME_TYPE);
        Ok(Self { rpc_urls, game_type })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FR-10 / DM-10.1 — L2_RPC unset.
    #[test]
    fn from_env_missing_l2_rpc_errors() {
        let err = TzConfig::parse_from(|_| None).err().expect("must error");
        assert!(err.to_string().contains("L2_RPC must be set"));
    }

    // FR-10 / DM-10.2 — empty after split.
    #[test]
    fn from_env_only_commas_errors() {
        let err = TzConfig::parse_from(|k| match k {
            "L2_RPC" => Some(",".to_string()),
            _ => None,
        })
        .err()
        .expect("must error");
        assert!(err.to_string().contains("non-empty URL"));
    }

    // FR-10 / DM-10.3 — single URL.
    #[test]
    fn from_env_single_url() {
        let cfg = TzConfig::parse_from(|k| match k {
            "L2_RPC" => Some("https://a".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(cfg.rpc_urls, vec!["https://a".to_string()]);
        assert_eq!(cfg.game_type, DEFAULT_TZ_GAME_TYPE);
    }

    // FR-10 / DM-10.4 — multi URL with whitespace.
    #[test]
    fn from_env_multi_url_with_whitespace() {
        let cfg = TzConfig::parse_from(|k| match k {
            "L2_RPC" => Some("  https://a , https://b  ".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(cfg.rpc_urls, vec!["https://a".to_string(), "https://b".to_string()]);
    }

    // FR-10 / DM-10.5 — GAME_TYPE default.
    #[test]
    fn from_env_default_game_type_when_unset() {
        let cfg = TzConfig::parse_from(|k| match k {
            "L2_RPC" => Some("https://a".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(cfg.game_type, DEFAULT_TZ_GAME_TYPE);
    }

    // FR-10 / DM-10.6 — explicit GAME_TYPE.
    #[test]
    fn from_env_explicit_game_type() {
        let cfg = TzConfig::parse_from(|k| match k {
            "L2_RPC" => Some("https://a".to_string()),
            "GAME_TYPE" => Some("42".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(cfg.game_type, 42);
    }

    // FR-10 / DM-10.7 — non-numeric GAME_TYPE silently falls back.
    #[test]
    fn from_env_nonnumeric_game_type_falls_back() {
        let cfg = TzConfig::parse_from(|k| match k {
            "L2_RPC" => Some("https://a".to_string()),
            "GAME_TYPE" => Some("abc".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(cfg.game_type, DEFAULT_TZ_GAME_TYPE);
    }
}
