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
        Self::parse_env()
    }

    /// Same impl as `from_env` (PRD §FR-10): tz challenger reads identical env vars.
    pub fn challenger_from_env() -> Result<Self> {
        Self::parse_env()
    }

    fn parse_env() -> Result<Self> {
        let raw = env::var("L2_RPC").map_err(|_| {
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
        Ok(Self { rpc_urls, game_type: Self::parse_game_type() })
    }

    pub fn parse_game_type() -> u32 {
        env::var("GAME_TYPE").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_TZ_GAME_TYPE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex for serializing env mutation across tests in this module.
    // Required because tests share the process env and run concurrently by default.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear() {
        // Safety: env::remove_var is unsafe under Rust 2024; tests serialize via ENV_LOCK
        // and no other thread reads these vars concurrently with these tests.
        unsafe {
            env::remove_var("L2_RPC");
            env::remove_var("GAME_TYPE");
        }
    }

    // FR-10 / DM-10.1 — L2_RPC unset.
    #[test]
    fn from_env_missing_l2_rpc_errors() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        let err = TzConfig::from_env().err().expect("must error");
        assert!(err.to_string().contains("L2_RPC must be set"));
    }

    // FR-10 / DM-10.2 — empty after split.
    #[test]
    fn from_env_only_commas_errors() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", ",");
        }
        let err = TzConfig::from_env().err().expect("must error");
        assert!(err.to_string().contains("non-empty URL"));
        clear();
    }

    // FR-10 / DM-10.3 — single URL.
    #[test]
    fn from_env_single_url() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a");
        }
        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.rpc_urls, vec!["https://a".to_string()]);
        assert_eq!(cfg.game_type, DEFAULT_TZ_GAME_TYPE);
        clear();
    }

    // FR-10 / DM-10.4 — multi URL with whitespace.
    #[test]
    fn from_env_multi_url_with_whitespace() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "  https://a , https://b  ");
        }
        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.rpc_urls, vec!["https://a".to_string(), "https://b".to_string()]);
        clear();
    }

    // FR-10 / DM-10.5 — GAME_TYPE default.
    #[test]
    fn from_env_default_game_type_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a");
        }
        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.game_type, DEFAULT_TZ_GAME_TYPE);
        clear();
    }

    // FR-10 / DM-10.6 — explicit GAME_TYPE.
    #[test]
    fn from_env_explicit_game_type() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a");
            env::set_var("GAME_TYPE", "42");
        }
        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.game_type, 42);
        clear();
    }

    // FR-10 / DM-10.7 — non-numeric GAME_TYPE silently falls back.
    #[test]
    fn from_env_nonnumeric_game_type_falls_back() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a");
            env::set_var("GAME_TYPE", "abc");
        }
        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.game_type, DEFAULT_TZ_GAME_TYPE);
        clear();
    }

    // FR-10 / DM-10.8 — challenger_from_env parity with from_env.
    #[test]
    fn challenger_from_env_returns_identical_config() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a,https://b");
            env::set_var("GAME_TYPE", "1961");
        }
        let p = TzConfig::from_env().unwrap();
        let c = TzConfig::challenger_from_env().unwrap();
        assert_eq!(p, c);
        clear();
    }
}
