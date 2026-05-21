//! tz-specific environment-based configuration.
//!
//! - `L2_RPC` (required): comma-separated REST endpoint list. After split/trim/filter, must be
//!   non-empty.
//! - `GAME_TYPE` (optional, default `1961`): the registered tz `TeeDisputeGame` type. Non-numeric
//!   or absent values silently fall back to the default.
//! - `TZ_RANGE_ELF_PATH` (required for proposer): filesystem path to the compiled tz range ELF.
//!   Loaded at startup; automatically uploaded to the SP1 Cluster to obtain the artifact ID.
//! - `TZ_AGG_ELF_PATH` (required for proposer): filesystem path to the compiled tz aggregation ELF.
//!   Loaded at startup and passed directly to the cluster for each aggregation proof.
//!
//! `rollup_config_hash` is intentionally NOT a field — the proposer reads it from L1 via
//! `factory.game_impl(game_type).rollupConfigHash()` at construction.

use std::{env, path::PathBuf};

use anyhow::{anyhow, bail, Result};

pub const DEFAULT_TZ_GAME_TYPE: u32 = 1961;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TzConfig {
    pub rpc_urls: Vec<String>,
    pub game_type: u32,
    /// Filesystem path to the compiled tz range ELF. Required for the proposer.
    /// Loaded at startup and uploaded to the cluster to obtain the artifact ID.
    pub range_elf_path: PathBuf,
    /// Filesystem path to the compiled tz aggregation ELF. Required for the proposer.
    pub agg_elf_path: PathBuf,
}

impl TzConfig {
    /// Build config for the proposer. Requires `L2_RPC`, `TZ_RANGE_ELF_PATH`, `TZ_AGG_ELF_PATH`,
    /// and optionally `GAME_TYPE`.
    pub fn from_env() -> Result<Self> {
        let mut cfg = Self::parse_shared_env()?;

        let range_elf_path = env::var("TZ_RANGE_ELF_PATH")
            .map_err(|_| anyhow!("TZ_RANGE_ELF_PATH must be set for the tz proposer"))?;
        if range_elf_path.trim().is_empty() {
            bail!("TZ_RANGE_ELF_PATH must not be empty");
        }
        cfg.range_elf_path = PathBuf::from(range_elf_path);

        let agg_elf_path = env::var("TZ_AGG_ELF_PATH")
            .map_err(|_| anyhow!("TZ_AGG_ELF_PATH must be set for the tz proposer"))?;
        if agg_elf_path.trim().is_empty() {
            bail!("TZ_AGG_ELF_PATH must not be empty");
        }
        cfg.agg_elf_path = PathBuf::from(agg_elf_path);

        Ok(cfg)
    }

    /// Build config for the challenger. Requires only `L2_RPC` and optionally `GAME_TYPE`.
    /// ELF paths are not needed by the challenger and are set to empty.
    pub fn challenger_from_env() -> Result<Self> {
        Self::parse_shared_env()
    }

    /// Parse the env vars shared by both proposer and challenger: `L2_RPC` and `GAME_TYPE`.
    fn parse_shared_env() -> Result<Self> {
        let raw = env::var("L2_RPC").map_err(|_| {
            anyhow!("L2_RPC must be set for tz services (comma-separated endpoint list)")
        })?;
        let rpc_urls: Vec<String> =
            raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if rpc_urls.is_empty() {
            bail!("L2_RPC must contain at least one non-empty URL");
        }
        Ok(Self {
            rpc_urls,
            game_type: Self::parse_game_type(),
            range_elf_path: PathBuf::new(),
            agg_elf_path: PathBuf::new(),
        })
    }

    pub fn parse_game_type() -> u32 {
        match env::var("GAME_TYPE") {
            Ok(s) => s.parse().unwrap_or_else(|_| {
                tracing::warn!(value = %s, "GAME_TYPE is set but could not be parsed as u32; using default {}", DEFAULT_TZ_GAME_TYPE);
                DEFAULT_TZ_GAME_TYPE
            }),
            Err(_) => DEFAULT_TZ_GAME_TYPE,
        }
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
            env::remove_var("TZ_RANGE_ELF_PATH");
            env::remove_var("TZ_AGG_ELF_PATH");
        }
    }

    fn set_elf_paths() {
        unsafe {
            env::set_var("TZ_RANGE_ELF_PATH", "/tmp/tz-range.elf");
            env::set_var("TZ_AGG_ELF_PATH", "/tmp/tz-agg.elf");
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
        set_elf_paths();
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
        set_elf_paths();
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
        set_elf_paths();
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
        set_elf_paths();
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
        set_elf_paths();
        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.game_type, DEFAULT_TZ_GAME_TYPE);
        clear();
    }

    // DM-10.8 — challenger_from_env succeeds without ELF paths; proposer requires them.
    #[test]
    fn challenger_from_env_succeeds_without_elf_paths() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a,https://b");
            env::set_var("GAME_TYPE", "1961");
        }
        let c = TzConfig::challenger_from_env().unwrap();
        // Challenger does not require ELF paths.
        assert_eq!(c.rpc_urls, vec!["https://a".to_string(), "https://b".to_string()]);
        assert_eq!(c.game_type, 1961);
        // Proposer requires ELF paths — missing both should error.
        let err = TzConfig::from_env().err().expect("must error when ELF paths unset");
        assert!(
            err.to_string().contains("TZ_RANGE_ELF_PATH"),
            "error must mention TZ_RANGE_ELF_PATH, got: {err}"
        );
        clear();
    }

    // Phase 2 / DM-ELF-1 — missing TZ_RANGE_ELF_PATH causes from_env error.
    #[test]
    fn from_env_missing_range_elf_path_errors() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a");
        }
        let err = TzConfig::from_env().err().expect("must error when TZ_RANGE_ELF_PATH unset");
        assert!(
            err.to_string().contains("TZ_RANGE_ELF_PATH"),
            "error must mention TZ_RANGE_ELF_PATH, got: {err}"
        );
        clear();
    }

    // Phase 2 / DM-ELF-2 — missing TZ_AGG_ELF_PATH causes from_env error.
    #[test]
    fn from_env_missing_agg_elf_path_errors() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a");
            env::set_var("TZ_RANGE_ELF_PATH", "/tmp/tz-range.elf");
        }
        let err = TzConfig::from_env().err().expect("must error when TZ_AGG_ELF_PATH unset");
        assert!(
            err.to_string().contains("TZ_AGG_ELF_PATH"),
            "error must mention TZ_AGG_ELF_PATH, got: {err}"
        );
        clear();
    }

    // Phase 2 / DM-ELF-3 — ELF paths are parsed into TzConfig fields.
    #[test]
    fn from_env_elf_paths_parsed() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            env::set_var("L2_RPC", "https://a");
            env::set_var("TZ_RANGE_ELF_PATH", "/opt/tz/range.elf");
            env::set_var("TZ_AGG_ELF_PATH", "/opt/tz/agg.elf");
        }
        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.range_elf_path, PathBuf::from("/opt/tz/range.elf"));
        assert_eq!(cfg.agg_elf_path, PathBuf::from("/opt/tz/agg.elf"));
        clear();
    }
}
