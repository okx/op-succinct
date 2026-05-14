use alloy_primitives::B256;
use anyhow::{anyhow, Result};

pub struct TzConfig {
    pub rpc_urls: Vec<String>,
    /// tz dispute game type ID; default 1961
    pub game_type: u32,
    /// proposer only; None for challenger
    pub rollup_config_hash: Option<B256>,
}

impl TzConfig {
    pub fn from_env() -> Result<Self> {
        let rpc_urls = Self::parse_rpc_urls()?;
        let game_type = Self::parse_game_type();
        let hash_str = std::env::var("TZ_ROLLUP_CONFIG_HASH")
            .map_err(|_| anyhow!("TZ_ROLLUP_CONFIG_HASH not set"))?;
        let rollup_config_hash = hash_str
            .parse::<B256>()
            .map_err(|e| anyhow!("invalid TZ_ROLLUP_CONFIG_HASH: {e}"))?;
        Ok(Self { rpc_urls, game_type, rollup_config_hash: Some(rollup_config_hash) })
    }

    pub fn challenger_from_env() -> Result<Self> {
        Ok(Self {
            rpc_urls: Self::parse_rpc_urls()?,
            game_type: Self::parse_game_type(),
            rollup_config_hash: None,
        })
    }

    fn parse_rpc_urls() -> Result<Vec<String>> {
        let raw = std::env::var("TZ_RPC_URLS")
            .map_err(|_| anyhow!("TZ_RPC_URLS not set"))?;
        Ok(raw.split(',').map(str::trim).map(String::from).collect())
    }

    fn parse_game_type() -> u32 {
        std::env::var("TZ_GAME_TYPE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1961)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn clear_tz_env() {
        env::remove_var("TZ_RPC_URLS");
        env::remove_var("TZ_ROLLUP_CONFIG_HASH");
        env::remove_var("TZ_GAME_TYPE");
    }

    #[test]
    fn from_env_parses_all_vars() {
        clear_tz_env();
        env::set_var("TZ_RPC_URLS", "http://a:8080,http://b:8080");
        env::set_var(
            "TZ_ROLLUP_CONFIG_HASH",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        env::set_var("TZ_GAME_TYPE", "42");

        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.rpc_urls, vec!["http://a:8080", "http://b:8080"]);
        assert_eq!(cfg.game_type, 42);
        assert!(cfg.rollup_config_hash.is_some());
        clear_tz_env();
    }

    #[test]
    fn from_env_errors_when_rpc_urls_missing() {
        clear_tz_env();
        env::set_var(
            "TZ_ROLLUP_CONFIG_HASH",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert!(TzConfig::from_env().is_err());
        clear_tz_env();
    }

    #[test]
    fn from_env_errors_when_rollup_config_hash_missing() {
        clear_tz_env();
        env::set_var("TZ_RPC_URLS", "http://a:8080");
        assert!(TzConfig::from_env().is_err());
        clear_tz_env();
    }

    #[test]
    fn game_type_defaults_to_1961_when_unset() {
        clear_tz_env();
        env::set_var("TZ_RPC_URLS", "http://a:8080");
        env::set_var(
            "TZ_ROLLUP_CONFIG_HASH",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let cfg = TzConfig::from_env().unwrap();
        assert_eq!(cfg.game_type, 1961);
        clear_tz_env();
    }

    #[test]
    fn challenger_from_env_does_not_require_rollup_config_hash() {
        clear_tz_env();
        env::set_var("TZ_RPC_URLS", "http://a:8080");
        let cfg = TzConfig::challenger_from_env().unwrap();
        assert!(cfg.rollup_config_hash.is_none());
        clear_tz_env();
    }
}
