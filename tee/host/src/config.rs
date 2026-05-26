//! Host configuration loaded from toml + env override (`TEE_HOST__SECTION__FIELD`).

use std::path::Path;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub enclave: EnclaveConfig,
    pub attestation: AttestationConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: String,
    #[serde(default = "default_retention_secs")]
    pub task_retention_secs: u64,
    /// Dedup window: identical witness body within this window returns the
    /// existing task_id instead of starting a new task.
    #[serde(default = "default_dedup_ttl_secs")]
    pub dedup_ttl_secs: u64,
    /// Background log frequency for task status.
    #[serde(default = "default_monitor_interval_secs")]
    pub monitor_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnclaveConfig {
    /// Used when feature = "vsock" (Linux + prod).
    #[serde(default)]
    pub vsock_cid: u32,
    #[serde(default)]
    pub vsock_port: u32,
    /// Used otherwise (dev / macOS / CI).
    #[serde(default = "default_tcp_addr")]
    pub tcp_addr: String,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationConfig {
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let _ = dotenvy::dotenv();
        let cfg = ::config::Config::builder()
            .add_source(::config::File::from(path.as_ref()))
            .add_source(::config::Environment::with_prefix("TEE_HOST").separator("__"))
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}

fn default_retention_secs() -> u64 { 3600 }
fn default_dedup_ttl_secs() -> u64 { 300 }
fn default_monitor_interval_secs() -> u64 { 30 }
fn default_tcp_addr() -> String { "127.0.0.1:7878".into() }
fn default_request_timeout_secs() -> u64 { 180 }
fn default_cache_ttl_secs() -> u64 { 60 }

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write to a tempfile under cargo's target/ (the only directory guaranteed
    /// writable from `cargo test`). System tempdirs (`/var/folders/...`) may be
    /// blocked by sandbox.
    fn write_toml(toml: &str) -> tempfile::NamedTempFile {
        let dir = std::env::var("CARGO_TARGET_TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap().join("target/test-tmp"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = tempfile::Builder::new().suffix(".toml").tempfile_in(&dir).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        f
    }

    /// Serialize env-touching tests via a static mutex. The `config` crate reads
    /// the *process* env, so parallel tests can race without this.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn clear_tee_host_env() {
        let keys: Vec<String> = std::env::vars()
            .filter(|(k, _)| k.starts_with("TEE_HOST__"))
            .map(|(k, _)| k)
            .collect();
        for k in keys {
            // SAFETY: held under env_lock() for the duration of the test.
            unsafe { std::env::remove_var(&k); }
        }
    }

    #[test]
    fn loads_minimal_toml_with_defaults() {
        let _g = env_lock();
        clear_tee_host_env();
        let toml = r#"
[server]
bind_addr = "127.0.0.1:1234"
[enclave]
[attestation]
"#;
        let f = write_toml(toml);
        let cfg = Config::load(f.path()).expect("load");
        assert_eq!(cfg.server.bind_addr, "127.0.0.1:1234");
        assert_eq!(cfg.server.task_retention_secs, 3600);
        assert_eq!(cfg.server.dedup_ttl_secs, 300);
        assert_eq!(cfg.server.monitor_interval_secs, 30);
        assert_eq!(cfg.enclave.tcp_addr, "127.0.0.1:7878");
        assert_eq!(cfg.enclave.request_timeout_secs, 180);
        assert_eq!(cfg.attestation.cache_ttl_secs, 60);
    }

    #[test]
    fn env_override_beats_toml_value() {
        let _g = env_lock();
        clear_tee_host_env();
        const KEY: &str = "TEE_HOST__SERVER__BIND_ADDR";
        let toml = r#"
[server]
bind_addr = "127.0.0.1:1234"
[enclave]
[attestation]
"#;
        let f = write_toml(toml);
        // SAFETY: held under env_lock() for the duration of this test.
        unsafe { std::env::set_var(KEY, "0.0.0.0:9999"); }
        let cfg = Config::load(f.path()).expect("load");
        unsafe { std::env::remove_var(KEY); }
        assert_eq!(cfg.server.bind_addr, "0.0.0.0:9999");
    }
}
