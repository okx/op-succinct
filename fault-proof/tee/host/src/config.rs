use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct HostConfig {
    pub server: ServerConfig,
    pub enclave: EnclaveConfig,
    #[serde(default)]
    pub attestation: AttestationConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: String,
    #[serde(default = "default_retention")]
    pub task_retention_secs: u64,
    #[serde(default = "default_dedup")]
    pub dedup_ttl_secs: u64,
    #[serde(default = "default_monitor")]
    pub monitor_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnclaveConfig {
    #[serde(default)]
    pub vsock_cid: u32,
    #[serde(default)]
    pub vsock_port: u32,
    #[serde(default = "default_tcp_addr")]
    pub tcp_addr: String,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationConfig {
    #[serde(default = "default_attestation_ttl")]
    pub cache_ttl_secs: u64,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self { cache_ttl_secs: default_attestation_ttl() }
    }
}

fn default_retention() -> u64 {
    3600
}
fn default_dedup() -> u64 {
    300
}
fn default_monitor() -> u64 {
    30
}
fn default_tcp_addr() -> String {
    "127.0.0.1:7878".into()
}
fn default_request_timeout() -> u64 {
    180
}
fn default_attestation_ttl() -> u64 {
    60
}

const ENV_PREFIX: &str = "TEE_HOST__";

pub fn load_config(path: &str) -> Result<HostConfig, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let mut config: HostConfig =
        toml::from_str(&content).map_err(|e| format!("failed to parse TOML: {e}"))?;
    apply_env_overrides(&mut config);
    Ok(config)
}

fn apply_env_overrides(config: &mut HostConfig) {
    if let Ok(v) = std::env::var(format!("{ENV_PREFIX}SERVER__BIND_ADDR")) {
        config.server.bind_addr = v;
    }
    if let Ok(v) = std::env::var(format!("{ENV_PREFIX}SERVER__TASK_RETENTION_SECS")) {
        if let Ok(n) = v.parse() {
            config.server.task_retention_secs = n;
        }
    }
    if let Ok(v) = std::env::var(format!("{ENV_PREFIX}SERVER__DEDUP_TTL_SECS")) {
        if let Ok(n) = v.parse() {
            config.server.dedup_ttl_secs = n;
        }
    }
    if let Ok(v) = std::env::var(format!("{ENV_PREFIX}SERVER__MONITOR_INTERVAL_SECS")) {
        if let Ok(n) = v.parse() {
            config.server.monitor_interval_secs = n;
        }
    }
    if let Ok(v) = std::env::var(format!("{ENV_PREFIX}ENCLAVE__TCP_ADDR")) {
        config.enclave.tcp_addr = v;
    }
    if let Ok(v) = std::env::var(format!("{ENV_PREFIX}ENCLAVE__REQUEST_TIMEOUT_SECS")) {
        if let Ok(n) = v.parse() {
            config.enclave.request_timeout_secs = n;
        }
    }
    if let Ok(v) = std::env::var(format!("{ENV_PREFIX}ATTESTATION__CACHE_TTL_SECS")) {
        if let Ok(n) = v.parse() {
            config.attestation.cache_ttl_secs = n;
        }
    }
}

pub fn resolve_config_path(cli_path: Option<&str>) -> Result<String, String> {
    if let Some(p) = cli_path {
        return Ok(p.to_string());
    }
    if let Ok(p) = std::env::var("TEE_HOST_CONFIG") {
        return Ok(p);
    }
    let default = "config.toml";
    if std::path::Path::new(default).exists() {
        return Ok(default.to_string());
    }
    Err("config not found. Hint: cp config.example.toml config.toml".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn minimal_toml_applies_defaults() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "[server]\nbind_addr = \"0.0.0.0:8080\"\n[enclave]").unwrap();
        let cfg = load_config(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.server.bind_addr, "0.0.0.0:8080");
        assert_eq!(cfg.server.task_retention_secs, 3600);
        assert_eq!(cfg.server.dedup_ttl_secs, 300);
        assert_eq!(cfg.server.monitor_interval_secs, 30);
        assert_eq!(cfg.enclave.tcp_addr, "127.0.0.1:7878");
        assert_eq!(cfg.enclave.request_timeout_secs, 180);
        assert_eq!(cfg.attestation.cache_ttl_secs, 60);
    }

    #[test]
    fn full_toml_parses_all_fields() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "[server]\nbind_addr = \"0.0.0.0:9090\"\ntask_retention_secs = 7200\ndedup_ttl_secs = 600\nmonitor_interval_secs = 15\n\n[enclave]\nvsock_cid = 16\nvsock_port = 5005\ntcp_addr = \"10.0.0.1:7878\"\nrequest_timeout_secs = 300\n\n[attestation]\ncache_ttl_secs = 120"
        )
        .unwrap();
        let cfg = load_config(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.server.task_retention_secs, 7200);
        assert_eq!(cfg.server.dedup_ttl_secs, 600);
        assert_eq!(cfg.enclave.vsock_cid, 16);
        assert_eq!(cfg.enclave.tcp_addr, "10.0.0.1:7878");
        assert_eq!(cfg.attestation.cache_ttl_secs, 120);
    }

    #[test]
    fn missing_config_returns_hint() {
        let result = resolve_config_path(None);
        if result.is_err() {
            assert!(result.unwrap_err().contains("cp config.example.toml config.toml"));
        }
    }

    #[test]
    fn invalid_toml_returns_error() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "not valid toml {{{{").unwrap();
        let result = load_config(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse TOML"));
    }
}
