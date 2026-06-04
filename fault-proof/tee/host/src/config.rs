use serde::Deserialize;

fn default_task_retention() -> u64 {
    3600
}
fn default_dedup_ttl() -> u64 {
    300
}
fn default_monitor_interval() -> u64 {
    30
}
fn default_tcp_addr() -> String {
    "127.0.0.1:7878".to_string()
}
fn default_request_timeout() -> u64 {
    180
}
fn default_cache_ttl() -> u64 {
    60
}

#[derive(Debug, Deserialize, Clone)]
pub struct HostConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub enclave: EnclaveConfig,
    #[serde(default)]
    pub attestation: AttestationConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    #[serde(default = "default_task_retention")]
    pub task_retention_secs: u64,
    #[serde(default = "default_dedup_ttl")]
    pub dedup_ttl_secs: u64,
    #[serde(default = "default_monitor_interval")]
    pub monitor_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
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

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self {
            vsock_cid: 0,
            vsock_port: 0,
            tcp_addr: default_tcp_addr(),
            request_timeout_secs: default_request_timeout(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AttestationConfig {
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self { cache_ttl_secs: default_cache_ttl() }
    }
}

pub fn load_config(config_path: Option<&str>) -> Result<HostConfig, String> {
    let mut builder = config::Config::builder();

    let path = config_path
        .map(|p| p.to_string())
        .or_else(|| std::env::var("TEE_HOST_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".to_string());

    if std::path::Path::new(&path).exists() {
        builder = builder.add_source(config::File::with_name(&path).required(false));
    }

    builder = builder
        .add_source(config::Environment::with_prefix("TEE_HOST").separator("__").try_parsing(true));

    let cfg = builder.build().map_err(|e| format!("config build error: {e}"))?;
    let host_config: HostConfig =
        cfg.try_deserialize().map_err(|e| format!("config parse error: {e}"))?;

    Ok(host_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_parsing_applies_defaults() {
        let toml_str = r#"
[server]
bind_addr = "0.0.0.0:18080"
"#;
        let cfg: HostConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.server.bind_addr, "0.0.0.0:18080");
        assert_eq!(cfg.server.task_retention_secs, 3600);
        assert_eq!(cfg.server.dedup_ttl_secs, 300);
        assert_eq!(cfg.server.monitor_interval_secs, 30);
        assert_eq!(cfg.enclave.tcp_addr, "127.0.0.1:7878");
        assert_eq!(cfg.enclave.request_timeout_secs, 180);
        assert_eq!(cfg.attestation.cache_ttl_secs, 60);
    }

    #[test]
    fn toml_parsing_custom_values() {
        let toml_str = r#"
[server]
bind_addr = "0.0.0.0:9999"
task_retention_secs = 7200
dedup_ttl_secs = 600
monitor_interval_secs = 15

[enclave]
tcp_addr = "10.0.0.1:7878"
request_timeout_secs = 60

[attestation]
cache_ttl_secs = 120
"#;
        let cfg: HostConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.server.bind_addr, "0.0.0.0:9999");
        assert_eq!(cfg.server.task_retention_secs, 7200);
        assert_eq!(cfg.server.dedup_ttl_secs, 600);
        assert_eq!(cfg.server.monitor_interval_secs, 15);
        assert_eq!(cfg.enclave.tcp_addr, "10.0.0.1:7878");
        assert_eq!(cfg.enclave.request_timeout_secs, 60);
        assert_eq!(cfg.attestation.cache_ttl_secs, 120);
    }

    #[test]
    fn enclave_config_defaults() {
        let enc = EnclaveConfig::default();
        assert_eq!(enc.vsock_cid, 0);
        assert_eq!(enc.vsock_port, 0);
        assert_eq!(enc.tcp_addr, "127.0.0.1:7878");
        assert_eq!(enc.request_timeout_secs, 180);
    }

    #[test]
    fn attestation_config_defaults() {
        let att = AttestationConfig::default();
        assert_eq!(att.cache_ttl_secs, 60);
    }
}
