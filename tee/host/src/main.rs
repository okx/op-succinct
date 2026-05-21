//! `xlayer-tee-host` binary entry.

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use xlayer_tee_host::{
    config::Config, server::AppState, EnclaveClient, TaskManager,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config_path = parse_config_arg()
        .or_else(|| std::env::var("TEE_HOST_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".into());
    let config = Arc::new(Config::load(&config_path).with_context(|| {
        format!("load config from {}", config_path)
    })?);
    tracing::info!(?config, "config loaded");

    let enclave = Arc::new(
        EnclaveClient::connect(config.enclave.clone())
            .await
            .context("connect enclave")?,
    );
    let tasks = Arc::new(TaskManager::new(
        config.server.task_retention_secs,
        config.server.dedup_ttl_secs,
    ));

    tokio::spawn(xlayer_tee_host::task_manager::run_retention_sweeper(tasks.clone()));
    tokio::spawn(xlayer_tee_host::server::run_task_monitor(
        tasks.clone(),
        enclave.clone(),
        config.server.monitor_interval_secs,
    ));

    let state = AppState {
        config: config.clone(),
        tasks,
        enclave,
        info_cache: Arc::new(Mutex::new(None)),
    };
    let app = xlayer_tee_host::server::router(state);

    let listener = tokio::net::TcpListener::bind(&config.server.bind_addr)
        .await
        .with_context(|| format!("bind {}", config.server.bind_addr))?;
    tracing::info!(addr = %config.server.bind_addr, "xlayer-tee-host listening");

    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

/// Accepts `--config <path>` or `--config=<path>`.
fn parse_config_arg() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" {
            return args.next();
        }
        if let Some(v) = a.strip_prefix("--config=") {
            return Some(v.to_string());
        }
    }
    None
}
