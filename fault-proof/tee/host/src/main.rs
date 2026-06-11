use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use xlayer_tee_types::wire;

use xlayer_tee_host::{
    config::load_config,
    enclave_client::EnclaveClient,
    mem,
    server::{self, AppState, AttestationCache},
    task_manager::TaskManager,
};

#[derive(Parser)]
#[command(name = "xlayer-tee-host")]
struct Cli {
    #[arg(long, env = "TEE_HOST_CONFIG")]
    config: Option<String>,
}

fn init_tracing() {
    let format = std::env::var("TEE_HOST_LOG_FORMAT").unwrap_or_default();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if format == "json" {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

#[tokio::main]
async fn main() {
    init_tracing();

    let cli = Cli::parse();
    let config = match load_config(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Hint: cp config.example.toml config.toml");
            std::process::exit(2);
        }
    };

    let config = Arc::new(config);
    let bind_addr = config.server.bind_addr.clone();

    let task_manager = Arc::new(TaskManager::new(Arc::clone(&config)));
    let enclave = Arc::new(EnclaveClient::new(Arc::clone(&config)));

    let state = Arc::new(AppState {
        task_manager: Arc::clone(&task_manager),
        enclave: Arc::clone(&enclave),
        config: Arc::clone(&config),
        attestation_cache: Arc::new(tokio::sync::Mutex::new(AttestationCache::new())),
    });

    let body_limit = wire::MAX_RANGE_BODY_BYTES + 1024;

    let app = Router::new()
        .route("/tee/task", post(server::create_task))
        .route("/tee/task/:id", get(server::query_task))
        .route("/tee/task/:id", delete(server::delete_task))
        .route("/tee/info", get(server::query_attestation))
        .route("/debug/*rest", get(server::proxy_debug))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(Arc::clone(&state));

    let monitor_state = Arc::clone(&state);
    tokio::spawn(async move {
        server::run_monitor(monitor_state).await;
    });

    let sweeper_state = Arc::clone(&state);
    tokio::spawn(async move {
        server::run_sweeper(sweeper_state).await;
    });

    // Spawn a periodic RSS logger. Interval comes from env, default 5s.
    let rss_interval_secs: u64 = std::env::var("TEE_HOST_MEM_LOG_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    mem::spawn_rss_logger(rss_interval_secs);

    tracing::info!(
        bind_addr = %bind_addr,
        rss_log_interval_secs = rss_interval_secs,
        "xlayer-tee-host starting"
    );

    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind {bind_addr}: {e}");
        std::process::exit(1);
    });

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        tracing::error!(error = %e, "server error");
    });
}
