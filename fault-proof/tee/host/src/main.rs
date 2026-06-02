use std::sync::Arc;

use clap::Parser;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use xlayer_tee_host::{
    config,
    enclave_client::EnclaveClient,
    server::{AppState, AttestationCache},
    task_manager::TaskManager,
};

#[derive(Parser)]
#[command(name = "xlayer-tee-host")]
struct Cli {
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).json().init();

    let cli = Cli::parse();
    let config_path = match config::resolve_config_path(cli.config.as_deref()) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}");
            std::process::exit(2);
        }
    };
    let host_config = match config::load_config(&config_path) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            std::process::exit(2);
        }
    };

    let bind_addr = host_config.server.bind_addr.clone();
    let task_manager = TaskManager::new(host_config.server.clone());
    let enclave_client = EnclaveClient::new(host_config.enclave.clone());

    let state = Arc::new(AppState {
        task_manager,
        enclave_client,
        attestation: Mutex::new(AttestationCache { doc: None, fetched_at: None }),
        config: host_config,
    });

    tokio::spawn(xlayer_tee_host::server::monitor_loop(state.clone()));
    tokio::spawn(xlayer_tee_host::server::sweeper_loop(state.clone()));

    let router = xlayer_tee_host::server::build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.expect("bind listener");
    tracing::info!("xlayer-tee-host listening on {bind_addr}");
    axum::serve(listener, router).await.expect("serve");
}
