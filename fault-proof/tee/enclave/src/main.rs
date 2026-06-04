use std::sync::Arc;

use anyhow::Result;
#[cfg(all(target_os = "linux", feature = "vsock"))]
use sha3::{Digest, Keccak256};
use tracing::info;

use xlayer_tee_enclave::{gc, keys, server, task_manager::TaskManager};

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[tokio::main]
#[allow(unreachable_code)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    keys::init_dev_keys();
    info!("enclave key initialized, address={}", keys::enclave_address());

    #[cfg(not(all(target_os = "linux", feature = "vsock")))]
    let pcr0: [u8; 32] = [0u8; 32];

    #[cfg(all(target_os = "linux", feature = "vsock"))]
    let pcr0: [u8; 32] = {
        let raw = xlayer_tee_enclave::attestation::read_pcr0()?;
        let hash = Keccak256::digest(&raw);
        let c: [u8; 32] = hash.into();
        assert_ne!(c, [0u8; 32], "PCR0 hash must not be all zeros");
        c
    };

    let max_inflight: usize = parse_env("MAX_INFLIGHT_TASKS", 0);
    let ttl_secs: u64 = parse_env("TERMINAL_TTL_SECS", 3600);

    let manager = Arc::new(TaskManager::new(pcr0, max_inflight, ttl_secs));
    info!(max_inflight = max_inflight, ttl_secs = ttl_secs, "task manager initialized");

    if ttl_secs > 0 {
        tokio::spawn(gc::run_gc_loop(manager.clone(), 60));
    }

    let router = server::build_router(manager);

    #[cfg(not(all(target_os = "linux", feature = "vsock")))]
    {
        let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:7878".to_string());
        let listener = tokio::net::TcpListener::bind(&listen).await?;
        info!(listen = %listen, "serving on TCP");
        axum::serve(listener, router).await?;
    }

    #[cfg(all(target_os = "linux", feature = "vsock"))]
    {
        use hyper_util::service::TowerToHyperService;
        use tokio_vsock::VsockListener;

        let port: u32 = parse_env("VSOCK_PORT", 7878);
        let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port);
        let mut listener = VsockListener::bind(addr)?;
        info!(port = port, "serving on vsock");
        loop {
            let (stream, _addr) = listener.accept().await?;
            let svc = TowerToHyperService::new(router.clone());
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, svc)
                .await
                {
                    tracing::error!("vsock connection error: {e}");
                }
            });
        }
    }

    Ok(())
}
