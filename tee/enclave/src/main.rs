//! xlayer-tee-enclave binary entry.
//!
//! Default build (no features): TCP `127.0.0.1:7878` with hardcoded dev key,
//! placeholder attestation, and PCR0 = `[0u8; 32]`. Run via
//! `cargo run -p xlayer-tee-enclave`.
//!
//! `--features vsock` (linux only, real Nitro): vsock listener on
//! `(VMADDR_CID_ANY, VSOCK_PORT)`, fresh `OsRng` ENCLAVE_KEY, NSM-produced
//! attestation document, and real PCR0 read via `NSM DescribePCR { index: 0 }`.
//!
//! Task-manager environment variables:
//! - `MAX_INFLIGHT_TASKS`: 0 (auto = num_cpus / 2) or a positive integer
//! - `TERMINAL_TTL_SECS`: how long terminal task state persists (default 3600s)
//!
//! **EIP712 domain is *not* configured at startup.** `chainId` and
//! `verifyingContract` come per-request via the `x-eip712-chain-id` and
//! `x-eip712-verifying-contract` headers on `POST /tasks/range` (see
//! `xlayer_tee_types::paths`). One EIF can therefore serve any number of
//! verifier contracts and L1 chains — redeploying the verifier does **not**
//! require rebuilding the EIF or re-attesting.

use std::sync::Arc;

use tracing::info;
use xlayer_tee_enclave::{
    gc::run_gc_loop,
    keys::{enclave_address, enclave_pubkey_uncompressed, init_dev_keys},
    server::{AppState, router},
    task_manager::TaskManager,
};

#[cfg(all(target_os = "linux", feature = "vsock"))]
use {
    axum::serve::Listener,
    std::io,
    tokio_vsock::{VsockAddr, VsockListener, VsockStream},
};

const DEFAULT_TTL_SECS: u64 = 3600;
const ENV_MAX_INFLIGHT: &str = "MAX_INFLIGHT_TASKS";
const ENV_TERMINAL_TTL_SECS: &str = "TERMINAL_TTL_SECS";

#[cfg(all(target_os = "linux", feature = "vsock"))]
const VSOCK_PORT: u32 = 7878;
#[cfg(all(target_os = "linux", feature = "vsock"))]
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

// ---------------------------------------------------------------------------
// vsock listener adapter (linux + vsock only)
//
// axum's `serve` API expects something that implements `axum::serve::Listener`;
// the stock `tokio_vsock::VsockListener` doesn't. We wrap it in a small mpsc
// adapter so axum can drive it with the same `accept().await` pattern.
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "vsock"))]
struct VsockListenerAdapter {
    rx: tokio::sync::mpsc::Receiver<(VsockStream, VsockAddr)>,
}

#[cfg(all(target_os = "linux", feature = "vsock"))]
impl VsockListenerAdapter {
    fn new(mut listener: VsockListener) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(conn) => {
                        if tx.send(conn).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => tracing::error!(error = %e, "vsock accept error"),
                }
            }
        });
        Self { rx }
    }
}

#[cfg(all(target_os = "linux", feature = "vsock"))]
impl Listener for VsockListenerAdapter {
    type Io = VsockStream;
    type Addr = VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        self.rx.recv().await.expect("vsock accept channel closed")
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT))
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    init_dev_keys();

    // dev build: PCR0 is a mock all-zero measurement.
    // vsock build: read real PCR0 via NSM and compress the 48-byte SHA-384
    //   into 32 bytes via keccak256 so it fits the signed RangeJournal.pcr0
    //   field and matches EXPECTED_PCR0_HASH baked into the SP1 aggregation
    //   vkey.
    #[cfg(not(all(target_os = "linux", feature = "vsock")))]
    let pcr0: [u8; 32] = [0u8; 32];
    #[cfg(all(target_os = "linux", feature = "vsock"))]
    let pcr0: [u8; 32] = {
        let raw = xlayer_tee_enclave::attestation::read_pcr0()
            .expect("NSM DescribePCR { index: 0 } must succeed inside the enclave");
        alloy_primitives::keccak256(&raw).0
    };

    let max_inflight: usize = std::env::var(ENV_MAX_INFLIGHT)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0); // 0 = auto
    let ttl_secs: u64 = std::env::var(ENV_TERMINAL_TTL_SECS)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TTL_SECS);

    let task_manager = TaskManager::new(pcr0, max_inflight, ttl_secs);

    // GC loop runs forever in the background; aborts on runtime drop.
    tokio::spawn(run_gc_loop(Arc::clone(&task_manager)));

    let state = AppState::new(Arc::clone(&task_manager));
    let app = router(state);

    #[cfg(all(target_os = "linux", feature = "vsock"))]
    {
        let vsock_addr = VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT);
        let listener = VsockListener::bind(vsock_addr).expect("vsock bind failed");

        info!(
            cid = VMADDR_CID_ANY,
            port = VSOCK_PORT,
            signer = %enclave_address(),
            signer_pubkey = %hex::encode(enclave_pubkey_uncompressed()),
            pcr0 = %hex::encode(pcr0),
            max_inflight = task_manager.max_inflight(),
            ttl_secs,
            "xlayer-tee-enclave (vsock build, real NSM) listening; EIP712 domain set per-request",
        );

        axum::serve(VsockListenerAdapter::new(listener), app)
            .await
            .expect("axum vsock server failed");
    }

    #[cfg(not(all(target_os = "linux", feature = "vsock")))]
    {
        let addr: std::net::SocketAddr = std::env::var("LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:7878".into())
            .parse()
            .expect("invalid LISTEN address");

        let listener = tokio::net::TcpListener::bind(addr).await.expect("bind failed");

        info!(
            %addr,
            signer = %enclave_address(),
            signer_pubkey = %hex::encode(enclave_pubkey_uncompressed()),
            max_inflight = task_manager.max_inflight(),
            ttl_secs,
            "xlayer-tee-enclave (dev build, async task model) listening; EIP712 domain set per-request",
        );

        axum::serve(listener, app).await.expect("axum server failed");
    }
}
