//! Independent TradeZone Defender binary.
//!
//! Runs its own main loop, config, and signer — fully separate from the Proposer and L1
//! Challenger. It watches the X Layer Withdraw-challenge contract and, before each challenge's
//! response deadline, answers with a locally-verified inclusion proof.
//!
//! Signer: no transaction signer is wired in this stage. The challenge/prove ABI and its on-chain
//! submission path are not yet delivered (the sender is the in-memory mock seam below), so the
//! binary constructs no signer and makes NO signer-policy guarantee. When the real challenge sender
//! adapter lands it will construct and validate its own signer; nothing here should be read as a
//! promise that a remote/HSM signer is already enforced.
//!
//! Challenge-contract seam: the real X Layer challenge/prove ABI is not yet finalized, so the
//! binary wires the in-memory `MockChallengeContract` and logs a prominent warning. When the real
//! ABI lands, only the event-source/reader/sender implementations change — the watcher, handler
//! state machine, and local verification are unchanged.
//!
//! Topology: the challenge contract and the RootManager live on X Layer / L2. `DEFENDER_L2_RPC`
//! (the X Layer/L2 provider) supplies challenge events, the L2 tip used for finality gating,
//! challenge status/deadline reads, the current/latest RootManager root, and the eventual proof
//! transaction. The witness builder RPC supplies only record/proof witness data.

use std::sync::Arc;

use alloy_provider::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use clap::Parser;
use fault_proof::tz::{
    defender::{
        challenge_contract::{ChallengeEventSource, MockChallengeContract, ScanWindow},
        config::DefenderConfig,
        handler::{Handler, InFlightGate},
        rootmanager_client::RootManagerClient,
        supervisor::Supervisor,
        watcher::Watcher,
        witness_wb::WbWitnessSource,
    },
    withdraw::wb_client::WbClient,
};
use op_succinct_host_utils::setup_logger;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

#[derive(Parser)]
#[command(name = "tz-defender")]
struct Args {
    #[arg(long, default_value = ".env.tz-defender")]
    env_file: String,
}

fn main() {
    let args = Args::parse();
    if let Err(e) = dotenv::from_filename(&args.env_file) {
        eprintln!("error: failed to load env file '{}': {}", args.env_file, e);
        std::process::exit(1);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run())
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });
}

/// The watcher tip is the current L2 block height read from the X Layer/L2 provider — never the L1
/// settlement provider. The watcher then gates events by the configured finality depth.
async fn l2_watch_tip<P: Provider>(l2_provider: &P) -> Result<u64> {
    l2_provider.get_block_number().await.context("failed to read X Layer/L2 block height")
}

async fn run() -> Result<()> {
    setup_logger();

    let config = DefenderConfig::from_env()?;
    tracing::info!(
        challenge_contract = %config.challenge_contract,
        root_manager = %config.root_manager,
        wb_endpoint = %config.wb_endpoint,
        chain_id = config.chain_id,
        finality_blocks = config.finality_blocks,
        max_resend = config.max_resend,
        cache_capacity = config.cache_capacity,
        "tz-defender configuration loaded"
    );

    // No transaction signer is constructed here: this stage sends no real prove transaction (the
    // challenge sender is the mock seam below), so building an unused signer — which would also
    // read shared signer env and could fall back to a local key — is deliberately omitted. The
    // real signer is constructed and validated by the challenge sender adapter when the
    // on-chain ABI is delivered.

    // Witness Builder v2 client + witness-source adapter (record/proof witness data only).
    let wb = Arc::new(WbClient::new(config.wb_endpoint.clone(), config.chain_id)?);
    let witness = Arc::new(WbWitnessSource::new(wb));

    // X Layer / L2 provider: challenge events, the L2 tip for finality gating, challenge
    // status/deadline reads, and the current/latest RootManager root all read here.
    let l2_rpc = std::env::var("DEFENDER_L2_RPC")
        .context("DEFENDER_L2_RPC must be set (X Layer/L2 RPC for events, tip, and RootManager)")?;
    let l2_provider = ProviderBuilder::default()
        .connect_http(l2_rpc.parse().context("DEFENDER_L2_RPC must be a URL")?);
    let root_manager = Arc::new(RootManagerClient::new(config.root_manager, l2_provider.clone()));

    // Challenge-contract seam: mock until the real X Layer ABI is wired.
    tracing::warn!(
        "tz-defender is running against the in-memory MockChallengeContract seam: the real X \
         Layer Withdraw-challenge ABI is not yet wired. Watcher/handler/verification are final; \
         only the challenge event-source/reader/sender implementations will be swapped in."
    );
    let challenge = Arc::new(MockChallengeContract::new());

    // Global single-process in-flight gate (at most one broadcast in flight); lost on restart.
    let gate = InFlightGate::new();
    let watcher = Watcher::new(challenge.clone());
    let handler = Handler::new(
        challenge.clone(),
        challenge.clone(),
        witness,
        root_manager,
        config.chain_id,
        config.cache_capacity,
        config.deadline_safety_margin.as_secs(),
        config.max_resend,
    );
    let mut supervisor = Supervisor::new(
        watcher,
        handler,
        challenge.clone(),
        gate,
        config.finality_blocks,
        config.startup_lookback,
        config.reorg_safety_margin,
    );

    // Startup recovery: rescan an EXPLICIT bounded window (finality applied once), reconcile
    // still-open challenges by current on-chain status only. `config.startup_lookback` reaches the
    // scan path here (the reviewed binary called a parameterless watch()).
    match l2_watch_tip(&l2_provider).await {
        Ok(head) => {
            let actionable_to = head.saturating_sub(config.finality_blocks);
            let startup_window = ScanWindow {
                from_block: actionable_to.saturating_sub(config.startup_lookback),
                to_block: actionable_to,
            };
            match challenge.watch_opened(startup_window).await {
                Ok(rediscovered) => {
                    if let Err(e) = supervisor.reconcile_on_startup(&rediscovered).await {
                        tracing::error!(error = %e, "startup reconciliation failed");
                    }
                }
                Err(e) => tracing::error!(error = %e, "startup rescan failed"),
            }
        }
        Err(e) => tracing::error!(error = %e, "failed to read X Layer/L2 head for startup rescan"),
    }

    tracing::info!("tz-defender started; entering supervisor loop");
    loop {
        // Pass the RAW L2 latest head; the supervisor computes actionable_to = H - finality_blocks
        // exactly once (Model A).
        match l2_watch_tip(&l2_provider).await {
            Ok(l2_head) => {
                if let Err(e) = supervisor.tick(l2_head).await {
                    tracing::error!(error = %e, "supervisor tick failed");
                }
            }
            Err(e) => tracing::error!(error = %e, "failed to read X Layer/L2 head"),
        }
        tokio::time::sleep(config.retry_backoff).await;
    }
}
