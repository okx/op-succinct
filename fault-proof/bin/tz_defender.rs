//! Independent TradeZone Defender binary.
//!
//! Runs its own main loop, config, and signer — fully separate from the Proposer and L1
//! Challenger. It watches the X Layer Withdraw-challenge contract and, before each challenge's
//! response deadline, answers with a locally-verified inclusion proof.
//!
//! Signer: optional, enabled only when `XLAYER_SIGNER_ENABLED=true`. The Defender may run without
//! a signer (local verification only, no on-chain broadcast), so the gate is checked before the
//! signer environment is read. When enabled, the binary builds its XLayer signer from the shared
//! signer environment and asks it to serve the asset-management refOrderId lookup endpoint, so the
//! order IDs the Defender issues for its own responses are answerable by the asset-management
//! callback from the moment it starts. The challenge/prove ABI's on-chain submission path is not
//! yet delivered (the sender is the in-memory mock seam below), so the signer handle is reserved
//! for that sender rather than used to broadcast today; no proof transaction is sent by this
//! binary yet.
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
        challenge_contract::{ChallengeEventSource, ScanWindow},
        challenge_manager::ChallengeManagerContract,
        config::DefenderConfig,
        context::make_defender_context,
        handler::{Handler, InFlightGate},
        leaf_locator::DirectLeafLocator,
        rootmanager_client::RootManagerClient,
        signer::wire_defender_signer,
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

    // Resolve the protected configuration items before any component reads the environment, so a
    // value backed by the key service is resolved (or fails closed) rather than being consumed as
    // the literal placeholder. Matches the other service entrypoints.
    op_succinct_config_kms::init_startup_config().unwrap_or_else(|e| {
        eprintln!("error: startup config resolution failed: {e}");
        std::process::exit(1);
    });

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run())
        .unwrap_or_else(|e| {
            // Print the whole error chain: a signer or lookup-endpoint misconfiguration must be
            // diagnosable from the startup log alone, not just as "failed to initialize".
            eprintln!("error: {e:#}");
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

    // Challenge-contract seam: the real ChallengeManager adapter (WithdrawNotInRoot only), wired
    // with the direct leaf-locator — the event carries the Merkle leaf explicitly, so the leaf is
    // read straight from it. The Defender hosts the asset-management refOrderId lookup endpoint for
    // the order IDs it issues, but it does not consume a reverse lookup to find leaves, so nothing
    // about a reverse-lookup service gates the challenge-listening chain. One honest limitation
    // remains: the challenge/prove ABI's on-chain submission path is not yet delivered, so
    // submitWithdrawProof calldata is built but not broadcast; the shared signer is reserved for
    // that sender.
    let ctx = make_defender_context(&config);
    let challenge: Arc<ChallengeManagerContract<DirectLeafLocator>> =
        Arc::new(ChallengeManagerContract::new(
            l2_provider.clone(),
            config.challenge_contract,
            config.chain_id,
            ctx.locator,
        ));

    // Signer + refOrderId lookup endpoint: conditional on XLAYER_SIGNER_ENABLED, and built by the
    // same function the integration tests call, so the wiring under test is the wiring that ships.
    //
    // The Defender has different signer requirements from the Proposer and Challenger: it may run
    // without a signer, verifying challenges locally without broadcasting a prove transaction. The
    // gate is checked before the signer environment is read, because reading it always requires at
    // least one signer type to be configured. Only the XLayer signer type is considered; there is
    // no fallback to the HSM, Web3Signer, or Local signers.
    //
    // A misconfigured signer, or a lookup address that cannot be bound, stops startup instead of
    // silently leaving the asset-management callback unanswered for the order IDs this service
    // issues.
    let _listener_client =
        wire_defender_signer(&challenge).await.context("failed to wire the Defender signer")?;

    // Cross-repo leaf-encoding compatibility gate: the sole entry to the Witness-Builder proof
    // flow, bound to the deployed challenge contract + chain id. Built by the shared challenge
    // context so the integration tests exercise the same wiring; it is unconditionally mismatched
    // until a deployment-bound compatibility declaration exists.
    let leaf_encoding_gate = ctx.leaf_encoding_gate;
    tracing::info!(
        challenge_contract = %config.challenge_contract,
        "tz-defender wired the real ChallengeManager adapter (WithdrawNotInRoot only) with the \
         direct event-leaf locator and the shared signer; the Witness-Builder proof flow stays \
         behind the leaf-encoding compatibility gate until the contract and Witness-Builder \
         encodings are declared compatible for this deployment, and the on-chain submission path \
         is not yet wired, so no proof transaction is broadcast"
    );

    // Global single-process in-flight gate (at most one broadcast in flight); lost on restart.
    let gate = InFlightGate::new();
    let watcher = Watcher::new(challenge.clone());
    let handler = Handler::new(
        challenge.clone(),
        challenge.clone(),
        witness,
        root_manager,
        leaf_encoding_gate,
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
