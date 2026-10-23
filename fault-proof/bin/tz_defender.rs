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
        handler::{Handler, InFlightGate},
        leaf_encoding_gate::{DeploymentTarget, LeafEncodingGate},
        leaf_locator::DirectLeafLocator,
        rootmanager_client::RootManagerClient,
        supervisor::Supervisor,
        watcher::Watcher,
        witness_wb::WbWitnessSource,
    },
    withdraw::wb_client::WbClient,
};
use op_succinct_host_utils::setup_logger;
use op_succinct_signer_utils::SignerLock;
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

    // Signer + refOrderId lookup endpoint: conditional on XLAYER_SIGNER_ENABLED.
    //
    // The Defender has different signer requirements from the Proposer and Challenger: it may run
    // without a signer, verifying challenges locally without broadcasting a prove transaction. The
    // gate is checked OUTSIDE `SignerLock::from_env()` because `from_env()` always requires at
    // least one signer type to be configured and bails when none is set. Only the XLayer signer
    // type is considered here; the Defender does not fall back to the HSM, Web3Signer, or Local
    // signers.
    //
    // When enabled, the signer and its lookup endpoint are built before any shared handle exists:
    // the lookup endpoint has to be bound while the signer is still exclusively owned, so it can
    // be wrapped in the shared handle afterwards (mutable-before-Arc). A misconfigured signer or an
    // unbindable lookup address then stops startup instead of silently leaving the asset-management
    // callback unanswered for the order IDs this service issues.
    let signer: Option<Arc<SignerLock>> = match std::env::var("XLAYER_SIGNER_ENABLED") {
        Ok(v) if v.to_lowercase() == "true" => {
            let s = SignerLock::from_env()
                .await
                .context("failed to initialize XLayer signer (XLAYER_SIGNER_ENABLED=true)")?;
            s.maybe_spawn_xlayer_verify_server()
                .await
                .context("failed to spawn xlayer verify server")?;
            Some(Arc::new(s))
        }
        _ => {
            tracing::info!(
                "XLAYER_SIGNER_ENABLED not set or false; running without a transaction signer. \
                     The Defender will verify challenges locally but will not broadcast prove \
                     transactions on-chain."
            );
            None
        }
    };

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
    let locator = DirectLeafLocator;
    let mut challenge = ChallengeManagerContract::new(
        l2_provider.clone(),
        config.challenge_contract,
        config.chain_id,
        locator,
    );
    // Reserve the shared signer on the adapter only when one was constructed. With no signer the
    // adapter keeps its default `None` and the scripted/offline path is unchanged.
    if let Some(ref s) = signer {
        challenge.set_signer(Arc::clone(s));
    }
    let challenge = Arc::new(challenge);

    // Cross-repo leaf-encoding compatibility gate: the sole entry to the Witness-Builder proof
    // flow, bound to the deployed challenge contract + chain id. Production passes no compatibility
    // declaration — none is published yet and none is constructible from local config/env/flags —
    // so the gate is unconditionally mismatched and every proof path is withheld with an observable
    // Blocked status; there is no local re-encode shim to mask it. The expected encoding
    // version / canonical hash / Witness-Builder identity are placeholders here: with no
    // declaration to match, they are never compared. Lifting fail-closed is a separate
    // contract/WB prerequisite (publish an authenticated, immutable declaration + wire an
    // authenticated read).
    let leaf_encoding_gate = Arc::new(LeafEncodingGate::new(
        DeploymentTarget {
            address: config.challenge_contract,
            chain_id: config.chain_id,
            expected_encoding_version: 0,
            expected_canonical_encoding_hash: alloy_primitives::B256::ZERO,
            expected_witness_builder_id: alloy_primitives::B256::ZERO,
        },
        None,
    ));
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
