//! Independent TradeZone Defender binary (spec §7.4, §7.5).
//!
//! Runs its OWN main loop, config, and signer — fully separate from the Proposer and L1
//! Challenger. It watches the X Layer Withdraw-challenge contract and, before each challenge's
//! response deadline, answers with a locally-verified historical inclusion proof.
//!
//! Signer policy (KB): production MUST use a remote/HSM-backed signer (`XLayerRemoteSigner`,
//! `CloudHsmSigner`, or `Web3Signer`) — never `LocalSigner`. This binary builds its signer via
//! `SignerLock::from_env`, the same env-driven path the proposer/challenger use, which enforces
//! that policy.
//!
//! Challenge-contract seam (spec §5 decision 1): the real X Layer challenge/prove ABI is not yet
//! finalized, so the binary wires the in-memory `MockChallengeContract` and logs a prominent
//! warning. When the real ABI lands, only the `ChallengeContract` implementation changes — the
//! watcher, handler state machine, and local verification are unchanged.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_provider::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use clap::Parser;
use fault_proof::tz::{
    defender::{
        challenge_contract::MockChallengeContract,
        config::DefenderConfig,
        handler::{Handler, HandlerOutcome},
        rootmanager_client::RootManagerClient,
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

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
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
        cache_capacity = config.cache_capacity,
        "tz-defender configuration loaded"
    );

    // Independent signer (KB rule: remote/HSM-backed, never LocalSigner — enforced by SignerLock).
    let _signer = SignerLock::from_env().await.context("failed to build defender signer")?;

    // Witness Builder v2 client + witness-source adapter.
    let wb = Arc::new(WbClient::new(config.wb_endpoint.clone(), config.chain_id)?);
    let witness = Arc::new(WbWitnessSource::new(wb));

    // RootManager (finalized covering roots) is read on the settlement L1 view.
    let l1_rpc = std::env::var("DEFENDER_L1_RPC")
        .context("DEFENDER_L1_RPC must be set (settlement-layer RPC for TZRootManager reads)")?;
    let l1_provider = ProviderBuilder::default()
        .connect_http(l1_rpc.parse().context("DEFENDER_L1_RPC must be a URL")?);
    let root_manager = Arc::new(RootManagerClient::new(config.root_manager, l1_provider.clone()));

    // Challenge-contract seam (decision 1): mock until the real X Layer ABI is wired.
    tracing::warn!(
        "tz-defender is running against the in-memory MockChallengeContract seam: the real X \
         Layer Withdraw-challenge ABI is not yet wired. Watcher/handler/verification are final; \
         only the ChallengeContract implementation will be swapped in."
    );
    let challenge = Arc::new(MockChallengeContract::new());

    let mut watcher = Watcher::new(challenge.clone(), config.finality_blocks);
    let handler = Handler::new(
        challenge.clone(),
        witness,
        root_manager,
        config.cache_capacity,
        config.deadline_safety_margin.as_secs(),
    );

    tracing::info!("tz-defender started; entering watch loop");
    loop {
        match l1_provider.get_block_number().await {
            Ok(l2_tip) => match watcher.poll(l2_tip).await {
                Ok(events) => {
                    for ev in events {
                        let now = now_unix();
                        match handler.handle(&ev, now).await {
                            Ok(HandlerOutcome::Proved(tx)) => tracing::info!(
                                leaf = %ev.leaf_hash, %tx, "defender proved challenge"
                            ),
                            Ok(HandlerOutcome::VerifyFailed) => tracing::error!(
                                leaf = %ev.leaf_hash,
                                "ALERT: local proof verification failed; no transaction sent"
                            ),
                            Ok(HandlerOutcome::StoppedNoProof) => tracing::error!(
                                leaf = %ev.leaf_hash,
                                "ALERT: deadline reached without a usable proof"
                            ),
                            Ok(other) => tracing::info!(
                                leaf = %ev.leaf_hash, ?other, "defender handled challenge"
                            ),
                            Err(e) => {
                                tracing::error!(leaf = %ev.leaf_hash, error = %e, "handler error")
                            }
                        }
                    }
                }
                Err(e) => tracing::error!(error = %e, "challenge watcher poll failed"),
            },
            Err(e) => tracing::error!(error = %e, "failed to read settlement tip"),
        }
        tokio::time::sleep(config.retry_backoff).await;
    }
}
