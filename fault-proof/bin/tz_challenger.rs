use std::sync::Arc;

use alloy_provider::ProviderBuilder;
use anyhow::Result;
use clap::Parser;
use fault_proof::{
    challenger::OPSuccinctChallenger,
    config::{ChallengerConfig, TzGameValidatorConfig},
    contract::{AnchorStateRegistry, DisputeGameFactory},
    prometheus::ChallengerGauge,
    tz::game_validator::TzGameValidator,
};
use op_succinct_host_utils::{
    metrics::{init_metrics, MetricsGauge},
    setup_logger,
};
use op_succinct_signer_utils::SignerLock;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

#[derive(Parser)]
#[command(name = "tz-challenger")]
struct Args {
    #[arg(long, default_value = ".env.tz-challenger")]
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

async fn run() -> Result<()> {
    setup_logger();

    let challenger_config = ChallengerConfig::from_env()?;
    challenger_config.log();
    let validator_config = TzGameValidatorConfig::from_env()?;
    validator_config.log();

    let challenger_signer = SignerLock::from_env().await?;
    let l1_provider = ProviderBuilder::default().connect_http(challenger_config.l1_rpc.clone());

    let anchor_state_registry = AnchorStateRegistry::new(
        challenger_config.anchor_state_registry_address,
        l1_provider.clone(),
    );
    let factory = DisputeGameFactory::new(challenger_config.factory_address, l1_provider.clone());

    let game_validator =
        Arc::new(TzGameValidator::new(anchor_state_registry.clone(), validator_config.l2_rpc)?);

    let mut challenger = OPSuccinctChallenger::new_with_game_validator(
        challenger_config,
        l1_provider,
        anchor_state_registry,
        factory,
        challenger_signer,
        game_validator,
    );

    ChallengerGauge::register_all();
    init_metrics(&challenger.config.metrics_port);
    ChallengerGauge::init_all();

    challenger.run().await.expect("Runs in an infinite loop");
    Ok(())
}
