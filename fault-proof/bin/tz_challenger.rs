use std::sync::Arc;

use alloy_provider::ProviderBuilder;
use anyhow::Result;
use clap::Parser;
use fault_proof::{
    challenger::OPSuccinctChallenger,
    config::ChallengerConfig,
    contract::{AnchorStateRegistry, DisputeGameFactory},
    prometheus::ChallengerGauge,
    tz::{chain_client::TzChainClient, config::TzConfig, l2_provider::TzL2Provider},
    L2ProviderTrait,
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

    // for tz: parse TzConfig (sync) before tokio starts
    let tz_config = TzConfig::challenger_from_env().unwrap_or_else(|e| {
        eprintln!("error: invalid tz config: {e}");
        std::process::exit(1);
    });

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(tz_config))
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });
}

async fn run(tz_config: TzConfig) -> Result<()> {
    setup_logger();

    // for tz: ChallengerConfig::from_env() parses L2_RPC as a single Url; override it with the
    // first endpoint so comma-separated tz RPC lists don't cause a parse error. The tz challenger
    // never uses challenger_config.l2_rpc (L2 access goes through TzL2Provider instead).
    if let Some(first) = tz_config.rpc_urls.first() {
        std::env::set_var("L2_RPC", first);
    }
    let challenger_config = ChallengerConfig::from_env()?;
    challenger_config.log();

    let tz_client = Arc::new(TzChainClient::new(tz_config.rpc_urls));
    let l2_provider: Arc<dyn L2ProviderTrait + Send + Sync> =
        Arc::new(TzL2Provider { tz_client: Arc::clone(&tz_client) });

    let challenger_signer = SignerLock::from_env().await?;
    let l1_provider = ProviderBuilder::default().connect_http(challenger_config.l1_rpc.clone());

    let anchor_state_registry = AnchorStateRegistry::new(
        challenger_config.anchor_state_registry_address,
        l1_provider.clone(),
    );
    let factory = DisputeGameFactory::new(challenger_config.factory_address, l1_provider.clone());

    let mut challenger = OPSuccinctChallenger::new_with_l2_provider(
        challenger_config,
        l1_provider,
        anchor_state_registry,
        factory,
        challenger_signer,
        l2_provider,
    );

    ChallengerGauge::register_all();
    init_metrics(&challenger.config.metrics_port);
    ChallengerGauge::init_all();

    challenger.run().await.expect("Runs in an infinite loop");
    Ok(())
}
