use std::sync::Arc;

use alloy_provider::ProviderBuilder;
use anyhow::Result;
use clap::Parser;
use fault_proof::{
    config::ProposerConfig,
    contract::{AnchorStateRegistry, DisputeGameFactory},
    prometheus::ProposerGauge,
    proposer::OPSuccinctProposer,
    tz::chain_client::TzChainClient,
    tz::config::TzConfig,
    tz::l2_provider::TzL2Provider,
    L2ProviderTrait,
};
use op_succinct_host_utils::{
    fetcher::OPSuccinctDataFetcher,
    metrics::{init_metrics, MetricsGauge},
    setup_logger,
};
use op_succinct_proof_utils::initialize_host;
use op_succinct_signer_utils::SignerLock;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

static TZ_RANGE_ELF: &[u8] = include_bytes!("../elfs/tz-range.elf");
static TZ_AGGREGATION_ELF: &[u8] = include_bytes!("../elfs/tz-aggregation.elf");

#[derive(Parser)]
#[command(name = "tz-proposer")]
struct Args {
    #[arg(long, default_value = ".env.tz-proposer")]
    env_file: String,
}

fn main() {
    let args = Args::parse();
    if let Err(e) = dotenv::from_filename(&args.env_file) {
        eprintln!("error: failed to load env file '{}': {}", args.env_file, e);
        std::process::exit(1);
    }

    // for tz: parse TzConfig (sync) before tokio starts so set_var is single-threaded safe
    let tz_config = TzConfig::from_env().unwrap_or_else(|e| {
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

    // for tz: ProposerConfig::from_env() parses L2_RPC as a single Url; override it with the
    // first endpoint so comma-separated tz RPC lists don't cause a parse error. The tz proposer
    // never uses proposer_config.l2_rpc (L2 access goes through TzL2Provider instead).
    if let Some(first) = tz_config.rpc_urls.first() {
        std::env::set_var("L2_RPC", first);
    }
    let proposer_config = ProposerConfig::from_env()?;
    proposer_config.log();

    let tz_client = Arc::new(TzChainClient::new(tz_config.rpc_urls));
    let l2_provider: Arc<dyn L2ProviderTrait + Send + Sync> =
        Arc::new(TzL2Provider { tz_client });

    let proposer_signer = SignerLock::from_env().await?;
    let l1_provider = ProviderBuilder::new().connect_http(proposer_config.l1_rpc.clone());

    let anchor_state_registry = AnchorStateRegistry::new(
        proposer_config.anchor_state_registry_address,
        l1_provider.clone(),
    );
    let factory = DisputeGameFactory::new(proposer_config.factory_address, l1_provider.clone());

    // for tz: use new() without rollup_config; tz node does not support optimism_rollupConfig
    let fetcher = OPSuccinctDataFetcher::new();
    let host = initialize_host(Arc::new(fetcher.clone()));

    let proposer = Arc::new(
        OPSuccinctProposer::new_with_l2_provider(
            proposer_config,
            proposer_signer,
            anchor_state_registry,
            factory,
            Arc::new(fetcher),
            host,
            l2_provider,
            TZ_RANGE_ELF,
            TZ_AGGREGATION_ELF,
        )
        .await?,
    );

    ProposerGauge::register_all();
    init_metrics(&proposer.config.metrics_port);
    ProposerGauge::init_all();

    // validate_anchor_l2_block is skipped inside startup_validations via #[cfg(not(feature="tz"))]
    proposer.run().await.expect("Runs in an infinite loop");
    Ok(())
}
