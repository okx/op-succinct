use std::sync::Arc;

use alloy_provider::ProviderBuilder;
use anyhow::Result;
use fault_proof::{
    config::ProposerConfig,
    contract::{AnchorStateRegistry, DisputeGameFactory},
    prometheus::ProposerGauge,
    proposer::OPSuccinctProposer,
    tz_chain_client::TzChainClient,
    tz_l2_provider::TzL2Provider,
    tz_proposer_config::TzConfig,
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

// for tz: placeholder ELF; replace with real tz range program ELF in Phase 2
static TZ_RANGE_ELF: &[u8] = include_bytes!("../elfs/tz-range.elf");

fn main() {
    dotenv::from_filename(".env.tz-proposer").ok();

    // for tz: parse TzConfig (sync) before tokio starts so set_var is single-threaded safe
    let tz_config = TzConfig::from_env().expect("invalid tz config");

    // for tz: inject GAME_TYPE so ProposerConfig::from_env() succeeds
    if std::env::var("GAME_TYPE").is_err() {
        std::env::set_var("GAME_TYPE", tz_config.game_type.to_string());
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(tz_config))
        .unwrap();
}

async fn run(tz_config: TzConfig) -> Result<()> {
    setup_logger();

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
            tz_config.rollup_config_hash.expect("TZ_ROLLUP_CONFIG_HASH must be set"),
            TZ_RANGE_ELF,
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
