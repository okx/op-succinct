use std::{sync::Arc, time::Duration};

use alloy_provider::ProviderBuilder;
use anyhow::Result;
use fault_proof::{
    challenger::OPSuccinctChallenger,
    config::ChallengerConfig,
    contract::{AnchorStateRegistry, DisputeGameFactory},
    prometheus::ChallengerGauge,
    tz::chain_client::TzChainClient,
    tz::l2_provider::TzL2Provider,
    tz::proposer_config::TzConfig,
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

fn main() {
    dotenv::from_filename(".env.tz-challenger").ok();

    // for tz: parse TzConfig (sync) before tokio starts
    let tz_config = TzConfig::challenger_from_env().expect("invalid tz config");

    // for tz: inject GAME_TYPE so ChallengerConfig::from_env() succeeds
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

    let challenger_config = ChallengerConfig::from_env()?;
    challenger_config.log();

    let tz_client = Arc::new(TzChainClient::new(tz_config.rpc_urls));
    let l2_provider: Arc<dyn L2ProviderTrait + Send + Sync> =
        Arc::new(TzL2Provider { tz_client: Arc::clone(&tz_client) });

    // for tz: background task polls /chain/confirmed_block_info every 60s to pre-fill cache
    // so fetch_game does not miss checkpoints observed between sync_state cycles
    let poll_client = Arc::clone(&tz_client);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = poll_client.get_confirmed_block_info().await {
                tracing::warn!("tz: checkpoint poll failed: {e}");
            }
        }
    });

    let challenger_signer = SignerLock::from_env().await?;
    let l1_provider = ProviderBuilder::default()
        .connect_http(challenger_config.l1_rpc.clone());

    let anchor_state_registry = AnchorStateRegistry::new(
        challenger_config.anchor_state_registry_address,
        l1_provider.clone(),
    );
    let factory =
        DisputeGameFactory::new(challenger_config.factory_address, l1_provider.clone());

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
