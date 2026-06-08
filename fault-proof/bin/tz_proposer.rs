use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::{SolEvent, SolValue};
use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use fault_proof::{
    config::ProposerConfig,
    contract::{
        AnchorStateRegistry,
        DisputeGameFactory::{self, DisputeGameCreated},
    },
    prometheus::ProposerGauge,
    proposer::OPSuccinctProposer,
    tz::{chain_client::TzChainClient, config::TzConfig, l2_provider::TzL2Provider},
    L2ProviderTrait, TX_REVERTED_PREFIX,
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

#[derive(Parser)]
#[command(name = "tz-proposer")]
struct Args {
    #[arg(long, default_value = ".env.tz-proposer")]
    env_file: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the normal proposer loop.
    Run {
        /// Do not auto-create new games; only sync existing games and handle proof/resolve tasks.
        #[arg(long)]
        defend_only: bool,
    },
    /// Create one bounded dummy game for TZ integration testing, then exit.
    CreateDummyGame {
        /// Expected anchor/start block. Used for validation only; factory extraData stores end
        /// block.
        #[arg(long, default_value_t = 0)]
        start_block: u64,
        /// L2 block number encoded in the game's extraData.
        #[arg(long, default_value_t = 36_000)]
        end_block: u64,
        /// Parent game index encoded in the game's extraData.
        #[arg(long, default_value_t = u32::MAX)]
        parent_game_index: u32,
        /// Dummy rootClaim to propose.
        #[arg(
            long,
            default_value = "0x0000000000000000000000000000000000000000000000000000000000000001"
        )]
        root_claim: B256,
    },
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
        .block_on(run(tz_config, args.command))
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });
}

async fn run(tz_config: TzConfig, command: Option<Command>) -> Result<()> {
    setup_logger();

    // for tz: ProposerConfig::from_env() parses L2_RPC as a single Url; override it with the
    // first endpoint so comma-separated tz RPC lists don't cause a parse error. The tz proposer
    // never uses proposer_config.l2_rpc (L2 access goes through TzL2Provider instead).
    if let Some(first) = tz_config.rpc_urls.first() {
        std::env::set_var("L2_RPC", first);
    }
    let mut proposer_config = ProposerConfig::from_env()?;
    let command = command.unwrap_or(Command::Run { defend_only: false });
    if matches!(&command, Command::Run { defend_only: true }) {
        proposer_config.proposal_interval_in_blocks = u64::MAX;
        tracing::warn!("TZ proposer defend-only mode enabled; automatic game creation is disabled");
    }
    proposer_config.log();

    match command {
        Command::Run { .. } => run_proposer_loop(tz_config, proposer_config).await,
        Command::CreateDummyGame { start_block, end_block, parent_game_index, root_claim } => {
            create_dummy_game(
                proposer_config,
                start_block,
                end_block,
                parent_game_index,
                root_claim,
            )
            .await
        }
    }
}

async fn run_proposer_loop(tz_config: TzConfig, proposer_config: ProposerConfig) -> Result<()> {
    let tz_client = Arc::new(TzChainClient::new(tz_config.rpc_urls));
    let l2_provider: Arc<dyn L2ProviderTrait + Send + Sync> = Arc::new(TzL2Provider { tz_client });

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

async fn create_dummy_game(
    proposer_config: ProposerConfig,
    start_block: u64,
    end_block: u64,
    parent_game_index: u32,
    root_claim: B256,
) -> Result<()> {
    if end_block <= start_block {
        bail!("end_block ({end_block}) must be greater than start_block ({start_block})");
    }

    let proposer_signer = SignerLock::from_env().await?;
    let l1_provider = ProviderBuilder::new().connect_http(proposer_config.l1_rpc.clone());

    let anchor_state_registry = AnchorStateRegistry::new(
        proposer_config.anchor_state_registry_address,
        l1_provider.clone(),
    );
    let factory = DisputeGameFactory::new(proposer_config.factory_address, l1_provider.clone());

    let respected_game_type = anchor_state_registry.respectedGameType().call().await?;
    if proposer_config.game_type != respected_game_type {
        bail!(
            "configured GAME_TYPE {} does not match respected game type {}",
            proposer_config.game_type,
            respected_game_type
        );
    }

    let anchor_l2_block = anchor_state_registry.getAnchorRoot().call().await?._1;
    if anchor_l2_block != U256::from(start_block) {
        tracing::warn!(
            expected_start_block = start_block,
            anchor_l2_block = %anchor_l2_block,
            "Creating dummy game with an anchor block that differs from --start-block"
        );
    }

    let extra_data = (U256::from(end_block), parent_game_index).abi_encode_packed();
    let existing_game = factory
        .games(proposer_config.game_type, root_claim, extra_data.clone().into())
        .call()
        .await?
        .proxy;
    if existing_game != Address::ZERO {
        tracing::info!(
            game_address = ?existing_game,
            end_block,
            parent_game_index,
            root_claim = ?root_claim,
            "Dummy game already exists"
        );
        return Ok(());
    }

    let init_bond = factory.initBonds(proposer_config.game_type).call().await?;
    let transaction_request = factory
        .create(proposer_config.game_type, root_claim, extra_data.into())
        .value(init_bond)
        .into_transaction_request();

    tracing::info!(
        start_block,
        end_block,
        parent_game_index,
        root_claim = ?root_claim,
        init_bond = %init_bond,
        signer = ?proposer_signer.address(),
        "Creating one-shot TZ dummy game"
    );

    let receipt = proposer_signer
        .send_transaction_request_with_timeout(
            proposer_config.l1_rpc.clone(),
            transaction_request,
            proposer_config.tx_confirmation_timeout,
        )
        .await?;

    if !receipt.status() {
        bail!("{TX_REVERTED_PREFIX} {receipt:?}");
    }

    let game_address = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| {
            DisputeGameCreated::decode_log(&log.inner).ok().map(|event| event.disputeProxy)
        })
        .ok_or_else(|| anyhow::anyhow!("Could not find DisputeGameCreated event in receipt"))?;

    tracing::info!(
        game_address = ?game_address,
        tx_hash = ?receipt.transaction_hash,
        end_block,
        root_claim = ?root_claim,
        "Dummy game created successfully"
    );

    Ok(())
}
