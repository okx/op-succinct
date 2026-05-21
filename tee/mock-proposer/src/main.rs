//! Local-dev proposer mock.
//!
//! Fetches L1+L2 data from a running OP Stack devnet via op-succinct's
//! `OPSuccinctDataFetcher` + `SingleChainOPSuccinctHost`, generates a real
//! `DefaultWitnessData`, rkyv-serializes it and POSTs to `xlayer-tee-host`.
//! Then polls until the task reaches a terminal state and prints the result.
//!
//! Not part of the production proposer — this stays local for E2E testing
//! while the real op-succinct fault-proof proposer is being modified.

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use clap::Parser;
use op_succinct_ethereum_host_utils::host::SingleChainOPSuccinctHost;
use op_succinct_host_utils::{fetcher::OPSuccinctDataFetcher, host::OPSuccinctHost};
use rkyv::rancor::Error as RkyvError;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "xlayer-tee-mock-proposer",
    about = "Local-dev mock: fetch real witness from devnet, POST to tee-host."
)]
struct Args {
    /// L1 execution RPC URL (also exported as `L1_RPC`).
    #[arg(long, env = "L1_RPC")]
    l1_rpc: String,

    /// L1 beacon RPC URL (also exported as `L1_BEACON_RPC`).
    /// Required when range spans blob-carrying L1 blocks.
    #[arg(long, env = "L1_BEACON_RPC")]
    l1_beacon_rpc: Option<String>,

    /// L2 execution RPC URL (also exported as `L2_RPC`).
    #[arg(long, env = "L2_RPC")]
    l2_rpc: String,

    /// L2 rollup node RPC (the `op-node` endpoint, also exported as `L2_NODE_RPC`).
    #[arg(long, env = "L2_NODE_RPC")]
    l2_node_rpc: String,

    /// L2 block range start (agreed boundary).
    #[arg(long)]
    start_block: u64,

    /// L2 block range end (claimed boundary).
    #[arg(long)]
    end_block: u64,

    /// tee-host base URL.
    #[arg(long, default_value = "http://127.0.0.1:18080")]
    tee_host: String,

    /// Polling interval (seconds) for GET /tee/task/{id}.
    #[arg(long, default_value_t = 2)]
    poll_secs: u64,

    /// Maximum total wait for a Finished/Failed result (seconds).
    #[arg(long, default_value_t = 600)]
    poll_timeout_secs: u64,

    /// If set, fall back to timestamp-based L1 head when the L2 node has no
    /// SafeDB. Match the production proposer default of `true` for devnets.
    #[arg(long, default_value_t = true)]
    safe_db_fallback: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    if args.end_block <= args.start_block {
        bail!("end_block ({}) must be > start_block ({})", args.end_block, args.start_block);
    }

    // op-succinct's fetcher reads RPCs from process env; mirror CLI args to env.
    export_rpc_env(&args);

    info!(
        l1_rpc = %args.l1_rpc,
        l2_rpc = %args.l2_rpc,
        l2_node_rpc = %args.l2_node_rpc,
        start = args.start_block,
        end = args.end_block,
        "fetching rollup config and L1 config"
    );
    let fetcher = Arc::new(
        OPSuccinctDataFetcher::new_with_rollup_config()
            .await
            .context("OPSuccinctDataFetcher::new_with_rollup_config")?,
    );

    let host = SingleChainOPSuccinctHost::new(fetcher.clone());

    info!("fetching host args from devnet");
    let host_args = host
        .fetch(args.start_block, args.end_block, None, args.safe_db_fallback)
        .await
        .context("host.fetch")?;

    info!("running witness generator (may take ~tens of seconds on real chain)");
    let witness = host.run(&host_args).await.context("host.run")?;

    let witness_bytes = rkyv::to_bytes::<RkyvError>(&witness)
        .context("rkyv-serialize witness")?
        .to_vec();
    info!(
        size_bytes = witness_bytes.len(),
        "witness ready, posting to tee-host"
    );

    let task_id = post_witness(&args, witness_bytes).await?;
    info!(%task_id, "submitted to tee-host; polling for result");
    poll_until_terminal(&args, &task_id).await
}

fn export_rpc_env(args: &Args) {
    // SAFETY: process-global mutation, performed once at startup before any
    // op-succinct code reads env.
    unsafe {
        std::env::set_var("L1_RPC", &args.l1_rpc);
        std::env::set_var("L2_RPC", &args.l2_rpc);
        std::env::set_var("L2_NODE_RPC", &args.l2_node_rpc);
        if let Some(b) = &args.l1_beacon_rpc {
            std::env::set_var("L1_BEACON_RPC", b);
        }
    }
}

async fn post_witness(args: &Args, body: Vec<u8>) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let resp = client
        .post(format!("{}/tee/task", args.tee_host.trim_end_matches('/')))
        .header("content-type", "application/octet-stream")
        .header("x-start-blk-height", args.start_block.to_string())
        .header("x-end-blk-height", args.end_block.to_string())
        .body(body)
        .send()
        .await
        .context("POST /tee/task")?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.context("parse POST response")?;
    if !status.is_success() || body["code"].as_i64() != Some(0) {
        bail!("tee-host rejected POST: {}", body);
    }
    body["data"]["taskId"]
        .as_str()
        .map(str::to_string)
        .context("missing data.taskId in POST response")
}

async fn poll_until_terminal(args: &Args, task_id: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/tee/task/{}", args.tee_host.trim_end_matches('/'), task_id);
    let deadline = std::time::Instant::now() + Duration::from_secs(args.poll_timeout_secs);
    let interval = Duration::from_secs(args.poll_secs.max(1));

    loop {
        if std::time::Instant::now() > deadline {
            bail!("polling timed out after {}s", args.poll_timeout_secs);
        }
        let resp: serde_json::Value =
            client.get(&url).send().await?.json().await.context("GET /tee/task/{id}")?;
        if resp["code"].as_i64() != Some(0) {
            bail!("tee-host error: {}", resp);
        }
        let status = resp["data"]["status"].as_str().unwrap_or("Unknown");
        info!(status = %status, "polled task");
        if status != "Running" {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            return Ok(());
        }
        tokio::time::sleep(interval).await;
    }
}
