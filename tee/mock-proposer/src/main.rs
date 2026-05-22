//! Local-dev proposer mock.
//!
//! Submits a witness to `xlayer-tee-host`, polls for the TEE proof, and
//! optionally drives the SP1 aggregation guest with that proof (execute or
//! prove). Stays local for E2E testing while the production proposer is
//! being modified.

use std::{sync::Arc, time::Duration};

use alloy_consensus::Header;
use alloy_primitives::{hex, Address, Bytes, B256};
use alloy_sol_types::{sol, SolValue};
use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::{Parser, ValueEnum};
use op_succinct_client_utils::{
    boot::BootInfoStruct,
    types::{AggregationInputs, RangeProof},
};
use op_succinct_elfs::AGGREGATION_ELF;
use op_succinct_ethereum_host_utils::host::SingleChainOPSuccinctHost;
use op_succinct_host_utils::{fetcher::OPSuccinctDataFetcher, host::OPSuccinctHost};
use rkyv::rancor::Error as RkyvError;
use sp1_sdk::{
    blocking::{CpuProver, Prover, ProveRequest},
    Elf, SP1Stdin,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

// Mirror of the enclave's `RangeJournal` — used to ABI-decode `proofBytes`.
sol! {
    struct RangeJournal {
        bytes32 pcr0;
        bytes32 configHash;
        bytes32 l1OriginHash;
        uint64  l2BlockNumber;
        bytes32 prevOutputRoot;
        bytes32 outputRoot;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AggMode {
    /// Print the TEE task result and stop.
    Skip,
    /// SP1 execute the aggregation guest (no SNARK output).
    Execute,
    /// SP1 prove the aggregation guest (compressed SNARK).
    Prove,
}

#[derive(Parser, Debug)]
#[command(
    name = "xlayer-tee-mock-proposer",
    about = "Local-dev mock: fetch real witness from devnet, POST to tee-host, optionally drive the aggregation guest."
)]
struct Args {
    /// L1 execution RPC URL (also exported as `L1_RPC`).
    #[arg(long, env = "L1_RPC")]
    l1_rpc: String,

    /// L1 beacon RPC URL (also exported as `L1_BEACON_RPC`).
    #[arg(long, env = "L1_BEACON_RPC")]
    l1_beacon_rpc: Option<String>,

    /// L2 execution RPC URL (also exported as `L2_RPC`).
    #[arg(long, env = "L2_RPC")]
    l2_rpc: String,

    /// L2 rollup node RPC (also exported as `L2_NODE_RPC`).
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

    /// Fall back to timestamp-based L1 head when the L2 node has no SafeDB.
    #[arg(long, default_value_t = true)]
    safe_db_fallback: bool,

    /// What to do once the TEE proof comes back.
    #[arg(long, value_enum, default_value = "skip")]
    agg_mode: AggMode,

    /// Prover address committed into `AggregationOutputs.proverAddress`.
    /// Only used when `--agg-mode` ≠ skip.
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
    prover_address: Address,
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

    // op-succinct's fetcher reads RPCs from process env; mirror CLI args.
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

    let witness_bytes =
        rkyv::to_bytes::<RkyvError>(&witness).context("rkyv-serialize witness")?.to_vec();
    info!(size_bytes = witness_bytes.len(), "witness ready, posting to tee-host");

    let task_id = post_witness(&args, witness_bytes).await?;
    info!(%task_id, "submitted to tee-host; polling for result");

    let task_response = poll_until_terminal(&args, &task_id).await?;
    println!("{}", serde_json::to_string_pretty(&task_response)?);

    if args.agg_mode == AggMode::Skip {
        return Ok(());
    }
    run_aggregation(&args, &fetcher, &task_response).await
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
    let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
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

async fn poll_until_terminal(args: &Args, task_id: &str) -> Result<serde_json::Value> {
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
            return Ok(resp);
        }
        tokio::time::sleep(interval).await;
    }
}

// =============================================================================
// Aggregation driver
// =============================================================================

async fn run_aggregation(
    args: &Args,
    fetcher: &Arc<OPSuccinctDataFetcher>,
    task_response: &serde_json::Value,
) -> Result<()> {
    let status = task_response["data"]["status"].as_str().unwrap_or("");
    if status != "Finished" {
        bail!("cannot aggregate: task ended in {status}");
    }

    // Decode proofBytes (hex string with "0x" prefix) → (RangeJournal, signature).
    let proof_bytes_hex = task_response["data"]["proofBytes"]
        .as_str()
        .context("missing data.proofBytes")?;
    let proof_bytes = hex::decode(proof_bytes_hex.trim_start_matches("0x"))
        .context("decode proofBytes hex")?;
    let (journal, signature) = <(RangeJournal, Bytes)>::abi_decode_params(&proof_bytes)
        .context("ABI-decode (RangeJournal, signature) from proofBytes")?;
    let signature = signature.to_vec();
    if signature.len() != 65 {
        bail!("signature length {} != 65", signature.len());
    }
    info!(
        l2_block = journal.l2BlockNumber,
        pcr0 = %journal.pcr0,
        l1_origin = %journal.l1OriginHash,
        "decoded TEE proof"
    );

    // Fetch the attestation document covering this enclave session.
    let attestation = fetch_attestation(&args.tee_host).await?;
    info!(attestation_bytes = attestation.len(), "fetched attestation doc");

    // Build BootInfoStruct from the signed journal — these five fields are
    // exactly what the aggregation guest will reconstruct when verifying.
    let boot = BootInfoStruct {
        l1Head: journal.l1OriginHash,
        l2PreRoot: journal.prevOutputRoot,
        l2PostRoot: journal.outputRoot,
        l2BlockNumber: journal.l2BlockNumber,
        rollupConfigHash: journal.configHash,
    };
    let boot_infos = vec![boot.clone()];

    // L1 header chain: fetch from the journal's l1Head as checkpoint. The
    // aggregation guest walks this chain backwards and confirms every
    // boot_info.l1Head lies on it.
    let headers = fetcher
        .get_header_preimages(&boot_infos, journal.l1OriginHash)
        .await
        .context("fetch L1 header preimages")?;
    let latest_l1_checkpoint_head = headers
        .last()
        .map(|h| h.hash_slow())
        .context("get_header_preimages returned empty chain")?;

    let stdin = build_stdin(
        boot_infos,
        signature,
        attestation,
        headers,
        latest_l1_checkpoint_head,
        args.prover_address,
    )?;

    match args.agg_mode {
        AggMode::Skip => unreachable!("handled in main"),
        AggMode::Execute => run_execute(stdin).await,
        AggMode::Prove => run_prove(stdin).await,
    }
}

async fn fetch_attestation(tee_host: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .get(format!("{}/tee/info", tee_host.trim_end_matches('/')))
        .send()
        .await?
        .json()
        .await
        .context("GET /tee/info")?;
    if resp["code"].as_i64() != Some(0) {
        bail!("tee-host /tee/info error: {}", resp);
    }
    let b64 = resp["data"]["attestationDoc"]
        .as_str()
        .context("missing data.attestationDoc")?;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("base64-decode attestation_doc")
}

fn build_stdin(
    boot_infos: Vec<BootInfoStruct>,
    tee_signature: Vec<u8>,
    attestation: Vec<u8>,
    headers: Vec<Header>,
    latest_l1_checkpoint_head: B256,
    prover_address: Address,
) -> Result<SP1Stdin> {
    let range_proofs = vec![RangeProof::Tee { signature: tee_signature }];

    let mut stdin = SP1Stdin::default();
    stdin.write(&AggregationInputs {
        boot_infos,
        range_proofs,
        latest_l1_checkpoint_head,
        // multi_block_vkey is only used in the SP1 branch; safe to zero
        // when every leaf is a TEE leaf.
        multi_block_vkey: [0u32; 8],
        prover_address,
    });
    let headers_cbor = serde_cbor::to_vec(&headers).context("CBOR-encode headers")?;
    stdin.write_vec(headers_cbor);
    // The guest reads this conditionally — only if range_proofs contains a
    // Tee variant, which is always the case here.
    stdin.write_vec(attestation);
    Ok(stdin)
}

async fn run_execute(stdin: SP1Stdin) -> Result<()> {
    info!("running SP1 execute on aggregation guest");
    let (pv, report) = tokio::task::spawn_blocking(move || {
        let prover = CpuProver::new();
        prover
            .execute(Elf::Static(AGGREGATION_ELF), stdin)
            .calculate_gas(true)
            .deferred_proof_verification(false)
            .run()
    })
    .await
    .context("execute task panicked")??;
    println!("public_values_len = {}", pv.to_vec().len());
    println!("cycles  = {}", report.total_instruction_count());
    println!("syscalls = {:?}", report.syscall_counts);
    Ok(())
}

async fn run_prove(stdin: SP1Stdin) -> Result<()> {
    info!("running SP1 prove on aggregation guest (compressed)");
    let proof = tokio::task::spawn_blocking(move || -> Result<_> {
        let prover = CpuProver::new();
        let pk = prover.setup(Elf::Static(AGGREGATION_ELF))?;
        let proof = prover.prove(&pk, stdin).compressed().run()?;
        Ok(proof)
    })
    .await
    .context("prove task panicked")??;
    let bytes = proof.public_values.to_vec();
    println!("proof generated; public_values_len = {}", bytes.len());
    println!("public_values_hex = 0x{}", hex::encode(&bytes));
    Ok(())
}
