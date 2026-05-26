//! Local-dev proposer mock.
//!
//! Splits the requested L2 block range into contiguous chunks of size
//! `--chunk-size`, submits each as its own witness to `xlayer-tee-host`
//! (concurrency capped by `--max-concurrent-witness`), polls until all
//! return TEE proofs, then — when `--agg-mode` ≠ skip — drives the SP1
//! aggregation guest with the *vector* of (BootInfo, signature) pairs.
//! The guest already enforces continuity between adjacent chunks and a
//! single attestation-derived signer across them, so all sub-tasks must
//! hit the same enclave.

use std::{sync::Arc, time::Duration};

use alloy_consensus::Header;
use alloy_primitives::{hex, Address, Bytes, B256};
use alloy_sol_types::SolValue;
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
use tokio::{sync::Semaphore, task::JoinSet};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use xlayer_tee_types::RangeJournal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AggMode {
    /// Print per-chunk TEE task results and stop.
    Skip,
    /// SP1 execute the aggregation guest (no SNARK output).
    Execute,
    /// SP1 prove the aggregation guest (compressed SNARK).
    Prove,
}

#[derive(Parser, Debug)]
#[command(
    name = "xlayer-tee-mock-proposer",
    about = "Local-dev mock: split a range into chunks, fetch witness per chunk, POST each to tee-host, optionally aggregate the returned TEE proofs."
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

    /// Overall L2 block range start (agreed boundary).
    #[arg(long)]
    start_block: u64,

    /// Overall L2 block range end (claimed boundary).
    #[arg(long)]
    end_block: u64,

    /// Size of each contiguous chunk submitted as a separate TEE task.
    /// The final chunk may be shorter than this when the range isn't
    /// evenly divisible.
    #[arg(long, default_value_t = 500)]
    chunk_size: u64,

    /// Cap on simultaneously in-flight `host.fetch + host.run + POST + poll`
    /// workers. `1` disables concurrency entirely. Tune down if your L1/L2
    /// RPC saturates.
    #[arg(long, default_value_t = 4)]
    max_concurrent_witness: usize,

    /// tee-host base URL. All chunks are sent to this single instance — the
    /// aggregation guest pins every leaf to a single attestation-derived
    /// signer, so the enclave session must be shared.
    #[arg(long, default_value = "http://127.0.0.1:18080")]
    tee_host: String,

    /// Polling interval (seconds) for GET /tee/task/{id}.
    #[arg(long, default_value_t = 2)]
    poll_secs: u64,

    /// Maximum total wait per chunk for a Finished/Failed result (seconds).
    #[arg(long, default_value_t = 600)]
    poll_timeout_secs: u64,

    /// Fall back to timestamp-based L1 head when the L2 node has no SafeDB.
    #[arg(long, default_value_t = true)]
    safe_db_fallback: bool,

    /// Explicit L1 head block hash to use as the derivation boundary. When set,
    /// bypasses op-succinct's `calculate_safe_l1_head` heuristic — useful on
    /// devnets where the SafeDB-based +20-block buffer is too small and kona
    /// halts with `Critical(EndOfSource)` before deriving any L2 blocks.
    /// Same value is passed to every chunk (kona only needs L1 ≥ chunk's own
    /// L1 origin, so a single forward head works for all chunks).
    /// Tip: `--l1-head $(cast block finalized --rpc-url $L1_RPC --field hash)`.
    #[arg(long)]
    l1_head: Option<B256>,

    /// What to do once all chunk TEE proofs come back.
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
    if args.chunk_size == 0 {
        bail!("chunk_size must be > 0");
    }
    if args.max_concurrent_witness == 0 {
        bail!("max_concurrent_witness must be ≥ 1");
    }
    let args = Arc::new(args);

    // op-succinct's fetcher reads RPCs from process env; mirror CLI args.
    export_rpc_env(&args);

    info!(
        l1_rpc = %args.l1_rpc,
        l2_rpc = %args.l2_rpc,
        l2_node_rpc = %args.l2_node_rpc,
        start = args.start_block,
        end = args.end_block,
        chunk_size = args.chunk_size,
        max_concurrent_witness = args.max_concurrent_witness,
        "fetching rollup config and L1 config"
    );
    let fetcher = Arc::new(
        OPSuccinctDataFetcher::new_with_rollup_config()
            .await
            .context("OPSuccinctDataFetcher::new_with_rollup_config")?,
    );

    let host = SingleChainOPSuccinctHost::new(fetcher.clone());

    let chunks = slice_range(args.start_block, args.end_block, args.chunk_size);
    info!(n_chunks = chunks.len(), "scheduling chunks");

    let results = run_all_chunks(args.clone(), host, chunks).await?;
    enforce_chunk_continuity(&results)?;

    // Per-chunk proofs (journal + signature) were printed via
    // `print_chunk_proof` as each chunk finished. Here we just emit a final
    // summary line so the operator can confirm the total count.
    println!("──── all {} chunk(s) proven ────", results.len());
    if args.agg_mode == AggMode::Skip {
        return Ok(());
    }
    run_aggregation(&args, &fetcher, &results).await
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

// =============================================================================
// Chunk planning + concurrent execution
// =============================================================================

/// Slice `[start, end]` into half-open contiguous chunks. Adjacent chunks
/// share a boundary block (chunk i's end == chunk i+1's start) so the
/// aggregation guest's `prev.l2PostRoot == curr.l2PreRoot` check holds.
fn slice_range(start: u64, end: u64, chunk_size: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut s = start;
    while s < end {
        let e = (s + chunk_size).min(end);
        out.push((s, e));
        s = e;
    }
    out
}

struct ChunkResult {
    range: (u64, u64),
    boot_info: BootInfoStruct,
    /// Full RangeJournal signed by the enclave. We keep it (instead of only
    /// the derived `boot_info`) so the per-chunk diagnostic print can show
    /// `pcr0` and the raw signed fields — useful when an aggregation run
    /// fails and you want to compare against `EXPECTED_PCR0_HASH`.
    journal: RangeJournal,
    signature: Vec<u8>,
    task_id: String,
}

async fn run_all_chunks(
    args: Arc<Args>,
    host: SingleChainOPSuccinctHost,
    chunks: Vec<(u64, u64)>,
) -> Result<Vec<ChunkResult>> {
    let n = chunks.len();
    // `witness_sem` gates the parallel witness-gen phase (heavy: L1/L2/beacon
    // RPCs through kona). tee-host now accepts concurrent POSTs and queues
    // them internally when the enclave hits its `max_inflight`, so we no
    // longer need a client-side mutex around POST + poll.
    let witness_sem = Arc::new(Semaphore::new(args.max_concurrent_witness));
    let mut joinset: JoinSet<(usize, Result<ChunkResult>)> = JoinSet::new();

    for (idx, (start, end)) in chunks.into_iter().enumerate() {
        let witness_sem_c = witness_sem.clone();
        let args_c = args.clone();
        let host_c = host.clone();
        joinset.spawn(async move {
            let result = submit_chunk(&args_c, &host_c, start, end, &witness_sem_c).await;
            (idx, result)
        });
    }

    let mut results: Vec<Option<ChunkResult>> = (0..n).map(|_| None).collect();
    while let Some(joined) = joinset.join_next().await {
        let (idx, chunk_result) = joined.context("chunk task panicked")?;
        match chunk_result {
            Ok(r) => {
                info!(
                    chunk_idx = idx,
                    chunk = format!("[{}, {}]", r.range.0, r.range.1),
                    task_id = %r.task_id,
                    "chunk finished"
                );
                results[idx] = Some(r);
            }
            Err(e) => {
                warn!(chunk_idx = idx, "chunk failed; aborting remaining tasks: {e:#}");
                joinset.abort_all();
                return Err(e.context(format!("chunk {idx} failed")));
            }
        }
    }
    Ok(results.into_iter().map(|x| x.expect("filled by loop")).collect())
}

async fn submit_chunk(
    args: &Args,
    host: &SingleChainOPSuccinctHost,
    chunk_start: u64,
    chunk_end: u64,
    witness_sem: &Arc<Semaphore>,
) -> Result<ChunkResult> {
    // ---- Phase 1: witness generation (parallel, gated by `witness_sem`) ----
    // Permit released as soon as witness_bytes is ready, so the next chunk
    // can start its own witness gen while this one sits at tee-host.
    let witness_bytes = {
        let _permit =
            witness_sem.clone().acquire_owned().await.expect("witness semaphore closed");

        info!(start = chunk_start, end = chunk_end, "chunk: fetching host args");
        let host_args = host
            .fetch(chunk_start, chunk_end, args.l1_head, args.safe_db_fallback)
            .await
            .with_context(|| format!("host.fetch chunk [{chunk_start}, {chunk_end}]"))?;

        info!(start = chunk_start, end = chunk_end, "chunk: running witness generator");
        let witness = host
            .run(&host_args)
            .await
            .with_context(|| format!("host.run chunk [{chunk_start}, {chunk_end}]"))?;
        rkyv::to_bytes::<RkyvError>(&witness).context("rkyv-serialize witness")?.to_vec()
    };

    // ---- Phase 2: submit + poll (concurrent, throttled at tee-host) ----
    // tee-host now accepts concurrent POSTs and queues them when the enclave
    // is at `max_inflight`, so we just POST and poll like a single client.
    info!(
        start = chunk_start,
        end = chunk_end,
        size_bytes = witness_bytes.len(),
        "chunk: posting witness to tee-host"
    );
    let task_id = post_witness(args, chunk_start, chunk_end, witness_bytes).await?;
    info!(start = chunk_start, end = chunk_end, %task_id, "chunk: polling for result");
    let response = poll_until_terminal(args, &task_id).await?;

    let status = response["data"]["status"].as_str().unwrap_or("");
    if status != "Finished" {
        bail!(
            "chunk [{chunk_start}, {chunk_end}] task {task_id} ended in {status}: {}",
            response
        );
    }
    let (proof_bytes_hex, journal, boot_info, signature) = parse_proof_bytes(&response)?;
    if boot_info.l2BlockNumber != chunk_end {
        bail!(
            "chunk [{chunk_start}, {chunk_end}] returned l2BlockNumber={} (expected {chunk_end})",
            boot_info.l2BlockNumber
        );
    }
    print_chunk_proof(chunk_start, chunk_end, &task_id, &journal, &signature, &proof_bytes_hex);
    Ok(ChunkResult { range: (chunk_start, chunk_end), boot_info, journal, signature, task_id })
}

/// Pretty-print the TEE proof returned for one chunk. Emitted as soon as a
/// chunk's task reaches `Finished`, so the operator can inspect each proof
/// even when the run continues into aggregation.
fn print_chunk_proof(
    chunk_start: u64,
    chunk_end: u64,
    task_id: &str,
    journal: &RangeJournal,
    signature: &[u8],
    proof_bytes_hex: &str,
) {
    println!("──── TEE proof: chunk [{chunk_start}, {chunk_end}] ────");
    println!("  task_id        = {task_id}");
    println!("  pcr0           = {:?}", journal.pcr0);
    println!("  configHash     = {:?}", journal.configHash);
    println!("  l1OriginHash   = {:?}", journal.l1OriginHash);
    println!("  l2BlockNumber  = {}", journal.l2BlockNumber);
    println!("  prevOutputRoot = {:?}", journal.prevOutputRoot);
    println!("  outputRoot     = {:?}", journal.outputRoot);
    println!("  signature(65B) = 0x{}", hex::encode(signature));
    println!("  proofBytes     = 0x{proof_bytes_hex}");
}

fn enforce_chunk_continuity(results: &[ChunkResult]) -> Result<()> {
    for pair in results.windows(2) {
        let (prev, curr) = (&pair[0], &pair[1]);
        if prev.boot_info.l2PostRoot != curr.boot_info.l2PreRoot {
            bail!(
                "chunk continuity broken: chunk@{} l2PostRoot={:?} != chunk@{} l2PreRoot={:?}",
                prev.boot_info.l2BlockNumber,
                prev.boot_info.l2PostRoot,
                curr.boot_info.l2BlockNumber,
                curr.boot_info.l2PreRoot,
            );
        }
        if prev.boot_info.rollupConfigHash != curr.boot_info.rollupConfigHash {
            bail!(
                "chunk rollupConfigHash mismatch between {} and {}",
                prev.boot_info.l2BlockNumber,
                curr.boot_info.l2BlockNumber,
            );
        }
    }
    Ok(())
}

// =============================================================================
// HTTP plumbing
// =============================================================================

async fn post_witness(
    args: &Args,
    chunk_start: u64,
    chunk_end: u64,
    body: Vec<u8>,
) -> Result<String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
    let resp = client
        .post(format!("{}/tee/task", args.tee_host.trim_end_matches('/')))
        .header("content-type", "application/octet-stream")
        .header("x-start-blk-height", chunk_start.to_string())
        .header("x-end-blk-height", chunk_end.to_string())
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
            bail!("polling task {task_id} timed out after {}s", args.poll_timeout_secs);
        }
        let resp: serde_json::Value =
            client.get(&url).send().await?.json().await.context("GET /tee/task/{id}")?;
        if resp["code"].as_i64() != Some(0) {
            bail!("tee-host error for task {task_id}: {}", resp);
        }
        let status = resp["data"]["status"].as_str().unwrap_or("Unknown");
        info!(task_id, status = %status, "polled task");
        if status != "Running" {
            return Ok(resp);
        }
        tokio::time::sleep(interval).await;
    }
}

fn parse_proof_bytes(
    task_response: &serde_json::Value,
) -> Result<(String, RangeJournal, BootInfoStruct, Vec<u8>)> {
    let proof_bytes_hex =
        task_response["data"]["proofBytes"].as_str().context("missing data.proofBytes")?;
    let proof_bytes = hex::decode(proof_bytes_hex.trim_start_matches("0x"))
        .context("decode proofBytes hex")?;
    let (journal, signature) = <(RangeJournal, Bytes)>::abi_decode_params(&proof_bytes)
        .context("ABI-decode (RangeJournal, signature) from proofBytes")?;
    let signature = signature.to_vec();
    if signature.len() != 65 {
        bail!("signature length {} != 65", signature.len());
    }
    let boot_info = BootInfoStruct {
        l1Head: journal.l1OriginHash,
        l2PreRoot: journal.prevOutputRoot,
        l2PostRoot: journal.outputRoot,
        l2BlockNumber: journal.l2BlockNumber,
        rollupConfigHash: journal.configHash,
    };
    let hex_clean = proof_bytes_hex.trim_start_matches("0x").to_string();
    Ok((hex_clean, journal, boot_info, signature))
}

// =============================================================================
// Aggregation driver
// =============================================================================

async fn run_aggregation(
    args: &Args,
    fetcher: &Arc<OPSuccinctDataFetcher>,
    results: &[ChunkResult],
) -> Result<()> {
    // Single attestation for the whole aggregation — all chunks were
    // signed by the same enclave session (same tee_host instance), so the
    // guest's session_signer derived from this doc covers every leaf.
    let attestation = fetch_attestation(&args.tee_host).await?;
    info!(attestation_bytes = attestation.len(), "fetched attestation doc");

    let boot_infos: Vec<BootInfoStruct> =
        results.iter().map(|r| r.boot_info.clone()).collect();
    let range_proofs: Vec<RangeProof> = results
        .iter()
        .map(|r| RangeProof::Tee { signature: r.signature.clone() })
        .collect();

    // The last chunk's L1 origin sits highest on L1; the guest will walk
    // back from this checkpoint and assert every chunk's l1Head appears
    // somewhere on the chain.
    let last_l1_head = results.last().expect("results non-empty").boot_info.l1Head;

    let headers = fetcher
        .get_header_preimages(&boot_infos, last_l1_head)
        .await
        .context("fetch L1 header preimages")?;
    let latest_l1_checkpoint_head = headers
        .last()
        .map(|h| h.hash_slow())
        .context("get_header_preimages returned empty chain")?;

    info!(
        n_leaves = boot_infos.len(),
        n_headers = headers.len(),
        l2_block_range = format!(
            "[{}, {}]",
            boot_infos.first().unwrap().l2PreRoot,
            boot_infos.last().unwrap().l2PostRoot,
        ),
        "building aggregation stdin"
    );

    let stdin = build_stdin(
        boot_infos,
        range_proofs,
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
    range_proofs: Vec<RangeProof>,
    attestation: Vec<u8>,
    headers: Vec<Header>,
    latest_l1_checkpoint_head: B256,
    prover_address: Address,
) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::default();
    stdin.write(&AggregationInputs {
        boot_infos,
        range_proofs,
        latest_l1_checkpoint_head,
        multi_block_vkey: [0u32; 8],
        prover_address,
    });
    let headers_cbor = serde_cbor::to_vec(&headers).context("CBOR-encode headers")?;
    stdin.write_vec(headers_cbor);
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_range_even_split() {
        assert_eq!(slice_range(0, 1000, 500), vec![(0, 500), (500, 1000)]);
    }

    #[test]
    fn slice_range_uneven_split() {
        assert_eq!(
            slice_range(8_610_000, 8_614_000, 1500),
            vec![(8_610_000, 8_611_500), (8_611_500, 8_613_000), (8_613_000, 8_614_000)],
        );
    }

    #[test]
    fn slice_range_smaller_than_chunk_size() {
        assert_eq!(slice_range(100, 200, 500), vec![(100, 200)]);
    }

    #[test]
    fn slice_range_exact_multiple() {
        let chunks = slice_range(0, 1500, 500);
        assert_eq!(chunks, vec![(0, 500), (500, 1000), (1000, 1500)]);
        for pair in chunks.windows(2) {
            assert_eq!(pair[0].1, pair[1].0);
        }
    }
}
