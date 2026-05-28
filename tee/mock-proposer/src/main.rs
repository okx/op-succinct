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

use std::{path::PathBuf, sync::Arc, time::Duration};

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
use op_succinct_proof_utils::{cluster_agg_proof, is_cluster_mode};
use rkyv::rancor::Error as RkyvError;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    blocking::{CpuProver, Prover, ProveRequest},
    Elf, SP1ProofMode, SP1Stdin,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProverBackend {
    /// Dispatch by env: use the self-hosted cluster when `SP1_PROVER=cluster`,
    /// otherwise fall back to the local CpuProver.
    Auto,
    /// Always use the local SP1 CpuProver. Slow but self-contained.
    Cpu,
    /// Always use the self-hosted SP1 cluster (requires `SP1_PROVER=cluster`
    /// + `CLI_CLUSTER_RPC` + an artifact store env var).
    Cluster,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProofMode {
    /// SP1 internal compressed proof. Cheap to generate; NOT verifiable on chain.
    Compressed,
    /// Groth16 SNARK. ~260-byte proof; verifiable by SP1VerifierGroth16 on chain.
    Groth16,
    /// PLONK SNARK. Larger proof, no trusted setup; verifiable by SP1VerifierPlonk on chain.
    Plonk,
}

impl ProofMode {
    fn to_sp1(self) -> SP1ProofMode {
        match self {
            ProofMode::Compressed => SP1ProofMode::Compressed,
            ProofMode::Groth16 => SP1ProofMode::Groth16,
            ProofMode::Plonk => SP1ProofMode::Plonk,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "xlayer-tee-mock-proposer",
    about = "Local-dev mock: split a range into chunks, fetch witness per chunk, POST each to tee-host, optionally aggregate the returned TEE proofs."
)]
struct Args {
    /// L1 execution RPC URL (also exported as `L1_RPC`). Required unless
    /// `--proofs-file` is set (cache is self-contained, no live RPC needed).
    #[arg(long, env = "L1_RPC")]
    l1_rpc: Option<String>,

    /// L1 beacon RPC URL (also exported as `L1_BEACON_RPC`).
    #[arg(long, env = "L1_BEACON_RPC")]
    l1_beacon_rpc: Option<String>,

    /// L2 execution RPC URL (also exported as `L2_RPC`). Required unless
    /// `--proofs-file` is set.
    #[arg(long, env = "L2_RPC")]
    l2_rpc: Option<String>,

    /// L2 rollup node RPC (also exported as `L2_NODE_RPC`). Required unless
    /// `--proofs-file` is set.
    #[arg(long, env = "L2_NODE_RPC")]
    l2_node_rpc: Option<String>,

    /// Overall L2 block range start (agreed boundary). Required unless
    /// `--proofs-file` is set (which replays cached chunks).
    #[arg(long)]
    start_block: Option<u64>,

    /// Overall L2 block range end (claimed boundary). Required unless
    /// `--proofs-file` is set.
    #[arg(long)]
    end_block: Option<u64>,

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

    /// Replay aggregation from a previously-saved proof cache. When set,
    /// the TEE flow (chunking, witness gen, POST /tee/task, polling, /tee/info)
    /// is skipped entirely; the chunks + attestation come from this JSON file.
    /// `--start-block` / `--end-block` / `--tee-host` are ignored in this mode.
    #[arg(long)]
    proofs_file: Option<PathBuf>,

    /// After a successful TEE run, dump every chunk's proof + the enclave's
    /// attestation doc to this path. Pair with `--proofs-file <same path>` on
    /// a later run to replay aggregation against a different SP1 backend (e.g.
    /// SP1 cluster) without paying for TEE witness gen again.
    #[arg(long)]
    save_proofs_file: Option<PathBuf>,

    /// Cluster proving timeout in seconds. Only used by the cluster backend.
    #[arg(long, default_value_t = 14_400)]
    cluster_timeout: u64,

    /// Which SP1 backend `--agg-mode prove` should target. `auto` mirrors
    /// `is_cluster_mode()` (env-driven); `cpu` forces local CpuProver; `cluster`
    /// forces the self-hosted SP1 cluster.
    #[arg(long, value_enum, default_value = "auto")]
    prover_backend: ProverBackend,

    /// SP1 proof mode. `compressed` (default) is the fastest to generate but
    /// can only be aggregated again or wrapped; pick `groth16` or `plonk` to
    /// get an on-chain-verifiable SNARK.
    #[arg(long, value_enum, default_value = "compressed")]
    proof_mode: ProofMode,

    /// Write the full `SP1ProofWithPublicValues` (bincode) to this path on a
    /// successful prove. Reload later with `SP1ProofWithPublicValues::load()`.
    /// Convention in op-succinct is `*.bin`.
    #[arg(long)]
    output_proof: Option<PathBuf>,
}

/// On-disk format for `--save-proofs-file` / `--proofs-file`.
///
/// Self-contained: replay mode reads this file and needs no L1/L2 RPC.
#[derive(Serialize, Deserialize)]
struct ProofCache {
    chunks: Vec<ProofCacheChunk>,
    /// COSE_Sign1 NSM attestation doc, base64(STANDARD) — same encoding as
    /// `/tee/info`'s `data.attestationDoc`.
    attestation_b64: String,
    /// CBOR-encoded `Vec<alloy_consensus::Header>` covering every chunk's
    /// `l1Head` back to the L1 checkpoint head. base64(STANDARD).
    headers_cbor_b64: String,
    /// `headers.last().hash_slow()` — passed to the aggregation guest as the
    /// checkpoint it walks back from. Stored explicitly so replay doesn't have
    /// to hash + parse the headers blob just to recover it.
    latest_l1_checkpoint_head: B256,
}

#[derive(Serialize, Deserialize)]
struct ProofCacheChunk {
    start: u64,
    end: u64,
    /// `0x`-prefixed ABI-encoded `(RangeJournal, signature)` blob — same as
    /// `data.proofBytes` returned by `GET /tee/task/{id}`.
    proof_bytes_hex: String,
}

/// Aggregation guest inputs shared between live and replay modes.
struct AggregationContext {
    attestation: Vec<u8>,
    headers: Vec<Header>,
    latest_l1_checkpoint_head: B256,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    if args.chunk_size == 0 {
        bail!("chunk_size must be > 0");
    }
    if args.max_concurrent_witness == 0 {
        bail!("max_concurrent_witness must be ≥ 1");
    }
    let args = Arc::new(args);

    let (results, agg_ctx) = if let Some(path) = args.proofs_file.clone() {
        info!(path = %path.display(), "replay mode: loading proofs from cache");
        let (results, attestation, headers, latest_l1_checkpoint_head) = load_proof_cache(&path)?;
        enforce_chunk_continuity(&results)?;
        println!("──── replaying {} cached chunk(s) ────", results.len());
        let ctx = AggregationContext { attestation, headers, latest_l1_checkpoint_head };
        (results, Some(ctx))
    } else {
        // Live TEE flow — RPCs are required, and we need the fetcher to drive
        // witness gen and (later) header preimages.
        require_rpcs(&args)?;
        export_rpc_env(&args);
        let start_block = args.start_block.context("--start-block is required when --proofs-file is not set")?;
        let end_block = args.end_block.context("--end-block is required when --proofs-file is not set")?;
        if end_block <= start_block {
            bail!("end_block ({end_block}) must be > start_block ({start_block})");
        }

        info!(
            l1_rpc = %args.l1_rpc.as_deref().unwrap_or(""),
            l2_rpc = %args.l2_rpc.as_deref().unwrap_or(""),
            l2_node_rpc = %args.l2_node_rpc.as_deref().unwrap_or(""),
            "fetching rollup config and L1 config"
        );
        let fetcher = Arc::new(
            OPSuccinctDataFetcher::new_with_rollup_config()
                .await
                .context("OPSuccinctDataFetcher::new_with_rollup_config")?,
        );

        let host = SingleChainOPSuccinctHost::new(fetcher.clone());
        let chunks = slice_range(start_block, end_block, args.chunk_size);
        info!(
            start = start_block,
            end = end_block,
            chunk_size = args.chunk_size,
            max_concurrent_witness = args.max_concurrent_witness,
            n_chunks = chunks.len(),
            "scheduling chunks"
        );
        let results = run_all_chunks(args.clone(), host, chunks).await?;
        enforce_chunk_continuity(&results)?;
        println!("──── all {} chunk(s) proven ────", results.len());

        // Build aggregation inputs once if we'll need them — for `--agg-mode prove/execute`
        // and/or for `--save-proofs-file`. Otherwise skip the extra L1 fetches.
        let need_agg_ctx = args.agg_mode != AggMode::Skip || args.save_proofs_file.is_some();
        let agg_ctx = if need_agg_ctx {
            let attestation = fetch_attestation(&args.tee_host).await?;
            let boot_infos: Vec<BootInfoStruct> =
                results.iter().map(|r| r.boot_info.clone()).collect();
            let last_l1_head = results
                .last()
                .context("internal: chunk results are empty after collection")?
                .boot_info
                .l1Head;
            let headers = fetcher
                .get_header_preimages(&boot_infos, last_l1_head)
                .await
                .context("fetch L1 header preimages")?;
            let latest_l1_checkpoint_head = headers
                .last()
                .map(|h| h.hash_slow())
                .context("get_header_preimages returned empty chain")?;

            if let Some(path) = args.save_proofs_file.as_ref() {
                save_proof_cache(
                    path,
                    &results,
                    &attestation,
                    &headers,
                    latest_l1_checkpoint_head,
                )?;
                info!(path = %path.display(), "wrote proof cache");
            }
            Some(AggregationContext { attestation, headers, latest_l1_checkpoint_head })
        } else {
            None
        };
        (results, agg_ctx)
    };

    if args.agg_mode == AggMode::Skip {
        return Ok(());
    }
    let ctx = agg_ctx
        .context("internal: aggregation context missing for non-skip mode")?;
    run_aggregation(&args, &results, ctx).await
}

/// Validate that the three required RPC URLs are present for the live TEE flow.
fn require_rpcs(args: &Args) -> Result<()> {
    if args.l1_rpc.is_none() {
        bail!("--l1-rpc (or env L1_RPC) is required unless --proofs-file is set");
    }
    if args.l2_rpc.is_none() {
        bail!("--l2-rpc (or env L2_RPC) is required unless --proofs-file is set");
    }
    if args.l2_node_rpc.is_none() {
        bail!("--l2-node-rpc (or env L2_NODE_RPC) is required unless --proofs-file is set");
    }
    Ok(())
}

fn export_rpc_env(args: &Args) {
    // SAFETY: process-global mutation, performed once at startup before any
    // op-succinct code reads env. Caller ensures the live-flow RPCs are Some.
    unsafe {
        if let Some(v) = &args.l1_rpc {
            std::env::set_var("L1_RPC", v);
        }
        if let Some(v) = &args.l2_rpc {
            std::env::set_var("L2_RPC", v);
        }
        if let Some(v) = &args.l2_node_rpc {
            std::env::set_var("L2_NODE_RPC", v);
        }
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
    results
        .into_iter()
        .enumerate()
        .map(|(idx, x)| x.with_context(|| format!("chunk {idx} produced no result")))
        .collect()
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
        let _permit = witness_sem
            .clone()
            .acquire_owned()
            .await
            .context("witness semaphore closed")?;

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
    let text = resp.text().await.context("read POST response body")?;
    let json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            // Non-JSON usually means axum 413 (witness > MAX_RANGE_BODY_BYTES).
            let preview: String = text.chars().take(256).collect();
            bail!(
                "tee-host returned non-JSON response: status={status} body=\"{preview}\" \
                 (json parse error: {e}). 413 means witness exceeds MAX_RANGE_BODY_BYTES; \
                 reduce --chunk-size."
            );
        }
    };
    if !status.is_success() || json["code"].as_i64() != Some(0) {
        bail!("tee-host rejected POST: {}", json);
    }
    json["data"]["taskId"]
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
    parse_proof_bytes_hex(proof_bytes_hex)
}

/// Decode the same `(RangeJournal, signature)` blob as [`parse_proof_bytes`],
/// but starting from a raw hex string instead of a task-response JSON object.
/// Used by the `--proofs-file` replay path.
fn parse_proof_bytes_hex(
    proof_bytes_hex: &str,
) -> Result<(String, RangeJournal, BootInfoStruct, Vec<u8>)> {
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
// Proof cache (save / load)
// =============================================================================

fn save_proof_cache(
    path: &std::path::Path,
    results: &[ChunkResult],
    attestation: &[u8],
    headers: &[Header],
    latest_l1_checkpoint_head: B256,
) -> Result<()> {
    let chunks: Vec<ProofCacheChunk> = results
        .iter()
        .map(|r| {
            // RangeJournal doesn't derive Clone — rebuild by copying each
            // (`Copy`) field so we can hand an owned value to abi_encode_params.
            let journal = RangeJournal {
                pcr0: r.journal.pcr0,
                configHash: r.journal.configHash,
                l1OriginHash: r.journal.l1OriginHash,
                l2BlockNumber: r.journal.l2BlockNumber,
                prevOutputRoot: r.journal.prevOutputRoot,
                outputRoot: r.journal.outputRoot,
            };
            let proof_bytes =
                (journal, Bytes::from(r.signature.clone())).abi_encode_params();
            ProofCacheChunk {
                start: r.range.0,
                end: r.range.1,
                proof_bytes_hex: format!("0x{}", hex::encode(&proof_bytes)),
            }
        })
        .collect();
    let headers_cbor =
        serde_cbor::to_vec(&headers.to_vec()).context("CBOR-encode headers for cache")?;
    let cache = ProofCache {
        chunks,
        attestation_b64: base64::engine::general_purpose::STANDARD.encode(attestation),
        headers_cbor_b64: base64::engine::general_purpose::STANDARD.encode(&headers_cbor),
        latest_l1_checkpoint_head,
    };
    let json = serde_json::to_string_pretty(&cache).context("serialize proof cache")?;
    std::fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn load_proof_cache(
    path: &std::path::Path,
) -> Result<(Vec<ChunkResult>, Vec<u8>, Vec<Header>, B256)> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let cache: ProofCache = serde_json::from_str(&raw).context("parse proof cache JSON")?;
    let attestation = base64::engine::general_purpose::STANDARD
        .decode(&cache.attestation_b64)
        .context("base64-decode attestation_b64")?;
    let headers_cbor = base64::engine::general_purpose::STANDARD
        .decode(&cache.headers_cbor_b64)
        .context("base64-decode headers_cbor_b64")?;
    let headers: Vec<Header> =
        serde_cbor::from_slice(&headers_cbor).context("CBOR-decode cached headers")?;
    let expected_head = headers
        .last()
        .map(|h| h.hash_slow())
        .context("cached headers vec is empty")?;
    if expected_head != cache.latest_l1_checkpoint_head {
        bail!(
            "cached headers tail hash {:?} != cached latest_l1_checkpoint_head {:?}",
            expected_head, cache.latest_l1_checkpoint_head,
        );
    }
    let mut results = Vec::with_capacity(cache.chunks.len());
    for c in cache.chunks {
        let (_, journal, boot_info, signature) = parse_proof_bytes_hex(&c.proof_bytes_hex)
            .with_context(|| format!("chunk [{}, {}] proof_bytes_hex", c.start, c.end))?;
        if boot_info.l2BlockNumber != c.end {
            bail!(
                "cached chunk [{}, {}] has l2BlockNumber={} (expected {})",
                c.start, c.end, boot_info.l2BlockNumber, c.end,
            );
        }
        results.push(ChunkResult {
            range: (c.start, c.end),
            boot_info,
            journal,
            signature,
            task_id: format!("cached-[{},{}]", c.start, c.end),
        });
    }
    Ok((results, attestation, headers, cache.latest_l1_checkpoint_head))
}

// =============================================================================
// Aggregation driver
// =============================================================================

async fn run_aggregation(
    args: &Args,
    results: &[ChunkResult],
    ctx: AggregationContext,
) -> Result<()> {
    // Single attestation for the whole aggregation — all chunks were
    // signed by the same enclave session (same tee_host instance), so the
    // guest's session_signer derived from this doc covers every leaf.
    let AggregationContext { attestation, headers, latest_l1_checkpoint_head } = ctx;
    info!(attestation_bytes = attestation.len(), "using attestation doc");

    let boot_infos: Vec<BootInfoStruct> =
        results.iter().map(|r| r.boot_info.clone()).collect();
    let range_proofs: Vec<RangeProof> = results
        .iter()
        .map(|r| RangeProof::Tee { signature: r.signature.clone() })
        .collect();

    let (first, last) = match (boot_infos.first(), boot_infos.last()) {
        (Some(f), Some(l)) => (f, l),
        _ => bail!("aggregation requires at least one chunk; got 0"),
    };
    info!(
        n_leaves = boot_infos.len(),
        n_headers = headers.len(),
        l2_block_range = format!("[{}, {}]", first.l2PreRoot, last.l2PostRoot),
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
        AggMode::Prove => run_prove(
            stdin,
            args.prover_backend,
            args.proof_mode.to_sp1(),
            args.cluster_timeout,
            args.output_proof.as_deref(),
        )
        .await,
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

async fn run_prove(
    stdin: SP1Stdin,
    backend: ProverBackend,
    mode: SP1ProofMode,
    cluster_timeout: u64,
    output_proof: Option<&std::path::Path>,
) -> Result<()> {
    let use_cluster = match backend {
        ProverBackend::Auto => is_cluster_mode(),
        ProverBackend::Cluster => true,
        ProverBackend::Cpu => false,
    };
    let proof = if use_cluster {
        info!(?backend, ?mode, cluster_timeout, "running SP1 prove via self-hosted cluster");
        cluster_agg_proof(cluster_timeout, mode, stdin).await?
    } else {
        info!(?backend, ?mode, "running SP1 prove on aggregation guest via CpuProver");
        tokio::task::spawn_blocking(move || -> Result<_> {
            let prover = CpuProver::new();
            let pk = prover.setup(Elf::Static(AGGREGATION_ELF))?;
            let proof = prover.prove(&pk, stdin).mode(mode).run()?;
            Ok(proof)
        })
        .await
        .context("prove task panicked")??
    };
    let public_values = proof.public_values.to_vec();
    println!("proof complete; public_values_len = {}", public_values.len());
    println!("public_values_hex = 0x{}", hex::encode(&public_values));
    // `proof.bytes()` returns the on-chain-verifiable proof blob (the third
    // argument to `ISP1Verifier.verifyProof`). It is empty for compressed
    // proofs, so we only print when there's something to submit.
    let on_chain_bytes = proof.bytes();
    if on_chain_bytes.is_empty() {
        info!("proof_bytes is empty (compressed mode is not on-chain verifiable)");
    } else {
        println!("proof_bytes_hex = 0x{}", hex::encode(&on_chain_bytes));
    }
    if let Some(path) = output_proof {
        proof.save(path).with_context(|| format!("save proof to {}", path.display()))?;
        println!("proof saved to {}", path.display());
    }
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
