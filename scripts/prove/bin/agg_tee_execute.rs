//! Minimal CLI to exercise the TEE-range verification path inside the SP1
//! aggregation program. Runs `Prover::execute` (no real ZK proof generated)
//! against a single TEE-signed range — useful for sanity-checking that the
//! enclave's signature + this program's hardcoded approved-enclave set are
//! consistent before paying for a full prove.
//!
//! Two input modes:
//! * `--proof <hex>` — whole ABI-encoded `RangeJournalWire` blob from the
//!   enclave; all 7 fields are decoded automatically. **Preferred path.**
//! * The 7 individual `--pcr0 / --config-hash / ... / --signature` args —
//!   kept for debugging / hand-crafted inputs. Ignored when `--proof` is
//!   given.
//!
//! Usage:
//! ```bash
//! cargo run --release --bin agg_tee_execute -- \
//!   --l1-rpc http://localhost:8545 \
//!   --proof 0xc980...00000000
//! ```

use alloy_consensus::Header;
use alloy_eips::BlockId;
use alloy_primitives::{Address, B256};
use alloy_sol_types::{sol, SolValue};
use anyhow::{Context, Result};
use clap::Parser;
use op_succinct_client_utils::{
    boot::BootInfoStruct,
    types::{AggregationInputs, RangeProof},
};
use op_succinct_elfs::AGGREGATION_ELF;
use op_succinct_host_utils::fetcher::OPSuccinctDataFetcher;
use sp1_sdk::{blocking, blocking::Prover, Elf, SP1Stdin};

sol! {
    /// Wire-level shape of what the enclave ABI-encodes and ships back over
    /// the HTTP boundary. Field order + types must match
    /// `xlayer-tee-types::RangeJournalWire` exactly.
    struct RangeJournalWire {
        bytes32 pcr0;
        bytes32 configHash;
        bytes32 l1OriginHash;
        uint64  l2BlockNumber;
        bytes32 prevOutputRoot;
        bytes32 outputRoot;
        bytes   signature;
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// L1 execution RPC (used to fetch the header at `l1Head`).
    #[arg(long, default_value = "http://localhost:8545")]
    l1_rpc: String,

    /// Whole ABI-encoded `RangeJournalWire` hex blob from the enclave.
    /// When given, the 7 individual field args are ignored. Standard `0x`
    /// prefix accepted.
    #[arg(long)]
    proof: Option<String>,

    /// `keccak256(NSM PCR0)` — must match an entry in `APPROVED_TEE_ENCLAVES`.
    #[arg(long, required_unless_present = "proof")]
    pcr0: Option<B256>,

    /// `hash_rollup_config(&rollup_config)`.
    #[arg(long, required_unless_present = "proof")]
    config_hash: Option<B256>,

    /// L1 head hash anchoring the range (also referenced as `BootInfoStruct.l1Head`).
    #[arg(long, required_unless_present = "proof")]
    l1_origin: Option<B256>,

    /// Claimed L2 block number at the end of the range.
    #[arg(long, required_unless_present = "proof")]
    l2_block: Option<u64>,

    /// L2 output root at `l2_block - range_size` (= start of range).
    #[arg(long, required_unless_present = "proof")]
    prev_output_root: Option<B256>,

    /// L2 output root at `l2_block` (= end of range).
    #[arg(long, required_unless_present = "proof")]
    output_root: Option<B256>,

    /// 65-byte secp256k1 signature `r ‖ s ‖ v` (v ∈ {27, 28}).
    #[arg(long, required_unless_present = "proof")]
    signature: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (pcr0, config_hash, l1_origin, l2_block, prev_output_root, output_root, signature) =
        if let Some(p) = args.proof.as_ref() {
            let hex_str = p.strip_prefix("0x").unwrap_or(p);
            let bytes = hex::decode(hex_str).context("decode --proof hex")?;
            // The enclave encodes via `(RangeJournal, bytes).abi_encode_params()`
            // (see tee/host/src/packager.rs) — no outer 0x20 offset wrapper.
            // Must decode in params mode; plain `abi_decode` would read the
            // first 32 bytes as an outer offset and bail with
            // "type check failed for offset (usize)".
            let w = RangeJournalWire::abi_decode_params(&bytes)
                .context("abi-decode RangeJournalWire (params mode)")?;
            println!("→ decoded journal:");
            println!("    pcr0           = {:?}", w.pcr0);
            println!("    configHash     = {:?}", w.configHash);
            println!("    l1OriginHash   = {:?}", w.l1OriginHash);
            println!("    l2BlockNumber  = {}", w.l2BlockNumber);
            println!("    prevOutputRoot = {:?}", w.prevOutputRoot);
            println!("    outputRoot     = {:?}", w.outputRoot);
            println!("    signature.len  = {}", w.signature.len());
            (
                w.pcr0,
                w.configHash,
                w.l1OriginHash,
                w.l2BlockNumber,
                w.prevOutputRoot,
                w.outputRoot,
                w.signature.to_vec(),
            )
        } else {
            let sig_hex = args.signature.as_deref().expect("clap required_unless_present");
            let sig_bytes = hex::decode(sig_hex.strip_prefix("0x").unwrap_or(sig_hex))
                .context("decode --signature hex")?;
            (
                args.pcr0.unwrap(),
                args.config_hash.unwrap(),
                args.l1_origin.unwrap(),
                args.l2_block.unwrap(),
                args.prev_output_root.unwrap(),
                args.output_root.unwrap(),
                sig_bytes,
            )
        };
    anyhow::ensure!(
        signature.len() == 65,
        "signature must be 65 bytes, got {}",
        signature.len()
    );

    let boot = BootInfoStruct {
        l1Head: l1_origin,
        l2PreRoot: prev_output_root,
        l2PostRoot: output_root,
        l2BlockNumber: l2_block,
        rollupConfigHash: config_hash,
    };

    println!("→ fetching L1 header at hash {:?}", l1_origin);
    // OPSuccinctDataFetcher::new() reads L1_RPC / L2_RPC / L2_NODE_RPC from
    // env and panics if any is missing. The TEE-execute path only needs L1,
    // but we still need to satisfy the fetcher's constructor — so unconditionally
    // overwrite L1_RPC from --l1-rpc, and fill in dummies for the L2 vars if
    // the operator didn't already set them.
    std::env::set_var("L1_RPC", &args.l1_rpc);
    if std::env::var("L2_RPC").is_err() {
        std::env::set_var("L2_RPC", &args.l1_rpc);
    }
    if std::env::var("L2_NODE_RPC").is_err() {
        std::env::set_var("L2_NODE_RPC", &args.l1_rpc);
    }
    let fetcher = OPSuccinctDataFetcher::new();
    let header: Header = fetcher
        .get_l1_header(BlockId::hash(l1_origin))
        .await
        .context("fetch L1 header at l1_origin")?;
    println!(
        "  fetched header — number={}, parent={:?}",
        header.number, header.parent_hash
    );

    // Single-range aggregation input: one BootInfoStruct, one TEE proof.
    let agg_inputs = AggregationInputs {
        boot_infos: vec![boot],
        range_proofs: vec![RangeProof::Tee {
            pcr0,
            signature,
        }],
        latest_l1_checkpoint_head: l1_origin,
        // TEE-only path — `verify_sp1_proof` never gets called, vkey ignored.
        multi_block_vkey: [0u32; 8],
        prover_address: Address::ZERO,
    };

    let mut stdin = SP1Stdin::default();
    stdin.write(&agg_inputs);
    let headers_cbor = serde_cbor::to_vec(&vec![header])?;
    stdin.write_vec(headers_cbor);

    println!("→ executing aggregation program (no proof generation)");
    // sp1_sdk::blocking::CpuProver internally calls `block_on` to drive
    // SP1's async core, which panics if invoked from within a tokio
    // runtime worker (this main fn is `#[tokio::main]`). Push the
    // blocking call onto a dedicated thread so SP1 can spin up its own
    // runtime there without colliding with ours.
    let execute_result = tokio::task::spawn_blocking(move || {
        let prover = blocking::CpuProver::new();
        prover.execute(Elf::Static(AGGREGATION_ELF), stdin).run()
    })
    .await
    .context("execute join failed")?;

    match execute_result {
        Ok((public_values, report)) => {
            println!("✅ aggregation execute passed");
            println!("   total instructions: {}", report.total_instruction_count());
            println!("   public_values (ABI-encoded AggregationOutputs):");
            println!("     0x{}", hex::encode(public_values.as_slice()));
        }
        Err(e) => {
            println!("❌ aggregation execute failed: {e:#}");
            std::process::exit(1);
        }
    }
    Ok(())
}
