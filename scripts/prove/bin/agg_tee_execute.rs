//! Minimal CLI to exercise the TEE-range verification path inside the SP1
//! aggregation program. Runs `Prover::execute` (no real ZK proof generated)
//! against a single TEE-signed range — useful for sanity-checking that the
//! enclave's signature + the program's attestation-verification path are
//! consistent before paying for a full prove.
//!
//! **stdin layout (matches `programs/aggregation/src/main.rs`)**:
//! 1. `AggregationInputs` (bincode)
//! 2. CBOR-encoded `Vec<Header>` (L1 header chain)
//! 3. Raw COSE_Sign1 attestation doc bytes — read conditionally when
//!    `range_proofs` contains any `RangeProof::Tee` variant.
//!
//! Two range-proof input modes:
//! * `--proof <hex>` — whole ABI-encoded `RangeJournalWire` blob from the
//!   enclave; all 7 fields are decoded automatically. **Preferred path.**
//! * The 6 individual `--config-hash / --l1-origin / --l2-block /
//!   --prev-output-root / --output-root / --signature` args — kept for
//!   debugging / hand-crafted inputs. Ignored when `--proof` is given.
//!
//! Note: `--proof` decodes a `pcr0` field for human inspection, but the
//! aggregation guest **does not read it from the wire** anymore — it uses
//! the vkey-baked `EXPECTED_PCR0_HASH` const. The attestation doc is what
//! ultimately pins the signer.
//!
//! Usage:
//! ```bash
//! cargo run --release --bin agg_tee_execute -- \
//!   --l1-rpc http://localhost:8545 \
//!   --proof 0xc980...00000000 \
//!   --attestation 0x8444a101... (raw COSE_Sign1 hex, fetched from tee-host /tee/info)
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

    /// Raw COSE_Sign1 attestation doc, hex-encoded. Fetch from a running
    /// tee-host via `GET /tee/info → data.attestationDoc` (base64); decode
    /// to bytes, then hex-encode for this flag. Required when verifying a
    /// TEE leaf.
    #[arg(long)]
    attestation: String,

    /// Whole ABI-encoded `RangeJournalWire` hex blob from the enclave.
    /// When given, the 6 individual field args are ignored. Standard `0x`
    /// prefix accepted.
    #[arg(long)]
    proof: Option<String>,

    #[arg(long, required_unless_present = "proof")] config_hash: Option<B256>,
    #[arg(long, required_unless_present = "proof")] l1_origin: Option<B256>,
    #[arg(long, required_unless_present = "proof")] l2_block: Option<u64>,
    #[arg(long, required_unless_present = "proof")] prev_output_root: Option<B256>,
    #[arg(long, required_unless_present = "proof")] output_root: Option<B256>,
    #[arg(long, required_unless_present = "proof")] signature: Option<String>,
}

fn decode_hex(label: &str, s: &str) -> Result<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).with_context(|| format!("decode {label} hex"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let attestation_bytes = decode_hex("--attestation", &args.attestation)?;
    println!("→ attestation doc: {} bytes", attestation_bytes.len());

    let (config_hash, l1_origin, l2_block, prev_output_root, output_root, signature) =
        if let Some(p) = args.proof.as_ref() {
            let bytes = decode_hex("--proof", p)?;
            // The enclave encodes via `(RangeJournal, bytes).abi_encode_params()`
            // (see tee/host/src/packager.rs) — no outer 0x20 offset wrapper.
            let w = RangeJournalWire::abi_decode_params(&bytes)
                .context("abi-decode RangeJournalWire (params mode)")?;
            println!("→ decoded journal (informational; guest uses vkey-baked PCR0):");
            println!("    pcr0           = {:?}", w.pcr0);
            println!("    configHash     = {:?}", w.configHash);
            println!("    l1OriginHash   = {:?}", w.l1OriginHash);
            println!("    l2BlockNumber  = {}", w.l2BlockNumber);
            println!("    prevOutputRoot = {:?}", w.prevOutputRoot);
            println!("    outputRoot     = {:?}", w.outputRoot);
            println!("    signature.len  = {}", w.signature.len());
            (w.configHash, w.l1OriginHash, w.l2BlockNumber, w.prevOutputRoot,
             w.outputRoot, w.signature.to_vec())
        } else {
            let sig_hex = args.signature.as_deref().expect("clap required_unless_present");
            let sig_bytes = decode_hex("--signature", sig_hex)?;
            (args.config_hash.unwrap(), args.l1_origin.unwrap(),
             args.l2_block.unwrap(), args.prev_output_root.unwrap(),
             args.output_root.unwrap(), sig_bytes)
        };
    anyhow::ensure!(signature.len() == 65, "signature must be 65 bytes, got {}", signature.len());

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
    // but we still need to satisfy the fetcher's constructor.
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
    println!("  fetched header — number={}, parent={:?}", header.number, header.parent_hash);

    let agg_inputs = AggregationInputs {
        boot_infos: vec![boot],
        // RangeProof::Tee no longer carries pcr0 — vkey-baked
        // EXPECTED_PCR0_HASH replaces it; signer comes from attestation.
        range_proofs: vec![RangeProof::Tee { signature }],
        latest_l1_checkpoint_head: l1_origin,
        // multi_block_vkey only used in the SP1 branch; safe to zero
        // when every leaf is a TEE leaf.
        multi_block_vkey: [0u32; 8],
        prover_address: Address::ZERO,
    };

    // stdin layout matches programs/aggregation/src/main.rs:
    //   1. AggregationInputs (bincode via SP1Stdin::write)
    //   2. CBOR Vec<Header>
    //   3. Raw COSE_Sign1 attestation bytes (read conditionally when
    //      any RangeProof::Tee variant is present — always the case here)
    let mut stdin = SP1Stdin::default();
    stdin.write(&agg_inputs);
    let headers_cbor = serde_cbor::to_vec(&vec![header])?;
    stdin.write_vec(headers_cbor);
    stdin.write_vec(attestation_bytes);

    println!("→ executing aggregation program (no proof generation)");
    // sp1_sdk::blocking::CpuProver internally calls block_on; push onto a
    // dedicated thread so SP1 can spin up its own runtime without
    // colliding with the outer #[tokio::main] runtime.
    let execute_result = tokio::task::spawn_blocking(move || {
        let prover = blocking::CpuProver::new();
        prover.execute(Elf::Static(AGGREGATION_ELF), stdin).run()
    })
    .await
    .context("execute join failed")?;

    match execute_result {
        Ok((public_values, report)) => {
            if public_values.as_slice().is_empty() {
                println!("❌ aggregation execute panicked before commit (guest aborted)");
                println!("   total instructions: {}", report.total_instruction_count());
                std::process::exit(1);
            }
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
