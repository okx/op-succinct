//! Export the SP1 proving/verifying key material of the range program ELF.
//!
//! At sp1-sdk 6.1.0 the CPU `setup` returns `SP1ProvingKey { vk, elf }`, so the proving key is
//! fully described by the ELF plus the serialized verifying key. This tool writes:
//! - `range-vk.bin`: bincode-serialized `SP1VerifyingKey` (canonical, reusable form);
//! - `range-vk.json`: the same verifying key as JSON (readable copy);
//! - `range-pk.json`: how to rebuild the proving key from the ELF and `range-vk.bin`;
//! - `range-vk-commitment.txt`: the range vkey commitment and `bytes32()` of the verifying key.
//!
//! Before returning it re-reads the written key, recomputes the commitment, rebuilds the proving
//! key and runs `setup` a second time; any mismatch is an error.

use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use anyhow::{ensure, Context, Result};
use clap::Parser;
use op_succinct_client_utils::types::u32_to_u8;
use serde_json::json;
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1ProvingKey, SP1VerifyingKey};

const VK_BIN: &str = "range-vk.bin";
const VK_JSON: &str = "range-vk.json";
const PK_JSON: &str = "range-pk.json";
const COMMITMENT_TXT: &str = "range-vk-commitment.txt";

#[derive(Parser, Debug)]
#[command(about = "Export SP1 pk/vk files for the range program ELF")]
struct Args {
    /// Path to the range program ELF.
    #[arg(long, default_value = "elf/range-elf-embedded")]
    elf: PathBuf,

    /// Directory the key files are written to.
    #[arg(long, default_value = "elf/keys/range-elf-embedded")]
    out_dir: PathBuf,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The on-chain range vkey commitment form, `B256::from(u32_to_u8(vk.hash_u32()))`.
fn range_vkey_commitment(vk: &SP1VerifyingKey) -> B256 {
    B256::from(u32_to_u8(vk.hash_u32()))
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = dir.join(name);
    fs::write(&path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let elf_bytes =
        fs::read(&args.elf).with_context(|| format!("failed to read {}", args.elf.display()))?;
    let elf_sha256 = sha256_hex(&elf_bytes);
    println!("ELF: {} ({} bytes, sha256 {elf_sha256})", args.elf.display(), elf_bytes.len());

    let prover = ProverClient::builder().cpu().build().await;
    let pk = prover.setup(Elf::from(elf_bytes.clone())).await?;
    let vk = pk.verifying_key().clone();

    let vk_bin = bincode::serialize(&vk)?;
    let vk_sha256 = sha256_hex(&vk_bin);
    let commitment = range_vkey_commitment(&vk);
    let vk_bytes32 = vk.bytes32();

    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("failed to create {}", args.out_dir.display()))?;
    write(&args.out_dir, VK_BIN, &vk_bin)?;
    write(&args.out_dir, VK_JSON, &serde_json::to_vec_pretty(&vk)?)?;
    let pk_manifest = json!({
        "format": "sp1-sdk 6.1.0 SP1ProvingKey = (vk, elf)",
        "elf_path": args.elf.display().to_string(),
        "elf_sha256": elf_sha256,
        "vk_file": VK_BIN,
        "vk_sha256": vk_sha256,
        "reconstruct": "SP1ProvingKey::new(bincode::deserialize(vk.bin), Elf::from(elf bytes))",
    });
    write(&args.out_dir, PK_JSON, &serde_json::to_vec_pretty(&pk_manifest)?)?;
    write(
        &args.out_dir,
        COMMITMENT_TXT,
        format!("range_vkey_commitment = {commitment}\nvk_bytes32 = {vk_bytes32}\n").as_bytes(),
    )?;

    // Self-check 1: the written verifying key round-trips to the same commitment.
    let vk_read: SP1VerifyingKey = bincode::deserialize(&fs::read(args.out_dir.join(VK_BIN))?)?;
    ensure!(
        range_vkey_commitment(&vk_read) == commitment && vk_read.bytes32() == vk_bytes32,
        "commitment recomputed from {VK_BIN} does not match"
    );
    println!("check: {VK_BIN} round-trip commitment matches");

    // Self-check 2: the proving key rebuilt from (vk, elf) exposes the same verifying key.
    let rebuilt = SP1ProvingKey::new(vk_read, Elf::from(elf_bytes.clone()));
    ensure!(
        bincode::serialize(rebuilt.verifying_key())? == vk_bin,
        "verifying key of the rebuilt proving key does not match"
    );
    ensure!(**rebuilt.elf() == *elf_bytes, "ELF of the rebuilt proving key does not match");
    println!("check: SP1ProvingKey::new(vk, elf) verifying key matches");

    // Self-check 3: setup is deterministic for this ELF.
    let pk_again = prover.setup(Elf::from(elf_bytes)).await?;
    ensure!(
        bincode::serialize(pk_again.verifying_key())? == vk_bin,
        "second setup produced a different verifying key"
    );
    println!("check: second setup produced identical verifying key bytes");

    println!("range_vkey_commitment = {commitment}");
    println!("vk_bytes32 = {vk_bytes32}");
    println!("{VK_BIN} sha256 {vk_sha256}");
    println!("Keys written to {}", args.out_dir.display());

    Ok(())
}
