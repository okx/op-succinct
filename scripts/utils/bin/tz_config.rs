use alloy_primitives::B256;
use anyhow::Result;
use op_succinct_client_utils::types::u32_to_u8;
use op_succinct_elfs::{TZ_AGGREGATION_ELF, TZ_RANGE_ELF};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey};

#[tokio::main]
async fn main() -> Result<()> {
    let prover = ProverClient::builder().cpu().build().await;

    let range_pk = prover.setup(Elf::Static(TZ_RANGE_ELF)).await?;
    let range_vk = range_pk.verifying_key();
    let range_vk_hash = B256::from(u32_to_u8(range_vk.hash_u32()));
    println!("tz Range Verification Key Hash: {range_vk_hash}");

    let agg_pk = prover.setup(Elf::Static(TZ_AGGREGATION_ELF)).await?;
    let agg_vk = agg_pk.verifying_key();
    println!("tz Aggregation Verification Key Hash: {}", agg_vk.bytes32());

    Ok(())
}
