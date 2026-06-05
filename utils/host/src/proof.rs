use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use anyhow::{Context, Result};
use op_succinct_client_utils::{
    boot::BootInfoStruct,
    types::{AggregationInputs, RangeProof},
};
use sp1_sdk::{HashableKey, SP1Proof, SP1Stdin};

/// Get the stdin for the aggregation proof.
pub fn get_agg_proof_stdin(
    proofs: Vec<SP1Proof>,
    boot_infos: Vec<BootInfoStruct>,
    headers: Vec<Header>,
    multi_block_vkey: &sp1_sdk::SP1VerifyingKey,
    latest_checkpoint_head: B256,
    prover_address: Address,
) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::default();
    for proof in proofs {
        let SP1Proof::Compressed(compressed_proof) = proof else {
            return Err(anyhow::anyhow!("Invalid proof passed as compressed proof!"));
        };
        stdin.write_proof(*compressed_proof, multi_block_vkey.vk.clone());
    }

    let range_proofs = vec![RangeProof::Sp1; boot_infos.len()];

    // Write the aggregation inputs to the stdin.
    stdin.write(&AggregationInputs {
        boot_infos,
        range_proofs,
        latest_l1_checkpoint_head: latest_checkpoint_head,
        multi_block_vkey: multi_block_vkey.hash_u32(),
        prover_address,
    });
    // The headers have issues serializing with bincode, so use serde_json instead.
    let headers_bytes = serde_cbor::to_vec(&headers).unwrap();
    stdin.write_vec(headers_bytes);

    Ok(stdin)
}

/// Get the stdin for the TEE aggregation proof.
///
/// Stdin write order must match aggregation circuit read order:
/// 1. AggregationInputs (with RangeProof::Tee variants)
/// 2. CBOR-encoded L1 headers
/// 3. Attestation bytes (only for TEE batches)
pub fn get_agg_proof_stdin_tee(
    tee_signatures: Vec<Vec<u8>>,
    attestation_bytes: Vec<u8>,
    boot_infos: Vec<BootInfoStruct>,
    headers: Vec<Header>,
    latest_checkpoint_head: B256,
    prover_address: Address,
) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::default();

    let range_proofs: Vec<RangeProof> =
        tee_signatures.into_iter().map(|sig| RangeProof::Tee { signature: sig }).collect();

    stdin.write(&AggregationInputs {
        boot_infos,
        range_proofs,
        latest_l1_checkpoint_head: latest_checkpoint_head,
        multi_block_vkey: [0u32; 8],
        prover_address,
    });

    let headers_bytes =
        serde_cbor::to_vec(&headers).context("failed to CBOR-encode L1 headers for TEE agg stdin")?;
    stdin.write_vec(headers_bytes);

    stdin.write_vec(attestation_bytes);

    Ok(stdin)
}
