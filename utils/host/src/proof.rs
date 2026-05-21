use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use anyhow::Result;
use op_succinct_client_utils::{
    boot::BootInfoStruct,
    types::{AggregationInputs, RangeProof},
};
use sp1_sdk::{HashableKey, SP1Proof, SP1Stdin};

/// Get the stdin for the aggregation proof.
///
/// Builds an SP1-only aggregation: every range is tagged `RangeProof::Sp1`,
/// preserving the legacy behavior where each `BootInfoStruct` has a
/// matching SP1 compressed proof loaded into the recursion buffer. For
/// hybrid SP1 + TEE aggregations, use [`get_agg_proof_stdin_mixed`] (TODO,
/// added when the TEE proposer wiring lands).
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

    // SP1-only legacy path: every range gets `RangeProof::Sp1`. The
    // aggregation program then dispatches to `verify_sp1_proof` for each.
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
