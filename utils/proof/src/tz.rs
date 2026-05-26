//! tz twin-layer SP1 stdin protocol.

use anyhow::Result;
use op_succinct_client_utils::types::AggregationInputs;
use sp1_sdk::{SP1Proof, SP1Stdin, SP1VerifyingKey};

pub fn aggregation_stdin(
    compressed_proofs: Vec<SP1Proof>,
    range_vk: &SP1VerifyingKey,
    agg_inputs: &AggregationInputs,
) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    for proof in compressed_proofs {
        let SP1Proof::Compressed(compressed) = proof else {
            return Err(anyhow::anyhow!(
                "aggregation_stdin: range proofs must be Compressed variant"
            ));
        };
        stdin.write_proof(*compressed, range_vk.vk.clone());
    }
    stdin.write(agg_inputs);
    Ok(stdin)
}
