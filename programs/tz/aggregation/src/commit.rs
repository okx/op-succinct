use alloy_primitives::B256;
use op_succinct_client_utils::types::{AggregationInputs, AggregationOutputs, u32_to_u8};

/// Precondition: `inputs.boot_infos` is non-empty (enforced by `check_link`).
pub fn build_outputs(inputs: &AggregationInputs) -> AggregationOutputs {
    let first = &inputs.boot_infos[0];
    let last = inputs.boot_infos.last().expect("boot_infos non-empty");

    // l1Head / rollupConfigHash are forced to ZERO — tradezone has no L1
    // derivation step.
    AggregationOutputs {
        l1Head: B256::ZERO,
        l2PreRoot: first.l2PreRoot,
        l2PostRoot: last.l2PostRoot,
        l2BlockNumber: last.l2BlockNumber,
        rollupConfigHash: B256::ZERO,
        multiBlockVKey: B256::from(u32_to_u8(inputs.multi_block_vkey)),
        proverAddress: inputs.prover_address,
    }
}
