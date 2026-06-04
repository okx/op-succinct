use alloy_primitives::B256;
use op_succinct_client_utils::types::{AggregationInputs, AggregationOutputs, u32_to_u8};

/// Precondition: `inputs.boot_infos` is non-empty (enforced by `check_link`).
pub fn build_outputs(inputs: &AggregationInputs) -> AggregationOutputs {
    let first = &inputs.boot_infos[0];
    let last = inputs.boot_infos.last().expect("boot_infos non-empty");

    // l1Head passes through `inputs.latest_l1_checkpoint_head` so the on-chain
    // game.l1Head() CWIA arg drives the value end-to-end. Matches the upstream
    // aggregation program's l1Head output assignment pattern (tz skips the
    // upstream's L1 header chain walk — no L1 derivation to anchor here).
    //
    // rollupConfigHash stays ZERO — tradezone has no rollup config, and the
    // on-chain ROLLUP_CONFIG_HASH immutable is also deployed as ZERO.
    AggregationOutputs {
        l1Head: inputs.latest_l1_checkpoint_head,
        l2PreRoot: first.l2PreRoot,
        l2PostRoot: last.l2PostRoot,
        l2BlockNumber: last.l2BlockNumber,
        rollupConfigHash: B256::ZERO,
        multiBlockVKey: B256::from(u32_to_u8(inputs.multi_block_vkey)),
        proverAddress: inputs.prover_address,
    }
}
