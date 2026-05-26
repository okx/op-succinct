//! tz aggregation guest: chain N range BootInfoStructs into one
//! AggregationOutputs after recursive proof verification.

#![cfg_attr(target_os = "zkvm", no_main)]

#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

mod commit;
mod link_check;
mod verify;

use alloy_sol_types::SolValue;
use op_succinct_client_utils::types::AggregationInputs;

pub fn main() {
    let agg_inputs: AggregationInputs = sp1_zkvm::io::read();
    link_check::check_link(&agg_inputs.boot_infos);
    verify::verify_range_proofs(&agg_inputs);
    let outputs = commit::build_outputs(&agg_inputs);
    sp1_zkvm::io::commit_slice(&outputs.abi_encode());
}
