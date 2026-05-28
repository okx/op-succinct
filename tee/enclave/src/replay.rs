//! Replay logic — runs the op-succinct range program (kona derivation +
//! execution) inside the enclave and verifies the computed output_root
//! matches the witness's claim.
//!
//! Mirrors `op_succinct_range_utils::run_range_program` minus the
//! SP1-specific `sp1_zkvm::io::commit` epilogue — the enclave commits via an
//! ECDSA signature instead.
//!
//! The op-succinct `WitnessExecutor::run` trait method already enforces
//! `output_root == boot.claimed_l2_output_root` and returns an error on
//! mismatch; we map that error to [`Error::ClaimMismatch`].

use std::sync::Arc;

use alloy_primitives::B256;
use op_succinct_client_utils::{
    BlobStore,
    witness::{executor::{WitnessExecutor, get_inputs_for_pipeline}, preimage_store::PreimageStore},
};
use op_succinct_ethereum_client_utils::executor::ETHDAWitnessExecutor;

use crate::error::{Error, Result};

/// Re-run kona derivation + execution on the given witness oracle/beacon.
/// Returns the **computed** output root; the caller compares it against the
/// claim embedded in the boot info to detect mismatch.
pub async fn compute_output_root(
    oracle: Arc<PreimageStore>,
    beacon: BlobStore,
) -> Result<B256> {
    let executor = ETHDAWitnessExecutor::new();

    // Build pipeline inputs (boot info + cursor + l1/l2 providers).
    let (boot_info, input) = get_inputs_for_pipeline(oracle.clone()).await.map_err(|e| {
        Error::MalformedWitness(format!("get_inputs_for_pipeline: {e}"))
    })?;

    let Some((cursor, l1_provider, l2_provider)) = input else {
        return Err(Error::MalformedWitness(
            "get_inputs_for_pipeline returned no pipeline input".into(),
        ));
    };

    let rollup_config = Arc::new(boot_info.rollup_config.clone());
    let l1_config = Arc::new(boot_info.l1_config.clone());

    // Create derivation pipeline.
    let pipeline = executor
        .create_pipeline(
            rollup_config,
            l1_config,
            cursor.clone(),
            oracle,
            beacon,
            l1_provider,
            l2_provider.clone(),
        )
        .await
        .map_err(|e| Error::Internal(format!("create_pipeline: {e}")))?;

    // Run derivation + execution.
    //
    // `WitnessExecutor::run` internally asserts `output_root == boot.claimed_l2_output_root`
    // and errors with "Failed to validate L2 block" on mismatch. We pattern-
    // match on that string to return the structured [`Error::ClaimMismatch`].
    match executor.run(boot_info.clone(), pipeline, cursor, l2_provider).await {
        Ok(verified_boot) => Ok(verified_boot.claimed_l2_output_root),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("Failed to validate L2 block") {
                Err(Error::ClaimMismatch {
                    computed: [0u8; 32], // op-succinct error doesn't expose the computed root cleanly
                    claim: boot_info.claimed_l2_output_root.0,
                })
            } else {
                Err(Error::Internal(format!("kona run: {e}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! `compute_output_root` is integration-tested via the HTTP handler
    //! with a synthetic witness (see `tests/range_signing.rs`). A unit test
    //! that calls `compute_output_root` directly would need the same full
    //! preimage chain as the HTTP path, so there is nothing useful to test
    //! in isolation here.
}
