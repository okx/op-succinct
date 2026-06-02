use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use tokio::sync::oneshot;
use tracing::{error, info};
use xlayer_tee_types::{RangeJournalWire, RangeTaskResponse, TaskPhase, TaskStatusView};

use crate::{
    error::{Error, CLAIM_MISMATCH_SENTINEL},
    signing::sign_range_wire,
    task_manager::TaskEntry,
    witness::check_bounds,
};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn set_phase(entry: &TaskEntry, phase: TaskPhase) {
    let mut state = entry.state.lock();
    state.phase = phase;
}

fn set_failed(entry: &TaskEntry, err: &Error) {
    let mut state = entry.state.lock();
    state.status = TaskStatusView::Failed { kind: err.to_wire_kind(), message: err.to_string() };
    state.phase = TaskPhase::Terminal;
    state.end_time_ms = Some(now_ms());
}

fn set_finished(entry: &TaskEntry, response: RangeTaskResponse) {
    let mut state = entry.state.lock();
    state.status = TaskStatusView::Finished(Box::new(response));
    state.phase = TaskPhase::Terminal;
    state.end_time_ms = Some(now_ms());
}

pub async fn run_pipeline(
    entry: Arc<TaskEntry>,
    witness_bytes: Bytes,
    pcr0: [u8; 32],
    abort_rx: oneshot::Receiver<()>,
) {
    tokio::select! {
        biased;
        _ = abort_rx => {
            // Cancellation handled by task_manager::cancel
        }
        result = execute_phases(&entry, witness_bytes, pcr0) => {
            match result {
                Ok(response) => {
                    set_finished(&entry, response);
                }
                Err(err) => {
                    error!(task_id = %entry.task_id, error = %err, "pipeline failed");
                    set_failed(&entry, &err);
                }
            }
        }
    }
}

async fn execute_phases(
    entry: &TaskEntry,
    witness_bytes: Bytes,
    pcr0: [u8; 32],
) -> Result<RangeTaskResponse, Error> {
    // Phase 1: Deserialize witness
    set_phase(entry, TaskPhase::DeserializingWitness);
    info!(task_id = %entry.task_id, "phase: DeserializingWitness");

    let witness = deserialize_witness(&witness_bytes)?;

    // Phase 2: Load boot info
    set_phase(entry, TaskPhase::LoadingBootInfo);
    info!(task_id = %entry.task_id, "phase: LoadingBootInfo");

    let (oracle, beacon, boot) = load_boot_info(witness).await?;

    check_bounds(&boot)?;

    let config_hash = op_succinct_client_utils::boot::hash_rollup_config(&boot.rollup_config);

    // Phase 3: Running Kona
    set_phase(entry, TaskPhase::RunningKona);
    info!(task_id = %entry.task_id, "phase: RunningKona");

    let output_root = compute_output_root(oracle, beacon).await?;

    // Phase 4: Signing
    set_phase(entry, TaskPhase::Signing);
    info!(task_id = %entry.task_id, "phase: Signing");

    let wire = RangeJournalWire {
        pcr0,
        config_hash: config_hash.0,
        l1_origin_hash: boot.l1_head.0,
        l2_block_number: boot.claimed_l2_block_number,
        prev_output_root: boot.agreed_l2_output_root.0,
        output_root: output_root.0,
    };

    let signature = sign_range_wire(&wire)?;

    Ok(RangeTaskResponse { journal: wire, signature })
}

fn deserialize_witness(
    witness_bytes: &[u8],
) -> Result<op_succinct_client_utils::witness::DefaultWitnessData, Error> {
    use rkyv::util::AlignedVec;

    let mut aligned = AlignedVec::<16>::new();
    aligned.extend_from_slice(witness_bytes);

    rkyv::from_bytes::<op_succinct_client_utils::witness::DefaultWitnessData, rkyv::rancor::Error>(
        &aligned,
    )
    .map_err(|e| Error::DeserializeWitness(e.to_string()))
}

async fn load_boot_info(
    witness: op_succinct_client_utils::witness::DefaultWitnessData,
) -> Result<
    (
        Arc<op_succinct_client_utils::witness::preimage_store::PreimageStore>,
        op_succinct_client_utils::BlobStore,
        kona_proof::BootInfo,
    ),
    Error,
> {
    use op_succinct_client_utils::witness::WitnessData;

    let (oracle, beacon) = witness
        .get_oracle_and_blob_provider()
        .await
        .map_err(|e| Error::MalformedWitness(e.to_string()))?;

    let (boot, _pipeline_inputs) =
        op_succinct_client_utils::witness::executor::get_inputs_for_pipeline(oracle.clone())
            .await
            .map_err(|e| Error::MalformedWitness(format!("failed to load boot info: {e}")))?;

    Ok((oracle, beacon, boot))
}

async fn compute_output_root(
    oracle: Arc<op_succinct_client_utils::witness::preimage_store::PreimageStore>,
    beacon: op_succinct_client_utils::BlobStore,
) -> Result<alloy_primitives::B256, Error> {
    use kona_genesis::L1ChainConfig;
    use op_succinct_client_utils::witness::executor::get_inputs_for_pipeline;
    use op_succinct_ethereum_client_utils::executor::ETHDAWitnessExecutor;

    let (boot, pipeline_inputs) =
        get_inputs_for_pipeline(oracle.clone()).await.map_err(Error::Internal)?;

    let (cursor, l1_provider, l2_provider) = pipeline_inputs
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("missing pipeline inputs")))?;

    let rollup_config = Arc::new(boot.rollup_config.clone());
    let l1_config = Arc::new(L1ChainConfig::default());

    let executor = ETHDAWitnessExecutor::new();
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
        .map_err(Error::Internal)?;

    use op_succinct_client_utils::witness::executor::WitnessExecutor;
    match executor.run(boot, pipeline, cursor, l2_provider).await {
        Ok(verified_boot) => Ok(verified_boot.claimed_l2_output_root),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains(CLAIM_MISMATCH_SENTINEL) {
                Err(Error::ClaimMismatch {
                    claim: [0u8; 32], // Claim embedded in error string, not extractable
                })
            } else {
                Err(Error::Internal(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xlayer_tee_types::ErrorKind;

    #[test]
    fn deserialize_witness_rejects_empty_bytes() {
        let result = deserialize_witness(&[]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::DeserializeWitness(_)));
    }

    #[test]
    fn deserialize_witness_rejects_garbage_bytes() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let result = deserialize_witness(&garbage);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::DeserializeWitness(_)));
        assert_eq!(err.to_wire_kind(), ErrorKind::DeserializeRkyv);
    }

    #[test]
    fn claim_mismatch_sentinel_detection() {
        let error_msg =
            "Failed to validate L2 block #100 with claimed output root 0xabc. Got 0xdef instead";
        assert!(error_msg.contains(CLAIM_MISMATCH_SENTINEL));
    }

    #[test]
    fn non_mismatch_error_not_detected_as_claim_mismatch() {
        let other_error = "execution reverted: out of gas";
        assert!(!other_error.contains(CLAIM_MISMATCH_SENTINEL));
    }
}
