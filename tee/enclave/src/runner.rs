//! Range pipeline: deserialize witness → load boot info → run kona →
//! sign the packed journal.

use std::sync::Arc;

use kona_proof::BootInfo;
use op_succinct_client_utils::{boot::hash_rollup_config, witness::WitnessData};
use rkyv::rancor::Error as RkyvError;
use xlayer_tee_types::{RangeTaskResponse, TaskPhase, journal::RangeJournalWire};

use crate::{
    error::{Error, Result},
    replay::compute_output_root,
    signing::sign_range_wire,
    task_manager::TaskEntry,
    witness::{Witness, check_bounds},
};

pub async fn run_pipeline(
    entry: Arc<TaskEntry>,
    witness_bytes: bytes::Bytes,
    chain_id: u64,
    pcr0: [u8; 32],
) -> Result<RangeTaskResponse> {
    entry.set_phase(TaskPhase::DeserializingWitness).await;

    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(witness_bytes.len());
    aligned.extend_from_slice(&witness_bytes);
    let witness: Witness = rkyv::from_bytes::<Witness, RkyvError>(&aligned)
        .map_err(|e| Error::DeserializeWitness(e.to_string()))?;

    entry.set_phase(TaskPhase::LoadingBootInfo).await;
    let (oracle, beacon) = witness
        .get_oracle_and_blob_provider()
        .await
        .map_err(|e| Error::MalformedWitness(format!("oracle init: {e}")))?;
    let boot = BootInfo::load(oracle.as_ref())
        .await
        .map_err(|e| Error::MalformedWitness(format!("BootInfo::load: {e}")))?;
    check_bounds(&boot)?;

    entry.set_phase(TaskPhase::RunningKona).await;
    let output_root = compute_output_root(oracle.clone(), beacon).await?;

    entry.set_phase(TaskPhase::Signing).await;
    let wire = RangeJournalWire {
        pcr0,
        chain_id,
        config_hash: hash_rollup_config(&boot.rollup_config).0,
        l1_origin_hash: boot.l1_head.0,
        l2_block_number: boot.claimed_l2_block_number,
        prev_output_root: boot.agreed_l2_output_root.0,
        output_root: output_root.0,
    };
    let signature = sign_range_wire(&wire)?;

    Ok(RangeTaskResponse { journal: wire, signature })
}
