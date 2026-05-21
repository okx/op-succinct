//! Range pipeline broken out of the old sync `handle_range`.
//!
//! Each step calls `set_phase` on the shared `TaskEntry` so a polling
//! proposer can see in-flight progress. The pipeline body is identical to
//! the previous synchronous path — only the wrapping has changed.
//!
//! The whole future is awaited from `spawn_task` under a
//! `tokio::select!` that races against an `oneshot::Receiver<()>`; when
//! `DELETE /tasks/{id}` fires the sender, tokio simply drops this future
//! at its next `.await`, naturally aborting whatever phase is in progress.

use std::sync::Arc;

use alloy_sol_types::Eip712Domain;
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

/// Run the full derivation + execution + signing pipeline for one range task.
///
/// `witness_bytes` is the raw rkyv body posted by the host. `entry` is updated
/// in place with phase transitions; on success the caller stores the returned
/// `RangeTaskResponse` into `entry.status`.
pub async fn run_pipeline(
    entry: Arc<TaskEntry>,
    witness_bytes: bytes::Bytes,
    domain: Arc<Eip712Domain>,
    pcr0: [u8; 32],
) -> Result<RangeTaskResponse> {
    entry.set_phase(TaskPhase::DeserializingWitness).await;

    // rkyv 0.8 requires alignment; reqwest / axum body buffers aren't aligned.
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
        config_hash: hash_rollup_config(&boot.rollup_config).0,
        l1_origin_hash: boot.l1_head.0,
        l2_block_number: boot.claimed_l2_block_number,
        prev_output_root: boot.agreed_l2_output_root.0,
        output_root: output_root.0,
    };
    let signature = sign_range_wire(&wire, &domain)?;

    Ok(RangeTaskResponse { journal: wire, signature })
}
