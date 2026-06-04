//! A program that aggregates the proofs of the range program.

#![cfg_attr(target_os = "zkvm", no_main)]
#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

use alloy_consensus::Header;
use alloy_primitives::B256;
use alloy_sol_types::SolValue;
use op_succinct_client_utils::{
    boot::BootInfoStruct,
    types::{u32_to_u8, AggregationInputs, AggregationOutputs, RangeProof},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

mod tee;

pub fn main() {
    // Read in the public values corresponding to each range proof.
    let agg_inputs = sp1_zkvm::io::read::<AggregationInputs>();
    // Note: The headers are in order from start to end. We use serde_cbor as bincode serialization
    // causes issues with the zkVM.
    let headers_bytes = sp1_zkvm::io::read_vec();
    let headers: Vec<Header> = serde_cbor::from_slice(&headers_bytes).unwrap();

    // FR-1: parallel-index assertion
    assert!(!agg_inputs.boot_infos.is_empty());
    assert_eq!(
        agg_inputs.boot_infos.len(),
        agg_inputs.range_proofs.len(),
        "boot_infos and range_proofs must be parallel-indexed"
    );

    // FR-6: sequential assertions (BEFORE attestation read)
    agg_inputs.boot_infos.windows(2).for_each(|pair| {
        let (prev_boot_info, boot_info) = (&pair[0], &pair[1]);
        assert_eq!(prev_boot_info.l2PostRoot, boot_info.l2PreRoot);
        assert_eq!(prev_boot_info.rollupConfigHash, boot_info.rollupConfigHash);
    });

    // FR-5: homogeneity check
    let has_tee = agg_inputs.range_proofs.iter().any(|rp| matches!(rp, RangeProof::Tee { .. }));
    let has_sp1 = agg_inputs.range_proofs.iter().any(|rp| matches!(rp, RangeProof::Sp1));
    assert!(
        !(has_tee && has_sp1),
        "aggregation must be homogeneous: cannot mix Sp1 and Tee range proofs in one batch"
    );

    // FR-2: read attestation IFF TEE leaf exists (after sequential assertions)
    let session: Option<tee::types::VerifiedSession> = if has_tee {
        let attestation_bytes = sp1_zkvm::io::read_vec();
        Some(tee::verify_attestation(&attestation_bytes, &tee::types::TrustAnchors::default()))
    } else {
        None
    };

    // FR-3: per-leaf dispatch
    for (boot_info, range_proof) in agg_inputs.boot_infos.iter().zip(agg_inputs.range_proofs.iter())
    {
        match range_proof {
            RangeProof::Sp1 => {
                let serialized_boot_info = bincode::serialize(&boot_info).unwrap();
                let pv_digest = Sha256::digest(serialized_boot_info);
                sp1_lib::verify::verify_sp1_proof(&agg_inputs.multi_block_vkey, &pv_digest.into());
            }
            RangeProof::Tee { signature } => {
                let s = session.as_ref().expect("Tee leaf without attestation");
                tee::verify_tee_range_proof(boot_info, signature, s.pcr0_hash, s.signer);
            }
        }
    }

    // FR-6: L1 head chain backtrack (unchanged)
    let mut l1_heads_map: HashMap<B256, bool> =
        agg_inputs.boot_infos.iter().map(|boot_info| (boot_info.l1Head, false)).collect();

    let mut current_hash = agg_inputs.latest_l1_checkpoint_head;
    for header in headers.iter().rev() {
        assert_eq!(current_hash, header.hash_slow());

        if let Some(found) = l1_heads_map.get_mut(&current_hash) {
            *found = true;
        }

        current_hash = header.parent_hash;
    }

    for (l1_head, found) in l1_heads_map.iter() {
        assert!(*found, "l1 head {l1_head:?} not found in the provided header chain");
    }

    // FR-6: consolidation (unchanged)
    let first_boot_info = &agg_inputs.boot_infos[0];
    let last_boot_info = &agg_inputs.boot_infos[agg_inputs.boot_infos.len() - 1];
    let final_boot_info = BootInfoStruct {
        l2PreRoot: first_boot_info.l2PreRoot,
        l2BlockNumber: last_boot_info.l2BlockNumber,
        l2PostRoot: last_boot_info.l2PostRoot,
        l1Head: agg_inputs.latest_l1_checkpoint_head,
        rollupConfigHash: last_boot_info.rollupConfigHash,
    };

    // FR-5: vkey slot selection
    let multi_block_vkey_b256 = match &session {
        Some(s) => s.pcr0_hash,
        None => B256::from(u32_to_u8(agg_inputs.multi_block_vkey)),
    };

    let agg_outputs = AggregationOutputs {
        l1Head: final_boot_info.l1Head,
        l2PreRoot: final_boot_info.l2PreRoot,
        l2PostRoot: final_boot_info.l2PostRoot,
        l2BlockNumber: final_boot_info.l2BlockNumber,
        rollupConfigHash: final_boot_info.rollupConfigHash,
        multiBlockVKey: multi_block_vkey_b256,
        proverAddress: agg_inputs.prover_address,
    };

    sp1_zkvm::io::commit_slice(&agg_outputs.abi_encode());
}
