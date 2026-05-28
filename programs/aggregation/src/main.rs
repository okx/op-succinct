//! Aggregates range proofs into a single SP1 proof.
//!
//! Per-leaf dispatch:
//! - `RangeProof::Sp1` → `sp1_lib::verify::verify_sp1_proof` recursion.
//! - `RangeProof::Tee` → in-zkVM ECDSA ecrecover over `keccak256` of the
//!   packed range journal; signer pinned by the per-cycle AWS Nitro
//!   attestation document.

#![cfg_attr(target_os = "zkvm", no_main)]
#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

mod tee_attestation;

use alloy_consensus::Header;
use alloy_primitives::{b256, hex, keccak256, Address, B256};
use alloy_sol_types::SolValue;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use op_succinct_client_utils::{
    boot::BootInfoStruct,
    types::{u32_to_u8, AggregationInputs, AggregationOutputs, RangeProof},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use tee_attestation::{verify_attestation, TrustAnchors, VerifiedSession};

/// `keccak256(raw 48-byte NSM PCR0)` — same 32-byte form the enclave packs
/// into the journal. Replace before any deployment that accepts TEE leaves.
const EXPECTED_PCR0_HASH: B256 =
    b256!("c980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293");

/// AWS Nitro Enclaves Root-G1 P-384 public key, SEC1 uncompressed X ‖ Y
/// (no `0x04` prefix; 96 bytes). Valid until 2049-10-28.
const AWS_NITRO_ROOT_G1_PUBKEY: [u8; 96] = hex!(
    "fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051"
    "e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd"
    "095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4"
);

const TRUST_ANCHORS: TrustAnchors = TrustAnchors {
    expected_pcr0_hash: EXPECTED_PCR0_HASH,
    aws_root_pubkey: AWS_NITRO_ROOT_G1_PUBKEY,
};

/// Byte length of the packed range journal — must match
/// `xlayer-tee-types::journal::PACKED_JOURNAL_LEN`.
const PACKED_JOURNAL_LEN: usize = 168;

pub fn main() {
    let agg_inputs = sp1_zkvm::io::read::<AggregationInputs>();
    let headers_bytes = sp1_zkvm::io::read_vec();
    let headers: Vec<Header> = serde_cbor::from_slice(&headers_bytes).unwrap();
    assert!(!agg_inputs.boot_infos.is_empty());
    assert_eq!(
        agg_inputs.boot_infos.len(),
        agg_inputs.range_proofs.len(),
        "boot_infos and range_proofs must be parallel-indexed",
    );

    agg_inputs.boot_infos.windows(2).for_each(|pair| {
        let (prev, curr) = (&pair[0], &pair[1]);
        assert_eq!(prev.l2PostRoot, curr.l2PreRoot);
        assert_eq!(prev.rollupConfigHash, curr.rollupConfigHash);
    });

    let has_tee_leaf =
        agg_inputs.range_proofs.iter().any(|rp| matches!(rp, RangeProof::Tee { .. }));
    let session_signer: Option<Address> = if has_tee_leaf {
        let attestation_bytes = sp1_zkvm::io::read_vec();
        let VerifiedSession { signer } = verify_attestation(&attestation_bytes, &TRUST_ANCHORS);
        Some(signer)
    } else {
        None
    };

    for (boot_info, range_proof) in
        agg_inputs.boot_infos.iter().zip(agg_inputs.range_proofs.iter())
    {
        match range_proof {
            RangeProof::Sp1 => {
                let pv_digest = Sha256::digest(bincode::serialize(boot_info).unwrap());
                sp1_lib::verify::verify_sp1_proof(
                    &agg_inputs.multi_block_vkey,
                    &pv_digest.into(),
                );
            }
            RangeProof::Tee { signature } => {
                let signer = session_signer.expect("Tee leaf without attestation (unreachable)");
                verify_tee_range_proof(boot_info, signature, signer);
            }
        }
    }

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

    let first_boot_info = &agg_inputs.boot_infos[0];
    let last_boot_info = &agg_inputs.boot_infos[agg_inputs.boot_infos.len() - 1];
    let final_boot_info = BootInfoStruct {
        l2PreRoot: first_boot_info.l2PreRoot,
        l2BlockNumber: last_boot_info.l2BlockNumber,
        l2PostRoot: last_boot_info.l2PostRoot,
        l1Head: agg_inputs.latest_l1_checkpoint_head,
        rollupConfigHash: last_boot_info.rollupConfigHash,
    };

    let multi_block_vkey_b256 = B256::from(u32_to_u8(agg_inputs.multi_block_vkey));

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

/// Pack a range journal exactly as the enclave does in
/// `xlayer-tee-types::journal::RangeJournal::pack`.
fn pack_range_journal(
    pcr0: B256,
    config_hash: B256,
    l1_origin_hash: B256,
    l2_block_number: u64,
    prev_output_root: B256,
    output_root: B256,
) -> [u8; PACKED_JOURNAL_LEN] {
    let mut out = [0u8; PACKED_JOURNAL_LEN];
    out[0..32].copy_from_slice(pcr0.as_slice());
    out[32..64].copy_from_slice(config_hash.as_slice());
    out[64..96].copy_from_slice(l1_origin_hash.as_slice());
    out[96..104].copy_from_slice(&l2_block_number.to_be_bytes());
    out[104..136].copy_from_slice(prev_output_root.as_slice());
    out[136..168].copy_from_slice(output_root.as_slice());
    out
}

fn verify_tee_range_proof(
    boot_info: &BootInfoStruct,
    signature: &[u8],
    attested_signer: Address,
) {
    assert_eq!(
        signature.len(),
        65,
        "TEE signature must be 65 bytes (r ‖ s ‖ v), got {}",
        signature.len()
    );
    let packed = pack_range_journal(
        EXPECTED_PCR0_HASH,
        boot_info.rollupConfigHash,
        boot_info.l1Head,
        boot_info.l2BlockNumber,
        boot_info.l2PreRoot,
        boot_info.l2PostRoot,
    );
    let digest = keccak256(packed);

    let recovered_signer = ecrecover(&digest, signature);
    assert_eq!(
        recovered_signer, attested_signer,
        "TEE signer must match attested enclave pubkey \
         (recovered={recovered_signer:?}, attested={attested_signer:?})"
    );
}

fn ecrecover(digest: &B256, sig_65: &[u8]) -> Address {
    debug_assert_eq!(sig_65.len(), 65);
    let sig = Signature::from_slice(&sig_65[..64]).expect("malformed (r,s) signature");
    let rec_id_byte = sig_65[64].checked_sub(27).expect("signature v must be 27 or 28");
    let rec_id = RecoveryId::try_from(rec_id_byte).expect("invalid recovery id");

    let vk = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, rec_id)
        .expect("ecrecover: could not recover verifying key");
    let encoded = vk.to_encoded_point(false);
    let pubkey_bytes = encoded.as_bytes();
    debug_assert_eq!(pubkey_bytes.len(), 65);
    let hash = keccak256(&pubkey_bytes[1..]);
    Address::from_slice(&hash[12..])
}
