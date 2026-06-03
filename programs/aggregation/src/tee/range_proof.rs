use alloy_primitives::{keccak256, Address, B256};
use op_succinct_client_utils::boot::BootInfoStruct;

use super::crypto::{ecrecover, pack_range_journal};

pub fn verify_tee_range_proof(
    boot_info: &BootInfoStruct,
    signature: &[u8],
    attested_pcr0: &B256,
    attested_signer: &Address,
) {
    assert!(signature.len() == 65, "TEE signature must be 65 bytes");

    let packed = pack_range_journal(
        attested_pcr0,
        &boot_info.rollupConfigHash,
        &boot_info.l1Head,
        boot_info.l2BlockNumber,
        &boot_info.l2PreRoot,
        &boot_info.l2PostRoot,
    );

    let digest = keccak256(packed);
    let recovered = ecrecover(&B256::from(digest), signature);

    assert_eq!(
        recovered, *attested_signer,
        "TEE range proof signer mismatch: recovered {recovered}, expected {attested_signer}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn make_signed_range(
        boot_info: &BootInfoStruct,
        pcr0_hash: &B256,
        signing_key: &SigningKey,
    ) -> Vec<u8> {
        let packed = pack_range_journal(
            pcr0_hash,
            &boot_info.rollupConfigHash,
            &boot_info.l1Head,
            boot_info.l2BlockNumber,
            &boot_info.l2PreRoot,
            &boot_info.l2PostRoot,
        );
        let digest = keccak256(packed);
        let (signature, recovery_id) =
            signing_key.sign_prehash_recoverable(digest.as_slice()).unwrap();
        let mut sig_bytes = vec![0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte() + 27;
        sig_bytes
    }

    fn signer_address(signing_key: &SigningKey) -> Address {
        let vk = signing_key.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let bytes = uncompressed.as_bytes();
        let hash = keccak256(&bytes[1..]);
        Address::from_slice(&hash[12..])
    }

    fn test_boot_info() -> BootInfoStruct {
        BootInfoStruct {
            l1Head: B256::from([0x11; 32]),
            l2PreRoot: B256::from([0x22; 32]),
            l2PostRoot: B256::from([0x33; 32]),
            l2BlockNumber: 42,
            rollupConfigHash: B256::from([0x44; 32]),
        }
    }

    #[test]
    fn test_verify_tee_range_proof_correct_signer() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xCC; 32]).0.into()).unwrap();
        let signer = signer_address(&signing_key);
        let pcr0_hash = B256::from([0x55; 32]);
        let boot_info = test_boot_info();
        let sig = make_signed_range(&boot_info, &pcr0_hash, &signing_key);

        verify_tee_range_proof(&boot_info, &sig, &pcr0_hash, &signer);
    }

    #[test]
    #[should_panic(expected = "signer mismatch")]
    fn test_verify_tee_range_proof_wrong_signer() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xCC; 32]).0.into()).unwrap();
        let wrong_signer = Address::from([0xFF; 20]);
        let pcr0_hash = B256::from([0x55; 32]);
        let boot_info = test_boot_info();
        let sig = make_signed_range(&boot_info, &pcr0_hash, &signing_key);

        verify_tee_range_proof(&boot_info, &sig, &pcr0_hash, &wrong_signer);
    }

    #[test]
    #[should_panic(expected = "signer mismatch")]
    fn test_verify_tee_range_proof_tampered_l2_post_root() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xCC; 32]).0.into()).unwrap();
        let signer = signer_address(&signing_key);
        let pcr0_hash = B256::from([0x55; 32]);
        let boot_info = test_boot_info();
        let sig = make_signed_range(&boot_info, &pcr0_hash, &signing_key);

        let mut tampered = boot_info.clone();
        tampered.l2PostRoot = B256::ZERO;
        verify_tee_range_proof(&tampered, &sig, &pcr0_hash, &signer);
    }

    #[test]
    #[should_panic(expected = "signer mismatch")]
    fn test_verify_tee_range_proof_tampered_l1_head() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xCC; 32]).0.into()).unwrap();
        let signer = signer_address(&signing_key);
        let pcr0_hash = B256::from([0x55; 32]);
        let boot_info = test_boot_info();
        let sig = make_signed_range(&boot_info, &pcr0_hash, &signing_key);

        let mut tampered = boot_info.clone();
        tampered.l1Head = B256::ZERO;
        verify_tee_range_proof(&tampered, &sig, &pcr0_hash, &signer);
    }

    #[test]
    #[should_panic(expected = "signer mismatch")]
    fn test_verify_tee_range_proof_tampered_pcr0() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xCC; 32]).0.into()).unwrap();
        let signer = signer_address(&signing_key);
        let pcr0_hash = B256::from([0x55; 32]);
        let boot_info = test_boot_info();
        let sig = make_signed_range(&boot_info, &pcr0_hash, &signing_key);

        let different_pcr0 = B256::ZERO;
        verify_tee_range_proof(&boot_info, &sig, &different_pcr0, &signer);
    }

    #[test]
    #[should_panic(expected = "TEE signature must be 65 bytes")]
    fn test_verify_tee_range_proof_bad_sig_length_64() {
        let signer = Address::from([0x01; 20]);
        let pcr0_hash = B256::from([0x55; 32]);
        let boot_info = test_boot_info();
        let sig = vec![0u8; 64];

        verify_tee_range_proof(&boot_info, &sig, &pcr0_hash, &signer);
    }

    #[test]
    #[should_panic(expected = "TEE signature must be 65 bytes")]
    fn test_verify_tee_range_proof_bad_sig_length_66() {
        let signer = Address::from([0x01; 20]);
        let pcr0_hash = B256::from([0x55; 32]);
        let boot_info = test_boot_info();
        let sig = vec![0u8; 66];

        verify_tee_range_proof(&boot_info, &sig, &pcr0_hash, &signer);
    }
}
