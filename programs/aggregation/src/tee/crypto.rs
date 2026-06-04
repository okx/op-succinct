use alloy_primitives::{keccak256, Address, B256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use op_succinct_client_utils::boot::BootInfoStruct;

pub const PACKED_JOURNAL_SIZE: usize = 168;

pub fn pack_range_journal(
    pcr0_hash: B256,
    config_hash: B256,
    l1_origin_hash: B256,
    l2_block_number: u64,
    prev_output_root: B256,
    output_root: B256,
) -> [u8; PACKED_JOURNAL_SIZE] {
    let mut packed = [0u8; PACKED_JOURNAL_SIZE];
    packed[0..32].copy_from_slice(pcr0_hash.as_slice());
    packed[32..64].copy_from_slice(config_hash.as_slice());
    packed[64..96].copy_from_slice(l1_origin_hash.as_slice());
    packed[96..104].copy_from_slice(&l2_block_number.to_be_bytes());
    packed[104..136].copy_from_slice(prev_output_root.as_slice());
    packed[136..168].copy_from_slice(output_root.as_slice());
    packed
}

pub fn ecrecover(digest: &[u8; 32], sig_65: &[u8]) -> Address {
    assert!(sig_65.len() == 65, "signature must be 65 bytes");
    let sig = Signature::from_slice(&sig_65[..64]).expect("invalid signature bytes");
    let v = sig_65[64].checked_sub(27).expect("recovery id must be 27 or 28");
    let rec_id = RecoveryId::try_from(v).expect("invalid recovery id");
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, rec_id).expect("ecrecover failed");
    address_from_verifying_key(&vk)
}

pub fn address_from_pubkey(pubkey_sec1: &[u8]) -> Address {
    assert!(pubkey_sec1.len() == 65, "SEC1 uncompressed key must be 65 bytes");
    assert!(pubkey_sec1[0] == 0x04, "SEC1 prefix must be 0x04");
    let hash = keccak256(&pubkey_sec1[1..]);
    Address::from_slice(&hash[12..])
}

fn address_from_verifying_key(vk: &VerifyingKey) -> Address {
    let pubkey_bytes = vk.to_encoded_point(false);
    let pubkey_uncompressed = pubkey_bytes.as_bytes();
    address_from_pubkey(pubkey_uncompressed)
}

pub fn verify_tee_range_proof(
    boot_info: &BootInfoStruct,
    signature: &[u8],
    attested_pcr0: B256,
    attested_signer: Address,
) {
    assert!(signature.len() == 65, "TEE signature must be 65 bytes");
    let packed = pack_range_journal(
        attested_pcr0,
        boot_info.rollupConfigHash,
        boot_info.l1Head,
        boot_info.l2BlockNumber,
        boot_info.l2PreRoot,
        boot_info.l2PostRoot,
    );
    let digest: [u8; 32] = keccak256(&packed).into();
    let recovered = ecrecover(&digest, signature);
    assert_eq!(
        recovered, attested_signer,
        "TEE leaf signer mismatch: recovered {recovered} != attested {attested_signer}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn make_boot_info() -> BootInfoStruct {
        BootInfoStruct {
            l1Head: B256::from([0x03; 32]),
            l2PreRoot: B256::from([0x04; 32]),
            l2PostRoot: B256::from([0x05; 32]),
            l2BlockNumber: 42,
            rollupConfigHash: B256::from([0x02; 32]),
        }
    }

    fn sign_commitment(sk: &SigningKey, pcr0_hash: B256, boot_info: &BootInfoStruct) -> Vec<u8> {
        let packed = pack_range_journal(
            pcr0_hash,
            boot_info.rollupConfigHash,
            boot_info.l1Head,
            boot_info.l2BlockNumber,
            boot_info.l2PreRoot,
            boot_info.l2PostRoot,
        );
        let digest: [u8; 32] = keccak256(&packed).into();
        let (sig, rec_id) = sk.sign_prehash_recoverable(&digest).expect("signing failed");
        let mut sig_65 = [0u8; 65];
        sig_65[..64].copy_from_slice(&sig.to_bytes());
        sig_65[64] = rec_id.to_byte() + 27;
        sig_65.to_vec()
    }

    fn signer_address(sk: &SigningKey) -> Address {
        let vk = sk.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        address_from_pubkey(pubkey.as_bytes())
    }

    #[test]
    fn test_pack_range_journal_golden_vector() {
        let packed = pack_range_journal(
            B256::from([0x01; 32]),
            B256::from([0x02; 32]),
            B256::from([0x03; 32]),
            0x0102030405060708_u64,
            B256::from([0x04; 32]),
            B256::from([0x05; 32]),
        );

        assert_eq!(packed.len(), 168);
        assert_eq!(&packed[0..32], &[0x01; 32]);
        assert_eq!(&packed[32..64], &[0x02; 32]);
        assert_eq!(&packed[64..96], &[0x03; 32]);
        assert_eq!(&packed[96..104], &0x0102030405060708_u64.to_be_bytes());
        assert_eq!(&packed[104..136], &[0x04; 32]);
        assert_eq!(&packed[136..168], &[0x05; 32]);
    }

    #[test]
    fn test_ecrecover_roundtrip() {
        let sk = SigningKey::from_bytes(&[0xAA; 32].into()).unwrap();
        let expected_addr = signer_address(&sk);

        let digest = [0xBB; 32];
        let (sig, rec_id) = sk.sign_prehash_recoverable(&digest).expect("signing failed");
        let mut sig_65 = [0u8; 65];
        sig_65[..64].copy_from_slice(&sig.to_bytes());
        sig_65[64] = rec_id.to_byte() + 27;

        let recovered = ecrecover(&digest, &sig_65);
        assert_eq!(recovered, expected_addr);
    }

    #[test]
    fn test_ecrecover_invalid_recovery_id() {
        let cases = vec![
            (0u8, "recovery id underflow (< 27)"),
            (29u8, "recovery id overflow (> 28)"),
            (255u8, "recovery id max value"),
        ];
        for (v_byte, desc) in cases {
            let mut sig_65 = [0u8; 65];
            sig_65[64] = v_byte;
            let digest = [0xCC; 32];
            let result = std::panic::catch_unwind(|| ecrecover(&digest, &sig_65));
            assert!(result.is_err(), "should panic for {desc}");
        }
    }

    #[test]
    fn test_verify_tee_range_proof_correct_signer() {
        let sk = SigningKey::from_bytes(&[0xAA; 32].into()).unwrap();
        let pcr0_hash = B256::from([0x01; 32]);
        let boot_info = make_boot_info();
        let sig = sign_commitment(&sk, pcr0_hash, &boot_info);
        let addr = signer_address(&sk);

        verify_tee_range_proof(&boot_info, &sig, pcr0_hash, addr);
    }

    #[test]
    #[should_panic(expected = "signer mismatch")]
    fn test_verify_tee_range_proof_wrong_signer() {
        let sk = SigningKey::from_bytes(&[0xAA; 32].into()).unwrap();
        let pcr0_hash = B256::from([0x01; 32]);
        let boot_info = make_boot_info();
        let sig = sign_commitment(&sk, pcr0_hash, &boot_info);

        let wrong_sk = SigningKey::from_bytes(&[0xBB; 32].into()).unwrap();
        let wrong_addr = signer_address(&wrong_sk);

        verify_tee_range_proof(&boot_info, &sig, pcr0_hash, wrong_addr);
    }

    #[test]
    #[should_panic(expected = "signer mismatch")]
    fn test_verify_tee_range_proof_tampered_field() {
        let sk = SigningKey::from_bytes(&[0xAA; 32].into()).unwrap();
        let pcr0_hash = B256::from([0x01; 32]);
        let boot_info = make_boot_info();
        let sig = sign_commitment(&sk, pcr0_hash, &boot_info);
        let addr = signer_address(&sk);

        let mut tampered = boot_info;
        tampered.l2PostRoot = B256::from([0xFF; 32]);
        verify_tee_range_proof(&tampered, &sig, pcr0_hash, addr);
    }

    #[test]
    fn test_verify_tee_range_proof_wrong_sig_length() {
        let boot_info = make_boot_info();
        let cases = vec![(vec![0u8; 64], "too short"), (vec![0u8; 66], "too long")];
        for (sig, desc) in cases {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                verify_tee_range_proof(&boot_info, &sig, B256::from([0x01; 32]), Address::ZERO);
            }));
            assert!(result.is_err(), "should panic for {desc}");
        }
    }

    #[test]
    fn test_address_from_pubkey_valid() {
        let sk = SigningKey::from_bytes(&[0xCC; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = address_from_pubkey(pubkey.as_bytes());
        assert_ne!(addr, Address::ZERO);
    }

    #[test]
    #[should_panic(expected = "SEC1 uncompressed key must be 65 bytes")]
    fn test_address_from_pubkey_wrong_length() {
        address_from_pubkey(&[0x04; 33]);
    }

    #[test]
    #[should_panic(expected = "SEC1 prefix must be 0x04")]
    fn test_address_from_pubkey_wrong_prefix() {
        let mut key = [0u8; 65];
        key[0] = 0x03;
        address_from_pubkey(&key);
    }
}
