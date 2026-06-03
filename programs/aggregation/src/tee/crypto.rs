use alloy_primitives::{keccak256, Address, B256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// Pack a range journal into a fixed 168-byte commitment.
/// Layout: pcr0(32) | configHash(32) | l1Head(32) | l2BlockNumber(8 BE) | l2PreRoot(32) |
/// l2PostRoot(32)
pub fn pack_range_journal(
    pcr0_hash: &B256,
    config_hash: &B256,
    l1_head: &B256,
    l2_block_number: u64,
    l2_pre_root: &B256,
    l2_post_root: &B256,
) -> [u8; 168] {
    let mut packed = [0u8; 168];
    packed[0..32].copy_from_slice(pcr0_hash.as_slice());
    packed[32..64].copy_from_slice(config_hash.as_slice());
    packed[64..96].copy_from_slice(l1_head.as_slice());
    packed[96..104].copy_from_slice(&l2_block_number.to_be_bytes());
    packed[104..136].copy_from_slice(l2_pre_root.as_slice());
    packed[136..168].copy_from_slice(l2_post_root.as_slice());
    packed
}

/// Recover Ethereum address from a keccak256 digest and a 65-byte signature (r||s||v, v in
/// {27,28}).
pub fn ecrecover(digest: &B256, sig_65: &[u8]) -> Address {
    assert!(sig_65.len() == 65, "signature must be 65 bytes");
    let sig = Signature::from_slice(&sig_65[..64]).expect("invalid signature bytes");
    let rec_id = sig_65[64]
        .checked_sub(27)
        .and_then(|v| RecoveryId::try_from(v).ok())
        .expect("invalid recovery id: must be 27 or 28");
    let recovered_key = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, rec_id)
        .expect("ecrecover failed");
    address_from_verifying_key(&recovered_key)
}

fn address_from_verifying_key(key: &VerifyingKey) -> Address {
    let uncompressed = key.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    assert!(bytes.len() == 65 && bytes[0] == 0x04);
    let hash = keccak256(&bytes[1..]);
    Address::from_slice(&hash[12..])
}

/// Derive Ethereum address from a SEC1 uncompressed secp256k1 public key (65 bytes, 0x04 prefix).
pub fn address_from_pubkey(pubkey: &[u8]) -> Address {
    assert!(pubkey.len() == 65 && pubkey[0] == 0x04, "invalid SEC1 uncompressed pubkey");
    let hash = keccak256(&pubkey[1..]);
    Address::from_slice(&hash[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    #[test]
    fn test_pack_range_journal_golden_vector() {
        let pcr0_hash = B256::from([0x01; 32]);
        let config_hash = B256::from([0x02; 32]);
        let l1_head = B256::from([0x03; 32]);
        let l2_block_number: u64 = 0x0102030405060708;
        let l2_pre_root = B256::from([0x04; 32]);
        let l2_post_root = B256::from([0x05; 32]);

        let packed = pack_range_journal(
            &pcr0_hash,
            &config_hash,
            &l1_head,
            l2_block_number,
            &l2_pre_root,
            &l2_post_root,
        );

        assert_eq!(packed.len(), 168);
        assert_eq!(&packed[0..32], &[0x01; 32]);
        assert_eq!(&packed[32..64], &[0x02; 32]);
        assert_eq!(&packed[64..96], &[0x03; 32]);
        assert_eq!(&packed[96..104], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(&packed[104..136], &[0x04; 32]);
        assert_eq!(&packed[136..168], &[0x05; 32]);
    }

    #[test]
    fn test_ecrecover_roundtrip() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xAA; 32]).0.into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let expected_addr = address_from_verifying_key(verifying_key);

        let prehash = keccak256(b"test message");
        let (signature, recovery_id) =
            signing_key.sign_prehash_recoverable(prehash.as_slice()).unwrap();

        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte() + 27;

        let recovered = ecrecover(&prehash, &sig_bytes);
        assert_eq!(recovered, expected_addr);
    }

    #[test]
    #[should_panic(expected = "invalid recovery id: must be 27 or 28")]
    fn test_ecrecover_invalid_recovery_id_underflow() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xDD; 32]).0.into()).unwrap();
        let prehash = keccak256(b"test for bad v");
        let (signature, _) = signing_key.sign_prehash_recoverable(prehash.as_slice()).unwrap();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = 26;
        ecrecover(&prehash, &sig_bytes);
    }

    #[test]
    #[should_panic(expected = "ecrecover failed")]
    fn test_ecrecover_invalid_recovery_id_overflow() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xDD; 32]).0.into()).unwrap();
        let prehash = keccak256(b"test for bad v");
        let (signature, _) = signing_key.sign_prehash_recoverable(prehash.as_slice()).unwrap();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = 30;
        ecrecover(&prehash, &sig_bytes);
    }

    #[test]
    fn test_address_from_pubkey_roundtrip() {
        let signing_key = SigningKey::from_bytes(&B256::from([0xBB; 32]).0.into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let uncompressed = verifying_key.to_encoded_point(false);
        let pubkey_bytes = uncompressed.as_bytes();

        let addr1 = address_from_verifying_key(verifying_key);
        let addr2 = address_from_pubkey(pubkey_bytes);
        assert_eq!(addr1, addr2);
    }

    #[test]
    #[should_panic(expected = "invalid SEC1 uncompressed pubkey")]
    fn test_address_from_pubkey_wrong_prefix() {
        let mut pubkey = [0u8; 65];
        pubkey[0] = 0x02;
        address_from_pubkey(&pubkey);
    }

    #[test]
    #[should_panic(expected = "invalid SEC1 uncompressed pubkey")]
    fn test_address_from_pubkey_wrong_length() {
        let pubkey = [0x04; 64];
        address_from_pubkey(&pubkey);
    }
}
