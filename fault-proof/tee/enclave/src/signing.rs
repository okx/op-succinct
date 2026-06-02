use k256::ecdsa::signature::hazmat::PrehashSigner;
use sha3::{Digest, Keccak256};
use xlayer_tee_types::{RangeJournal, RangeJournalWire};

use crate::{error::Error, keys::enclave_signing_key};

pub fn sign_range_wire(wire: &RangeJournalWire) -> Result<[u8; 65], Error> {
    let journal = RangeJournal::from(wire);
    let packed = journal.pack();
    let digest = Keccak256::digest(packed);

    let signing_key = enclave_signing_key();
    let (signature, recovery_id) = signing_key
        .sign_prehash(digest.as_ref())
        .map_err(|e| Error::Internal(anyhow::anyhow!("signing failed: {e}")))?;

    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&signature.r().to_bytes());
    out[32..64].copy_from_slice(&signature.s().to_bytes());
    out[64] = recovery_id.to_byte() + 27;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{enclave_address, enclave_pubkey_uncompressed, init_dev_keys};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use xlayer_tee_types::journal::PACKED_JOURNAL_LEN;

    fn ensure_key_initialized() {
        init_dev_keys();
    }

    fn sample_wire() -> RangeJournalWire {
        RangeJournalWire {
            pcr0: [0u8; 32],
            config_hash: [0x11; 32],
            l1_origin_hash: [0x22; 32],
            l2_block_number: 42,
            prev_output_root: [0x33; 32],
            output_root: [0x44; 32],
        }
    }

    #[test]
    fn sign_range_wire_produces_65_bytes() {
        ensure_key_initialized();
        let wire = sample_wire();
        let sig = sign_range_wire(&wire).unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn sign_range_wire_v_is_27_or_28() {
        ensure_key_initialized();
        let wire = sample_wire();
        let sig = sign_range_wire(&wire).unwrap();
        assert!(sig[64] == 27 || sig[64] == 28, "v should be 27 or 28, got {}", sig[64]);
    }

    #[test]
    fn sign_range_wire_deterministic() {
        ensure_key_initialized();
        let wire = sample_wire();
        let sig1 = sign_range_wire(&wire).unwrap();
        let sig2 = sign_range_wire(&wire).unwrap();
        assert_eq!(sig1, sig2, "signing must be deterministic");
    }

    #[test]
    fn sign_range_wire_ecrecover_yields_enclave_address() {
        ensure_key_initialized();
        let wire = sample_wire();
        let sig_bytes = sign_range_wire(&wire).unwrap();

        let journal = RangeJournal::from(&wire);
        let packed = journal.pack();
        assert_eq!(packed.len(), PACKED_JOURNAL_LEN);
        let digest = Keccak256::digest(packed);

        let r_bytes: [u8; 32] = sig_bytes[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = sig_bytes[32..64].try_into().unwrap();
        let v = sig_bytes[64] - 27;

        let signature = Signature::from_scalars(r_bytes, s_bytes).unwrap();
        let recovery_id = RecoveryId::from_byte(v).unwrap();

        let recovered_key =
            VerifyingKey::recover_from_prehash(digest.as_ref(), &signature, recovery_id).unwrap();

        let recovered_point = recovered_key.to_encoded_point(false);
        let recovered_bytes = recovered_point.as_bytes();
        let recovered_hash = Keccak256::digest(&recovered_bytes[1..]);
        let recovered_addr = &recovered_hash[12..];

        let expected_addr = enclave_address();
        assert_eq!(
            recovered_addr,
            expected_addr.as_slice(),
            "ecrecover should yield the enclave address"
        );

        let pubkey = enclave_pubkey_uncompressed();
        assert_eq!(recovered_bytes, &pubkey[..]);
    }

    #[test]
    fn different_wire_produces_different_signature() {
        ensure_key_initialized();
        let wire1 = sample_wire();
        let mut wire2 = sample_wire();
        wire2.l2_block_number = 99;

        let sig1 = sign_range_wire(&wire1).unwrap();
        let sig2 = sign_range_wire(&wire2).unwrap();
        assert_ne!(sig1, sig2);
    }
}
