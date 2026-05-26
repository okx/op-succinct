//! ECDSA sign of the keccak256 digest over a packed [`RangeJournal`].

use alloy_primitives::{keccak256, FixedBytes};
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature};

use crate::{
    error::{Error, Result},
    keys::enclave_signing_key,
};
use xlayer_tee_types::{
    journal::{RangeJournal, RangeJournalWire},
    response::SIGNATURE_LEN,
};

/// secp256k1 v normalization: recovery id `0`/`1` → `27`/`28`.
const V_OFFSET: u8 = 27;

pub fn sign_range_journal(journal: &RangeJournal) -> Result<[u8; SIGNATURE_LEN]> {
    let digest = keccak256(journal.pack());
    sign_prehash(&digest)
}

pub fn sign_prehash(digest: &FixedBytes<32>) -> Result<[u8; SIGNATURE_LEN]> {
    let signing_key = enclave_signing_key();
    let (sig, recid): (Signature, RecoveryId) = signing_key
        .sign_prehash(digest.as_slice())
        .map_err(|e| Error::Signing(format!("k256 prehash sign: {e}")))?;
    let sig_bytes = sig.to_bytes();

    let mut out = [0u8; SIGNATURE_LEN];
    out[..64].copy_from_slice(&sig_bytes);
    out[64] = recid.to_byte() + V_OFFSET;
    Ok(out)
}

pub fn sign_range_wire(wire: &RangeJournalWire) -> Result<[u8; SIGNATURE_LEN]> {
    let journal: RangeJournal = wire.into();
    sign_range_journal(&journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use k256::ecdsa::{
        signature::hazmat::PrehashVerifier, RecoveryId as KRecoveryId, VerifyingKey,
    };

    use crate::keys::{enclave_address, init_dev_keys};

    fn sample_wire() -> RangeJournalWire {
        RangeJournalWire {
            pcr0: [0u8; 32],
            config_hash: [1u8; 32],
            l1_origin_hash: [2u8; 32],
            l2_block_number: 1800,
            prev_output_root: [3u8; 32],
            output_root: [4u8; 32],
        }
    }

    #[test]
    fn sign_then_recover_matches_enclave_address() {
        init_dev_keys();
        let wire = sample_wire();
        let journal: RangeJournal = (&wire).into();
        let sig = sign_range_journal(&journal).expect("sign");
        assert_eq!(sig.len(), 65);
        assert!(sig[64] == 27 || sig[64] == 28, "v must be 27 or 28, got {}", sig[64]);

        let digest = keccak256(journal.pack());
        let sig_only = Signature::from_slice(&sig[..64]).expect("sig parse");
        let recid_byte = sig[64] - V_OFFSET;
        let recid = KRecoveryId::try_from(recid_byte).expect("valid recid");
        let recovered = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig_only, recid)
            .expect("ecrecover");

        recovered.verify_prehash(digest.as_slice(), &sig_only).expect("verify");

        let recovered_uncompressed = recovered.to_encoded_point(false).as_bytes().to_vec();
        let recovered_addr_hash = alloy_primitives::keccak256(&recovered_uncompressed[1..]);
        let recovered_addr = Address::from_slice(&recovered_addr_hash[12..]);

        assert_eq!(recovered_addr, enclave_address());
    }
}
