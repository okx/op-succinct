//! EIP712 digest computation + ECDSA prehash sign of a [`RangeJournal`].

use alloy_primitives::FixedBytes;
use alloy_sol_types::{Eip712Domain, SolStruct};
use k256::ecdsa::{RecoveryId, Signature, signature::hazmat::PrehashSigner};

use crate::{error::{Error, Result}, keys::enclave_signing_key};
use xlayer_tee_types::{
    journal::{RangeJournal, RangeJournalWire},
    response::SIGNATURE_LEN,
};

/// secp256k1 v normalization: recovery id `0`/`1` → `27`/`28`.
const V_OFFSET: u8 = 27;

/// Sign a [`RangeJournal`] under the given EIP712 domain. Returns 65 bytes
/// `r || s || v` with v already normalized to 27/28.
pub fn sign_range_journal(
    journal: &RangeJournal,
    domain: &Eip712Domain,
) -> Result<[u8; SIGNATURE_LEN]> {
    let digest: FixedBytes<32> = journal.eip712_signing_hash(domain);
    sign_prehash(&digest)
}

/// Sign a 32-byte digest directly using the enclave key, returning 65 bytes
/// `r || s || v` (v ∈ {27, 28}).
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

/// Convenience: build a `RangeJournal` from the wire form, then sign.
pub fn sign_range_wire(
    wire: &RangeJournalWire,
    domain: &Eip712Domain,
) -> Result<[u8; SIGNATURE_LEN]> {
    let journal: RangeJournal = wire.into();
    sign_range_journal(&journal, domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use k256::ecdsa::{RecoveryId as KRecoveryId, VerifyingKey, signature::hazmat::PrehashVerifier};

    use crate::keys::{enclave_address, init_dev_keys};
    use xlayer_tee_types::eip712::{NAME, VERSION};

    fn test_domain() -> Eip712Domain {
        Eip712Domain {
            name: Some(NAME.into()),
            version: Some(VERSION.into()),
            chain_id: Some(alloy_primitives::U256::from(1u64)),
            verifying_contract: Some(
                "0x1111111111111111111111111111111111111111".parse::<Address>().unwrap(),
            ),
            salt: None,
        }
    }

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
        let domain = test_domain();
        let wire = sample_wire();
        let journal: RangeJournal = (&wire).into();
        let sig = sign_range_journal(&journal, &domain).expect("sign");
        assert_eq!(sig.len(), 65);
        assert!(sig[64] == 27 || sig[64] == 28, "v must be 27 or 28, got {}", sig[64]);

        // Recover and check against the enclave address.
        let digest = journal.eip712_signing_hash(&domain);
        let sig_only = Signature::from_slice(&sig[..64]).expect("sig parse");
        let recid_byte = sig[64] - V_OFFSET;
        let recid = KRecoveryId::try_from(recid_byte).expect("valid recid");
        let recovered = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig_only, recid)
            .expect("ecrecover");

        // Verify roundtrip: signature is valid on the digest.
        recovered.verify_prehash(digest.as_slice(), &sig_only).expect("verify");

        // Address derivation from recovered pubkey.
        let recovered_uncompressed =
            recovered.to_encoded_point(false /* compressed */).as_bytes().to_vec();
        let recovered_addr_hash = alloy_primitives::keccak256(&recovered_uncompressed[1..]);
        let recovered_addr = Address::from_slice(&recovered_addr_hash[12..]);

        assert_eq!(recovered_addr, enclave_address());
    }
}
