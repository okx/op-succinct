//! Encode `RangeJournal + signature` into `proofBytes` accepted by
//! `TeeDisputeGame.prove(bytes)`.

use alloy_sol_types::SolValue;
use xlayer_tee_types::{journal::SIGNATURE_LEN, RangeJournal, RangeJournalWire, RangeTaskResponse};

use crate::error::Result;

/// `proofBytes = abi.encode(RangeJournal journal, bytes signature)`.
///
/// `abi_encode_params` (no outer offset) so on-chain
/// `abi.decode(proofBytes, (RangeJournal, bytes))` lines up.
pub fn encode_proof_bytes(
    journal: &RangeJournalWire,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<Vec<u8>> {
    let sol_journal: RangeJournal = journal.into();
    let sig_bytes = alloy_primitives::Bytes::copy_from_slice(signature);
    Ok((sol_journal, sig_bytes).abi_encode_params())
}

/// Convenience wrapper around [`encode_proof_bytes`] that takes the full
/// enclave [`RangeTaskResponse`] (journal + signature) returned from
/// `GET /tasks/{id}` when the task is `Finished`.
pub fn encode_proof_bytes_from_response(resp: &RangeTaskResponse) -> Result<Vec<u8>> {
    encode_proof_bytes(&resp.journal, &resp.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_journal() -> RangeJournalWire {
        RangeJournalWire {
            pcr0: [0u8; 32],
            config_hash: [0x11; 32],
            l1_origin_hash: [0x22; 32],
            l2_block_number: 1800,
            prev_output_root: [0x33; 32],
            output_root: [0x44; 32],
        }
    }

    #[test]
    fn encodes_fixed_input_to_fixed_output() {
        let sig = [0u8; SIGNATURE_LEN];
        let bytes = encode_proof_bytes(&sample_journal(), &sig).unwrap();
        let h = hex::encode(&bytes);

        // ABI(RangeJournal, bytes signature) — verify recognisable fields.
        assert!(h.contains(&"11".repeat(32)), "configHash");
        assert!(h.contains(&"22".repeat(32)), "l1OriginHash");
        assert!(h.contains(&format!("{:0>64x}", 1800u64)), "l2BlockNumber");
        assert!(h.contains(&"33".repeat(32)), "prevOutputRoot");
        assert!(h.contains(&"44".repeat(32)), "outputRoot");
        assert!(h.contains(&format!("{:0>64x}", 65u64)), "sig length 65");
    }

    #[test]
    fn from_response_wraps_correctly() {
        let resp = RangeTaskResponse {
            journal: sample_journal(),
            signature: [0u8; SIGNATURE_LEN],
        };
        let direct = encode_proof_bytes(&resp.journal, &resp.signature).unwrap();
        let via_wrapper = encode_proof_bytes_from_response(&resp).unwrap();
        assert_eq!(direct, via_wrapper);
    }
}
