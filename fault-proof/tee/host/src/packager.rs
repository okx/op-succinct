use alloy_primitives::Bytes as AlloyBytes;
use alloy_sol_types::SolValue;
use xlayer_tee_types::{RangeJournal, RangeTaskResponse};

pub fn pack_proof_bytes(response: &RangeTaskResponse) -> Vec<u8> {
    let journal = RangeJournal::from(&response.journal);
    let sig = AlloyBytes::copy_from_slice(&response.signature);
    (journal, sig).abi_encode_params()
}

pub fn format_proof_hex(proof_bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(proof_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolValue;
    use xlayer_tee_types::journal::{RangeJournalWire, SIGNATURE_LEN};

    fn make_test_response(fill: u8, block_num: u64, sig_byte: u8) -> RangeTaskResponse {
        RangeTaskResponse {
            journal: RangeJournalWire {
                pcr0: [fill; 32],
                config_hash: [fill.wrapping_add(1); 32],
                l1_origin_hash: [fill.wrapping_add(2); 32],
                l2_block_number: block_num,
                prev_output_root: [fill.wrapping_add(3); 32],
                output_root: [fill.wrapping_add(4); 32],
            },
            signature: [sig_byte; SIGNATURE_LEN],
        }
    }

    #[test]
    fn round_trip_populated_fields() {
        let response = make_test_response(0x11, 12345, 0xAB);
        let encoded = pack_proof_bytes(&response);
        type ProofTuple = (RangeJournal, AlloyBytes);
        let decoded = ProofTuple::abi_decode_params(&encoded).unwrap();
        assert_eq!(decoded.0.pcr0.0, response.journal.pcr0);
        assert_eq!(decoded.0.configHash.0, response.journal.config_hash);
        assert_eq!(decoded.0.l1OriginHash.0, response.journal.l1_origin_hash);
        assert_eq!(decoded.0.l2BlockNumber, response.journal.l2_block_number);
        assert_eq!(decoded.0.prevOutputRoot.0, response.journal.prev_output_root);
        assert_eq!(decoded.0.outputRoot.0, response.journal.output_root);
        assert_eq!(decoded.1.as_ref(), &response.signature);
    }

    #[test]
    fn round_trip_zero_fields() {
        let response = make_test_response(0x00, 0, 0x00);
        let encoded = pack_proof_bytes(&response);
        type ProofTuple = (RangeJournal, AlloyBytes);
        let decoded = ProofTuple::abi_decode_params(&encoded).unwrap();
        assert_eq!(decoded.0.l2BlockNumber, 0);
        assert_eq!(decoded.0.pcr0.0, [0u8; 32]);
        assert_eq!(decoded.1.as_ref(), &[0u8; SIGNATURE_LEN]);
    }

    #[test]
    fn deterministic_encoding() {
        let response = make_test_response(0x42, 999, 0xFF);
        let enc1 = pack_proof_bytes(&response);
        let enc2 = pack_proof_bytes(&response);
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn uses_abi_encode_params_not_abi_encode() {
        let response = make_test_response(0x11, 100, 0xAA);
        let params_encoded = pack_proof_bytes(&response);
        let journal = RangeJournal::from(&response.journal);
        let sig = AlloyBytes::copy_from_slice(&response.signature);
        let full_encoded = (journal, sig).abi_encode();
        assert!(full_encoded.len() > params_encoded.len());
    }

    #[test]
    fn format_proof_hex_prefixed() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(format_proof_hex(&bytes), "0xdeadbeef");
    }
}
