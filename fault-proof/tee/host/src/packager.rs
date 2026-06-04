use alloy_primitives::Bytes as AlloBytes;
use alloy_sol_types::SolValue;
use xlayer_tee_types::{RangeJournal, RangeJournalWire};

pub fn pack_proof_bytes(wire: &RangeJournalWire, signature: &[u8; 65]) -> Vec<u8> {
    let journal = RangeJournal::from(wire);
    let sig_bytes = AlloBytes::copy_from_slice(signature);
    (journal, sig_bytes).abi_encode_params()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wire(pcr0: u8, cfg: u8, l1: u8, block: u64, prev: u8, out: u8) -> RangeJournalWire {
        RangeJournalWire {
            pcr0: [pcr0; 32],
            config_hash: [cfg; 32],
            l1_origin_hash: [l1; 32],
            l2_block_number: block,
            prev_output_root: [prev; 32],
            output_root: [out; 32],
        }
    }

    #[test]
    fn round_trip_typical_values() {
        let wire = make_wire(0x01, 0x02, 0x03, 12345678, 0x04, 0x05);
        let sig = [0xAB_u8; 65];
        let encoded = pack_proof_bytes(&wire, &sig);

        type ProofTuple = (RangeJournal, AlloBytes);
        let decoded =
            ProofTuple::abi_decode_params(&encoded).expect("abi_decode_params should succeed");
        let (journal, sig_bytes) = decoded;

        assert_eq!(journal.pcr0.0, [0x01; 32]);
        assert_eq!(journal.configHash.0, [0x02; 32]);
        assert_eq!(journal.l1OriginHash.0, [0x03; 32]);
        assert_eq!(journal.l2BlockNumber, 12345678);
        assert_eq!(journal.prevOutputRoot.0, [0x04; 32]);
        assert_eq!(journal.outputRoot.0, [0x05; 32]);
        assert_eq!(sig_bytes.as_ref(), &[0xAB; 65]);
    }

    #[test]
    fn deterministic_output() {
        let wire = make_wire(0x01, 0x02, 0x03, 42, 0x04, 0x05);
        let sig = [0xFF_u8; 65];
        let a = pack_proof_bytes(&wire, &sig);
        let b = pack_proof_bytes(&wire, &sig);
        assert_eq!(a, b, "same inputs must produce identical output");
    }

    #[test]
    fn round_trip_all_zero() {
        let wire = make_wire(0, 0, 0, 0, 0, 0);
        let sig = [0_u8; 65];
        let encoded = pack_proof_bytes(&wire, &sig);

        type ProofTuple = (RangeJournal, AlloBytes);
        let (journal, sig_bytes) =
            ProofTuple::abi_decode_params(&encoded).expect("decode should succeed");

        assert_eq!(journal.l2BlockNumber, 0);
        assert_eq!(sig_bytes.as_ref(), &[0u8; 65]);
    }

    #[test]
    fn round_trip_max_u64_block_number() {
        let wire = make_wire(0x01, 0x02, 0x03, u64::MAX, 0x04, 0x05);
        let sig = [0xCD_u8; 65];
        let encoded = pack_proof_bytes(&wire, &sig);

        type ProofTuple = (RangeJournal, AlloBytes);
        let (journal, _) = ProofTuple::abi_decode_params(&encoded).expect("decode should succeed");

        assert_eq!(journal.l2BlockNumber, u64::MAX);
    }

    #[test]
    fn uses_abi_encode_params_not_abi_encode() {
        let wire = make_wire(0x01, 0x02, 0x03, 42, 0x04, 0x05);
        let sig = [0xAB_u8; 65];
        let encoded = pack_proof_bytes(&wire, &sig);

        let journal = RangeJournal::from(&wire);
        let sig_bytes = AlloBytes::copy_from_slice(&sig);
        let wrong = (journal, sig_bytes).abi_encode();
        assert_ne!(encoded, wrong, "must use abi_encode_params, not abi_encode");
    }
}
