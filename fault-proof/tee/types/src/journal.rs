use alloy_primitives::FixedBytes;
use alloy_sol_types::sol;
use rkyv::{Archive, Deserialize, Serialize};

pub const PACKED_JOURNAL_LEN: usize = 168;
pub const SIGNATURE_LEN: usize = 65;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct RangeJournal {
        bytes32 pcr0;
        bytes32 configHash;
        bytes32 l1OriginHash;
        uint64  l2BlockNumber;
        bytes32 prevOutputRoot;
        bytes32 outputRoot;
    }
}

impl RangeJournal {
    pub fn pack(&self) -> [u8; PACKED_JOURNAL_LEN] {
        let mut buf = [0u8; PACKED_JOURNAL_LEN];
        buf[0..32].copy_from_slice(self.pcr0.as_slice());
        buf[32..64].copy_from_slice(self.configHash.as_slice());
        buf[64..96].copy_from_slice(self.l1OriginHash.as_slice());
        buf[96..104].copy_from_slice(&self.l2BlockNumber.to_be_bytes());
        buf[104..136].copy_from_slice(self.prevOutputRoot.as_slice());
        buf[136..168].copy_from_slice(self.outputRoot.as_slice());
        buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct RangeJournalWire {
    pub pcr0: [u8; 32],
    pub config_hash: [u8; 32],
    pub l1_origin_hash: [u8; 32],
    pub l2_block_number: u64,
    pub prev_output_root: [u8; 32],
    pub output_root: [u8; 32],
}

impl From<&RangeJournal> for RangeJournalWire {
    fn from(j: &RangeJournal) -> Self {
        Self {
            pcr0: j.pcr0.0,
            config_hash: j.configHash.0,
            l1_origin_hash: j.l1OriginHash.0,
            l2_block_number: j.l2BlockNumber,
            prev_output_root: j.prevOutputRoot.0,
            output_root: j.outputRoot.0,
        }
    }
}

impl From<&RangeJournalWire> for RangeJournal {
    fn from(w: &RangeJournalWire) -> Self {
        Self {
            pcr0: FixedBytes(w.pcr0),
            configHash: FixedBytes(w.config_hash),
            l1OriginHash: FixedBytes(w.l1_origin_hash),
            l2BlockNumber: w.l2_block_number,
            prevOutputRoot: FixedBytes(w.prev_output_root),
            outputRoot: FixedBytes(w.output_root),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct RangeTaskResponse {
    pub journal: RangeJournalWire,
    pub signature: [u8; SIGNATURE_LEN],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_journal(pcr0: u8, config: u8, l1: u8, block: u64, prev: u8, out: u8) -> RangeJournal {
        RangeJournal {
            pcr0: FixedBytes([pcr0; 32]),
            configHash: FixedBytes([config; 32]),
            l1OriginHash: FixedBytes([l1; 32]),
            l2BlockNumber: block,
            prevOutputRoot: FixedBytes([prev; 32]),
            outputRoot: FixedBytes([out; 32]),
        }
    }

    #[test]
    fn pack_length_and_field_offsets() {
        let journal = make_journal(0x01, 0x02, 0x03, 12345678, 0x04, 0x05);
        let packed = journal.pack();

        assert_eq!(packed.len(), PACKED_JOURNAL_LEN);
        assert_eq!(&packed[0..32], &[0x01; 32]);
        assert_eq!(&packed[32..64], &[0x02; 32]);
        assert_eq!(&packed[64..96], &[0x03; 32]);
        assert_eq!(&packed[96..104], &12345678_u64.to_be_bytes());
        assert_eq!(&packed[104..136], &[0x04; 32]);
        assert_eq!(&packed[136..168], &[0x05; 32]);
    }

    #[test]
    fn pack_l2_block_number_big_endian() {
        let journal = make_journal(0, 0, 0, 0x0102030405060708, 0, 0);
        let packed = journal.pack();
        assert_eq!(&packed[96..104], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn pack_different_fields_produce_different_bytes() {
        let baseline = make_journal(0x01, 0x02, 0x03, 100, 0x04, 0x05);
        let base_packed = baseline.pack();

        let offsets: &[(usize, usize)] =
            &[(0, 32), (32, 64), (64, 96), (96, 104), (104, 136), (136, 168)];
        let variants = [
            make_journal(0xFF, 0x02, 0x03, 100, 0x04, 0x05),
            make_journal(0x01, 0xFF, 0x03, 100, 0x04, 0x05),
            make_journal(0x01, 0x02, 0xFF, 100, 0x04, 0x05),
            make_journal(0x01, 0x02, 0x03, 999, 0x04, 0x05),
            make_journal(0x01, 0x02, 0x03, 100, 0xFF, 0x05),
            make_journal(0x01, 0x02, 0x03, 100, 0x04, 0xFF),
        ];

        for (i, variant) in variants.iter().enumerate() {
            let v_packed = variant.pack();
            assert_ne!(base_packed, v_packed, "field {i} change should produce different pack");
            let (start, end) = offsets[i];
            assert_ne!(
                &base_packed[start..end],
                &v_packed[start..end],
                "field {i} should differ at offset {start}..{end}"
            );
            for (j, &(s, e)) in offsets.iter().enumerate() {
                if j != i {
                    assert_eq!(
                        &base_packed[s..e],
                        &v_packed[s..e],
                        "field {j} should be unchanged when field {i} changes"
                    );
                }
            }
        }
    }

    #[test]
    fn pack_all_zero() {
        let journal = make_journal(0, 0, 0, 0, 0, 0);
        assert_eq!(journal.pack(), [0u8; PACKED_JOURNAL_LEN]);
    }

    #[test]
    fn pack_layout_freeze_regression() {
        let journal = make_journal(0xAA, 0xBB, 0xCC, 0xDDDDDDDDDDDDDDDD, 0xEE, 0xFF);
        let packed = journal.pack();

        let mut expected = [0u8; PACKED_JOURNAL_LEN];
        expected[0..32].copy_from_slice(&[0xAA; 32]);
        expected[32..64].copy_from_slice(&[0xBB; 32]);
        expected[64..96].copy_from_slice(&[0xCC; 32]);
        expected[96..104].copy_from_slice(&0xDDDDDDDDDDDDDDDD_u64.to_be_bytes());
        expected[104..136].copy_from_slice(&[0xEE; 32]);
        expected[136..168].copy_from_slice(&[0xFF; 32]);

        assert_eq!(packed, expected, "golden value regression failed");
    }

    #[test]
    fn journal_wire_round_trip_typical() {
        let journal = make_journal(0x01, 0x02, 0x03, 12345678, 0x04, 0x05);
        let wire = RangeJournalWire::from(&journal);
        let recovered = RangeJournal::from(&wire);
        assert_eq!(recovered, journal);
    }

    #[test]
    fn journal_wire_round_trip_all_zero() {
        let journal = make_journal(0, 0, 0, 0, 0, 0);
        let wire = RangeJournalWire::from(&journal);
        let recovered = RangeJournal::from(&wire);
        assert_eq!(recovered, journal);
    }

    #[test]
    fn journal_wire_round_trip_max_u64() {
        let journal = make_journal(0x01, 0x02, 0x03, u64::MAX, 0x04, 0x05);
        let wire = RangeJournalWire::from(&journal);
        let recovered = RangeJournal::from(&wire);
        assert_eq!(recovered, journal);
    }

    fn make_response(sig_byte: u8) -> RangeTaskResponse {
        let journal = make_journal(0x11, 0x22, 0x33, 42, 0x44, 0x55);
        RangeTaskResponse {
            journal: RangeJournalWire::from(&journal),
            signature: [sig_byte; SIGNATURE_LEN],
        }
    }

    #[test]
    fn range_task_response_rkyv_round_trip() {
        let cases = [0x42_u8, 0x00, 0xFF];
        for sig_byte in cases {
            let original = make_response(sig_byte);
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&original).expect("serialize failed");
            let archived = rkyv::access::<ArchivedRangeTaskResponse, rkyv::rancor::Error>(&bytes)
                .expect("access failed");
            let deserialized: RangeTaskResponse =
                rkyv::deserialize::<RangeTaskResponse, rkyv::rancor::Error>(archived)
                    .expect("deserialize failed");
            assert_eq!(deserialized, original, "sig_byte=0x{sig_byte:02X}");
            assert_eq!(deserialized.signature.len(), SIGNATURE_LEN);
        }
    }
}
