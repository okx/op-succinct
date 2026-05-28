//! `RangeJournal` — packed-bytes journal signed by the enclave per Range proof.

use alloy_primitives::FixedBytes;
use alloy_sol_types::sol;
use rkyv::{Archive, Deserialize, Serialize};

/// Byte length of the packed journal: 32 + 32 + 32 + 8 + 32 + 32.
pub const PACKED_JOURNAL_LEN: usize = 168;

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
    /// Concatenated bytes hashed by `keccak256` to produce the ECDSA signing digest.
    pub fn pack(&self) -> [u8; PACKED_JOURNAL_LEN] {
        let mut out = [0u8; PACKED_JOURNAL_LEN];
        out[0..32].copy_from_slice(&self.pcr0.0);
        out[32..64].copy_from_slice(&self.configHash.0);
        out[64..96].copy_from_slice(&self.l1OriginHash.0);
        out[96..104].copy_from_slice(&self.l2BlockNumber.to_be_bytes());
        out[104..136].copy_from_slice(&self.prevOutputRoot.0);
        out[136..168].copy_from_slice(&self.outputRoot.0);
        out
    }
}

/// rkyv-friendly mirror of [`RangeJournal`] for HTTP wire transmission.
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
