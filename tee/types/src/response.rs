//! HTTP response body type — rkyv-encoded.
//!
//! The enclave returns a [`RangeTaskResponse`] from `POST /tasks/range`,
//! which wraps the wire journal plus a 65-byte ECDSA signature.

use rkyv::{Archive, Deserialize, Serialize};

use crate::journal::RangeJournalWire;

/// Signature length in bytes: r(32) || s(32) || v(1).
/// `v` is normalized to 27 / 28.
pub const SIGNATURE_LEN: usize = 65;

/// Body of a successful `POST /tasks/range` response.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct RangeTaskResponse {
    pub journal: RangeJournalWire,
    pub signature: [u8; SIGNATURE_LEN],
}
