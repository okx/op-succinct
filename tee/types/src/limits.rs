//! Wire-level size and count limits that the enclave actively enforces.
//! Both sides must agree on these values; the proposer should reject upfront
//! and the enclave validates incoming requests as a defense-in-depth.
//!
//! Proposer-internal strategy parameters (range chunking granularity,
//! `intermediate_root` sampling rules) are NOT in this crate — the enclave
//! does not need to know them. The start/end blocks for each range request
//! are encoded in the witness's `BootInfo`; the aggregation
//! `intermediate_roots` are derived from the N range boundaries.

/// Maximum size of a single `/tasks/range` request body (rkyv DefaultWitnessData).
/// Proposer MUST reject witnesses exceeding this. Enclave axum body limit
/// is configured to this value.
pub const MAX_RANGE_BODY_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
