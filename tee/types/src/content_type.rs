//! HTTP `Content-Type` constants used by the enclave server.

/// Binary rkyv-encoded bodies (range / aggregation responses).
pub const OCTET_STREAM: &str = "application/octet-stream";

/// JSON error bodies and the `/attestation` endpoint metadata.
pub const JSON: &str = "application/json";
