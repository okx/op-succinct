//! xlayer-tee-enclave library — the actual ELF logic, split into modules
//! so that integration tests and the bin entry point share the same code path.

pub mod keys;
pub mod attestation;
pub mod witness;
pub mod replay;
pub mod signing;
pub mod error;
pub mod runner;
pub mod task_manager;
pub mod gc;
pub mod server;
