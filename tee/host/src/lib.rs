//! TEE Host: proposer ↔ enclave 协调层.
//!
//! See ../SPEC.md for the full specification.

pub mod api;
pub mod config;
pub mod enclave_client;
pub mod error;
pub mod packager;
pub mod server;
pub mod task_manager;

pub use config::Config;
pub use enclave_client::EnclaveClient;
pub use error::{Error, Result, CODE_INTERNAL_ERROR, CODE_INVALID_ARGUMENT, CODE_OK, CODE_RESOURCE_NOT_FOUND};
pub use server::{router, AppState};
pub use task_manager::TaskManager;
