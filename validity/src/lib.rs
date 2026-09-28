// `handle_proving_requests()` overflows rustc's default query depth when computing its
// future layout with the sp1-cluster proving types under the newer CI nightly. Raise the
// crate recursion limit as rustc suggests; build-config only, no behavioral change.
#![recursion_limit = "256"]

mod config;
mod contract;
mod db;
mod env;
mod prom;
mod proof_requester;
mod proposer;
mod types;
mod utils;

pub use config::*;
pub use contract::*;
pub use db::*;
pub use env::*;
pub use prom::*;
pub use proof_requester::*;
pub use proposer::*;
pub use types::*;
pub use utils::*;
