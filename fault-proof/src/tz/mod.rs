//! TradeZone (tz) custom L2 chain support for ZK Fault Dispute off-chain services.
//!
//! Phase 1 implementation behind the `tz` Cargo feature. xlayer behavior is unchanged when
//! the feature is OFF.
//!
//! Module layout:
//! - `chain_client`: REST + cache + eviction client for tz `/chain/confirmed_block_info`.
//! - `config`: Environment-based `TzConfig`.
//! - `game_validator`: TZ claim validation against one fixed witness-builder root oracle.
//! - `l2_provider`: `TzL2Provider` implementing `L2ProviderTrait` against the REST cache, and the
//!   `compute_tz_root_claim` formula.
//!
//! Upstream sync: this module is a downstream addition. Upstream files touched are
//! `Cargo.toml` (feature flag + optional deps), `src/lib.rs` (`pub mod tz` + trait
//! methods on `L2ProviderTrait`), and `src/proposer.rs` (cfg blocks + TZ provider wiring).
//! The shared challenger lifecycle remains chain-agnostic; `bin/tz_challenger.rs` injects
//! `TzGameValidator` through the upstream `GameValidator` interface. Run
//! `git diff upstream/main -- fault-proof/src/{lib,proposer,game_validator}.rs`
//! to inspect divergence before rebasing.

pub mod chain_client;
pub mod config;
pub mod game_validator;
pub mod l2_provider;
pub mod withdraw;
