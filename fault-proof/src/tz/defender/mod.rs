//! Independent TradeZone Defender service (spec §7.4).
//!
//! The Defender watches an X Layer Withdraw-challenge contract and, before each challenge's
//! response deadline, answers it with a historical inclusion proof taken from the Witness
//! Builder and verified locally. It runs as a fully independent binary (`tz-defender`) with its
//! own `main()` / config / signer — it never reads the Proposer's or Relayer's local caches as
//! authority, never creates L1 games, never mints roots, and never performs timeout settlement.
//!
//! The X Layer challenge/prove interface is not yet finalized, so it is abstracted behind the
//! [`challenge_contract::ChallengeContract`] trait with an in-memory
//! [`challenge_contract::MockChallengeContract`] (spec §5, decision 1); the real ABI later
//! replaces the mock without changing the state machine ([`handler::Handler`]).

pub mod cache;
pub mod challenge_contract;
pub mod config;
pub mod handler;
pub mod rootmanager_client;
pub mod verifier;
pub mod watcher;
pub mod witness_wb;

pub use challenge_contract::{ChallengeContract, ChallengeOpened, ChallengeStatus};
pub use config::DefenderConfig;
pub use handler::{Handler, HandlerOutcome};
