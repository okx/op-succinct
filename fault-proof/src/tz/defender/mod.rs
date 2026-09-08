//! Independent TradeZone Defender service (spec §7.4).
//!
//! The Defender watches an X Layer Withdraw-challenge contract and, before each challenge's
//! response deadline, answers it with a historical inclusion proof taken from the Witness
//! Builder and verified locally. It runs as a fully independent binary (`tz-defender`) with its
//! own `main()` / config / signer — it never reads the Proposer's or Relayer's local caches as
//! authority, never creates L1 games, never mints roots, and never performs timeout settlement.
//!
//! The X Layer challenge/prove interface is not yet finalized, so it is abstracted behind three
//! minimal, mockable seams — [`challenge_contract::ChallengeEventSource`],
//! [`challenge_contract::ChallengeReader`], and [`challenge_contract::ChallengeSender`], all keyed
//! by an opaque [`challenge_contract::ChallengeId`] — with an in-memory
//! [`challenge_contract::MockChallengeContract`]. The real ABI later replaces the mock without
//! changing the watcher, handler state machine, or local verification.

pub mod cache;
pub mod challenge_contract;
pub mod config;
pub mod handler;
pub mod rootmanager_client;
pub mod supervisor;
pub mod verifier;
pub mod watcher;
pub mod witness_wb;

pub use challenge_contract::{
    ChallengeEventSource, ChallengeId, ChallengeOpened, ChallengeReader, ChallengeSender,
    ChallengeStatus,
};
pub use config::DefenderConfig;
pub use handler::{ChallengeState, Handler};
pub use supervisor::Supervisor;
