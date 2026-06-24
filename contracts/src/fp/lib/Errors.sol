// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

////////////////////////////////////////////////////////////////
//            `OPSuccinctFaultDisputeGame` Errors             //
////////////////////////////////////////////////////////////////

/// @notice Thrown when the claim has already been challenged.
error ClaimAlreadyChallenged();

/// @notice Thrown when the game type of the parent game does not match the current game.
error UnexpectedGameType();

/// @notice Thrown when the parent game is invalid.
error InvalidParentGame();

/// @notice Thrown when the parent game is not resolved.
error ParentGameNotResolved();

/// @notice Thrown when the game is over.
error GameOver();

/// @notice Thrown when the game is not over.
error GameNotOver();

/// @notice Thrown when the proposal status is invalid.
error InvalidProposalStatus();

/// @notice Thrown when the game is initialized by an incorrect factory.
error IncorrectDisputeGameFactory();

////////////////////////////////////////////////////////////////
//          `TZOPSuccinctFaultDisputeGame` Errors             //
//          (TZ-spec additions per SPEC §12.4)                //
////////////////////////////////////////////////////////////////

/// @notice Thrown when derived numSegments is outside `[1, MAX_NUM_SEGMENTS]`.
/// @param  actual Derived numSegments value from CWIA calldata length.
error InvalidNumSegments(uint64 actual);

/// @notice Thrown when `batchSize % numSegments != 0` (SEGMENT_SIZE would not be a positive integer).
error InvalidBatchSize();

/// @notice Thrown by any mutator first-check when `status != IN_PROGRESS` (SPEC §11.9 Invariant 31).
/// @dev    resolve() uses V1's `ClaimAlreadyResolved` instead per SPEC §6 Phase 3 alignment note.
error GameAlreadyResolved();

/// @notice Thrown by challenge() / prove(bytes) when `claimData.status == UnchallengedAndValidProofProvided`
///         (SPEC §6 Phase 1/3.5 — game already early-finalized; reject for clarity vs ClaimAlreadyChallenged).
error AlreadyEarlyFinalized();

/// @notice Thrown by challenge() when caller has already countered another segment in this game
///         (SPEC §6 Phase 1 per-address dedup; `challengers[msg.sender].countered == true`).
error AlreadyCountered();

/// @notice Thrown by challenge() / prove(uint64,bytes) when segment index `k >= numSegments`.
error IndexOutOfRange();

/// @notice Thrown by prove(uint64,bytes) when segment k has no challenger (or prove(bytes) was used).
error IndexNotCountered();

/// @notice Thrown by prove(uint64,bytes) when segment k has already been successfully proven.
error AlreadyProved();

/// @notice Thrown by prove(bytes) early-finalize when claimData.status != Unchallenged.
error NotUnchallenged();

/// @notice Thrown by prove(bytes) early-finalize when called after challengeEnd().
error ChallengeWindowEnded();

/// @notice Thrown by prove(bytes) when parent game has already resolved CHALLENGER_WINS
///         (this game is doomed; off-chain SP1 work would be wasted).
error ParentAlreadyLost();
