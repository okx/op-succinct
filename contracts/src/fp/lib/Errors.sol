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
//         Anchor Root Force Sync — new custom errors         //
////////////////////////////////////////////////////////////////

// -- OPSuccinctFaultDisputeGame (extended four-preimage mode) --

/// @notice Thrown when an auto-delivery target is configured on a game that does not carry the
///         four-preimage root-claim layout. Auto-delivery is only valid for four-preimage games.
error InvalidPostAnchorConfig();

/// @notice Thrown when a configured cross-contract address is unusable: the game's auto-delivery
///         target has no contract code, or the sink's authorized-forwarder address is zero.
error InvalidPostAnchor();

/// @notice Thrown when the root claim does not equal the keccak256 commitment over the four
///         committed preimages (block hash, then app hash, then withdrawal root, then force root).
error InvalidRootClaimPreimage();

/// @notice Thrown when a four-preimage getter is called on a game created without the
///         four-preimage root-claim layout.
error RootClaimPreimageDisabled();

// -- PostAnchor (L1 forwarder) --

/// @notice Thrown when the anchor state registry address has no contract code.
error InvalidASR();

/// @notice Thrown when the portal address has no contract code.
error InvalidPortal();

/// @notice Thrown when the cross-chain root manager address is the zero address.
error InvalidRootManager();

/// @notice Thrown when the forwarded execution gas limit is zero.
error InvalidPushGasLimit();

/// @notice Thrown when the anchor state registry reports no current anchor game.
error NoAnchorGame();

// -- TZRootManager (target-chain sink) --

/// @notice Thrown when the caller is not the aliased authorized forwarder.
error Unauthorized();

/// @notice Thrown when either submitted root is zero. Zero roots are reserved to identify an
///         unrecorded checkpoint in the query API.
error InvalidRoot();

/// @notice Thrown when a checkpoint height is not strictly greater than the latest recorded height.
error StaleRoot();
