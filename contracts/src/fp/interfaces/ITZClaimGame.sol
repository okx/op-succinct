// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title ITZClaimGame
/// @notice The forwarder's read view of a four-preimage dispute game's committed checkpoint
///         hashes. The L2 sequence number is read through the standard dispute-game interface, so
///         it is not duplicated here.
interface ITZClaimGame {
    /// @notice The bridge root committed by the game at creation.
    /// @return The committed bridge root.
    function bridgeRoot() external view returns (bytes32);

    /// @notice The force root committed by the game at creation.
    /// @return The committed force root.
    function forceRoot() external view returns (bytes32);

    /// @notice The block hash committed by the game at creation.
    /// @return The committed block hash.
    function blockHash() external view returns (bytes32);

    /// @notice The app hash committed by the game at creation.
    /// @return The committed app hash.
    function appHash() external view returns (bytes32);
}
