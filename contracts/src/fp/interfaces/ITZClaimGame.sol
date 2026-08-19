// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title ITZClaimGame
/// @notice The forwarder's read view of a four-preimage dispute game's synced roots. The L2
///         sequence number is read through the standard dispute-game interface, so it is not
///         duplicated here.
interface ITZClaimGame {
    /// @notice The withdrawal root committed by the game at creation.
    /// @return The committed withdrawal root.
    function withdrawalRoot() external view returns (bytes32);

    /// @notice The force root committed by the game at creation.
    /// @return The committed force root.
    function forceRoot() external view returns (bytes32);
}
