// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title ITZRootManager
/// @notice The target-chain sink's fixed write entry point. The forwarder encodes exactly this
///         call; the selector and argument order are frozen.
interface ITZRootManager {
    /// @notice Records the latest synced roots and their height on the target chain.
    /// @param withdrawalRoot The synced withdrawal root.
    /// @param forceRoot The synced force root.
    /// @param l2BlockNumber The L2 block number (height) the roots correspond to.
    function record(bytes32 withdrawalRoot, bytes32 forceRoot, uint64 l2BlockNumber) external;
}
