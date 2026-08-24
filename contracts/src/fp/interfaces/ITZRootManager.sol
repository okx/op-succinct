// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title ITZRootManager
/// @notice The target-chain sink's fixed write entry point and checkpoint query surface. The
///         forwarder encodes exactly the record call; its selector and argument order are frozen.
interface ITZRootManager {
    /// @notice Records synced roots at their checkpoint height on the target chain.
    /// @param withdrawalRoot The synced withdrawal root.
    /// @param forceTxRoot The synced force-transaction root.
    /// @param checkpointBlockHeight The checkpoint height the roots correspond to.
    function record(bytes32 withdrawalRoot, bytes32 forceTxRoot, uint64 checkpointBlockHeight) external;

    /// @notice Returns roots for exactly `checkpointBlockHeight`. If that height was not recorded,
    ///         both returned roots are zero; the lookup never falls back to another checkpoint.
    function getRoots(uint64 checkpointBlockHeight) external view returns (bytes32 withdrawalRoot, bytes32 forceTxRoot);

    /// @notice Returns the highest recorded checkpoint and its roots. Before any checkpoint is
    ///         recorded, all three return values are zero.
    function getLatestRoots()
        external
        view
        returns (uint64 checkpointBlockHeight, bytes32 withdrawalRoot, bytes32 forceTxRoot);
}
