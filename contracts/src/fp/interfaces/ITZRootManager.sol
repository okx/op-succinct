// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title ITZRootManager
/// @notice The target-chain sink's fixed write entry point and checkpoint query surface. The
///         forwarder encodes exactly the record call; its selector and argument order are frozen.
interface ITZRootManager {
    /// @notice Records the synced checkpoint on the target chain. The height must be strictly
    ///         greater than the latest recorded checkpoint. The bridge and force roots must be
    ///         non-zero; the block hash and app hash may be zero.
    /// @param blockHeight The checkpoint height the fields correspond to.
    /// @param blockHash The synced block hash.
    /// @param appHash The synced app hash.
    /// @param bridgeRoot The synced bridge root.
    /// @param forceRoot The synced force root.
    function record(uint256 blockHeight, bytes32 blockHash, bytes32 appHash, bytes32 bridgeRoot, bytes32 forceRoot)
        external;

    /// @notice Returns the highest recorded checkpoint height and its bridge and force roots.
    ///         Before any checkpoint is recorded, all three return values are zero. This legacy
    ///         three-value projection keeps its selector, arity, and return order.
    function getLatestRoots() external view returns (uint256 blockHeight, bytes32 bridgeRoot, bytes32 forceRoot);

    /// @notice Returns the full latest checkpoint in one consistent read: height, block hash, app
    ///         hash, bridge root, and force root. Before any checkpoint is recorded, all five
    ///         return values are zero.
    function getLatestState()
        external
        view
        returns (uint256 blockHeight, bytes32 blockHash, bytes32 appHash, bytes32 bridgeRoot, bytes32 forceRoot);
}
