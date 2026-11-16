// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {AddressAliasHelper} from "@optimism/src/vendor/AddressAliasHelper.sol";

import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {InvalidPostAnchor, InvalidRoot, Unauthorized, StaleRoot} from "src/fp/lib/Errors.sol";

/// @title TZRootManager
/// @notice Target-chain sink for cross-chain checkpoint synchronization. It authenticates the
///         single L1 forwarder by its OP-Stack alias, stores only the latest committed checkpoint
///         (height, block hash, app hash, bridge root, force root), and accepts only strictly
///         increasing checkpoint heights. It holds no owner, admin, or upgrade surface: every trust
///         address is a constructor immutable.
contract TZRootManager is ITZRootManager {
    /// @notice The L1 forwarder authorized to record the checkpoint. Its target-chain caller
    ///         identity is this address run through the OP-Stack L1-to-L2 alias.
    address public immutable L1_POST_ANCHOR;

    /// @notice The height (L2 block number) of the latest recorded checkpoint. Never decreases.
    uint256 public l2BlockNumber;

    /// @notice The latest bridge root. Superseded checkpoints are not retained.
    bytes32 public latestBridgeRoot;

    /// @notice The latest force-transaction root. Superseded checkpoints are not retained.
    bytes32 public latestForceTxRoot;

    /// @notice The latest block hash. Appended after the pre-existing checkpoint fields so existing
    ///         storage slots and getter names stay stable. May be zero.
    bytes32 public latestBlockHash;

    /// @notice The latest app hash. Appended after the pre-existing checkpoint fields so existing
    ///         storage slots and getter names stay stable. May be zero.
    bytes32 public latestAppHash;

    /// @notice Emitted for the first recorded checkpoint or a strictly newer checkpoint.
    /// @param blockHeight The recorded checkpoint height.
    /// @param blockHash The recorded block hash.
    /// @param appHash The recorded app hash.
    /// @param bridgeRoot The recorded bridge root.
    /// @param forceRoot The recorded force-transaction root.
    event RootsRecorded(uint256 blockHeight, bytes32 blockHash, bytes32 appHash, bytes32 bridgeRoot, bytes32 forceRoot);

    /// @param l1PostAnchor_ The L1 forwarder contract address (pre-alias). Must be non-zero; it
    ///        cannot be code-verified from this chain, so correctness relies on deploy-time address
    ///        precomputation and a cross-chain smoke test.
    constructor(address l1PostAnchor_) {
        if (l1PostAnchor_ == address(0)) revert InvalidPostAnchor();
        L1_POST_ANCHOR = l1PostAnchor_;
    }

    /// @inheritdoc ITZRootManager
    function record(uint256 blockHeight, bytes32 blockHash, bytes32 appHash, bytes32 bridgeRoot, bytes32 forceRoot)
        external
    {
        // Only the OP-Stack alias of the single immutable L1 forwarder is authorized.
        if (msg.sender != AddressAliasHelper.applyL1ToL2Alias(L1_POST_ANCHOR)) revert Unauthorized();
        // Bridge and force roots must both be non-zero; block hash and app hash may be zero.
        if (bridgeRoot == bytes32(0) || forceRoot == bytes32(0)) revert InvalidRoot();
        // Height must be strictly greater than the latest; equal/lower/zero-at-init is stale.
        if (blockHeight <= l2BlockNumber) revert StaleRoot();

        // Every validation check precedes every write, so a revert leaves the prior checkpoint
        // fully intact (whole-tuple-or-nothing).
        latestBlockHash = blockHash;
        latestAppHash = appHash;
        latestBridgeRoot = bridgeRoot;
        latestForceTxRoot = forceRoot;
        l2BlockNumber = blockHeight;

        emit RootsRecorded(blockHeight, blockHash, appHash, bridgeRoot, forceRoot);
    }

    /// @inheritdoc ITZRootManager
    function getLatestRoots() external view returns (uint256 blockHeight, bytes32 bridgeRoot, bytes32 forceRoot) {
        return (l2BlockNumber, latestBridgeRoot, latestForceTxRoot);
    }

    /// @inheritdoc ITZRootManager
    function getLatestState()
        external
        view
        returns (uint256 blockHeight, bytes32 blockHash, bytes32 appHash, bytes32 bridgeRoot, bytes32 forceRoot)
    {
        return (l2BlockNumber, latestBlockHash, latestAppHash, latestBridgeRoot, latestForceTxRoot);
    }
}
