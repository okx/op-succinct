// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {AddressAliasHelper} from "@optimism/src/vendor/AddressAliasHelper.sol";

import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {InvalidPostAnchor, InvalidRoot, Unauthorized, StaleRoot} from "src/fp/lib/Errors.sol";

/// @title TZRootManager
/// @notice Target-chain sink for cross-chain root synchronization. It authenticates the single
///         L1 forwarder by its OP-Stack alias, stores committed roots by checkpoint, tracks the
///         latest checkpoint, enforces height non-regression, and allows a same-height root
///         correction. It holds no owner, admin, or upgrade surface: every trust address is a
///         constructor immutable.
contract TZRootManager is ITZRootManager {
    /// @notice The root pair recorded atomically for one checkpoint.
    struct CheckpointRoots {
        bytes32 withdrawalRoot;
        bytes32 forceTxRoot;
    }

    /// @notice The L1 forwarder authorized to record roots. Its target-chain caller identity is
    ///         this address run through the OP-Stack L1-to-L2 alias.
    address public immutable L1_POST_ANCHOR;

    /// @notice The height (L2 block number) of the latest recorded roots. Never decreases.
    uint64 public l2BlockNumber;

    /// @dev Exact-height history. Since record rejects either zero root, a zero-valued entry
    ///      unambiguously means that the checkpoint has not been recorded.
    mapping(uint64 => CheckpointRoots) private _rootsByCheckpoint;

    /// @notice Emitted when roots advance to a higher checkpoint or a same-height correction
    ///         overwrites the pair stored for that checkpoint.
    /// @param withdrawalRoot The recorded withdrawal root.
    /// @param forceTxRoot The recorded force-transaction root.
    /// @param checkpointBlockHeight The checkpoint height of the recorded roots.
    event RootsRecorded(bytes32 withdrawalRoot, bytes32 forceTxRoot, uint64 checkpointBlockHeight);

    /// @param l1PostAnchor_ The L1 forwarder contract address (pre-alias). Must be non-zero; it
    ///        cannot be code-verified from this chain, so correctness relies on deploy-time
    ///        address precomputation and a cross-chain smoke test.
    constructor(address l1PostAnchor_) {
        if (l1PostAnchor_ == address(0)) revert InvalidPostAnchor();
        L1_POST_ANCHOR = l1PostAnchor_;
    }

    /// @notice Records both synced roots at a checkpoint. Only the aliased L1 forwarder may call.
    /// @param newWithdrawalRoot The submitted withdrawal root.
    /// @param newForceTxRoot The submitted force-transaction root.
    /// @param newCheckpointBlockHeight The submitted checkpoint height.
    function record(bytes32 newWithdrawalRoot, bytes32 newForceTxRoot, uint64 newCheckpointBlockHeight) external {
        // Only the OP-Stack alias of the single immutable L1 forwarder is authorized.
        if (msg.sender != AddressAliasHelper.applyL1ToL2Alias(L1_POST_ANCHOR)) revert Unauthorized();
        if (newWithdrawalRoot == bytes32(0) || newForceTxRoot == bytes32(0)) revert InvalidRoot();

        uint64 currentHeight = l2BlockNumber;
        if (newCheckpointBlockHeight < currentHeight) {
            // A lower height is always stale.
            revert StaleRoot();
        } else if (newCheckpointBlockHeight == currentHeight) {
            // Same height: an exact duplicate is stale; any differing root is a correction that
            // overwrites both roots together while keeping the height unchanged. Before the first
            // checkpoint-zero write, the mapping value is the all-zero pair, so it is not stale.
            CheckpointRoots storage current = _rootsByCheckpoint[newCheckpointBlockHeight];
            if (newWithdrawalRoot == current.withdrawalRoot && newForceTxRoot == current.forceTxRoot) {
                revert StaleRoot();
            }
        }

        _rootsByCheckpoint[newCheckpointBlockHeight] = CheckpointRoots(newWithdrawalRoot, newForceTxRoot);
        l2BlockNumber = newCheckpointBlockHeight;

        emit RootsRecorded(newWithdrawalRoot, newForceTxRoot, newCheckpointBlockHeight);
    }

    /// @inheritdoc ITZRootManager
    function getRoots(uint64 checkpointBlockHeight)
        external
        view
        returns (bytes32 withdrawalRoot, bytes32 forceTxRoot)
    {
        CheckpointRoots storage roots = _rootsByCheckpoint[checkpointBlockHeight];
        return (roots.withdrawalRoot, roots.forceTxRoot);
    }

    /// @inheritdoc ITZRootManager
    function getLatestRoots()
        external
        view
        returns (uint64 checkpointBlockHeight, bytes32 withdrawalRoot, bytes32 forceTxRoot)
    {
        checkpointBlockHeight = l2BlockNumber;
        CheckpointRoots storage roots = _rootsByCheckpoint[checkpointBlockHeight];
        return (checkpointBlockHeight, roots.withdrawalRoot, roots.forceTxRoot);
    }
}
