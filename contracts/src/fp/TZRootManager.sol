// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {AddressAliasHelper} from "@optimism/src/vendor/AddressAliasHelper.sol";

import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {InvalidPostAnchor, Unauthorized, StaleRoot} from "src/fp/lib/Errors.sol";

/// @title TZRootManager
/// @notice Target-chain sink for cross-chain root synchronization. It authenticates the single
///         L1 forwarder by its OP-Stack alias, keeps only the latest committed roots, enforces
///         height non-regression, and allows a same-height root correction. It holds no owner,
///         admin, or upgrade surface: every trust address is a constructor immutable.
contract TZRootManager is ITZRootManager {
    /// @notice The L1 forwarder authorized to record roots. Its target-chain caller identity is
    ///         this address run through the OP-Stack L1-to-L2 alias.
    address public immutable L1_POST_ANCHOR;

    /// @notice The latest recorded withdrawal root.
    bytes32 public withdrawalRoot;

    /// @notice The latest recorded force root.
    bytes32 public forceRoot;

    /// @notice The height (L2 block number) of the latest recorded roots. Never decreases.
    uint64 public l2BlockNumber;

    /// @notice Emitted when the latest roots advance to a higher height or a same-height
    ///         correction overwrites the stored roots.
    /// @param withdrawalRoot The recorded withdrawal root.
    /// @param forceRoot The recorded force root.
    /// @param l2BlockNumber The height of the recorded roots.
    event RootsRecorded(bytes32 withdrawalRoot, bytes32 forceRoot, uint64 l2BlockNumber);

    /// @param l1PostAnchor_ The L1 forwarder contract address (pre-alias). Must be non-zero; it
    ///        cannot be code-verified from this chain, so correctness relies on deploy-time
    ///        address precomputation and a cross-chain smoke test.
    constructor(address l1PostAnchor_) {
        if (l1PostAnchor_ == address(0)) revert InvalidPostAnchor();
        L1_POST_ANCHOR = l1PostAnchor_;
    }

    /// @notice Records the latest synced roots. Only the aliased L1 forwarder may call.
    /// @param newWithdrawalRoot The submitted withdrawal root.
    /// @param newForceRoot The submitted force root.
    /// @param newL2BlockNumber The submitted height.
    function record(bytes32 newWithdrawalRoot, bytes32 newForceRoot, uint64 newL2BlockNumber) external {
        // Only the OP-Stack alias of the single immutable L1 forwarder is authorized.
        if (msg.sender != AddressAliasHelper.applyL1ToL2Alias(L1_POST_ANCHOR)) revert Unauthorized();

        uint64 currentHeight = l2BlockNumber;
        if (newL2BlockNumber < currentHeight) {
            // A lower height is always stale.
            revert StaleRoot();
        } else if (newL2BlockNumber == currentHeight) {
            // Same height: an exact duplicate is stale; any differing root is a correction that
            // overwrites the roots while keeping the height unchanged.
            if (newWithdrawalRoot == withdrawalRoot && newForceRoot == forceRoot) {
                revert StaleRoot();
            }
            withdrawalRoot = newWithdrawalRoot;
            forceRoot = newForceRoot;
        } else {
            // Strictly higher height: advance all three fields.
            withdrawalRoot = newWithdrawalRoot;
            forceRoot = newForceRoot;
            l2BlockNumber = newL2BlockNumber;
        }

        emit RootsRecorded(newWithdrawalRoot, newForceRoot, newL2BlockNumber);
    }
}
