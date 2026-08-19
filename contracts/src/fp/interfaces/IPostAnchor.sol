// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title IPostAnchor
/// @notice Minimal interface for the L1 forwarder's single permissionless delivery entry point.
///         The auto-delivery hook in the dispute game calls this after a successful anchor update.
interface IPostAnchor {
    /// @notice Reads the current valid anchor game's roots from the registry and enqueues one
    ///         fixed cross-chain delivery. Callable by anyone; the auto path and manual retry
    ///         share this single entry point.
    function push() external;
}
