// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title IPostAnchor
/// @notice Minimal interface for the L1 forwarder's permissionless latest-anchor delivery surface.
interface IPostAnchor {
    /// @notice Reads the current anchor game's roots from the registry and enqueues one
    ///         fixed cross-chain delivery. Callable by anyone so a delivery that did not execute
    ///         on the target chain can be retried.
    function push() external;
}
