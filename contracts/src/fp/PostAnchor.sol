// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {IOptimismPortal2} from "interfaces/L1/IOptimismPortal2.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";

import {IPostAnchor} from "src/fp/interfaces/IPostAnchor.sol";
import {ITZClaimGame} from "src/fp/interfaces/ITZClaimGame.sol";
import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {InvalidASR, InvalidPortal, InvalidRootManager, InvalidPushGasLimit, NoAnchorGame} from "src/fp/lib/Errors.sol";

/// @title PostAnchor
/// @notice Fixed, owner-less L1 forwarder. On each call it reads the current anchor game
///         from the registry (never from the caller), reads that game's roots and height, and
///         enqueues one fixed cross-chain delivery through the portal. It holds no mutable
///         delivery watermark because an L1 enqueue does not prove target-chain execution;
///         duplicate and stale deliveries are handled by the target-chain root manager.
contract PostAnchor is IPostAnchor {
    /// @notice The anchor state registry that selects and validates the current anchor game.
    IAnchorStateRegistry public immutable ASR;

    /// @notice The L1 portal used to enqueue the cross-chain delivery.
    IOptimismPortal2 public immutable XL_PORTAL;

    /// @notice The target-chain sink address that receives the delivery. It lives on the other
    ///         chain and cannot be code-verified from L1.
    address public immutable XL_ROOT_MANAGER;

    /// @notice The execution gas limit purchased for the target-chain record call.
    uint64 public immutable PUSH_GAS_LIMIT;

    /// @notice Emitted when a delivery is accepted by the L1 portal. This is an enqueue signal,
    ///         not a landing proof: the target-chain record executes later, asynchronously.
    /// @param game The anchor game whose roots were forwarded.
    /// @param l2BlockNumber The forwarded height.
    /// @param withdrawalRoot The forwarded withdrawal root.
    /// @param forceRoot The forwarded force root.
    event RootsEnqueued(address indexed game, uint256 indexed l2BlockNumber, bytes32 withdrawalRoot, bytes32 forceRoot);

    /// @param asr_ The anchor state registry (must have contract code).
    /// @param xlPortal_ The L1 portal (must have contract code).
    /// @param xlRootManager_ The target-chain sink address (must be non-zero; not code-verifiable).
    /// @param pushGasLimit_ The target-chain execution gas limit (must be non-zero).
    constructor(IAnchorStateRegistry asr_, IOptimismPortal2 xlPortal_, address xlRootManager_, uint64 pushGasLimit_) {
        if (address(asr_).code.length == 0) revert InvalidASR();
        if (address(xlPortal_).code.length == 0) revert InvalidPortal();
        if (xlRootManager_ == address(0)) revert InvalidRootManager();
        if (pushGasLimit_ == 0) revert InvalidPushGasLimit();
        ASR = asr_;
        XL_PORTAL = xlPortal_;
        XL_ROOT_MANAGER = xlRootManager_;
        PUSH_GAS_LIMIT = pushGasLimit_;
    }

    /// @inheritdoc IPostAnchor
    function push() external {
        // Structural source of truth: the caller cannot supply a game, root, or height.
        IDisputeGame game = IDisputeGame(address(ASR.anchorGame()));
        if (address(game) == address(0)) revert NoAnchorGame();

        uint256 height = game.l2SequenceNumber();
        bytes32 w = ITZClaimGame(address(game)).withdrawalRoot();
        bytes32 f = ITZClaimGame(address(game)).forceRoot();

        // Enqueue exactly one fixed delivery: fixed target, zero value, fixed gas, not a
        // creation, and the frozen record(w, f, height) calldata. No field is caller-controlled.
        // Repeated calls intentionally enqueue again so a delivery that did not execute on the
        // target chain can be retried permissionlessly.
        XL_PORTAL.depositTransaction(
            XL_ROOT_MANAGER, 0, PUSH_GAS_LIMIT, false, abi.encodeCall(ITZRootManager.record, (w, f, height))
        );

        emit RootsEnqueued(address(game), height, w, f);
    }
}
