// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {AddressAliasHelper} from "@optimism/src/vendor/AddressAliasHelper.sol";

import {TZRootManager} from "src/fp/TZRootManager.sol";
import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {InvalidPostAnchor, Unauthorized, StaleRoot} from "src/fp/lib/Errors.sol";

/// @notice Minimal wiring smoke tests for TZRootManager: aliased-sender authorization, monotonic
///         height with same-height correction, and the non-value-bearing surface. Full coverage is
///         a later stage's responsibility.
contract TZRootManagerTest is Test {
    TZRootManager internal manager;
    address internal constant L1_POST_ANCHOR = address(0xAB01);
    address internal aliasedSender;

    event RootsRecorded(bytes32 withdrawalRoot, bytes32 forceRoot, uint64 l2BlockNumber);

    function setUp() public {
        manager = new TZRootManager(L1_POST_ANCHOR);
        aliasedSender = AddressAliasHelper.applyL1ToL2Alias(L1_POST_ANCHOR);
    }

    function test_constructor_revertsOnZeroForwarder() public {
        vm.expectRevert(InvalidPostAnchor.selector);
        new TZRootManager(address(0));
    }

    function test_initialState_isZero() public view {
        assertEq(manager.l2BlockNumber(), 0);
        assertEq(manager.withdrawalRoot(), bytes32(0));
        assertEq(manager.forceRoot(), bytes32(0));
        assertEq(manager.L1_POST_ANCHOR(), L1_POST_ANCHOR);
    }

    function test_record_higherHeight_updatesAndEmits() public {
        bytes32 w = keccak256("w1");
        bytes32 f = keccak256("f1");
        vm.expectEmit(false, false, false, true, address(manager));
        emit RootsRecorded(w, f, 10);
        vm.prank(aliasedSender);
        manager.record(w, f, 10);
        assertEq(manager.withdrawalRoot(), w);
        assertEq(manager.forceRoot(), f);
        assertEq(manager.l2BlockNumber(), 10);
    }

    /// @notice Guarded-entry negative smoke: a non-aliased caller must revert with the exact
    ///         design error Unauthorized, never a generic revert.
    function test_record_nonAliasedSender_revertsUnauthorized() public {
        vm.expectRevert(Unauthorized.selector);
        vm.prank(address(0xBEEF));
        manager.record(keccak256("w"), keccak256("f"), 1);
    }

    /// @notice The raw (un-aliased) L1 forwarder address must not be authorized directly.
    function test_record_rawL1SenderWithoutAlias_revertsUnauthorized() public {
        vm.expectRevert(Unauthorized.selector);
        vm.prank(L1_POST_ANCHOR);
        manager.record(keccak256("w"), keccak256("f"), 1);
    }

    function test_record_lowerHeight_revertsStaleRoot() public {
        vm.prank(aliasedSender);
        manager.record(keccak256("w"), keccak256("f"), 10);
        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(keccak256("w2"), keccak256("f2"), 9);
    }

    function test_record_sameHeightIdenticalRoots_revertsStaleRoot() public {
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        vm.prank(aliasedSender);
        manager.record(w, f, 10);
        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(w, f, 10);
    }

    function test_record_sameHeightDifferentRoots_correctsKeepingHeight() public {
        vm.prank(aliasedSender);
        manager.record(keccak256("w"), keccak256("f"), 10);
        bytes32 w2 = keccak256("w2");
        bytes32 f2 = keccak256("f2");
        vm.expectEmit(false, false, false, true, address(manager));
        emit RootsRecorded(w2, f2, 10);
        vm.prank(aliasedSender);
        manager.record(w2, f2, 10);
        assertEq(manager.withdrawalRoot(), w2);
        assertEq(manager.forceRoot(), f2);
        assertEq(manager.l2BlockNumber(), 10);
    }

    function test_record_outOfOrderHigherWinsThenLowerFails() public {
        bytes32 highW = keccak256("high-w");
        bytes32 highF = keccak256("high-f");
        vm.prank(aliasedSender);
        manager.record(highW, highF, 100);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(keccak256("low-w"), keccak256("low-f"), 99);

        assertEq(manager.withdrawalRoot(), highW);
        assertEq(manager.forceRoot(), highF);
        assertEq(manager.l2BlockNumber(), 100);
    }

    function testFuzz_record_monotonicDecisionTree(
        uint64 firstHeight,
        bytes32 firstW,
        bytes32 firstF,
        uint64 secondHeight,
        bytes32 secondW,
        bytes32 secondF
    ) public {
        vm.assume(firstW != firstF);
        vm.assume(secondW != secondF);
        vm.assume(firstHeight > 0 || firstW != bytes32(0) || firstF != bytes32(0));

        vm.prank(aliasedSender);
        manager.record(firstW, firstF, firstHeight);

        if (secondHeight < firstHeight) {
            vm.expectRevert(StaleRoot.selector);
            vm.prank(aliasedSender);
            manager.record(secondW, secondF, secondHeight);
            assertEq(manager.withdrawalRoot(), firstW);
            assertEq(manager.forceRoot(), firstF);
            assertEq(manager.l2BlockNumber(), firstHeight);
        } else if (secondHeight == firstHeight && secondW == firstW && secondF == firstF) {
            vm.expectRevert(StaleRoot.selector);
            vm.prank(aliasedSender);
            manager.record(secondW, secondF, secondHeight);
            assertEq(manager.withdrawalRoot(), firstW);
            assertEq(manager.forceRoot(), firstF);
            assertEq(manager.l2BlockNumber(), firstHeight);
        } else {
            vm.prank(aliasedSender);
            manager.record(secondW, secondF, secondHeight);
            assertEq(manager.withdrawalRoot(), secondW);
            assertEq(manager.forceRoot(), secondF);
            assertEq(manager.l2BlockNumber(), secondHeight > firstHeight ? secondHeight : firstHeight);
        }
    }

    /// @notice Payable-surface negative smoke: record() is non-payable by design (no value flow),
    ///         so a nonzero-value call must revert.
    function test_record_rejectsValue() public {
        vm.deal(aliasedSender, 1 ether);
        vm.prank(aliasedSender);
        (bool ok,) = address(manager).call{value: 1 wei}(
            abi.encodeCall(ITZRootManager.record, (keccak256("w"), keccak256("f"), 5))
        );
        assertFalse(ok, "record must reject msg.value");
    }
}
