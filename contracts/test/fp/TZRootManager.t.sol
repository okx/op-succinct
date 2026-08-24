// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {AddressAliasHelper} from "@optimism/src/vendor/AddressAliasHelper.sol";

import {TZRootManager} from "src/fp/TZRootManager.sol";
import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {InvalidPostAnchor, InvalidRoot, Unauthorized, StaleRoot} from "src/fp/lib/Errors.sol";

contract TZRootManagerTest is Test {
    TZRootManager internal manager;
    address internal constant L1_POST_ANCHOR = address(0xAB01);
    address internal aliasedSender;

    event RootsRecorded(bytes32 withdrawalRoot, bytes32 forceTxRoot, uint64 checkpointBlockHeight);

    function setUp() public {
        manager = new TZRootManager(L1_POST_ANCHOR);
        aliasedSender = AddressAliasHelper.applyL1ToL2Alias(L1_POST_ANCHOR);
    }

    function _record(bytes32 withdrawalRoot, bytes32 forceTxRoot, uint64 checkpointBlockHeight) internal {
        vm.prank(aliasedSender);
        manager.record(withdrawalRoot, forceTxRoot, checkpointBlockHeight);
    }

    function _assertRoots(uint64 checkpointBlockHeight, bytes32 expectedWithdrawalRoot, bytes32 expectedForceTxRoot)
        internal
        view
    {
        (bytes32 withdrawalRoot, bytes32 forceTxRoot) = manager.getRoots(checkpointBlockHeight);
        assertEq(withdrawalRoot, expectedWithdrawalRoot);
        assertEq(forceTxRoot, expectedForceTxRoot);
    }

    function _assertLatest(uint64 expectedHeight, bytes32 expectedWithdrawalRoot, bytes32 expectedForceTxRoot)
        internal
        view
    {
        (uint64 checkpointBlockHeight, bytes32 withdrawalRoot, bytes32 forceTxRoot) = manager.getLatestRoots();
        assertEq(checkpointBlockHeight, expectedHeight);
        assertEq(withdrawalRoot, expectedWithdrawalRoot);
        assertEq(forceTxRoot, expectedForceTxRoot);
    }

    function test_constructor_revertsOnZeroForwarder() public {
        vm.expectRevert(InvalidPostAnchor.selector);
        new TZRootManager(address(0));
    }

    function test_initialState_queriesReturnZero() public view {
        assertEq(manager.L1_POST_ANCHOR(), L1_POST_ANCHOR);
        assertEq(manager.l2BlockNumber(), 0);
        _assertRoots(0, bytes32(0), bytes32(0));
        _assertRoots(42, bytes32(0), bytes32(0));
        _assertLatest(0, bytes32(0), bytes32(0));
    }

    function test_record_higherHeight_updatesQueriesAndEmitsMatchingValues() public {
        bytes32 w = keccak256("w1");
        bytes32 f = keccak256("f1");

        vm.expectEmit(false, false, false, true, address(manager));
        emit RootsRecorded(w, f, 10);
        _record(w, f, 10);

        _assertRoots(10, w, f);
        _assertLatest(10, w, f);
    }

    function test_record_sparseCheckpoints_preservesExactHeightHistory() public {
        bytes32 w10 = keccak256("w10");
        bytes32 f10 = keccak256("f10");
        bytes32 w100 = keccak256("w100");
        bytes32 f100 = keccak256("f100");

        _record(w10, f10, 10);
        _record(w100, f100, 100);

        _assertRoots(10, w10, f10);
        _assertRoots(11, bytes32(0), bytes32(0));
        _assertRoots(99, bytes32(0), bytes32(0));
        _assertRoots(100, w100, f100);
        _assertLatest(100, w100, f100);
    }

    function test_record_checkpointZero_isDistinguishedByNonZeroRoots() public {
        bytes32 w = keccak256("checkpoint-zero-w");
        bytes32 f = keccak256("checkpoint-zero-f");

        _record(w, f, 0);

        _assertRoots(0, w, f);
        _assertLatest(0, w, f);
    }

    function test_record_zeroWithdrawalRoot_revertsInvalidRootNoStateChange() public {
        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedSender);
        manager.record(bytes32(0), keccak256("f"), 10);

        _assertRoots(10, bytes32(0), bytes32(0));
        _assertLatest(0, bytes32(0), bytes32(0));
    }

    function test_record_zeroForceTxRoot_revertsInvalidRootNoStateChange() public {
        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedSender);
        manager.record(keccak256("w"), bytes32(0), 10);

        _assertRoots(10, bytes32(0), bytes32(0));
        _assertLatest(0, bytes32(0), bytes32(0));
    }

    function test_record_nonAliasedSender_revertsUnauthorized() public {
        vm.expectRevert(Unauthorized.selector);
        vm.prank(address(0xBEEF));
        manager.record(keccak256("w"), keccak256("f"), 1);
    }

    function test_record_rawL1SenderWithoutAlias_revertsUnauthorized() public {
        vm.expectRevert(Unauthorized.selector);
        vm.prank(L1_POST_ANCHOR);
        manager.record(keccak256("w"), keccak256("f"), 1);
    }

    function test_record_lowerHeight_revertsStaleRootAndPreservesHistory() public {
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        _record(w, f, 10);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(keccak256("w2"), keccak256("f2"), 9);

        _assertRoots(9, bytes32(0), bytes32(0));
        _assertRoots(10, w, f);
        _assertLatest(10, w, f);
    }

    function test_record_sameHeightIdenticalRoots_revertsStaleRoot() public {
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        _record(w, f, 10);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(w, f, 10);

        _assertRoots(10, w, f);
        _assertLatest(10, w, f);
    }

    function test_record_sameHeightDifferentRoots_correctsHistoryAndLatest() public {
        _record(keccak256("w"), keccak256("f"), 10);
        bytes32 correctedW = keccak256("w2");
        bytes32 correctedF = keccak256("f2");

        vm.expectEmit(false, false, false, true, address(manager));
        emit RootsRecorded(correctedW, correctedF, 10);
        _record(correctedW, correctedF, 10);

        _assertRoots(10, correctedW, correctedF);
        _assertLatest(10, correctedW, correctedF);
    }

    function testFuzz_record_monotonicDecisionTree(
        uint64 firstHeight,
        bytes32 firstW,
        bytes32 firstF,
        uint64 secondHeight,
        bytes32 secondW,
        bytes32 secondF
    ) public {
        vm.assume(firstW != bytes32(0));
        vm.assume(firstF != bytes32(0));
        vm.assume(secondW != bytes32(0));
        vm.assume(secondF != bytes32(0));

        _record(firstW, firstF, firstHeight);

        if (secondHeight < firstHeight) {
            vm.expectRevert(StaleRoot.selector);
            vm.prank(aliasedSender);
            manager.record(secondW, secondF, secondHeight);
            _assertRoots(secondHeight, bytes32(0), bytes32(0));
            _assertRoots(firstHeight, firstW, firstF);
            _assertLatest(firstHeight, firstW, firstF);
        } else if (secondHeight == firstHeight && secondW == firstW && secondF == firstF) {
            vm.expectRevert(StaleRoot.selector);
            vm.prank(aliasedSender);
            manager.record(secondW, secondF, secondHeight);
            _assertRoots(firstHeight, firstW, firstF);
            _assertLatest(firstHeight, firstW, firstF);
        } else {
            _record(secondW, secondF, secondHeight);
            _assertRoots(secondHeight, secondW, secondF);
            _assertLatest(secondHeight, secondW, secondF);
            if (secondHeight > firstHeight) {
                _assertRoots(firstHeight, firstW, firstF);
            }
        }
    }

    function test_record_rejectsValue() public {
        vm.deal(aliasedSender, 1 ether);
        vm.prank(aliasedSender);
        (bool ok,) = address(manager).call{value: 1 wei}(
            abi.encodeCall(ITZRootManager.record, (keccak256("w"), keccak256("f"), 5))
        );
        assertFalse(ok, "record must reject msg.value");
    }
}
