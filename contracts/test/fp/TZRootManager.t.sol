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

    event RootsRecorded(bytes32 withdrawalRoot, bytes32 forceTxRoot, uint256 checkpointBlockHeight);

    function setUp() public {
        manager = new TZRootManager(L1_POST_ANCHOR);
        aliasedSender = AddressAliasHelper.applyL1ToL2Alias(L1_POST_ANCHOR);
    }

    function _record(bytes32 withdrawalRoot, bytes32 forceTxRoot, uint256 checkpointBlockHeight) internal {
        vm.prank(aliasedSender);
        manager.record(withdrawalRoot, forceTxRoot, checkpointBlockHeight);
    }

    function _assertLatest(uint256 expectedHeight, bytes32 expectedWithdrawalRoot, bytes32 expectedForceTxRoot)
        internal
        view
    {
        (uint256 checkpointBlockHeight, bytes32 withdrawalRoot, bytes32 forceTxRoot) = manager.getLatestRoots();
        assertEq(checkpointBlockHeight, expectedHeight);
        assertEq(withdrawalRoot, expectedWithdrawalRoot);
        assertEq(forceTxRoot, expectedForceTxRoot);
        assertEq(manager.latestWithdrawalRoot(), expectedWithdrawalRoot);
        assertEq(manager.latestForceTxRoot(), expectedForceTxRoot);
    }

    function test_constructor_revertsOnZeroForwarder() public {
        vm.expectRevert(InvalidPostAnchor.selector);
        new TZRootManager(address(0));
    }

    function test_initialState_queriesReturnZero() public view {
        assertEq(manager.L1_POST_ANCHOR(), L1_POST_ANCHOR);
        assertEq(manager.l2BlockNumber(), 0);
        _assertLatest(0, bytes32(0), bytes32(0));
    }

    function test_record_higherHeight_updatesQueriesAndEmitsMatchingValues() public {
        bytes32 w = keccak256("w1");
        bytes32 f = keccak256("f1");

        vm.expectEmit(false, false, false, true, address(manager));
        emit RootsRecorded(w, f, 10);
        _record(w, f, 10);

        _assertLatest(10, w, f);
    }

    function test_record_higherCheckpointReplacesPreviouslyLatestRoots() public {
        bytes32 w10 = keccak256("w10");
        bytes32 f10 = keccak256("f10");
        bytes32 w100 = keccak256("w100");
        bytes32 f100 = keccak256("f100");

        _record(w10, f10, 10);
        _record(w100, f100, 100);

        _assertLatest(100, w100, f100);
    }

    function test_record_supportsHeightAboveUint64Max() public {
        uint256 height = uint256(type(uint64).max) + 1;
        bytes32 w = keccak256("w-above-uint64");
        bytes32 f = keccak256("f-above-uint64");

        _record(w, f, height);

        _assertLatest(height, w, f);
    }

    function test_record_checkpointZero_revertsStaleRoot() public {
        bytes32 w = keccak256("checkpoint-zero-w");
        bytes32 f = keccak256("checkpoint-zero-f");

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(w, f, 0);

        _assertLatest(0, bytes32(0), bytes32(0));
    }

    function test_record_zeroWithdrawalRoot_revertsInvalidRootNoStateChange() public {
        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedSender);
        manager.record(bytes32(0), keccak256("f"), 10);

        _assertLatest(0, bytes32(0), bytes32(0));
    }

    function test_record_zeroForceTxRoot_revertsInvalidRootNoStateChange() public {
        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedSender);
        manager.record(keccak256("w"), bytes32(0), 10);

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

    function test_record_lowerHeight_revertsStaleRootAndPreservesLatest() public {
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        _record(w, f, 10);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(keccak256("w2"), keccak256("f2"), 9);

        _assertLatest(10, w, f);
    }

    function test_record_sameHeightIdenticalRoots_revertsStaleRoot() public {
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        _record(w, f, 10);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(w, f, 10);

        _assertLatest(10, w, f);
    }

    function test_record_sameHeightDifferentRoots_revertsStaleRootAndPreservesLatest() public {
        bytes32 originalW = keccak256("w");
        bytes32 originalF = keccak256("f");
        _record(originalW, originalF, 10);
        bytes32 correctedW = keccak256("w2");
        bytes32 correctedF = keccak256("f2");

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(correctedW, correctedF, 10);

        _assertLatest(10, originalW, originalF);
    }

    function testFuzz_record_monotonicDecisionTree(
        uint256 firstHeight,
        bytes32 firstW,
        bytes32 firstF,
        uint256 secondHeight,
        bytes32 secondW,
        bytes32 secondF
    ) public {
        vm.assume(firstHeight > 0);
        vm.assume(firstW != bytes32(0));
        vm.assume(firstF != bytes32(0));
        vm.assume(secondW != bytes32(0));
        vm.assume(secondF != bytes32(0));

        _record(firstW, firstF, firstHeight);

        if (secondHeight <= firstHeight) {
            vm.expectRevert(StaleRoot.selector);
            vm.prank(aliasedSender);
            manager.record(secondW, secondF, secondHeight);
            _assertLatest(firstHeight, firstW, firstF);
        } else {
            _record(secondW, secondF, secondHeight);
            _assertLatest(secondHeight, secondW, secondF);
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
