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

    event RootsRecorded(uint256 blockHeight, bytes32 blockHash, bytes32 appHash, bytes32 bridgeRoot, bytes32 forceRoot);

    function setUp() public {
        manager = new TZRootManager(L1_POST_ANCHOR);
        aliasedSender = AddressAliasHelper.applyL1ToL2Alias(L1_POST_ANCHOR);
    }

    function _record(uint256 height, bytes32 b, bytes32 a, bytes32 w, bytes32 f) internal {
        vm.prank(aliasedSender);
        manager.record(height, b, a, w, f);
    }

    /// @dev Asserts the full five-tuple is consistent across the full query, the legacy projection,
    ///      and every individual storage getter.
    function _assertLatest(uint256 h, bytes32 b, bytes32 a, bytes32 w, bytes32 f) internal view {
        (uint256 sh, bytes32 sb, bytes32 sa, bytes32 sw, bytes32 sf) = manager.getLatestState();
        assertEq(sh, h, "state height");
        assertEq(sb, b, "state blockHash");
        assertEq(sa, a, "state appHash");
        assertEq(sw, w, "state bridgeRoot");
        assertEq(sf, f, "state forceRoot");

        (uint256 lh, bytes32 lw, bytes32 lf) = manager.getLatestRoots();
        assertEq(lh, h, "legacy height");
        assertEq(lw, w, "legacy bridgeRoot");
        assertEq(lf, f, "legacy forceRoot");

        assertEq(manager.l2BlockNumber(), h, "getter height");
        assertEq(manager.latestBlockHash(), b, "getter blockHash");
        assertEq(manager.latestAppHash(), a, "getter appHash");
        assertEq(manager.latestBridgeRoot(), w, "getter bridgeRoot");
        assertEq(manager.latestForceTxRoot(), f, "getter forceRoot");
    }

    function test_constructor_revertsOnZeroForwarder() public {
        vm.expectRevert(InvalidPostAnchor.selector);
        new TZRootManager(address(0));
    }

    function test_initialState_queriesReturnZero() public view {
        assertEq(manager.L1_POST_ANCHOR(), L1_POST_ANCHOR);
        _assertLatest(0, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function test_record_higherHeight_updatesQueriesAndEmitsMatchingValues() public {
        bytes32 b = keccak256("b1");
        bytes32 a = keccak256("a1");
        bytes32 w = keccak256("w1");
        bytes32 f = keccak256("f1");

        vm.expectEmit(false, false, false, true, address(manager));
        emit RootsRecorded(10, b, a, w, f);
        _record(10, b, a, w, f);

        _assertLatest(10, b, a, w, f);
    }

    function test_record_higherCheckpointReplacesPreviouslyLatest() public {
        _record(10, keccak256("b10"), keccak256("a10"), keccak256("w10"), keccak256("f10"));
        bytes32 b100 = keccak256("b100");
        bytes32 a100 = keccak256("a100");
        bytes32 w100 = keccak256("w100");
        bytes32 f100 = keccak256("f100");
        _record(100, b100, a100, w100, f100);

        _assertLatest(100, b100, a100, w100, f100);
    }

    function test_record_supportsHeightAboveUint64Max() public {
        uint256 height = uint256(type(uint64).max) + 1;
        bytes32 b = keccak256("b-above-uint64");
        bytes32 a = keccak256("a-above-uint64");
        bytes32 w = keccak256("w-above-uint64");
        bytes32 f = keccak256("f-above-uint64");

        _record(height, b, a, w, f);

        _assertLatest(height, b, a, w, f);
    }

    /// @notice Block hash and app hash may be zero; only bridge/force roots must be non-zero.
    function test_record_zeroBlockAndAppHash_allowed() public {
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        _record(10, bytes32(0), bytes32(0), w, f);
        _assertLatest(10, bytes32(0), bytes32(0), w, f);
    }

    /// @notice Equal bridge and force roots are legal as long as both are non-zero.
    function test_record_equalBridgeAndForceRoot_allowed() public {
        bytes32 x = keccak256("same");
        _record(10, keccak256("b"), keccak256("a"), x, x);
        _assertLatest(10, keccak256("b"), keccak256("a"), x, x);
    }

    function test_record_checkpointZero_revertsStaleRoot() public {
        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(0, keccak256("b"), keccak256("a"), keccak256("w"), keccak256("f"));

        _assertLatest(0, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function test_record_zeroBridgeRoot_revertsInvalidRootNoStateChange() public {
        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedSender);
        manager.record(10, keccak256("b"), keccak256("a"), bytes32(0), keccak256("f"));

        _assertLatest(0, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function test_record_zeroForceTxRoot_revertsInvalidRootNoStateChange() public {
        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedSender);
        manager.record(10, keccak256("b"), keccak256("a"), keccak256("w"), bytes32(0));

        _assertLatest(0, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function test_record_nonAliasedSender_revertsUnauthorized() public {
        vm.expectRevert(Unauthorized.selector);
        vm.prank(address(0xBEEF));
        manager.record(1, keccak256("b"), keccak256("a"), keccak256("w"), keccak256("f"));
    }

    function test_record_rawL1SenderWithoutAlias_revertsUnauthorized() public {
        vm.expectRevert(Unauthorized.selector);
        vm.prank(L1_POST_ANCHOR);
        manager.record(1, keccak256("b"), keccak256("a"), keccak256("w"), keccak256("f"));
    }

    /// @notice Authorization is checked before root validity: an unauthorized caller submitting
    ///         zero roots at a stale height still reverts Unauthorized (priority 1).
    function test_record_authCheckedBeforeRootAndHeight() public {
        vm.expectRevert(Unauthorized.selector);
        vm.prank(address(0xBEEF));
        manager.record(0, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    /// @notice Root validity is checked before height: a zero root at a stale height reverts
    ///         InvalidRoot (priority 2 over StaleRoot).
    function test_record_invalidRootCheckedBeforeStale() public {
        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedSender);
        manager.record(0, keccak256("b"), keccak256("a"), bytes32(0), keccak256("f"));
    }

    function test_record_lowerHeight_revertsStaleRootAndPreservesLatest() public {
        bytes32 b = keccak256("b");
        bytes32 a = keccak256("a");
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        _record(10, b, a, w, f);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(9, keccak256("b2"), keccak256("a2"), keccak256("w2"), keccak256("f2"));

        _assertLatest(10, b, a, w, f);
    }

    function test_record_sameHeightIdenticalRoots_revertsStaleRoot() public {
        bytes32 b = keccak256("b");
        bytes32 a = keccak256("a");
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        _record(10, b, a, w, f);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(10, b, a, w, f);

        _assertLatest(10, b, a, w, f);
    }

    function test_record_sameHeightDifferentRoots_revertsStaleRootAndPreservesLatest() public {
        bytes32 b = keccak256("b");
        bytes32 a = keccak256("a");
        bytes32 w = keccak256("w");
        bytes32 f = keccak256("f");
        _record(10, b, a, w, f);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(10, keccak256("b2"), keccak256("a2"), keccak256("w2"), keccak256("f2"));

        _assertLatest(10, b, a, w, f);
    }

    function test_record_uint256MaxHeightIsTerminal() public {
        uint256 maxHeight = type(uint256).max;
        bytes32 b = keccak256("b-max");
        bytes32 a = keccak256("a-max");
        bytes32 w = keccak256("w-max");
        bytes32 f = keccak256("f-max");
        _record(maxHeight, b, a, w, f);

        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedSender);
        manager.record(maxHeight, keccak256("b2"), keccak256("a2"), keccak256("w2"), keccak256("f2"));

        _assertLatest(maxHeight, b, a, w, f);
    }

    function testFuzz_record_monotonicDecisionTree(
        uint256 firstHeight,
        bytes32 firstB,
        bytes32 firstA,
        bytes32 firstW,
        bytes32 firstF,
        uint256 secondHeight,
        bytes32 secondB,
        bytes32 secondA,
        bytes32 secondW,
        bytes32 secondF
    ) public {
        vm.assume(firstHeight > 0);
        vm.assume(firstW != bytes32(0));
        vm.assume(firstF != bytes32(0));
        vm.assume(secondW != bytes32(0));
        vm.assume(secondF != bytes32(0));

        _record(firstHeight, firstB, firstA, firstW, firstF);

        if (secondHeight <= firstHeight) {
            vm.expectRevert(StaleRoot.selector);
            vm.prank(aliasedSender);
            manager.record(secondHeight, secondB, secondA, secondW, secondF);
            _assertLatest(firstHeight, firstB, firstA, firstW, firstF);
        } else {
            _record(secondHeight, secondB, secondA, secondW, secondF);
            _assertLatest(secondHeight, secondB, secondA, secondW, secondF);
        }
    }

    /// @notice Non-payable negative smoke: a value-bearing record call reverts.
    function test_record_rejectsValue() public {
        vm.deal(aliasedSender, 1 ether);
        vm.prank(aliasedSender);
        (bool ok,) = address(manager).call{value: 1 wei}(
            abi.encodeCall(ITZRootManager.record, (5, keccak256("b"), keccak256("a"), keccak256("w"), keccak256("f")))
        );
        assertFalse(ok, "record must reject msg.value");
    }
}
