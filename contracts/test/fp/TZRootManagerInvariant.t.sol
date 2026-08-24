// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {AddressAliasHelper} from "@optimism/src/vendor/AddressAliasHelper.sol";

import {TZRootManager} from "src/fp/TZRootManager.sol";
import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";

contract TZRootManagerHandler is Test {
    TZRootManager public manager;
    address public aliasedSender;
    address public rawForwarder;
    address public ordinaryCaller = address(0xB0B);
    address public otherAlias;

    mapping(uint64 => bytes32) public modelWithdrawalRoots;
    mapping(uint64 => bytes32) public modelForceTxRoots;
    bytes32 public modelLatestWithdrawalRoot;
    bytes32 public modelLatestForceTxRoot;
    uint64 public modelLatestHeight;
    uint64 public highestObservedHeight;
    uint256 public successfulRecords;
    uint256 public rejectedRecords;

    constructor(TZRootManager manager_, address rawForwarder_) {
        manager = manager_;
        rawForwarder = rawForwarder_;
        aliasedSender = AddressAliasHelper.applyL1ToL2Alias(rawForwarder_);
        otherAlias = AddressAliasHelper.applyL1ToL2Alias(address(0xCAFE));
    }

    function record(bytes32 withdrawalRoot, bytes32 forceTxRoot, uint64 height, uint8 actorSeed) external {
        (uint64 beforeHeight, bytes32 beforeLatestW, bytes32 beforeLatestF) = manager.getLatestRoots();
        (bytes32 beforeHeightW, bytes32 beforeHeightF) = manager.getRoots(height);
        uint8 actorKind = actorSeed % 4;
        bool authorized = actorKind == 0;

        if (authorized) {
            bool rootsValid = withdrawalRoot != bytes32(0) && forceTxRoot != bytes32(0);
            bool fresh = height > beforeHeight
                || (height == beforeHeight && (withdrawalRoot != beforeLatestW || forceTxRoot != beforeLatestF));
            bool shouldSucceed = rootsValid && fresh;

            vm.prank(aliasedSender);
            (bool ok,) =
                address(manager).call(abi.encodeCall(ITZRootManager.record, (withdrawalRoot, forceTxRoot, height)));

            if (shouldSucceed) {
                require(ok, "authorized valid record unexpectedly failed");
                modelWithdrawalRoots[height] = withdrawalRoot;
                modelForceTxRoots[height] = forceTxRoot;
                modelLatestWithdrawalRoot = withdrawalRoot;
                modelLatestForceTxRoot = forceTxRoot;
                modelLatestHeight = height;
                successfulRecords++;
            } else {
                require(!ok, "invalid or stale record unexpectedly succeeded");
                rejectedRecords++;
            }
        } else {
            address caller = actorKind == 1 ? ordinaryCaller : actorKind == 2 ? rawForwarder : otherAlias;
            vm.prank(caller);
            (bool ok,) =
                address(manager).call(abi.encodeCall(ITZRootManager.record, (withdrawalRoot, forceTxRoot, height)));
            require(!ok, "unauthorized record unexpectedly succeeded");
            rejectedRecords++;
        }

        (uint64 afterHeight, bytes32 afterLatestW, bytes32 afterLatestF) = manager.getLatestRoots();
        require(afterHeight >= beforeHeight, "latest height decreased");
        require(afterHeight == modelLatestHeight, "latest height model mismatch");
        require(afterLatestW == modelLatestWithdrawalRoot, "latest withdrawal root model mismatch");
        require(afterLatestF == modelLatestForceTxRoot, "latest force root model mismatch");

        (bytes32 afterHeightW, bytes32 afterHeightF) = manager.getRoots(height);
        if (afterHeightW != modelWithdrawalRoots[height] || afterHeightF != modelForceTxRoots[height]) {
            revert("checkpoint history model mismatch");
        }
        if (afterHeightW != beforeHeightW || afterHeightF != beforeHeightF) {
            require(authorized, "unauthorized history mutation");
            require(withdrawalRoot != bytes32(0) && forceTxRoot != bytes32(0), "zero-root history mutation");
        }

        if (afterHeight > highestObservedHeight) {
            highestObservedHeight = afterHeight;
        }
    }
}

contract TZRootManagerInvariantTest is StdInvariant, Test {
    TZRootManager internal manager;
    TZRootManagerHandler internal handler;
    address internal constant L1_POST_ANCHOR = address(0xAB01);

    function setUp() public {
        manager = new TZRootManager(L1_POST_ANCHOR);
        handler = new TZRootManagerHandler(manager, L1_POST_ANCHOR);
        targetContract(address(handler));
    }

    function invariant_latestRootsMatchModelAndHeightNeverDecreases() public view {
        (uint64 height, bytes32 withdrawalRoot, bytes32 forceTxRoot) = manager.getLatestRoots();
        assertEq(height, handler.modelLatestHeight());
        assertEq(withdrawalRoot, handler.modelLatestWithdrawalRoot());
        assertEq(forceTxRoot, handler.modelLatestForceTxRoot());
        assertGe(height, handler.highestObservedHeight());
    }

    function invariant_latestRootsAreBothZeroOrBothNonZero() public view {
        (, bytes32 withdrawalRoot, bytes32 forceTxRoot) = manager.getLatestRoots();
        assertEq(withdrawalRoot == bytes32(0), forceTxRoot == bytes32(0));
    }
}
