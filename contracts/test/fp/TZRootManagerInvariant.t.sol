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

    bytes32 public modelWithdrawalRoot;
    bytes32 public modelForceRoot;
    uint64 public modelHeight;
    uint64 public highestObservedHeight;
    uint256 public successfulRecords;
    uint256 public rejectedRecords;

    constructor(TZRootManager manager_, address rawForwarder_) {
        manager = manager_;
        rawForwarder = rawForwarder_;
        aliasedSender = AddressAliasHelper.applyL1ToL2Alias(rawForwarder_);
        otherAlias = AddressAliasHelper.applyL1ToL2Alias(address(0xCAFE));
    }

    function record(bytes32 withdrawalRoot, bytes32 forceRoot, uint64 height, uint8 actorSeed) external {
        uint64 beforeHeight = manager.l2BlockNumber();
        bytes32 beforeWithdrawalRoot = manager.withdrawalRoot();
        bytes32 beforeForceRoot = manager.forceRoot();
        uint8 actorKind = actorSeed % 4;
        bool authorized = actorKind == 0;

        if (authorized) {
            bool shouldSucceed = height > beforeHeight
                || (height == beforeHeight && (withdrawalRoot != beforeWithdrawalRoot || forceRoot != beforeForceRoot));

            vm.prank(aliasedSender);
            (bool ok,) =
                address(manager).call(abi.encodeCall(ITZRootManager.record, (withdrawalRoot, forceRoot, height)));

            if (shouldSucceed) {
                require(ok, "authorized record unexpectedly failed");
                modelWithdrawalRoot = withdrawalRoot;
                modelForceRoot = forceRoot;
                if (height > modelHeight) {
                    modelHeight = height;
                }
                successfulRecords++;
            } else {
                require(!ok, "stale record unexpectedly succeeded");
                rejectedRecords++;
            }
        } else {
            address caller = actorKind == 1 ? ordinaryCaller : actorKind == 2 ? rawForwarder : otherAlias;
            vm.prank(caller);
            (bool ok,) =
                address(manager).call(abi.encodeCall(ITZRootManager.record, (withdrawalRoot, forceRoot, height)));
            require(!ok, "unauthorized record unexpectedly succeeded");
            rejectedRecords++;
        }

        require(manager.l2BlockNumber() >= beforeHeight, "height decreased");
        if (manager.l2BlockNumber() > highestObservedHeight) {
            highestObservedHeight = manager.l2BlockNumber();
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

    function invariant_rootManagerMatchesModelAndNeverDecreases() public view {
        assertEq(manager.withdrawalRoot(), handler.modelWithdrawalRoot());
        assertEq(manager.forceRoot(), handler.modelForceRoot());
        assertEq(manager.l2BlockNumber(), handler.modelHeight());
        assertGe(manager.l2BlockNumber(), handler.highestObservedHeight());
    }
}
