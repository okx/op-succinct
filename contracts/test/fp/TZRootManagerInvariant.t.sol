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

    bytes32 public modelLatestBlockHash;
    bytes32 public modelLatestAppHash;
    bytes32 public modelLatestBridgeRoot;
    bytes32 public modelLatestForceTxRoot;
    uint256 public modelLatestHeight;
    uint256 public highestObservedHeight;
    uint256 public successfulRecords;
    uint256 public rejectedRecords;

    constructor(TZRootManager manager_, address rawForwarder_) {
        manager = manager_;
        rawForwarder = rawForwarder_;
        aliasedSender = AddressAliasHelper.applyL1ToL2Alias(rawForwarder_);
        otherAlias = AddressAliasHelper.applyL1ToL2Alias(address(0xCAFE));
    }

    function record(bytes32 b, bytes32 a, bytes32 w, bytes32 f, uint256 height, uint8 actorSeed) external {
        (uint256 beforeHeight, bytes32 beforeB, bytes32 beforeA, bytes32 beforeW, bytes32 beforeF) =
            manager.getLatestState();
        uint8 actorKind = actorSeed % 4;
        bool authorized = actorKind == 0;

        if (authorized) {
            bool rootsValid = w != bytes32(0) && f != bytes32(0);
            bool fresh = height > beforeHeight;
            bool shouldSucceed = rootsValid && fresh;

            vm.prank(aliasedSender);
            (bool ok,) = address(manager).call(abi.encodeCall(ITZRootManager.record, (height, b, a, w, f)));

            if (shouldSucceed) {
                require(ok, "authorized valid record unexpectedly failed");
                modelLatestBlockHash = b;
                modelLatestAppHash = a;
                modelLatestBridgeRoot = w;
                modelLatestForceTxRoot = f;
                modelLatestHeight = height;
                successfulRecords++;
            } else {
                require(!ok, "invalid or stale record unexpectedly succeeded");
                rejectedRecords++;
            }
        } else {
            address caller = actorKind == 1 ? ordinaryCaller : actorKind == 2 ? rawForwarder : otherAlias;
            vm.prank(caller);
            (bool ok,) = address(manager).call(abi.encodeCall(ITZRootManager.record, (height, b, a, w, f)));
            require(!ok, "unauthorized record unexpectedly succeeded");
            rejectedRecords++;
        }

        (uint256 afterHeight, bytes32 afterB, bytes32 afterA, bytes32 afterW, bytes32 afterF) = manager.getLatestState();
        require(afterHeight >= beforeHeight, "latest height decreased");
        require(afterHeight == modelLatestHeight, "latest height model mismatch");
        require(afterB == modelLatestBlockHash, "latest block hash model mismatch");
        require(afterA == modelLatestAppHash, "latest app hash model mismatch");
        require(afterW == modelLatestBridgeRoot, "latest bridge root model mismatch");
        require(afterF == modelLatestForceTxRoot, "latest force root model mismatch");

        if (afterHeight == beforeHeight) {
            require(afterB == beforeB, "rejected call changed block hash");
            require(afterA == beforeA, "rejected call changed app hash");
            require(afterW == beforeW, "rejected call changed bridge root");
            require(afterF == beforeF, "rejected call changed force root");
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

    function invariant_latestStateMatchesModelAndHeightNeverDecreases() public view {
        (uint256 height, bytes32 blockHash, bytes32 appHash, bytes32 bridgeRoot, bytes32 forceRoot) =
            manager.getLatestState();
        assertEq(height, handler.modelLatestHeight());
        assertEq(blockHash, handler.modelLatestBlockHash());
        assertEq(appHash, handler.modelLatestAppHash());
        assertEq(bridgeRoot, handler.modelLatestBridgeRoot());
        assertEq(forceRoot, handler.modelLatestForceTxRoot());
        assertEq(height, handler.highestObservedHeight());

        // Legacy projection and individual getters stay consistent with the full query.
        (uint256 legacyHeight, bytes32 legacyW, bytes32 legacyF) = manager.getLatestRoots();
        assertEq(legacyHeight, height);
        assertEq(legacyW, bridgeRoot);
        assertEq(legacyF, forceRoot);
        assertEq(manager.latestBlockHash(), blockHash);
        assertEq(manager.latestAppHash(), appHash);
        assertEq(manager.latestBridgeRoot(), bridgeRoot);
        assertEq(manager.latestForceTxRoot(), forceRoot);
    }

    function invariant_latestBridgeAndForceRootsAreBothZeroOrBothNonZero() public view {
        (,,, bytes32 bridgeRoot, bytes32 forceRoot) = manager.getLatestState();
        assertEq(bridgeRoot == bytes32(0), forceRoot == bytes32(0));
    }
}
