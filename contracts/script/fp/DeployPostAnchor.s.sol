// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {IOptimismPortal2} from "interfaces/L1/IOptimismPortal2.sol";

import {PostAnchor} from "src/fp/PostAnchor.sol";

/// @title DeployPostAnchor
/// @notice Deploys the L1 forwarder and asserts it landed at the precomputed address. The target
///         chain root manager address is precomputed and passed in; it cannot be code-verified
///         from L1, so correctness relies on this expected-address assertion and a cross-chain
///         smoke test.
contract DeployPostAnchor is Script {
    /// @notice Default target-chain execution gas limit when the environment does not override it.
    uint64 internal constant DEFAULT_PUSH_GAS_LIMIT = 150_000;

    function run() public returns (address postAnchor) {
        address asr = vm.envAddress("ANCHOR_STATE_REGISTRY");
        address xlPortal = vm.envAddress("XL_PORTAL_ADDRESS");
        address xlRootManager = vm.envAddress("XL_ROOT_MANAGER_ADDRESS");
        uint64 pushGasLimit = uint64(vm.envOr("PUSH_GAS_LIMIT", uint256(DEFAULT_PUSH_GAS_LIMIT)));
        address expected = vm.envOr("EXPECTED_POST_ANCHOR_ADDRESS", address(0));

        vm.startBroadcast();
        PostAnchor deployed =
            new PostAnchor(IAnchorStateRegistry(asr), IOptimismPortal2(payable(xlPortal)), xlRootManager, pushGasLimit);
        vm.stopBroadcast();

        postAnchor = address(deployed);
        console.log("PostAnchor deployed at:", postAnchor);
        console.log("Target-chain root manager:", xlRootManager);

        // Any drift from the precomputed address is fatal: the target chain root manager is
        // configured against the expected forwarder address and one-sided replacement is forbidden.
        if (expected != address(0)) {
            require(postAnchor == expected, "PostAnchor address mismatch");
        }
    }
}
