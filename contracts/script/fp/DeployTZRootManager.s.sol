// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {console} from "forge-std/console.sol";

import {TZRootManager} from "src/fp/TZRootManager.sol";
import {CrossChainDeploymentConfig} from "./CrossChainDeploymentConfig.s.sol";

/// @title DeployTZRootManager
/// @notice Deploys the target-chain root manager and asserts it landed at the precomputed address.
///         The manager authorizes the L1 forwarder by its alias; that forwarder address is
///         precomputed on L1 and passed in here. `EXPECTED_XL_ROOT_MANAGER_ADDRESS` is required
///         unless a development deployment explicitly sets `ALLOW_UNVERIFIED_DEPLOYMENT=true`.
contract DeployTZRootManager is CrossChainDeploymentConfig {
    function run() public returns (address rootManager) {
        address l1PostAnchor = vm.envAddress("L1_POST_ANCHOR_ADDRESS");
        address expected = _readExpectedAddress("EXPECTED_XL_ROOT_MANAGER_ADDRESS");

        vm.startBroadcast();
        TZRootManager deployed = new TZRootManager(l1PostAnchor);
        vm.stopBroadcast();

        rootManager = address(deployed);
        console.log("TZRootManager deployed at:", rootManager);
        console.log("Authorized L1 forwarder (pre-alias):", l1PostAnchor);

        // Any drift from the precomputed cross-chain address is fatal: the L1 forwarder is
        // configured against the expected address and one-sided replacement is forbidden.
        _assertExpectedAddress(rootManager, expected, "TZRootManager address mismatch");
    }
}
