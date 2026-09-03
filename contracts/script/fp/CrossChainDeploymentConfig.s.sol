// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Script} from "forge-std/Script.sol";

/// @notice Shared fail-fast validation for paired cross-chain deployment addresses.
abstract contract CrossChainDeploymentConfig is Script {
    string internal constant ALLOW_UNVERIFIED_DEPLOYMENT = "ALLOW_UNVERIFIED_DEPLOYMENT";

    /// @dev Production deployments require a non-zero precomputed address. Development deployments
    ///      may explicitly opt out, in which case a zero return value disables only the equality check.
    function _readExpectedAddress(string memory envVariable) internal view returns (address expected) {
        expected = vm.envOr(envVariable, address(0));
        bool allowUnverifiedDeployment = vm.envOr(ALLOW_UNVERIFIED_DEPLOYMENT, false);
        _validateExpectedAddressConfig(expected, allowUnverifiedDeployment);
    }

    function _validateExpectedAddressConfig(address expected, bool allowUnverifiedDeployment) internal pure {
        require(
            expected != address(0) || allowUnverifiedDeployment,
            "Missing expected address; explicitly allow unverified deployment only for development"
        );
    }

    function _assertExpectedAddress(address actual, address expected, string memory mismatchReason) internal pure {
        if (expected != address(0)) require(actual == expected, mismatchReason);
    }
}
