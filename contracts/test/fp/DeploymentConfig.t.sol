// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";

import {CrossChainDeploymentConfig} from "../../script/fp/CrossChainDeploymentConfig.s.sol";
import {DeployOPSuccinctLiteTz} from "../../script/fp/DeployOPSuccinctLiteTz.s.sol";
import {JSONDecoder} from "../helpers/JSONDecoder.sol";

contract CrossChainDeploymentConfigHarness is CrossChainDeploymentConfig {
    function validateExpectedAddressConfig(address expected, bool allowUnverifiedDeployment) external pure {
        _validateExpectedAddressConfig(expected, allowUnverifiedDeployment);
    }

    function assertExpectedAddress(address actual, address expected) external pure {
        _assertExpectedAddress(actual, expected, "address mismatch");
    }
}

contract DeployOPSuccinctLiteTzHarness is DeployOPSuccinctLiteTz {
    function validateImplementationConfig(JSONDecoder.FDGConfig memory config, bool allowDegradedPostAnchor)
        external
        pure
        returns (bool hasRootClaimPreimage, address postAnchor)
    {
        ImplementationConfig memory implementationConfig =
            _validateImplementationConfig(config, allowDegradedPostAnchor);
        return (implementationConfig.hasRootClaimPreimage, implementationConfig.postAnchor);
    }
}

contract DeploymentConfigTest is Test {
    CrossChainDeploymentConfigHarness internal addressHarness;
    DeployOPSuccinctLiteTzHarness internal tzHarness;

    function setUp() public {
        addressHarness = new CrossChainDeploymentConfigHarness();
        tzHarness = new DeployOPSuccinctLiteTzHarness();
    }

    function test_expectedAddressRequiredByDefault() public {
        vm.expectRevert(bytes("Missing expected address; explicitly allow unverified deployment only for development"));
        addressHarness.validateExpectedAddressConfig(address(0), false);
    }

    function test_expectedAddressCanBeSkippedOnlyWithExplicitDevelopmentOptIn() public view {
        addressHarness.validateExpectedAddressConfig(address(0), true);
        addressHarness.assertExpectedAddress(address(0x1234), address(0));
    }

    function test_expectedAddressIsCheckedWhenConfigured() public {
        address expected = address(0x1234);

        addressHarness.validateExpectedAddressConfig(expected, false);
        vm.expectRevert(bytes("address mismatch"));
        addressHarness.assertExpectedAddress(address(0x5678), expected);
    }

    function test_tzUsesJsonPostAnchorAsCanonicalValue() public view {
        JSONDecoder.FDGConfig memory config;
        config.hasRootClaimPreimage = true;
        config.postAnchorAddress = address(0xCAFE);

        (bool hasRootClaimPreimage, address postAnchor) = tzHarness.validateImplementationConfig(config, false);

        assertTrue(hasRootClaimPreimage);
        assertEq(postAnchor, config.postAnchorAddress);
    }

    function test_tzRejectsLegacyClaimLayout() public {
        JSONDecoder.FDGConfig memory config;
        config.postAnchorAddress = address(0xCAFE);

        vm.expectRevert(bytes("TradeZone requires root-claim preimages"));
        tzHarness.validateImplementationConfig(config, false);
    }

    function test_tzRejectsZeroPostAnchorByDefault() public {
        JSONDecoder.FDGConfig memory config;
        config.hasRootClaimPreimage = true;

        vm.expectRevert(bytes("postAnchorAddress is zero; explicitly enable degraded mode"));
        tzHarness.validateImplementationConfig(config, false);
    }

    function test_tzAllowsZeroPostAnchorOnlyInExplicitDegradedMode() public view {
        JSONDecoder.FDGConfig memory config;
        config.hasRootClaimPreimage = true;

        (bool hasRootClaimPreimage, address postAnchor) = tzHarness.validateImplementationConfig(config, true);

        assertTrue(hasRootClaimPreimage);
        assertEq(postAnchor, address(0));
    }
}
