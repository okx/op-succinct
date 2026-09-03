// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {Duration} from "src/dispute/lib/Types.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {ISP1Verifier} from "src/fp/interfaces/ISP1Verifier.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {AccessManager} from "src/fp/AccessManager.sol";
import {OPSuccinctFaultDisputeGame} from "src/fp/OPSuccinctFaultDisputeGame.sol";
import {InvalidPostAnchorConfig, InvalidPostAnchor} from "src/fp/lib/Errors.sol";

/// @notice Constructor-configuration smoke tests for the extended dispute game. These deploy the
///         game implementation directly (no clone) to exercise the auto-delivery configuration
///         matrix, the immutable getters, and the version bump.
/// @dev Clone-based behavior (four-preimage commitment binding, preimage getters, extraData length
///      selection, and the closeGame delivery hook) requires the full factory / anchor-state
///      registry harness, which pulls the pinned optimism contracts. Those runtime paths are
///      covered by the independent testing stage; this file proves the constructor wiring.
contract OPSuccinctFaultDisputeGamePostAnchorTest is Test {
    Duration internal dur;

    function setUp() public {
        dur = Duration.wrap(3600);
    }

    function _deploy(bool hasPreimage, address postAnchor) internal returns (OPSuccinctFaultDisputeGame) {
        return new OPSuccinctFaultDisputeGame(
            dur,
            dur,
            IDisputeGameFactory(address(0)),
            ISP1Verifier(address(0)),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            0,
            IAnchorStateRegistry(address(0)),
            AccessManager(payable(address(0))),
            hasPreimage,
            postAnchor
        );
    }

    function test_ctor_legacyConfig_ok() public {
        OPSuccinctFaultDisputeGame g = _deploy(false, address(0));
        assertFalse(g.HAS_ROOT_CLAIM_PREIMAGE());
        assertEq(g.POST_ANCHOR(), address(0));
    }

    function test_ctor_tzDegradedConfig_ok() public {
        OPSuccinctFaultDisputeGame g = _deploy(true, address(0));
        assertTrue(g.HAS_ROOT_CLAIM_PREIMAGE());
        assertEq(g.POST_ANCHOR(), address(0));
    }

    function test_ctor_tzConfig_ok() public {
        // address(this) has contract code, satisfying the delivery-target no-code guard.
        OPSuccinctFaultDisputeGame g = _deploy(true, address(this));
        assertTrue(g.HAS_ROOT_CLAIM_PREIMAGE());
        assertEq(g.POST_ANCHOR(), address(this));
    }

    /// @notice Guarded-entry negative smoke: a delivery target on a legacy (non-four-preimage)
    ///         game is rejected with the exact design error.
    function test_ctor_deliveryOnLegacy_revertsInvalidPostAnchorConfig() public {
        vm.expectRevert(InvalidPostAnchorConfig.selector);
        _deploy(false, address(this));
    }

    /// @notice Guarded-entry negative smoke: a delivery target with no contract code is rejected
    ///         with the exact design error.
    function test_ctor_deliveryNoCode_revertsInvalidPostAnchor() public {
        vm.expectRevert(InvalidPostAnchor.selector);
        _deploy(true, address(0xBEEF));
    }

    function test_version_is210() public {
        OPSuccinctFaultDisputeGame g = _deploy(false, address(0));
        assertEq(g.version(), "2.1.0");
    }
}
