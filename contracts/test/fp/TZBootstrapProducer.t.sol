// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Testing
import "forge-std/Test.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ProxyAdmin} from "@optimism/src/universal/ProxyAdmin.sol";

// Libraries
import {Claim, Duration, GameType, Hash, Proposal} from "src/dispute/lib/Types.sol";
import {BadExtraData} from "src/dispute/lib/Errors.sol";
import {OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE} from "src/lib/Types.sol";

// Contracts
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {AnchorStateRegistry} from "src/dispute/AnchorStateRegistry.sol";
import {AccessManager} from "src/fp/AccessManager.sol";
import {OPSuccinctFaultDisputeGame} from "src/fp/OPSuccinctFaultDisputeGame.sol";
import {SP1MockVerifier} from "src/utils/SP1MockVerifier.sol";

// Interfaces
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {ISP1Verifier} from "src/fp/interfaces/ISP1Verifier.sol";
import {ISystemConfig} from "interfaces/L1/ISystemConfig.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";

// Utils
import {MockOptimismPortal2} from "../../src/utils/MockOptimismPortal2.sol";
import {MockSystemConfig} from "../../src/utils/MockSystemConfig.sol";
import {TZBootstrapExtraData} from "../helpers/TZBootstrapExtraData.sol";

/// @notice Deterministic verification of the TradeZone bootstrap producer/encoder.
/// @dev The TradeZone deploy script (`script/fp/DeployOPSuccinctLiteTz.s.sol`) compiles as part of
///      the Foundry project. Its bootstrap-game creation path calls
///      `TZBootstrapExtraData.encodeExtended` / `TZBootstrapExtraData.commitRootClaim`; this suite
///      exercises those exact functions and asserts the 164-byte layout and keccak commitment order
///      in isolation. It also round-trips the encoder output through a real extended
///      `OPSuccinctFaultDisputeGame` created via the factory: the extended implementation accepts
///      the encoder's 164-byte payload (getters return the committed preimages) and rejects the old
///      36-byte legacy payload with the design error `BadExtraData` (the IR-001 failure reproduced).
contract TZBootstrapProducerTest is Test {
    DisputeGameFactory internal factory;
    AnchorStateRegistry internal anchorStateRegistry;
    AccessManager internal accessManager;
    MockOptimismPortal2 internal portal;
    OPSuccinctFaultDisputeGame internal gameImpl;

    address internal proposer = address(0x123);
    address internal challenger = address(0x456);

    uint256 internal disputeGameFinalityDelaySeconds = 1000;
    GameType internal gameType = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);
    Duration internal maxChallengeDuration = Duration.wrap(12 hours);
    Duration internal maxProveDuration = Duration.wrap(3 days);

    uint256 internal constant INIT_BOND = 1 ether;
    uint256 internal constant CHALLENGER_BOND_AMOUNT = 1 ether;

    // Fixed preimages for the deterministic checks (arbitrary but distinct).
    bytes32 internal constant BH = keccak256("bootstrap-block-hash");
    bytes32 internal constant AH = keccak256("bootstrap-app-hash");
    bytes32 internal constant WR = keccak256("bootstrap-withdrawal-root");
    bytes32 internal constant FR = keccak256("bootstrap-force-root");
    uint256 internal constant L2_BLOCK = 1000;

    function setUp() public {
        ProxyAdmin proxyAdmin = new ProxyAdmin(address(this));

        DisputeGameFactory factoryImpl = new DisputeGameFactory();
        Proxy factoryProxy = new Proxy(address(proxyAdmin));
        proxyAdmin.upgradeAndCall(
            payable(address(factoryProxy)),
            address(factoryImpl),
            abi.encodeWithSelector(DisputeGameFactory.initialize.selector, address(this))
        );
        factory = DisputeGameFactory(address(factoryProxy));

        SP1MockVerifier sp1Verifier = new SP1MockVerifier();
        MockSystemConfig mockSystemConfig = new MockSystemConfig(address(this));
        portal = new MockOptimismPortal2(gameType, disputeGameFinalityDelaySeconds);

        Proposal memory startingAnchorRoot = Proposal({root: Hash.wrap(keccak256("genesis")), l2SequenceNumber: 0});
        AnchorStateRegistry registryImpl = new AnchorStateRegistry(disputeGameFinalityDelaySeconds);
        Proxy registryProxy = new Proxy(address(proxyAdmin));
        proxyAdmin.upgradeAndCall(
            payable(address(registryProxy)),
            address(registryImpl),
            abi.encodeCall(
                AnchorStateRegistry.initialize,
                (
                    ISystemConfig(address(mockSystemConfig)),
                    IDisputeGameFactory(address(factory)),
                    startingAnchorRoot,
                    gameType
                )
            )
        );
        anchorStateRegistry = AnchorStateRegistry(address(registryProxy));

        accessManager = new AccessManager(2 weeks, IDisputeGameFactory(address(factory)));
        accessManager.setProposer(proposer, true);
        accessManager.setChallenger(challenger, true);

        // Extended implementation: HAS_ROOT_CLAIM_PREIMAGE == true, no PostAnchor (degraded, valid).
        gameImpl = new OPSuccinctFaultDisputeGame(
            maxChallengeDuration,
            maxProveDuration,
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            CHALLENGER_BOND_AMOUNT,
            IAnchorStateRegistry(address(anchorStateRegistry)),
            accessManager,
            true,
            address(0)
        );

        factory.setInitBond(gameType, INIT_BOND);
        factory.setImplementation(gameType, IDisputeGame(address(gameImpl)));
    }

    // -----------------------------------------------------------------
    // Pure encoder layout + commitment (no harness dependency)
    // -----------------------------------------------------------------

    /// @notice The extended payload is exactly 164 bytes and lays out every field at the offset the
    ///         on-chain getters read (l2SequenceNumber at 0, parentIndex at 32, blockHash at 36,
    ///         appHash at 68, withdrawalRoot at 100, forceRoot at 132).
    function test_encoder_extendedLayout() public pure {
        uint32 parentIndex = type(uint32).max;
        bytes memory extra = TZBootstrapExtraData.encodeExtended(L2_BLOCK, parentIndex, BH, AH, WR, FR);
        assertEq(extra.length, TZBootstrapExtraData.EXTENDED_EXTRA_DATA_LEN, "extended length");
        assertEq(extra.length, 164, "extended length literal");

        assertEq(uint256(_word(extra, 0)), L2_BLOCK, "l2SequenceNumber@0");
        assertEq(uint256(uint32(bytes4(_word(extra, 32)))), uint256(parentIndex), "parentIndex@32");
        assertEq(_word(extra, 36), BH, "blockHash@36");
        assertEq(_word(extra, 68), AH, "appHash@68");
        assertEq(_word(extra, 100), WR, "withdrawalRoot@100");
        assertEq(_word(extra, 132), FR, "forceRoot@132");
    }

    /// @notice The legacy payload is exactly 36 bytes (byte-for-byte the historical layout).
    function test_encoder_legacyLayout() public pure {
        uint32 parentIndex = type(uint32).max;
        bytes memory legacy = TZBootstrapExtraData.encodeLegacy(L2_BLOCK, parentIndex);
        assertEq(legacy.length, TZBootstrapExtraData.LEGACY_EXTRA_DATA_LEN, "legacy length");
        assertEq(legacy.length, 36, "legacy length literal");
        assertEq(uint256(_word(legacy, 0)), L2_BLOCK, "l2SequenceNumber@0");
        assertEq(uint256(uint32(bytes4(_word(legacy, 32)))), uint256(parentIndex), "parentIndex@32");
    }

    /// @notice The commitment is keccak256 over the fixed order block, app, withdrawal, force.
    function test_encoder_rootClaimCommitmentOrder() public pure {
        bytes32 expected = keccak256(abi.encodePacked(BH, AH, WR, FR));
        assertEq(TZBootstrapExtraData.commitRootClaim(BH, AH, WR, FR), expected, "commitment order");
    }

    // -----------------------------------------------------------------
    // Round-trip against a real extended game created via the factory
    // -----------------------------------------------------------------

    /// @notice The extended implementation accepts the encoder's 164-byte payload + committed
    ///         rootClaim, and the on-chain getters return exactly the encoded preimages.
    function test_extendedProducer_roundTrip_accepted() public {
        bytes32 rootClaim = TZBootstrapExtraData.commitRootClaim(BH, AH, WR, FR);
        bytes memory extra = TZBootstrapExtraData.encodeExtended(L2_BLOCK, type(uint32).max, BH, AH, WR, FR);

        vm.warp(block.timestamp + 1000);
        vm.deal(proposer, INIT_BOND);
        vm.prank(proposer);
        OPSuccinctFaultDisputeGame g = OPSuccinctFaultDisputeGame(
            address(factory.create{value: INIT_BOND}(gameType, Claim.wrap(rootClaim), extra))
        );

        assertEq(g.HAS_ROOT_CLAIM_PREIMAGE(), true, "extended impl");
        assertEq(g.rootClaim().raw(), rootClaim, "rootClaim bound to preimages");
        assertEq(g.blockHash(), BH, "blockHash getter");
        assertEq(g.appHash(), AH, "appHash getter");
        assertEq(g.withdrawalRoot(), WR, "withdrawalRoot getter");
        assertEq(g.forceRoot(), FR, "forceRoot getter");
        assertEq(g.extraData().length, 164, "extraData length");
    }

    /// @notice Reproduces IR-001: the old bootstrap producer encoded a 36-byte legacy payload
    ///         against this extended implementation; the length guard rejects it with BadExtraData.
    function test_extendedImpl_rejectsLegacyPayload_BadExtraData() public {
        bytes memory legacy = TZBootstrapExtraData.encodeLegacy(L2_BLOCK, type(uint32).max);
        assertEq(legacy.length, 36, "legacy length");

        vm.warp(block.timestamp + 1000);
        vm.deal(proposer, INIT_BOND);
        vm.prank(proposer);
        vm.expectRevert(BadExtraData.selector);
        factory.create{value: INIT_BOND}(gameType, Claim.wrap(keccak256("legacy-root")), legacy);
    }

    // -----------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------

    /// @dev Reads the 32-byte word at byte `offset` within a memory `bytes` value.
    function _word(bytes memory data, uint256 offset) private pure returns (bytes32 out) {
        // memory-safe: reads a single word strictly inside `data`'s content region.
        assembly ("memory-safe") {
            out := mload(add(add(data, 0x20), offset))
        }
    }
}
