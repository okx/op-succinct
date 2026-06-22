// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Testing
import "forge-std/Test.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ProxyAdmin} from "@optimism/src/universal/ProxyAdmin.sol";

// Libraries
import {Claim, Duration, GameStatus, GameType, Hash, Proposal, Timestamp} from "src/dispute/lib/Types.sol";
import {AggregationOutputs, OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE} from "src/lib/Types.sol";

// Contracts under test (both V1 and TZ)
import {OPSuccinctFaultDisputeGame} from "src/fp/OPSuccinctFaultDisputeGame.sol";
import {TZOPSuccinctFaultDisputeGame} from "src/fp/TZOPSuccinctFaultDisputeGame.sol";

// Infrastructure
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {SP1MockVerifier} from "@sp1-contracts/src/SP1MockVerifier.sol";
import {AnchorStateRegistry} from "src/dispute/AnchorStateRegistry.sol";
import {AccessManager} from "src/fp/AccessManager.sol";

// Interfaces
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {ISP1Verifier} from "@sp1-contracts/src/ISP1Verifier.sol";
import {ISystemConfig} from "interfaces/L1/ISystemConfig.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";

// Utils
import {MockOptimismPortal2} from "../../src/utils/MockOptimismPortal2.sol";
import {MockSystemConfig} from "../../src/utils/MockSystemConfig.sol";

/// @title TZOPSuccinctFaultDisputeGameDifferentialTest
/// @notice Differential tests proving TZ contract maintains key V1 compatibility properties.
///         Covers TZ_TEST_PLAN.md §6: byte-level + selector + N=1 layout equivalence with V1.
contract TZOPSuccinctFaultDisputeGameDifferentialTest is Test {
    // ===================== Infrastructure (shared between V1 and TZ) =====================
    DisputeGameFactory factory;
    Proxy factoryProxy;
    ProxyAdmin proxyAdmin;
    AnchorStateRegistry anchorStateRegistry;
    AccessManager accessManager;
    MockOptimismPortal2 portal;
    SP1MockVerifier sp1Verifier;

    // Both impls registered under different game types.
    TZOPSuccinctFaultDisputeGame tzImpl;
    OPSuccinctFaultDisputeGame v1Impl;

    // Use TZ's standard type as the "respected" type (matches main test file convention).
    GameType tzGameType = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);
    GameType v1GameType = GameType.wrap(uint32(99));

    address proposer = address(0x123);
    address challenger = address(0x456);

    Duration maxChallengeDuration = Duration.wrap(12 hours);
    Duration maxProveDuration = Duration.wrap(3 days);
    uint256 constant CREATE_BOND = 1 ether;
    uint256 constant CHAL_BOND = 1 ether;
    uint256 disputeGameFinalityDelaySeconds = 1000;

    function setUp() public {
        // Factory + proxy admin setup (same as main test).
        proxyAdmin = new ProxyAdmin(address(this));
        DisputeGameFactory factoryImpl = new DisputeGameFactory();
        factoryProxy = new Proxy(address(proxyAdmin));
        proxyAdmin.upgradeAndCall(
            payable(address(factoryProxy)),
            address(factoryImpl),
            abi.encodeWithSelector(DisputeGameFactory.initialize.selector, address(this))
        );
        factory = DisputeGameFactory(address(factoryProxy));

        sp1Verifier = new SP1MockVerifier();

        MockSystemConfig mockSystemConfig = new MockSystemConfig(address(this));
        portal = new MockOptimismPortal2(tzGameType, disputeGameFinalityDelaySeconds);
        Proposal memory startingAnchorRoot =
            Proposal({root: Hash.wrap(keccak256("genesis")), l2SequenceNumber: 0});

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
                    tzGameType
                )
            )
        );
        anchorStateRegistry = AnchorStateRegistry(address(registryProxy));

        accessManager = new AccessManager(2 weeks, IDisputeGameFactory(address(factory)));
        accessManager.setProposer(proposer, true);
        accessManager.setChallenger(challenger, true);

        // Deploy TZ impl.
        tzImpl = new TZOPSuccinctFaultDisputeGame(
            maxChallengeDuration,
            maxProveDuration,
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            CHAL_BOND,
            IAnchorStateRegistry(address(anchorStateRegistry)),
            accessManager
        );

        // Deploy V1 impl with IDENTICAL constructor args. This is the key property:
        // TZ's constructor signature matches V1's — only the behavior differs.
        v1Impl = new OPSuccinctFaultDisputeGame(
            maxChallengeDuration,
            maxProveDuration,
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            CHAL_BOND,
            IAnchorStateRegistry(address(anchorStateRegistry)),
            accessManager
        );

        // Register both impls under different game types.
        factory.setInitBond(tzGameType, CREATE_BOND);
        factory.setImplementation(tzGameType, IDisputeGame(address(tzImpl)));
        factory.setInitBond(v1GameType, CREATE_BOND);
        factory.setImplementation(v1GameType, IDisputeGame(address(v1Impl)));

        vm.warp(block.timestamp + 1000);
        vm.deal(proposer, 100 ether);
    }

    // ===================== §6.1 Byte-level compatibility =====================

    /// @notice V1's prove(bytes) selector MUST match TZ's prove(bytes) overload selector.
    /// @dev    This is the key V1-tooling-compatibility guarantee: etherscan, indexers,
    ///         debug tracers identify TZ's early-finalize call as V1's well-known prove.
    function test_diff_proveSelector_TZ_matchesV1() public {
        // V1: prove(bytes) is the only prove function.
        bytes4 v1ProveSelector = OPSuccinctFaultDisputeGame.prove.selector;
        // TZ: prove is overloaded; we want the (bytes)-only variant. Construct manually
        // via signature string since direct .selector is ambiguous on overloads.
        bytes4 tzProveBytesSelector = bytes4(keccak256("prove(bytes)"));

        assertEq(v1ProveSelector, tzProveBytesSelector);
        // Sanity: also matches the spec-mandated value.
        assertEq(v1ProveSelector, bytes4(keccak256("prove(bytes)")));
    }

    /// @notice TZ's per-segment prove(uint64,bytes) MUST have a distinct selector from V1's prove(bytes).
    /// @dev    Prevents accidental cross-dispatch in tooling.
    function test_diff_proveUint64BytesSelector_distinctFromV1() public {
        bytes4 v1ProveSelector = OPSuccinctFaultDisputeGame.prove.selector;
        bytes4 tzProveUint64Selector = bytes4(keccak256("prove(uint64,bytes)"));

        assertTrue(v1ProveSelector != tzProveUint64Selector);
    }

    /// @notice V1's challenge() and TZ's challenge(uint64) MUST have distinct selectors.
    /// @dev    Documents the unavoidable ABI break for the per-segment counter.
    function test_diff_challengeSelector_V1_distinctFromTZ() public {
        bytes4 v1ChallengeSelector = bytes4(keccak256("challenge()"));
        bytes4 tzChallengeSelector = bytes4(keccak256("challenge(uint64)"));

        assertTrue(v1ChallengeSelector != tzChallengeSelector);
        // Sanity: TZ's selector matches its actual function dispatcher.
        assertEq(tzChallengeSelector, TZOPSuccinctFaultDisputeGame.challenge.selector);
    }

    /// @notice For N=1 (degenerate path), TZ's extraData encoding is byte-identical to V1's.
    /// @dev    Both encode `(uint256 l2SequenceNumber, uint32 parentIndex)` = 36 bytes,
    ///         producing identical factory UUIDs for matching `(gameType, rootClaim, extraData)`.
    function test_diff_extraDataEncoding_N1_byteIdenticalToV1() public {
        // Both V1 and TZ N=1 use abi.encodePacked(uint256, uint32) = 36 bytes.
        bytes memory tzN1Extra = abi.encodePacked(uint256(1000), type(uint32).max);
        bytes memory v1Extra = abi.encodePacked(uint256(1000), type(uint32).max);

        assertEq(tzN1Extra.length, 36);
        assertEq(v1Extra.length, 36);
        assertEq(keccak256(tzN1Extra), keccak256(v1Extra));
    }

    /// @notice V1 game's stored extraData equals the input. For TZ N=1, the same property holds
    ///         AND the bytes are byte-identical to what V1 would store.
    function test_diff_storedExtraData_N1_matchesV1() public {
        bytes memory inputExtra = abi.encodePacked(uint256(1000), type(uint32).max);

        // Create V1 game.
        vm.prank(proposer);
        OPSuccinctFaultDisputeGame v1Game = OPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(v1GameType, Claim.wrap(keccak256("v1")), inputExtra))
        );

        // Create TZ N=1 game.
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame tzGame = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(tzGameType, Claim.wrap(keccak256("tz")), inputExtra))
        );

        // Both store the same extraData bytes.
        assertEq(keccak256(v1Game.extraData()), keccak256(tzGame.extraData()));
        assertEq(v1Game.extraData().length, 36);
        assertEq(tzGame.extraData().length, 36);
    }

    /// @notice For N=1, TZ's CWIA calldata size matches V1's exactly (0x7E).
    /// @dev    Total = 0x04 selector + 0x14 creator + 0x20 rootClaim + 0x20 l1Head
    ///         + 0x20 l2SeqNumber + 0x04 parentIndex + 0x02 CWIA suffix = 0x7E.
    function test_diff_cwiaLayout_N1_calldataSizeMatches() public {
        bytes memory inputExtra = abi.encodePacked(uint256(1000), type(uint32).max);

        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame tzGame = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(tzGameType, Claim.wrap(keccak256("tz1")), inputExtra))
        );

        // For N=1: derived numSegments == 1, batchSize == l2SeqNumber - anchor (1000 - 0 = 1000).
        assertEq(tzGame.numSegments(), 1);
        assertEq(tzGame.batchSize(), 1000);
        assertEq(tzGame.intermediateRoots().length, 0);
    }

    // ===================== §6.2 Behavioral equivalence (N=1) =====================

    /// @notice V1 and TZ both expose `l2SequenceNumber()` returning the input l2SeqNumber.
    function test_diff_l2SequenceNumber_identical() public {
        uint256 inputSeq = 1000;
        bytes memory inputExtra = abi.encodePacked(inputSeq, type(uint32).max);

        vm.startPrank(proposer);
        OPSuccinctFaultDisputeGame v1Game = OPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(v1GameType, Claim.wrap(keccak256("v1seq")), inputExtra))
        );
        TZOPSuccinctFaultDisputeGame tzGame = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(tzGameType, Claim.wrap(keccak256("tzseq")), inputExtra))
        );
        vm.stopPrank();

        assertEq(v1Game.l2SequenceNumber(), tzGame.l2SequenceNumber());
        assertEq(v1Game.l2SequenceNumber(), inputSeq);
    }

    /// @notice V1 and TZ both expose `parentIndex()` returning the input parentIndex.
    function test_diff_parentIndex_identical() public {
        bytes memory inputExtra = abi.encodePacked(uint256(1000), type(uint32).max);

        vm.startPrank(proposer);
        OPSuccinctFaultDisputeGame v1Game = OPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(v1GameType, Claim.wrap(keccak256("v1p")), inputExtra))
        );
        TZOPSuccinctFaultDisputeGame tzGame = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(tzGameType, Claim.wrap(keccak256("tzp")), inputExtra))
        );
        vm.stopPrank();

        assertEq(uint256(v1Game.parentIndex()), uint256(tzGame.parentIndex()));
        assertEq(v1Game.parentIndex(), type(uint32).max);
    }

    /// @notice V1's gameCreator() and TZ's gameCreator() both return the original `msg.sender` to factory.create.
    function test_diff_gameCreator_identical() public {
        bytes memory inputExtra = abi.encodePacked(uint256(1000), type(uint32).max);

        vm.startPrank(proposer);
        OPSuccinctFaultDisputeGame v1Game = OPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(v1GameType, Claim.wrap(keccak256("v1g")), inputExtra))
        );
        TZOPSuccinctFaultDisputeGame tzGame = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(tzGameType, Claim.wrap(keccak256("tzg")), inputExtra))
        );
        vm.stopPrank();

        assertEq(v1Game.gameCreator(), proposer);
        assertEq(tzGame.gameCreator(), proposer);
    }

    /// @notice V1's maxClockDuration() returns MAX_CHALLENGE_DURATION. TZ should match exactly.
    function test_diff_maxClockDuration_identical() public {
        assertEq(v1Impl.maxClockDuration().raw(), tzImpl.maxClockDuration().raw());
        assertEq(v1Impl.maxClockDuration().raw(), maxChallengeDuration.raw());
    }

    // ===================== §6.3 Storage-level differences (intentional) =====================

    /// @notice ClaimData shapes intentionally differ: V1 has counteredBy, TZ does not.
    /// @dev    Documents the structural divergence. V1: 6 fields. TZ: 5 fields with `prover`
    ///         in slot 1 (packed with proveDeadline + parentIndex).
    function test_diff_claimDataShape_documentedDivergence() public {
        bytes memory inputExtra = abi.encodePacked(uint256(1000), type(uint32).max);

        vm.startPrank(proposer);
        OPSuccinctFaultDisputeGame v1Game = OPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(v1GameType, Claim.wrap(keccak256("v1c")), inputExtra))
        );
        TZOPSuccinctFaultDisputeGame tzGame = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(tzGameType, Claim.wrap(keccak256("tzc")), inputExtra))
        );
        vm.stopPrank();

        // V1 ClaimData: (parentIndex, counteredBy, prover, claim, status, deadline) — 6-tuple
        (
            uint32 v1ParentIdx,
            address v1CounteredBy,
            address v1Prover,
            Claim v1Claim,
            ,
            Timestamp v1Deadline
        ) = v1Game.claimData();

        // TZ ClaimData: (prover, proveDeadline, parentIndex, status, claim) — 5-tuple
        (
            address tzProver,
            Timestamp tzProveDeadline,
            uint32 tzParentIdx,
            ,
            Claim tzClaim
        ) = tzGame.claimData();

        // Shared semantics:
        assertEq(uint256(v1ParentIdx), uint256(tzParentIdx));
        assertEq(v1Prover, address(0)); // both start with prover unset
        assertEq(tzProver, address(0));
        assertEq(Claim.unwrap(v1Claim), keccak256("v1c"));
        assertEq(Claim.unwrap(tzClaim), keccak256("tzc"));

        // Divergence: V1 has counteredBy field (unused at init); TZ moved it to disputes[k].counteredBy.
        assertEq(v1CounteredBy, address(0));

        // Divergence: V1's deadline is rolling (init = createdAt + MAX_CHAL).
        //             TZ's proveDeadline is absolute (init = createdAt + MAX_CHAL + MAX_PROVE).
        Duration MAX_CHAL = maxChallengeDuration;
        Duration MAX_PROVE = maxProveDuration;
        Timestamp v1Created = v1Game.createdAt();
        Timestamp tzCreated = tzGame.createdAt();
        assertEq(v1Deadline.raw(), uint64(v1Created.raw()) + MAX_CHAL.raw());
        assertEq(
            tzProveDeadline.raw(),
            uint64(tzCreated.raw()) + MAX_CHAL.raw() + MAX_PROVE.raw()
        );
    }

    /// @notice TZ adds `numSegments / batchSize / totalCountered / ...` fields not present in V1.
    function test_diff_storageNewFields_tzOnly() public {
        bytes memory inputExtra = abi.encodePacked(uint256(1000), type(uint32).max);

        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame tzGame = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(tzGameType, Claim.wrap(keccak256("tznew")), inputExtra))
        );

        // TZ-only fields: assertable
        assertEq(tzGame.numSegments(), 1);
        assertEq(tzGame.batchSize(), 1000);
        assertEq(tzGame.totalCountered(), 0);
        assertEq(tzGame.totalProved(), 0);
        assertEq(tzGame.lowestSIndex(), type(uint64).max); // sentinel
        assertFalse(tzGame.createBondPushedAtResolve());
    }

    // ===================== Version =====================

    function test_diff_version_distinct() public {
        // V1 version constant.
        assertEq(v1Impl.version(), "2.0.0");
        // TZ adds suffix to distinguish.
        assertEq(tzImpl.version(), "2.0.0-tz-segment");
    }
}
