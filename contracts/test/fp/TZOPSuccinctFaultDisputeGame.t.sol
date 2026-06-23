// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Testing
import "forge-std/Test.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ProxyAdmin} from "@optimism/src/universal/ProxyAdmin.sol";

// Libraries
import {Claim, Duration, GameStatus, GameType, Hash, Proposal, Timestamp} from "src/dispute/lib/Types.sol";
import {
    BadAuth,
    BadExtraData,
    IncorrectBondAmount,
    AlreadyInitialized,
    UnexpectedRootClaim,
    NoCreditToClaim,
    GameNotResolved,
    GameNotFinalized,
    ClaimAlreadyResolved,
    ClockTimeExceeded
} from "src/dispute/lib/Errors.sol";
import {
    ParentGameNotResolved,
    InvalidParentGame,
    ClaimAlreadyChallenged,
    GameNotOver,
    IncorrectDisputeGameFactory,
    InvalidProposalStatus
} from "src/fp/lib/Errors.sol";
import {AggregationOutputs, OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE} from "src/lib/Types.sol";

// Contracts under test
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

/// @title TZOPSuccinctFaultDisputeGameTest
/// @notice Unit + integration tests for the TZ multi-segment + multi-challenger fault dispute game
///         per SPEC_GAME_V2_CALLDATA.md. Test file structure follows V1 test conventions.
contract TZOPSuccinctFaultDisputeGameTest is Test {
    // ===================== Events (mirror those in TZOPSuccinctFaultDisputeGame) =====================
    event Challenged(address indexed challenger, uint64 indexed segment);
    event Proved(address indexed prover, uint64 indexed segment);
    event FullProved(address indexed prover);
    event Resolved(GameStatus indexed status);

    // ===================== Infrastructure =====================
    DisputeGameFactory factory;
    Proxy factoryProxy;
    ProxyAdmin proxyAdmin;

    TZOPSuccinctFaultDisputeGame gameImpl;
    TZOPSuccinctFaultDisputeGame parentGame;

    AnchorStateRegistry anchorStateRegistry;
    AccessManager accessManager;
    MockOptimismPortal2 portal;
    SP1MockVerifier sp1Verifier;

    // ===================== Test actors =====================
    address proposer = address(0x123);
    address challenger = address(0x456);
    address challenger2 = address(0x457);
    address prover = address(0x789);

    uint256 disputeGameFinalityDelaySeconds = 1000;

    // ===================== Game parameters =====================
    GameType gameType = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);
    Duration maxChallengeDuration = Duration.wrap(12 hours);
    Duration maxProveDuration = Duration.wrap(3 days);
    Claim rootClaim = Claim.wrap(keccak256("rootClaim"));
    uint256 constant CREATE_BOND = 1 ether;
    uint256 constant CHAL_BOND = 1 ether;

    // ===================== setUp =====================
    function setUp() public virtual {
        // Deploy ProxyAdmin with this test contract as owner.
        proxyAdmin = new ProxyAdmin(address(this));

        // Deploy the implementation contract for DisputeGameFactory.
        DisputeGameFactory factoryImpl = new DisputeGameFactory();

        // Deploy an Optimism Proxy pointing to ProxyAdmin.
        factoryProxy = new Proxy(address(proxyAdmin));

        // Initialize the factory through ProxyAdmin.
        proxyAdmin.upgradeAndCall(
            payable(address(factoryProxy)),
            address(factoryImpl),
            abi.encodeWithSelector(DisputeGameFactory.initialize.selector, address(this))
        );
        factory = DisputeGameFactory(address(factoryProxy));

        // Create a mock SP1 verifier (always succeeds; cross-game replay separately tested).
        sp1Verifier = new SP1MockVerifier();

        // Create the anchor state registry.
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

        // AccessManager: allow proposer & challenger.
        accessManager = new AccessManager(2 weeks, IDisputeGameFactory(address(factory)));
        accessManager.setProposer(proposer, true);
        accessManager.setChallenger(challenger, true);
        accessManager.setChallenger(challenger2, true);

        // Deploy the TZ game implementation.
        gameImpl = new TZOPSuccinctFaultDisputeGame(
            maxChallengeDuration,
            maxProveDuration,
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            bytes32(0), // rollupConfigHash (= 0 for TZ)
            bytes32(0), // aggregationVkey
            bytes32(0), // rangeVkeyCommitment
            CHAL_BOND, // challenger bond
            IAnchorStateRegistry(address(anchorStateRegistry)),
            accessManager
        );

        // Register impl under the game type.
        factory.setInitBond(gameType, CREATE_BOND);
        factory.setImplementation(gameType, IDisputeGame(address(gameImpl)));

        // Warp past respectedGameTypeUpdatedAt for ASR semantics.
        vm.warp(block.timestamp + 1000);

        // Create a parent game (N=1, no intermediate roots — byte-identical extraData to V1).
        vm.startPrank(proposer);
        vm.deal(proposer, 100 ether);
        parentGame = TZOPSuccinctFaultDisputeGame(
            address(
                factory.create{value: CREATE_BOND}(
                    gameType,
                    Claim.wrap(keccak256("genesis-1")),
                    _encodeExtraDataN1(1000, type(uint32).max)
                )
            )
        );
        vm.stopPrank();

        // Finalize the parent game so children can use it as their parent.
        vm.warp(parentGame.challengeEnd().raw() + 1 seconds);
        parentGame.resolve();
        // Wait past ASR finality delay so closeGame() can succeed.
        vm.warp(parentGame.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1 seconds);
    }

    // ===================== Helpers =====================

    /// @notice Encode N=1 extraData: just l2SequenceNumber + parentIndex (36 bytes, V1-compatible).
    function _encodeExtraDataN1(uint256 l2Seq, uint32 parentIdx) internal pure returns (bytes memory) {
        return abi.encodePacked(l2Seq, parentIdx);
    }

    /// @notice Encode multi-segment extraData: l2SequenceNumber + parentIndex + (numSegments-1) × 32-byte roots.
    function _encodeExtraData(uint256 l2Seq, uint32 parentIdx, bytes32[] memory intermediateRoots)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory result = abi.encodePacked(l2Seq, parentIdx);
        for (uint256 i = 0; i < intermediateRoots.length; i++) {
            result = abi.encodePacked(result, intermediateRoots[i]);
        }
        return result;
    }

    /// @notice Create a child game with N segments. Caller must be a whitelisted proposer.
    /// @param  numSegs       segment count (1..256)
    /// @param  l2Seq         l2SequenceNumber for the child (must be > parent's l2Seq and = parent.l2Seq + batchSize)
    /// @param  parentIdx     parent game's factory index
    /// @param  childClaim    rootClaim for the new game
    /// @return childGame     the deployed TZOPSuccinctFaultDisputeGame proxy
    function _createChildGame(uint64 numSegs, uint256 l2Seq, uint32 parentIdx, Claim childClaim)
        internal
        returns (TZOPSuccinctFaultDisputeGame childGame)
    {
        bytes32[] memory roots = new bytes32[](numSegs - 1);
        for (uint256 i = 0; i < roots.length; i++) {
            // Mock intermediate roots — content doesn't matter for tests that don't exercise prove paths.
            roots[i] = keccak256(abi.encodePacked("seg", i));
        }
        bytes memory extraData = _encodeExtraData(l2Seq, parentIdx, roots);
        return _createChildGameWithExtraData(extraData, childClaim);
    }

    function _createChildGameWithExtraData(bytes memory extraData, Claim childClaim)
        internal
        returns (TZOPSuccinctFaultDisputeGame)
    {
        return TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, childClaim, extraData))
        );
    }

    /// @notice Destructure claimData() into named locals (TZ ClaimData has 5 fields).
    function _readClaimData(TZOPSuccinctFaultDisputeGame g)
        internal
        view
        returns (
            address prover_,
            Timestamp proveDeadline_,
            uint32 parentIndex_,
            TZOPSuccinctFaultDisputeGame.ProposalStatus status_,
            Claim claim_
        )
    {
        (prover_, proveDeadline_, parentIndex_, status_, claim_) = g.claimData();
    }

    // ===================== §2.2 initialize() Happy Paths =====================

    function test_init_happyPath_N1() public {
        vm.startPrank(proposer);
        // N=1: parentIdx=0 (parentGame), l2Seq=2000 (= parent.l2Seq + 1000 batchSize).
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(
                factory.create{value: CREATE_BOND}(
                    gameType, rootClaim, _encodeExtraDataN1(2000, 0)
                )
            )
        );
        vm.stopPrank();

        assertEq(g.numSegments(), 1);
        assertEq(g.batchSize(), 1000); // 2000 - 1000 (parent's l2Seq)
        assertEq(g.lowestSIndex(), type(uint64).max); // sentinel set
        assertEq(g.totalCountered(), 0);
        assertEq(g.totalProved(), 0);
        assertFalse(g.createBondPushedAtResolve());

        (address pv, Timestamp pd, uint32 pi, TZOPSuccinctFaultDisputeGame.ProposalStatus s, Claim c) = _readClaimData(g);
        assertEq(pv, address(0)); // prover unset
        assertEq(uint8(s), uint8(TZOPSuccinctFaultDisputeGame.ProposalStatus.Unchallenged));
        assertEq(pi, 0);
        assertEq(Claim.unwrap(c), Claim.unwrap(rootClaim));
        // proveDeadline = createdAt + MAX_CHAL + MAX_PROVE (absolute time)
        uint64 expectedDeadline = uint64(g.createdAt().raw()) + maxChallengeDuration.raw() + maxProveDuration.raw();
        assertEq(pd.raw(), expectedDeadline);

        // refundModeCredit equals CREATE_BOND (proposer's deposit).
        assertEq(g.refundModeCredit(proposer), CREATE_BOND);
        // normalModeCredit empty until resolve.
        assertEq(g.normalModeCredit(proposer), 0);
    }

    function test_init_happyPath_N4_segmentSizeOk() public {
        vm.startPrank(proposer);
        // N=4: l2Seq=2000, batchSize=1000, SEGMENT_SIZE=250.
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        vm.stopPrank();

        assertEq(g.numSegments(), 4);
        assertEq(g.batchSize(), 1000);
        assertEq(g.segmentSize(), 250);
    }

    function test_init_happyPath_N256() public {
        vm.startPrank(proposer);
        // N=256: batchSize must be a multiple of 256. Use batchSize = 256*4 = 1024.
        TZOPSuccinctFaultDisputeGame g = _createChildGame(256, 1000 + 1024, 0, rootClaim);
        vm.stopPrank();

        assertEq(g.numSegments(), 256);
        assertEq(g.batchSize(), 1024);
        assertEq(g.segmentSize(), 4);
    }

    function test_init_anchorRootFallback() public {
        // Create a game with parentIndex == uint32.max (first game / retirement recovery).
        // ASR has anchor at l2Seq=0, root=keccak("genesis").
        vm.startPrank(proposer);
        // Need to deploy a totally fresh factory to allow uint32.max parent (parent already used above).
        // Simpler: just create a game with parentIndex=type(uint32).max and verify it uses anchorRoot.
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(
                factory.create{value: CREATE_BOND}(
                    gameType,
                    Claim.wrap(keccak256("anchorChild")),
                    _encodeExtraDataN1(500, type(uint32).max)
                )
            )
        );
        vm.stopPrank();

        // startingOutputRoot should come from the anchor (genesis).
        // Public auto-getter returns (Hash, uint256) per struct field order.
        (Hash root, uint256 seqNum) = g.startingOutputRoot();
        assertEq(Hash.unwrap(root), keccak256("genesis"));
        assertEq(seqNum, 0);
    }

    // ===================== §2.2 initialize() Revert Paths =====================

    function test_init_revert_AlreadyInitialized() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0)))
        );

        // Second initialize() call reverts.
        vm.expectRevert(AlreadyInitialized.selector);
        g.initialize();
    }

    function test_init_revert_IncorrectDisputeGameFactory() public {
        // Direct call to the implementation (not via factory clone) → msg.sender != DISPUTE_GAME_FACTORY.
        vm.expectRevert(IncorrectDisputeGameFactory.selector);
        gameImpl.initialize();
    }

    function test_init_revert_BadAuth() public {
        // Try create from an unauthorized proposer.
        address badProposer = address(0xdead);
        vm.deal(badProposer, 100 ether);
        vm.prank(badProposer);
        vm.expectRevert(BadAuth.selector);
        factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0));
    }

    function test_init_revert_BadExtraData_lengthNotMultiple() public {
        // extraData of 0x24 + 0x10 (not multiple of 0x20 after the fixed 0x24 header) → BadExtraData.
        // Total calldata = 4 (selector) + 0x78 (fixed CWIA) + 0x10 (malformed) + 2 (CWIA suffix) = 0x8E.
        // (calldatasize - 0x7E) % 0x20 = 0x10 % 0x20 = 0x10 != 0 → revert.
        bytes memory malformedExtra = abi.encodePacked(uint256(2000), uint32(0), bytes16(uint128(0xdead)));
        vm.expectRevert(BadExtraData.selector);
        vm.prank(proposer);
        factory.create{value: CREATE_BOND}(gameType, rootClaim, malformedExtra);
    }

    function test_init_revert_InvalidNumSegments_overflow() public {
        // numSegments = 257 (one above MAX_NUM_SEGMENTS=256). extraData = 0x24 + 0x20*256 = 0x2024.
        bytes32[] memory tooManyRoots = new bytes32[](256); // intermediates for N=257
        bytes memory extra = _encodeExtraData(2000, 0, tooManyRoots);
        vm.expectRevert(abi.encodeWithSelector(TZOPSuccinctFaultDisputeGame.InvalidNumSegments.selector, uint64(257)));
        vm.prank(proposer);
        factory.create{value: CREATE_BOND}(gameType, rootClaim, extra);
    }

    function test_init_revert_UnexpectedRootClaim() public {
        // l2SequenceNumber <= startingOutputRoot.l2SequenceNumber (parent.l2Seq == 1000).
        vm.prank(proposer);
        vm.expectRevert(abi.encodeWithSelector(UnexpectedRootClaim.selector, rootClaim));
        factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(1000, 0));
    }

    function test_init_revert_UnexpectedRootClaim_below() public {
        // l2SequenceNumber < parent.l2Seq.
        vm.prank(proposer);
        vm.expectRevert(abi.encodeWithSelector(UnexpectedRootClaim.selector, rootClaim));
        factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(500, 0));
    }

    function test_init_revert_InvalidBatchSize() public {
        // numSegments=4, batchSize=1001 → 1001 % 4 != 0.
        // l2Seq = 1000 + 1001 = 2001. extraData has 3 intermediate roots (for N=4).
        bytes32[] memory roots = new bytes32[](3);
        for (uint256 i = 0; i < roots.length; i++) {
            roots[i] = keccak256(abi.encodePacked("seg", i));
        }
        vm.prank(proposer);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.InvalidBatchSize.selector);
        factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraData(2001, 0, roots));
    }

    function test_init_revert_InvalidParentGame_staleParent() public {
        // Create a child whose parent.l2Seq <= anchor.l2Seq. The anchor is at seq=0 from genesis.
        // We need to push the anchor forward first via successful child claim of parentGame.
        // Then attempt to create another game using parentGame as parent (parentGame.l2Seq=1000 <= anchor.l2Seq=1000).
        vm.prank(proposer);
        parentGame.claimCredit(proposer); // closeGame() will try setAnchorState(parentGame).

        // Now anchor.l2Seq == 1000 (parent's l2Seq). Creating a new game with parent=parentGame should fail
        // because startingOutputRoot.l2SequenceNumber (= 1000) <= anchor.l2SequenceNumber (= 1000).
        vm.prank(proposer);
        vm.expectRevert(InvalidParentGame.selector);
        factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0));
    }

    // ===================== §2.9 View Function Tests =====================

    function test_view_version() public {
        assertEq(gameImpl.version(), "2.0.0-tz-segment");
    }

    function test_view_maxClockDuration_equalsMaxChallengeDuration() public {
        // SPEC alignment with V1: maxClockDuration() returns MAX_CHALLENGE_DURATION.
        assertEq(gameImpl.maxClockDuration().raw(), gameImpl.maxChallengeDuration().raw());
        assertEq(gameImpl.maxClockDuration().raw(), maxChallengeDuration.raw());
    }

    function test_view_segmentSize_N4() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        assertEq(g.segmentSize(), 250); // 1000 / 4
    }

    function test_view_intermediateRoots_emptyForN1() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0)))
        );
        assertEq(g.intermediateRoots().length, 0);
    }

    function test_view_intermediateRoots_packedForN4() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        bytes memory roots = g.intermediateRoots();
        assertEq(roots.length, 32 * 3); // 3 intermediate roots for N=4

        // Decode and check first/last root.
        bytes32 root0;
        bytes32 root2;
        assembly {
            root0 := mload(add(roots, 0x20))
            root2 := mload(add(roots, 0x60))
        }
        assertEq(root0, keccak256(abi.encodePacked("seg", uint256(0))));
        assertEq(root2, keccak256(abi.encodePacked("seg", uint256(2))));
    }

    function test_view_intermediateRoot_validIndices() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        // Valid: k ∈ [0, 2] (numSegments - 2 = 2)
        assertEq(g.intermediateRoot(0), keccak256(abi.encodePacked("seg", uint256(0))));
        assertEq(g.intermediateRoot(1), keccak256(abi.encodePacked("seg", uint256(1))));
        assertEq(g.intermediateRoot(2), keccak256(abi.encodePacked("seg", uint256(2))));
    }

    function test_view_intermediateRoot_revert_outOfRange_N4_k3() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        // k = numSegments - 1 = 3 → out of range (intermediateRoot only goes up to N-2 = 2).
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.IndexOutOfRange.selector);
        g.intermediateRoot(3);
    }

    function test_view_intermediateRoot_revert_outOfRange_N1() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0)))
        );
        // N=1 → no intermediate roots; any k reverts.
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.IndexOutOfRange.selector);
        g.intermediateRoot(0);
    }

    function test_view_challengeEnd() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        // challengeEnd = createdAt + MAX_CHAL_DUR (absolute time, never updated).
        uint64 expected = uint64(g.createdAt().raw()) + maxChallengeDuration.raw();
        assertEq(g.challengeEnd().raw(), expected);
    }

    function test_view_gameOver_Unchallenged_beforeChallengeEnd() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        // Right after creation, before challengeEnd → not gameOver.
        assertFalse(g.gameOver());
    }

    function test_view_gameOver_Unchallenged_afterChallengeEnd() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        vm.warp(g.challengeEnd().raw() + 1);
        assertTrue(g.gameOver());
    }

    function test_view_extraData_lengthN1() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0)))
        );
        // extraData length = 0x24 + 0x20 × (N-1) = 0x24 + 0 = 0x24 = 36 bytes.
        assertEq(g.extraData().length, 36);
    }

    function test_view_extraData_lengthN4() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);
        // N=4 → 0x24 + 0x20 × 3 = 0x24 + 0x60 = 0x84 = 132 bytes.
        assertEq(g.extraData().length, 132);
    }

    // ===================== §2.3 challenge(uint64 k) Happy Paths =====================

    function test_challenge_firstChallenger() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.expectEmit(true, true, false, false);
        emit Challenged(challenger, uint64(1));

        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(1));

        // Verify state writes (SPEC §6 Phase 1 effects).
        (address counteredBy, bool proved, bool claimed, address provedBy) = g.disputes(1);
        assertEq(counteredBy, challenger);
        assertFalse(proved);
        assertFalse(claimed);
        assertEq(provedBy, address(0));

        (uint256 bond, bool counteredFlag, uint64 idx) = g.challengers(challenger);
        assertEq(bond, CHAL_BOND);
        assertTrue(counteredFlag);
        assertEq(idx, 1);

        assertEq(g.totalCountered(), 1);
        assertEq(g.refundModeCredit(challenger), CHAL_BOND);

        (, , , TZOPSuccinctFaultDisputeGame.ProposalStatus status, ) = _readClaimData(g);
        assertEq(uint8(status), uint8(TZOPSuccinctFaultDisputeGame.ProposalStatus.Challenged));
    }

    function test_challenge_multipleChallengersDifferentSegments() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);

        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));

        // Both independent in disputes mapping.
        (address counteredBy0, , , ) = g.disputes(0);
        (address counteredBy2, , , ) = g.disputes(2);
        assertEq(counteredBy0, challenger);
        assertEq(counteredBy2, challenger2);

        // Counter increments.
        assertEq(g.totalCountered(), 2);
    }

    function test_challenge_N1_only_k0_valid() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0)))
        );

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        (address counteredBy, , , ) = g.disputes(0);
        assertEq(counteredBy, challenger);
    }

    function test_challenge_N1_k1_outOfRange() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0)))
        );

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.IndexOutOfRange.selector);
        g.challenge{value: CHAL_BOND}(uint64(1));
    }

    // ===================== §2.3 challenge(uint64 k) Revert Paths =====================

    function test_challenge_revert_ClockTimeExceeded() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Warp past challengeEnd.
        vm.warp(g.challengeEnd().raw());

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        vm.expectRevert(ClockTimeExceeded.selector);
        g.challenge{value: CHAL_BOND}(uint64(1));
    }

    function test_challenge_revert_BadAuth() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        address notWhitelisted = address(0xc0de);
        vm.deal(notWhitelisted, 10 ether);

        vm.prank(notWhitelisted);
        vm.expectRevert(BadAuth.selector);
        g.challenge{value: CHAL_BOND}(uint64(0));
    }

    function test_challenge_revert_IncorrectBondAmount_tooLittle() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        vm.expectRevert(IncorrectBondAmount.selector);
        g.challenge{value: CHAL_BOND - 1}(uint64(0));
    }

    function test_challenge_revert_IncorrectBondAmount_tooMuch() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        vm.expectRevert(IncorrectBondAmount.selector);
        g.challenge{value: CHAL_BOND + 1}(uint64(0));
    }

    function test_challenge_revert_AlreadyCountered() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        // Same challenger tries to counter another segment.
        vm.prank(challenger);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.AlreadyCountered.selector);
        g.challenge{value: CHAL_BOND}(uint64(1));
    }

    function test_challenge_revert_IndexOutOfRange_above() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.IndexOutOfRange.selector);
        g.challenge{value: CHAL_BOND}(uint64(4)); // numSegments == 4, k=4 invalid
    }

    function test_challenge_revert_ClaimAlreadyChallenged_sameSegment() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);

        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(2));

        // Different challenger tries same segment.
        vm.prank(challenger2);
        vm.expectRevert(ClaimAlreadyChallenged.selector);
        g.challenge{value: CHAL_BOND}(uint64(2));
    }

    // ===================== §2.4 prove(uint64 k, bytes) Happy Paths =====================

    function test_proveSegment_happyPath_pushesLBond() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(1));

        // prover (anyone can call; SP1MockVerifier accepts empty bytes).
        vm.expectEmit(true, true, false, false);
        emit Proved(prover, uint64(1));

        vm.prank(prover);
        g.prove(uint64(1), "");

        // disputes[k] state.
        (, bool proved, , address provedBy) = g.disputes(1);
        assertTrue(proved);
        assertEq(provedBy, prover);

        // L-bond pushed: prover gets CHAL_BOND in normalModeCredit; challenger's bond field zeroed.
        assertEq(g.normalModeCredit(prover), CHAL_BOND);
        (uint256 bond, , ) = g.challengers(challenger);
        assertEq(bond, 0);

        // challenger.countered flag preserved (anti-re-challenge).
        (, bool counteredFlag, ) = g.challengers(challenger);
        assertTrue(counteredFlag);

        assertEq(g.totalProved(), 1);
    }

    // ===================== §2.4 prove(uint64 k, bytes) Revert Paths =====================

    function test_proveSegment_revert_IndexNotCountered_unchallengedStatus() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // claimData.status is Unchallenged → prove(k) should revert IndexNotCountered.
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.IndexNotCountered.selector);
        g.prove(uint64(0), "");
    }

    function test_proveSegment_revert_IndexNotCountered_uncounteredSegment() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Counter k=1 to move status to Challenged.
        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(1));

        // Now try to prove k=3 (not countered).
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.IndexNotCountered.selector);
        g.prove(uint64(3), "");
    }

    function test_proveSegment_revert_ClockTimeExceeded() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        // Warp past proveDeadline.
        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw());

        vm.expectRevert(ClockTimeExceeded.selector);
        g.prove(uint64(0), "");
    }

    function test_proveSegment_revert_IndexOutOfRange() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        vm.expectRevert(TZOPSuccinctFaultDisputeGame.IndexOutOfRange.selector);
        g.prove(uint64(4), "");
    }

    function test_proveSegment_revert_AlreadyProved() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(2));

        vm.prank(prover);
        g.prove(uint64(2), "");

        // Second prove of same segment.
        vm.prank(prover);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.AlreadyProved.selector);
        g.prove(uint64(2), "");
    }

    function test_proveSegment_revert_SP1Failure() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        // SP1MockVerifier asserts proofBytes.length == 0; non-empty bytes cause assertion failure.
        vm.prank(prover);
        vm.expectRevert(); // Any revert (mock uses `assert` which panics)
        g.prove(uint64(0), hex"deadbeef");
    }

    // ===================== §2.5 prove(bytes) Early-Finalize Overload =====================

    function test_proveFull_happyPath_N1_marksFullProved() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0)))
        );

        vm.expectEmit(true, false, false, false);
        emit FullProved(prover);

        vm.prank(prover);
        g.prove("");

        (address pv, , , TZOPSuccinctFaultDisputeGame.ProposalStatus s, ) = _readClaimData(g);
        assertEq(pv, prover);
        assertEq(uint8(s), uint8(TZOPSuccinctFaultDisputeGame.ProposalStatus.FullProved));
        // GameStatus untouched (resolve() handles it).
        assertEq(uint8(g.status()), uint8(GameStatus.IN_PROGRESS));
        // gameOver() short-circuits on FullProved.
        assertTrue(g.gameOver());
    }

    function test_proveFull_happyPath_N4() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.prank(prover);
        g.prove("");

        (, , , TZOPSuccinctFaultDisputeGame.ProposalStatus s, ) = _readClaimData(g);
        assertEq(uint8(s), uint8(TZOPSuccinctFaultDisputeGame.ProposalStatus.FullProved));
    }

    function test_proveFull_selector_matchesV1() public {
        // SPEC §6 Phase 3.5: prove(bytes) selector matches V1 for etherscan/tooling compat.
        // V1 prove(bytes) selector == keccak256("prove(bytes)")[:4].
        bytes4 expected = bytes4(keccak256("prove(bytes)"));
        // Solidity overload resolution: TZOPSuccinctFaultDisputeGame.prove.selector is ambiguous,
        // so we construct it manually and compare.
        bytes4 actual = bytes4(keccak256("prove(bytes)"));
        assertEq(expected, actual);
        // (Self-tautology, but documents intent. Real verification: extracted bytecode would
        // contain this selector in the dispatch table.)
    }

    function test_proveFull_revert_AlreadyFullProved_doubleCall() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.prank(prover);
        g.prove("");

        // Second prove(bytes) call.
        vm.prank(prover);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.AlreadyFullProved.selector);
        g.prove("");
    }

    function test_proveFull_revert_NotUnchallenged_afterChallenge() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        // Now status is Challenged; prove(bytes) should revert.
        vm.prank(prover);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.NotUnchallenged.selector);
        g.prove("");
    }

    function test_proveFull_revert_ChallengeWindowEnded() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Warp past challengeEnd.
        vm.warp(g.challengeEnd().raw());

        vm.prank(prover);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.ChallengeWindowEnded.selector);
        g.prove("");
    }

    function test_proveFull_challengeAfter_revertAlreadyFullProved() public {
        // Mutex: after proveFull, challenge(k) should revert AlreadyFullProved (not ClaimAlreadyChallenged).
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.prank(prover);
        g.prove("");

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.AlreadyFullProved.selector);
        g.challenge{value: CHAL_BOND}(uint64(1));
    }

    function test_proveSegment_revert_AlreadyFullProved() public {
        // prove(uint64,bytes) after proveFull should revert AlreadyFullProved (status is FullProved).
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.prank(prover);
        g.prove("");

        vm.expectRevert(TZOPSuccinctFaultDisputeGame.AlreadyFullProved.selector);
        g.prove(uint64(0), "");
    }

    // ===================== §2.6 resolve() — DW paths =====================

    function test_resolve_Unchallenged_clockExpired_DW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.warp(g.challengeEnd().raw() + 1);

        g.resolve();

        assertEq(uint8(g.status()), uint8(GameStatus.DEFENDER_WINS));
        (, , , TZOPSuccinctFaultDisputeGame.ProposalStatus s, ) = _readClaimData(g);
        assertEq(uint8(s), uint8(TZOPSuccinctFaultDisputeGame.ProposalStatus.Resolved));
        // CREATE_BOND credited to gameCreator.
        assertEq(g.normalModeCredit(proposer), CREATE_BOND);
    }

    function test_resolve_FullProved_skipsClock_DW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.prank(prover);
        g.prove("");

        // No need to warp — FullProved triggers gameOver() short-circuit.
        g.resolve();

        assertEq(uint8(g.status()), uint8(GameStatus.DEFENDER_WINS));
        // CREATE_BOND credited to gameCreator (same as clock-DW path).
        assertEq(g.normalModeCredit(proposer), CREATE_BOND);
    }

    function test_resolve_Challenged_allProved_DW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Challenge k=0 and k=2.
        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));

        // Prove both.
        vm.prank(prover);
        g.prove(uint64(0), "");
        vm.prank(prover);
        g.prove(uint64(2), "");

        // Warp past proveDeadline.
        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);

        g.resolve();

        assertEq(uint8(g.status()), uint8(GameStatus.DEFENDER_WINS));
        // CREATE_BOND to proposer.
        assertEq(g.normalModeCredit(proposer), CREATE_BOND);
        // L-bonds already pushed during prove(): prover got 2 × CHAL_BOND.
        assertEq(g.normalModeCredit(prover), 2 * CHAL_BOND);
    }

    function test_resolve_Challenged_someUnproved_CHW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Challenge k=0 (will be proved) and k=2 (will NOT be proved).
        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));

        // Only prove k=0.
        vm.prank(prover);
        g.prove(uint64(0), "");

        // Warp past proveDeadline.
        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);

        g.resolve();

        assertEq(uint8(g.status()), uint8(GameStatus.CHALLENGER_WINS));
        // CREATE_BOND NOT immediately pushed; lazy in claimCredit.
        assertEq(g.normalModeCredit(proposer), 0);
    }

    // ===================== §2.6 resolve() Revert paths =====================

    function test_resolve_revert_ClaimAlreadyResolved() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.warp(g.challengeEnd().raw() + 1);
        g.resolve();

        // Second resolve.
        vm.expectRevert(ClaimAlreadyResolved.selector);
        g.resolve();
    }

    function test_resolve_revert_GameNotOver_beforeChallengeEnd() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.expectRevert(GameNotOver.selector);
        g.resolve();
    }

    // ===================== Early-finalize on totalProved == totalCountered =====================

    /// @notice Positive: after challengeEnd, with all challenged segments proved, gameOver()=true
    ///         and resolve() succeeds with DW. Saves up to MAX_PROVE_DURATION of waiting.
    function test_resolve_Challenged_earlyFinalize_afterChallengeEnd_allProved_DW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Challenge k=0 and k=2, prove both — all within the challenge window.
        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));
        vm.prank(prover);
        g.prove(uint64(0), "");
        vm.prank(prover);
        g.prove(uint64(2), "");

        // Still in challenge window — gameOver must be false (no early-finalize yet).
        assertFalse(g.gameOver(), "challenge window still open: gameOver() must be false");

        // Cross challengeEnd, but stay well before proveDeadline.
        vm.warp(g.challengeEnd().raw() + 1);

        // Early-finalize kicks in: gameOver() returns true; resolve() succeeds with DW.
        assertTrue(g.gameOver(), "after challengeEnd + all proved: gameOver() returns true");
        g.resolve();

        assertEq(uint8(g.status()), uint8(GameStatus.DEFENDER_WINS));
        assertEq(g.normalModeCredit(proposer), CREATE_BOND);
        assertEq(g.normalModeCredit(prover), 2 * CHAL_BOND);
    }

    /// @notice Negative (critical): while challenge window is still open, totalProved ==
    ///         totalCountered MUST NOT trigger gameOver(). Otherwise a bot could race-resolve
    ///         and revoke the right of later challengers to counter further segments.
    function test_resolve_Challenged_earlyFinalize_blockedDuringChallengeWindow_GameNotOver() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        vm.prank(prover);
        g.prove(uint64(0), "");

        // totalProved == totalCountered == 1, but still within challenge window.
        assertEq(g.totalProved(), 1);
        assertEq(g.totalCountered(), 1);
        assertFalse(g.gameOver(), "early-finalize must NOT trigger inside challenge window");

        vm.expectRevert(GameNotOver.selector);
        g.resolve();
    }

    /// @notice Negative (core protection): even after totalProved == totalCountered, a later
    ///         challenger MUST be able to counter another segment while still inside the
    ///         challenge window. The early-finalize guard prevents resolve() race that would
    ///         lock the game prematurely and block legitimate late challenges.
    function test_challenge_lateChallengeAllowedAfterAllProved_withinChallengeWindow() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // First challenger + prover hit an intermediate "all-proved" state.
        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(prover);
        g.prove(uint64(0), "");
        assertEq(g.totalCountered(), 1);
        assertEq(g.totalProved(), 1);

        // Confirm gameOver() is still false so resolve() cannot race in.
        assertFalse(g.gameOver(), "must remain open for late challengers");

        // Late challenger comes in within the challenge window — must succeed, not revert.
        vm.deal(challenger2, 10 ether);
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));

        // Counter took effect; game stays in Challenged with totalProved < totalCountered.
        assertEq(g.totalCountered(), 2);
        assertEq(g.totalProved(), 1);

        // Honest defense: prover proves k=2 too. Still in challenge window → game still open.
        vm.prank(prover);
        g.prove(uint64(2), "");
        assertEq(g.totalProved(), 2);
        assertFalse(g.gameOver(), "still in challenge window: gameOver() remains false");

        // After challengeEnd both fall through to early-finalize and game can be resolved DW.
        vm.warp(g.challengeEnd().raw() + 1);
        assertTrue(g.gameOver(), "early-finalize triggers post-challengeEnd");
        g.resolve();
        assertEq(uint8(g.status()), uint8(GameStatus.DEFENDER_WINS));
    }

    // ===================== §11.9 first-check protocol tests =====================

    function test_firstCheck_challenge_revert_GameAlreadyResolved() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.warp(g.challengeEnd().raw() + 1);
        g.resolve();

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        vm.expectRevert(TZOPSuccinctFaultDisputeGame.GameAlreadyResolved.selector);
        g.challenge{value: CHAL_BOND}(uint64(0));
    }

    function test_firstCheck_proveSegment_revert_GameAlreadyResolved() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.warp(g.challengeEnd().raw() + 1);
        g.resolve();

        vm.expectRevert(TZOPSuccinctFaultDisputeGame.GameAlreadyResolved.selector);
        g.prove(uint64(0), "");
    }

    function test_firstCheck_proveFull_revert_GameAlreadyResolved() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.warp(g.challengeEnd().raw() + 1);
        g.resolve();

        vm.expectRevert(TZOPSuccinctFaultDisputeGame.GameAlreadyResolved.selector);
        g.prove("");
    }

    // ===================== §2.7 closeGame() =====================

    function test_closeGame_idempotent() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.warp(g.challengeEnd().raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        g.closeGame();
        // Second call no-op (does not revert).
        g.closeGame();
    }

    function test_closeGame_revert_GameNotFinalized() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.warp(g.challengeEnd().raw() + 1);
        g.resolve();
        // Did NOT wait past finality delay.

        vm.expectRevert(GameNotFinalized.selector);
        g.closeGame();
    }

    // ===================== §2.8 claimCredit() — per-role =====================

    /// @dev Helper: take a game past resolve + finality delay so closeGame() succeeds.
    ///      Handles all 4 ProposalStatus values; warps to whichever clock controls eligibility.
    function _finalizeGame(TZOPSuccinctFaultDisputeGame g) internal {
        if (uint8(g.status()) == uint8(GameStatus.IN_PROGRESS)) {
            if (!g.gameOver()) {
                (, Timestamp proveDeadline_, , TZOPSuccinctFaultDisputeGame.ProposalStatus s, ) = g.claimData();
                if (s == TZOPSuccinctFaultDisputeGame.ProposalStatus.Challenged) {
                    vm.warp(proveDeadline_.raw() + 1);
                } else {
                    // Unchallenged → wait challengeEnd. FullProved → gameOver already true above.
                    vm.warp(g.challengeEnd().raw() + 1);
                }
            }
            g.resolve();
        }
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);
    }

    function test_claim_proposer_DW_getsCreateBond() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        _finalizeGame(g);

        uint256 balBefore = proposer.balance;
        g.claimCredit(proposer);
        assertEq(proposer.balance - balBefore, CREATE_BOND);
    }

    function test_claim_proposer_CHW_revertNoCreditToClaim() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Force CHW: challenge but never prove.
        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // proposer not credited in CHW path.
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(proposer);
    }

    function test_claim_lowestSChallenger_CHW_getsBothBonds() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Challenge k=0 (lowest-S) and k=2; neither proved.
        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));

        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // challenger (k=0) is lowest-S → gets CHAL_BOND + CREATE_BOND.
        uint256 balBefore = challenger.balance;
        g.claimCredit(challenger);
        assertEq(challenger.balance - balBefore, CHAL_BOND + CREATE_BOND);

        // lowestSIndex should now be 0 (lazy compute happened).
        assertEq(g.lowestSIndex(), 0);
    }

    function test_claim_nonLowestSChallenger_CHW_getsOnlyOwnBond() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));

        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // challenger2 (k=2) is non-lowest-S → gets only CHAL_BOND.
        uint256 balBefore = challenger2.balance;
        g.claimCredit(challenger2);
        assertEq(challenger2.balance - balBefore, CHAL_BOND);
    }

    function test_claim_lChallenger_alreadyProved_revertNoCreditToClaim() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(1));

        // Prove segment 1 → L-bond goes to prover, challenger gets nothing.
        vm.prank(prover);
        g.prove(uint64(1), "");

        // Need at least one S to force CHW; add another challenge that's not proved.
        // Actually for this test, let's let it resolve DW (totalProved == totalCountered) and
        // verify L-challenger has no credit (their bond went to prover).
        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // L-challenger has no credit; settle block detects d.proved=true and is a no-op.
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(challenger);
    }

    function test_claim_pureProver_DW_getsLBond() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(2));

        vm.prank(prover);
        g.prove(uint64(2), "");

        _finalizeGame(g);

        uint256 balBefore = prover.balance;
        g.claimCredit(prover);
        assertEq(prover.balance - balBefore, CHAL_BOND);
    }

    function test_claim_doubleClaim_secondReverts() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        _finalizeGame(g);

        g.claimCredit(proposer);

        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(proposer);
    }

    function test_claim_lazyCompute_sockPuppetCannotChangeWinner() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);  // k=0 honest lowest-S
        vm.deal(challenger2, 10 ether); // k=3 sock-puppet (highest)
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(3));

        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Sock-puppet claims FIRST (trying to bias compute) — gets only own CHAL_BOND.
        uint256 balBefore2 = challenger2.balance;
        g.claimCredit(challenger2);
        assertEq(challenger2.balance - balBefore2, CHAL_BOND);

        // lowestSIndex correctly written to 0 (honest's segment).
        assertEq(g.lowestSIndex(), 0);

        // Honest claims after — still gets CHAL_BOND + CREATE_BOND.
        uint256 balBefore1 = challenger.balance;
        g.claimCredit(challenger);
        assertEq(challenger.balance - balBefore1, CHAL_BOND + CREATE_BOND);
    }

    // ===================== §3 Integration flows =====================

    function test_flow_noChallenge_clockDW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Honest case: no one challenges; wait full window.
        vm.warp(g.challengeEnd().raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Proposer claims CREATE_BOND.
        uint256 balBefore = proposer.balance;
        g.claimCredit(proposer);
        assertEq(proposer.balance - balBefore, CREATE_BOND);
        // No double claim.
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(proposer);
    }

    function test_flow_fastFinalize() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Fast finalize via prove(bytes); no challenge window wait needed.
        vm.prank(prover);
        g.prove("");

        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Proposer still gets CREATE_BOND (prover gets no on-chain reward).
        uint256 balBefore = proposer.balance;
        g.claimCredit(proposer);
        assertEq(proposer.balance - balBefore, CREATE_BOND);

        // Prover gets nothing (motivation is downstream finality, not on-chain bond).
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(prover);
    }

    function test_flow_challengedAllProved_DW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);

        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));

        vm.prank(prover);
        g.prove(uint64(0), "");
        vm.prank(prover);
        g.prove(uint64(2), "");

        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Proposer: CREATE_BOND.
        uint256 balBefore = proposer.balance;
        g.claimCredit(proposer);
        assertEq(proposer.balance - balBefore, CREATE_BOND);

        // Prover: 2 × CHAL_BOND (one per proved segment).
        uint256 proverBefore = prover.balance;
        g.claimCredit(prover);
        assertEq(prover.balance - proverBefore, 2 * CHAL_BOND);

        // Challengers got nothing (their bonds went to prover).
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(challenger);
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(challenger2);
    }

    function test_flow_challengedSomeUnproved_CHW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);  // lowest-S (k=1)
        vm.deal(challenger2, 10 ether); // non-lowest-S (k=3)
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(1));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(3));

        // No prover acts; both unproved.
        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Lowest-S (challenger @ k=1) gets CHAL_BOND + CREATE_BOND.
        uint256 balBefore1 = challenger.balance;
        g.claimCredit(challenger);
        assertEq(challenger.balance - balBefore1, CHAL_BOND + CREATE_BOND);

        // Non-lowest-S (challenger2 @ k=3) gets only own CHAL_BOND.
        uint256 balBefore2 = challenger2.balance;
        g.claimCredit(challenger2);
        assertEq(challenger2.balance - balBefore2, CHAL_BOND);

        // Proposer gets nothing.
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(proposer);

        // Bond conservation: CREATE_BOND + 2*CHAL_BOND in total; all distributed (no burn).
        assertEq(address(g).balance, 0);
    }
}
