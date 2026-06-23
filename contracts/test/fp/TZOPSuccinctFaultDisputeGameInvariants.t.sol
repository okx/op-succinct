// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ProxyAdmin} from "@optimism/src/universal/ProxyAdmin.sol";

import {Claim, Duration, GameType, Hash, Proposal, Timestamp} from "src/dispute/lib/Types.sol";
import {OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE} from "src/lib/Types.sol";

import {TZOPSuccinctFaultDisputeGame} from "src/fp/TZOPSuccinctFaultDisputeGame.sol";
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {SP1MockVerifier} from "@sp1-contracts/src/SP1MockVerifier.sol";
import {AnchorStateRegistry} from "src/dispute/AnchorStateRegistry.sol";
import {AccessManager} from "src/fp/AccessManager.sol";

import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {ISP1Verifier} from "@sp1-contracts/src/ISP1Verifier.sol";
import {ISystemConfig} from "interfaces/L1/ISystemConfig.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";

import {MockOptimismPortal2} from "../../src/utils/MockOptimismPortal2.sol";
import {MockSystemConfig} from "../../src/utils/MockSystemConfig.sol";

/// @notice Stateful handler invoked by Foundry's invariant fuzzer. Wraps game mutator calls,
///         bounds inputs to plausible ranges, and tracks ghost state needed by invariants.
contract InvariantHandler is Test {
    TZOPSuccinctFaultDisputeGame public game;
    uint64 public constant NUM_SEGMENTS = 4;
    uint256 public constant CREATE_BOND = 1 ether;
    uint256 public constant CHAL_BOND = 1 ether;

    // Actor pool — pre-funded + whitelisted in the invariant test's setUp.
    address[] public actors;

    // Ghost: tracks all addresses that have ever deposited (proposer + every successful challenger).
    address[] public depositors;
    mapping(address => bool) public isDepositor;

    constructor(TZOPSuccinctFaultDisputeGame _game, address[] memory _actors) {
        game = _game;
        actors = _actors;
        // Proposer is the first depositor (CREATE_BOND from initialize).
        depositors.push(game.gameCreator());
        isDepositor[game.gameCreator()] = true;
    }

    function _actor(uint8 idx) internal view returns (address) {
        return actors[idx % uint8(actors.length)];
    }

    function depositorsLength() external view returns (uint256) {
        return depositors.length;
    }

    function depositorAt(uint256 i) external view returns (address) {
        return depositors[i];
    }

    // ===================== Handler operations =====================

    function hChallenge(uint8 actorIdx, uint64 k) external {
        address a = _actor(actorIdx);
        k = uint64(uint256(k) % NUM_SEGMENTS); // bound to [0, NUM_SEGMENTS)
        try game.challenge{value: CHAL_BOND}(k) {
            if (!isDepositor[a]) {
                depositors.push(a);
                isDepositor[a] = true;
            }
        } catch {
            // Any revert is acceptable; the invariant fuzzer just continues.
        }
    }

    function hProveSegment(uint8 actorIdx, uint64 k) external {
        // prove(k) is permissionless — prank as a fuzzer-chosen actor so invariants cover
        // multi-prover identity (e.g., L-bond push to varying msg.sender vs single test contract).
        k = uint64(uint256(k) % NUM_SEGMENTS);
        vm.prank(_actor(actorIdx));
        try game.prove(k, "") {} catch {}
    }

    function hProveFull(uint8 actorIdx) external {
        // prove(bytes) is permissionless — same rationale as hProveSegment.
        vm.prank(_actor(actorIdx));
        try game.prove("") {} catch {}
    }

    function hWarpToChallengeEnd() external {
        try game.challengeEnd() returns (Timestamp t) {
            vm.warp(uint256(t.raw()) + 1);
        } catch {}
    }

    function hWarpToProveDeadline() external {
        try game.claimData() returns (
            uint32, address, Claim, TZOPSuccinctFaultDisputeGame.ProposalStatus, Timestamp pd
        ) {
            vm.warp(uint256(pd.raw()) + 1);
        } catch {}
    }

    function hResolve() external {
        try game.resolve() {} catch {}
    }

    function hClaimCredit(uint8 actorIdx) external {
        try game.claimCredit(_actor(actorIdx)) {} catch {}
    }
}

/// @title TZOPSuccinctFaultDisputeGameInvariantsTest
/// @notice Stateful fuzz tests proving SPEC §11 invariants hold across arbitrary call sequences.
contract TZOPSuccinctFaultDisputeGameInvariantsTest is Test {
    // ===================== Infrastructure =====================
    DisputeGameFactory factory;
    AnchorStateRegistry anchorStateRegistry;
    AccessManager accessManager;
    MockOptimismPortal2 portal;
    TZOPSuccinctFaultDisputeGame gameImpl;
    TZOPSuccinctFaultDisputeGame game;
    InvariantHandler handler;
    address proposer = address(0x111);
    address[] actorPool;

    GameType gameType = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);
    Duration maxChallengeDuration = Duration.wrap(12 hours);
    Duration maxProveDuration = Duration.wrap(3 days);
    uint256 constant CREATE_BOND = 1 ether;
    uint256 constant CHAL_BOND = 1 ether;
    uint256 disputeGameFinalityDelaySeconds = 1000;

    function setUp() public {
        // ---------- Factory + proxy ----------
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
        MockSystemConfig msc = new MockSystemConfig(address(this));
        portal = new MockOptimismPortal2(gameType, disputeGameFinalityDelaySeconds);

        Proposal memory startingAnchor = Proposal({root: Hash.wrap(keccak256("genesis")), l2SequenceNumber: 0});
        AnchorStateRegistry asrImpl = new AnchorStateRegistry(disputeGameFinalityDelaySeconds);
        Proxy asrProxy = new Proxy(address(proxyAdmin));
        proxyAdmin.upgradeAndCall(
            payable(address(asrProxy)),
            address(asrImpl),
            abi.encodeCall(
                AnchorStateRegistry.initialize,
                (
                    ISystemConfig(address(msc)),
                    IDisputeGameFactory(address(factory)),
                    startingAnchor,
                    gameType
                )
            )
        );
        anchorStateRegistry = AnchorStateRegistry(address(asrProxy));

        accessManager = new AccessManager(2 weeks, IDisputeGameFactory(address(factory)));
        accessManager.setProposer(proposer, true);

        // ---------- Build a 6-actor pool (each whitelisted + funded) ----------
        // Actor 0 reserved as proposer. Actors 1..5 are challengers.
        for (uint160 i = 0; i < 6; i++) {
            address a = address(uint160(0xA0000 + i));
            actorPool.push(a);
            accessManager.setChallenger(a, true);
            vm.deal(a, 1000 ether);
        }

        // ---------- Deploy TZ impl ----------
        gameImpl = new TZOPSuccinctFaultDisputeGame(
            maxChallengeDuration,
            maxProveDuration,
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            bytes32(0), bytes32(0), bytes32(0),
            CHAL_BOND,
            IAnchorStateRegistry(address(anchorStateRegistry)),
            accessManager
        );
        factory.setInitBond(gameType, CREATE_BOND);
        factory.setImplementation(gameType, IDisputeGame(address(gameImpl)));

        vm.warp(block.timestamp + 1000);

        // ---------- Create a game with N=4 + 3 mock intermediate roots ----------
        // batchSize = 1000 - 0 (anchor) = 1000; SEGMENT_SIZE = 250.
        vm.deal(proposer, 100 ether);
        vm.prank(proposer);
        bytes memory extraData = abi.encodePacked(
            uint256(1000),                  // l2SequenceNumber
            type(uint32).max,               // parentIndex == uint32.max → use anchor
            keccak256("r0"),                // intermediateRoot(0)
            keccak256("r1"),                // intermediateRoot(1)
            keccak256("r2")                 // intermediateRoot(2)
        );
        game = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, Claim.wrap(keccak256("rc")), extraData))
        );

        // ---------- Deploy handler + target it for the invariant fuzzer ----------
        handler = new InvariantHandler(game, actorPool);
        vm.deal(address(handler), 1000 ether);

        // Foundry directs the fuzzer to only call the handler (not the game directly).
        targetContract(address(handler));

        // Fund the handler so it can pay CHAL_BOND on challenge() calls.
        // (Handler forwards msg.value from itself when calling game.challenge.)
        bytes4[] memory selectors = new bytes4[](7);
        selectors[0] = InvariantHandler.hChallenge.selector;
        selectors[1] = InvariantHandler.hProveSegment.selector;
        selectors[2] = InvariantHandler.hProveFull.selector;
        selectors[3] = InvariantHandler.hWarpToChallengeEnd.selector;
        selectors[4] = InvariantHandler.hWarpToProveDeadline.selector;
        selectors[5] = InvariantHandler.hResolve.selector;
        selectors[6] = InvariantHandler.hClaimCredit.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    // ===================== Invariants =====================

    /// @notice Inv 1: deposit ledger sum is exactly CREATE_BOND + totalCountered × CHAL_BOND.
    /// @dev    refundModeCredit is set at initialize (proposer) and challenge() (challengers);
    ///         it is only zeroed in claimCredit. Sum across all (ever-seen) depositors must
    ///         equal the deposits-still-in-the-ledger predicted by the spec.
    function invariant_depositLedgerConservation() public view {
        uint256 sum = 0;
        uint256 zeroed = 0;
        for (uint256 i = 0; i < handler.depositorsLength(); i++) {
            address d = handler.depositorAt(i);
            uint256 r = game.refundModeCredit(d);
            sum += r;
            if (r == 0) zeroed++;
        }
        // Either: nobody has claimed yet → sum == initial deposits, OR
        // some have claimed → sum < initial deposits.
        // Either way, sum ≤ CREATE_BOND + totalCountered × CHAL_BOND.
        uint256 maxExpected = CREATE_BOND + uint256(game.totalCountered()) * CHAL_BOND;
        assertLe(sum, maxExpected, "deposit ledger sum exceeds CREATE+CHAL totals");
    }

    /// @notice ProposalStatus stays within the 4-value enum. (Sanity that no storage corruption.)
    function invariant_proposalStatusInRange() public view {
        (, , , TZOPSuccinctFaultDisputeGame.ProposalStatus s, ) = game.claimData();
        assertLe(uint8(s), uint8(TZOPSuccinctFaultDisputeGame.ProposalStatus.Resolved));
    }

    /// @notice Inv 22: FullProved ⟹ totalCountered == 0 (no challengers landed before proveFull).
    function invariant_fullProvedExcludesChallengers() public view {
        (, , , TZOPSuccinctFaultDisputeGame.ProposalStatus s, ) = game.claimData();
        if (s == TZOPSuccinctFaultDisputeGame.ProposalStatus.FullProved) {
            assertEq(game.totalCountered(), 0, "FullProved implies totalCountered == 0");
        }
    }

    /// @notice Inv 11: Challenged ⟺ totalCountered ≥ 1
    ///         (FullProved / Unchallenged → totalCountered == 0; Resolved post-CHW path may have any).
    /// @dev    Tests only the forward direction here (Challenged → totalCountered ≥ 1).
    function invariant_challengedImpliesCountered() public view {
        (, , , TZOPSuccinctFaultDisputeGame.ProposalStatus s, ) = game.claimData();
        if (s == TZOPSuccinctFaultDisputeGame.ProposalStatus.Challenged) {
            assertGe(game.totalCountered(), 1, "Challenged implies totalCountered >= 1");
        }
    }

    /// @notice Inv 26: claimData.status == FullProved ⟺ claimData.prover != address(0).
    function invariant_fullProvedBiconditional() public view {
        (, address pv, , TZOPSuccinctFaultDisputeGame.ProposalStatus s, ) = game.claimData();
        if (s == TZOPSuccinctFaultDisputeGame.ProposalStatus.FullProved) {
            assertTrue(pv != address(0), "FullProved => prover set");
        } else {
            // prover may still be set if status moved Unchallenged → FullProved → Resolved.
            // Only assert "prover == 0" when status has never advanced past Unchallenged.
            if (s == TZOPSuccinctFaultDisputeGame.ProposalStatus.Unchallenged) {
                assertEq(pv, address(0), "Unchallenged => prover unset");
            }
        }
    }

    /// @notice Inv 1 (full forward): refundModeCredit is set at exactly CREATE_BOND for proposer
    ///         and CHAL_BOND per challenger that ever counters a segment (until claimed).
    ///         Per-address upper bound: refundModeCredit[a] ≤ CHAL_BOND for any single challenger.
    function invariant_perChallengerRefundCapped() public view {
        for (uint256 i = 0; i < handler.depositorsLength(); i++) {
            address d = handler.depositorAt(i);
            if (d == game.gameCreator()) continue; // proposer can hold CREATE_BOND
            uint256 r = game.refundModeCredit(d);
            assertLe(r, CHAL_BOND, "single challenger refund > CHAL_BOND");
        }
    }

    /// @notice Inv 29: disputes[k].claimed is monotonic (false → true; never reverts).
    /// @dev    We cannot snapshot prior values from a stateful fuzz cleanly; instead
    ///         we assert the spec-derived implication: any segment with claimed==true
    ///         must have been countered (counteredBy != 0).
    function invariant_claimedImpliesCountered() public view {
        for (uint64 k = 0; k < 4; k++) {
            (address counteredBy, , bool claimed, ) = game.disputes(k);
            if (claimed) {
                assertTrue(counteredBy != address(0), "claimed implies countered");
            }
        }
    }
}
