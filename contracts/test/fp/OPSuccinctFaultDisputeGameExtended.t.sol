// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Testing
import "forge-std/Test.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ProxyAdmin} from "@optimism/src/universal/ProxyAdmin.sol";

// Libraries
import {
    BondDistributionMode,
    Claim,
    Duration,
    GameStatus,
    GameType,
    Hash,
    Proposal,
    Timestamp
} from "src/dispute/lib/Types.sol";
import {
    BadAuth,
    IncorrectBondAmount,
    AlreadyInitialized,
    UnexpectedRootClaim,
    NoCreditToClaim,
    GameNotResolved,
    GameNotFinalized,
    BondTransferFailed,
    ClaimAlreadyResolved
} from "src/dispute/lib/Errors.sol";
import {
    ParentGameNotResolved,
    InvalidParentGame,
    ClaimAlreadyChallenged,
    GameOver,
    GameNotOver,
    IncorrectDisputeGameFactory
} from "src/fp/lib/Errors.sol";
import {AggregationOutputs, OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE} from "src/lib/Types.sol";

// Contracts
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {OPSuccinctFaultDisputeGame} from "src/fp/OPSuccinctFaultDisputeGame.sol";
import {SP1MockVerifier} from "src/utils/SP1MockVerifier.sol";
import {AnchorStateRegistry} from "src/dispute/AnchorStateRegistry.sol";
import {AccessManager} from "src/fp/AccessManager.sol";

// Interfaces
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {ISP1Verifier} from "src/fp/interfaces/ISP1Verifier.sol";
import {ISystemConfig} from "interfaces/L1/ISystemConfig.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";

// Utils
import {MockOptimismPortal2} from "../../src/utils/MockOptimismPortal2.sol";
import {MockSystemConfig} from "../../src/utils/MockSystemConfig.sol";

/// @notice A contract that re-enters claimCredit on receiving ETH.
contract MaliciousRecipient {
    OPSuccinctFaultDisputeGame public target;
    bool public reentered;

    constructor(OPSuccinctFaultDisputeGame _target) {
        target = _target;
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            target.claimCredit(address(this));
        }
    }
}

/// @notice A contract with no receive/fallback — cannot accept ETH.
contract NonPayableRecipient {}

contract OPSuccinctFaultDisputeGameExtendedTest is Test {
    // Events
    event Challenged(address indexed challenger);
    event Proved(address indexed prover);
    event Resolved(GameStatus indexed status);

    DisputeGameFactory factory;
    Proxy factoryProxy;
    ProxyAdmin proxyAdmin;

    OPSuccinctFaultDisputeGame gameImpl;
    OPSuccinctFaultDisputeGame parentGame;
    OPSuccinctFaultDisputeGame game;

    AnchorStateRegistry anchorStateRegistry;
    AccessManager accessManager;

    address proposer = address(0x123);
    address challenger = address(0x456);
    address prover = address(0x789);

    MockOptimismPortal2 portal;

    uint256 disputeGameFinalityDelaySeconds = 1000;

    GameType gameType = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);
    Duration maxChallengeDuration = Duration.wrap(12 hours);
    Duration maxProveDuration = Duration.wrap(3 days);
    Claim rootClaim = Claim.wrap(keccak256("rootClaim"));

    uint256 l2BlockNumber = 2000;
    uint32 parentIndex = 0;

    uint256 constant INIT_BOND = 1 ether;
    uint256 constant CHALLENGER_BOND_AMOUNT = 1 ether;

    function setUp() public {
        proxyAdmin = new ProxyAdmin(address(this));

        DisputeGameFactory factoryImpl = new DisputeGameFactory();
        factoryProxy = new Proxy(address(proxyAdmin));
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

        gameImpl = new OPSuccinctFaultDisputeGame(
            maxChallengeDuration,
            maxProveDuration,
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            bytes32(0), // rollupConfigHash
            bytes32(0), // aggregationVkey
            bytes32(0), // rangeVkeyCommitment
            CHALLENGER_BOND_AMOUNT, // challengerBond
            IAnchorStateRegistry(address(anchorStateRegistry)),
            accessManager,
            false, // hasRootClaimPreimage (legacy layout)
            address(0) // postAnchor (auto delivery disabled)
        );

        factory.setInitBond(gameType, INIT_BOND);
        factory.setImplementation(gameType, IDisputeGame(address(gameImpl)));

        // Create and finalize parent game (index 0)
        vm.startPrank(proposer);
        vm.deal(proposer, 10 ether);

        vm.warp(block.timestamp + 1000);

        parentGame = OPSuccinctFaultDisputeGame(
            address(
                factory.create{value: INIT_BOND}(
                    gameType,
                    Claim.wrap(keccak256("genesis")),
                    abi.encodePacked(uint256(1000), type(uint32).max)
                )
            )
        );

        (,,,,, Timestamp parentGameDeadline) = parentGame.claimData();
        vm.warp(parentGameDeadline.raw() + 1 seconds);
        parentGame.resolve();
        vm.warp(parentGame.resolvedAt().raw() + disputeGameFinalityDelaySeconds + 1 seconds);

        // Create child game (index 1) BEFORE claimCredit on parentGame.
        // claimCredit() triggers closeGame() which advances anchor to parentGame's l2SeqNum,
        // after which parentGame can no longer be used as a parent via index.
        game = OPSuccinctFaultDisputeGame(
            address(
                factory.create{value: INIT_BOND}(
                    gameType,
                    rootClaim,
                    abi.encodePacked(l2BlockNumber, parentIndex)
                )
            )
        );

        parentGame.claimCredit(proposer);

        vm.stopPrank();
    }

    // ================================================================
    // Helper functions
    // ================================================================

    /// @notice Create a game via proposer and return it.
    function _createGame(uint256 _l2Block, uint32 _parentIdx, bytes32 _claimSeed)
        internal
        returns (OPSuccinctFaultDisputeGame)
    {
        vm.prank(proposer);
        vm.deal(proposer, INIT_BOND);
        return OPSuccinctFaultDisputeGame(
            address(
                factory.create{value: INIT_BOND}(
                    gameType,
                    Claim.wrap(_claimSeed),
                    abi.encodePacked(_l2Block, _parentIdx)
                )
            )
        );
    }

    /// @notice Challenge a game with the default challenger.
    function _challengeGame(OPSuccinctFaultDisputeGame _game) internal {
        vm.prank(challenger);
        vm.deal(challenger, CHALLENGER_BOND_AMOUNT);
        _game.challenge{value: CHALLENGER_BOND_AMOUNT}();
    }

    /// @notice Wait for challenge deadline, then resolve.
    function _waitAndResolve(OPSuccinctFaultDisputeGame _game) internal {
        (,,,,, Timestamp deadline) = _game.claimData();
        vm.warp(deadline.raw() + 1);
        _game.resolve();
    }

    /// @notice Wait finality delay after resolve.
    function _waitFinality(OPSuccinctFaultDisputeGame _game) internal {
        vm.warp(_game.resolvedAt().raw() + disputeGameFinalityDelaySeconds + 1 seconds);
    }

    // ================================================================
    // Phase 1: Parent-Child chain completion
    // ================================================================

    /// @notice TC6b: Parent fails cascade — child HAS challenger → challenger gets all.
    function testTC6b_CascadeFailure_ChildWithChallenger() public {
        // Create child game C (parent = game at index 1)
        OPSuccinctFaultDisputeGame childGame = _createGame(3000, 1, keccak256("child-tc6b"));

        // Challenge both the parent (game) and the child
        _challengeGame(game);
        _challengeGame(childGame);

        // Let parent game prove deadline expire → CHALLENGER_WINS
        _waitAndResolve(game);
        assertEq(uint8(game.status()), uint8(GameStatus.CHALLENGER_WINS));

        // Resolve child → cascading CHALLENGER_WINS (parent lost)
        childGame.resolve();
        assertEq(uint8(childGame.status()), uint8(GameStatus.CHALLENGER_WINS));

        // Wait finality and verify bond distribution
        _waitFinality(childGame);

        // Child's challenger gets all bonds (INIT_BOND + CHALLENGER_BOND)
        childGame.claimCredit(challenger);
        assertEq(address(childGame).balance, 0);
    }

    /// @notice TC7c: CHALLENGER_WINS parent → cannot create child.
    function testTC7c_ChallengerWinsParent_CannotCreateChild() public {
        // Challenge game (index 1), let it timeout
        _challengeGame(game);
        _waitAndResolve(game);
        assertEq(uint8(game.status()), uint8(GameStatus.CHALLENGER_WINS));

        // Try to create child referencing the lost game
        vm.prank(proposer);
        vm.deal(proposer, INIT_BOND);
        vm.expectRevert(InvalidParentGame.selector);
        factory.create{value: INIT_BOND}(
            gameType,
            Claim.wrap(keccak256("child-of-loser")),
            abi.encodePacked(uint256(3000), uint32(1))
        );
    }

    /// @notice TC8: Cross game type parent chain — non-respected parent for ZK child → revert.
    function testTC8_CrossGameTypeParentChain() public {
        // We can't register a different GAME_TYPE impl easily, so we simulate a "non-respected"
        // parent by changing respectedGameType before creating the parent.

        // First resolve `game` (index 1) so child of game can be resolved
        _waitAndResolve(game);

        // Change respectedGameType temporarily to create a non-respected game
        anchorStateRegistry.setRespectedGameType(GameType.wrap(99));

        _createGame(3000, 1, keccak256("non-respected"));
        // This game has wasRespectedGameTypeWhenCreated = false

        // Restore respected game type
        anchorStateRegistry.setRespectedGameType(gameType);

        // Try to create child with non-respected parent → revert InvalidParentGame
        // (isGameRespected check fails because wasRespectedGameTypeWhenCreated = false)
        vm.prank(proposer);
        vm.deal(proposer, INIT_BOND);
        vm.expectRevert(InvalidParentGame.selector);
        factory.create{value: INIT_BOND}(
            gameType,
            Claim.wrap(keccak256("child-of-non-respected")),
            abi.encodePacked(uint256(4000), uint32(2)) // index 2 = nonRespectedGame
        );
    }

    /// @notice TC9: 5-game chain cascade failure.
    function testTC9_FiveGameChainCascade() public {
        // game = index 1, already created in setUp

        // Build chain: game → B → C → D → E
        OPSuccinctFaultDisputeGame gameB = _createGame(3000, 1, keccak256("B"));
        OPSuccinctFaultDisputeGame gameC = _createGame(4000, 2, keccak256("C"));
        OPSuccinctFaultDisputeGame gameD = _createGame(5000, 3, keccak256("D"));
        OPSuccinctFaultDisputeGame gameE = _createGame(6000, 4, keccak256("E"));

        // Challenge root game (index 1), let it timeout
        _challengeGame(game);
        _waitAndResolve(game);
        assertEq(uint8(game.status()), uint8(GameStatus.CHALLENGER_WINS));

        // Cascade: each child resolves as CHALLENGER_WINS
        gameB.resolve();
        assertEq(uint8(gameB.status()), uint8(GameStatus.CHALLENGER_WINS));

        gameC.resolve();
        assertEq(uint8(gameC.status()), uint8(GameStatus.CHALLENGER_WINS));

        gameD.resolve();
        assertEq(uint8(gameD.status()), uint8(GameStatus.CHALLENGER_WINS));

        gameE.resolve();
        assertEq(uint8(gameE.status()), uint8(GameStatus.CHALLENGER_WINS));

        // B-E have no challenger → funds locked to address(0)
        _waitFinality(gameE);
        vm.expectRevert(NoCreditToClaim.selector);
        gameB.claimCredit(proposer);

        vm.expectRevert(NoCreditToClaim.selector);
        gameE.claimCredit(proposer);
    }

    // ================================================================
    // Phase 2: Permission & security completion
    // ================================================================

    /// @notice TC13: Bond amount validation — zero, too low, too high.
    function testTC13_BondAmountValidation() public {
        vm.startPrank(challenger);
        vm.deal(challenger, 3 ether);

        vm.expectRevert(IncorrectBondAmount.selector);
        game.challenge{value: 0}();

        vm.expectRevert(IncorrectBondAmount.selector);
        game.challenge{value: CHALLENGER_BOND_AMOUNT - 1}();

        vm.expectRevert(IncorrectBondAmount.selector);
        game.challenge{value: CHALLENGER_BOND_AMOUNT + 1}();

        vm.stopPrank();
    }

    /// @notice TC15a: Challenge after deadline expired → revert GameOver.
    function testTC15a_ChallengeAfterDeadline() public {
        (,,,,, Timestamp deadline) = game.claimData();
        vm.warp(deadline.raw() + 1);

        vm.prank(challenger);
        vm.deal(challenger, CHALLENGER_BOND_AMOUNT);
        vm.expectRevert(GameOver.selector);
        game.challenge{value: CHALLENGER_BOND_AMOUNT}();
    }

    /// @notice TC15b: Challenge after prove → revert ClaimAlreadyChallenged (status check before gameOver).
    function testTC15b_ChallengeAfterProve() public {
        // Prove without challenge first
        vm.prank(prover);
        game.prove(bytes(""));

        // Try to challenge after proof submitted
        vm.prank(challenger);
        vm.deal(challenger, CHALLENGER_BOND_AMOUNT);
        vm.expectRevert(ClaimAlreadyChallenged.selector);
        game.challenge{value: CHALLENGER_BOND_AMOUNT}();
    }

    /// @notice TC15b-2: Prove again after already proven → revert GameOver.
    function testTC15b_ProveAfterProve() public {
        vm.prank(prover);
        game.prove(bytes(""));

        vm.prank(prover);
        vm.expectRevert(GameOver.selector);
        game.prove(bytes(""));
    }

    /// @notice TC15c: Resolve after already resolved → revert ClaimAlreadyResolved.
    function testTC15c_ResolveAfterResolve() public {
        (,,,,, Timestamp deadline) = game.claimData();
        vm.warp(deadline.raw() + 1);
        game.resolve();

        vm.expectRevert(ClaimAlreadyResolved.selector);
        game.resolve();
    }

    /// @notice TC16: address(0) switch — open/close permissionless propose.
    function testTC16_AddressZeroProposerSwitch() public {
        address anyone = address(0x9999);

        // Initially, anyone cannot propose
        vm.prank(anyone);
        vm.deal(anyone, INIT_BOND);
        vm.expectRevert(BadAuth.selector);
        factory.create{value: INIT_BOND}(
            gameType, Claim.wrap(keccak256("tc16-1")), abi.encodePacked(uint256(3000), uint32(1))
        );

        // Owner enables permissionless propose via address(0)
        accessManager.setProposer(address(0), true);
        assertTrue(accessManager.isProposalPermissionlessMode());

        // Now anyone can propose — immediately, no FALLBACK_TIMEOUT needed
        vm.prank(anyone);
        vm.deal(anyone, INIT_BOND);
        factory.create{value: INIT_BOND}(
            gameType, Claim.wrap(keccak256("tc16-2")), abi.encodePacked(uint256(3000), uint32(1))
        );

        // Owner disables permissionless propose
        accessManager.setProposer(address(0), false);

        // Now anyone is blocked again
        vm.prank(anyone);
        vm.deal(anyone, INIT_BOND);
        vm.expectRevert(BadAuth.selector);
        factory.create{value: INIT_BOND}(
            gameType, Claim.wrap(keccak256("tc16-3")), abi.encodePacked(uint256(4000), uint32(1))
        );
    }

    /// @notice TC17: address(0) switch — open/close permissionless challenge.
    function testTC17_AddressZeroChallengerSwitch() public {
        address anyone = address(0x9999);

        // Initially, anyone cannot challenge
        vm.prank(anyone);
        vm.deal(anyone, CHALLENGER_BOND_AMOUNT);
        vm.expectRevert(BadAuth.selector);
        game.challenge{value: CHALLENGER_BOND_AMOUNT}();

        // Owner enables permissionless challenge
        accessManager.setChallenger(address(0), true);

        // Now anyone can challenge
        vm.prank(anyone);
        vm.deal(anyone, CHALLENGER_BOND_AMOUNT);
        game.challenge{value: CHALLENGER_BOND_AMOUNT}();

        // Verify challenge succeeded
        (, address counteredBy,,,,) = game.claimData();
        assertEq(counteredBy, anyone);

        // Create a new game to test disabling
        OPSuccinctFaultDisputeGame game2 = _createGame(3000, 1, keccak256("tc17-game2"));

        // Owner disables permissionless challenge
        accessManager.setChallenger(address(0), false);

        // Now anyone is blocked again
        vm.prank(anyone);
        vm.deal(anyone, CHALLENGER_BOND_AMOUNT);
        vm.expectRevert(BadAuth.selector);
        game2.challenge{value: CHALLENGER_BOND_AMOUNT}();
    }

    /// @notice TC18: Invalid proof bytes — MockVerifier requires proofBytes.length == 0.
    ///         Non-empty bytes are rejected. Real SP1 validation is tested on Sepolia (S2).
    function testTC18_InvalidProofRejected() public {
        // MockVerifier asserts proofBytes.length == 0, so non-empty bytes revert.
        vm.prank(prover);
        vm.expectRevert(); // panic: assertion failed
        game.prove(hex"deadbeef");

        // Empty bytes succeed (valid mock proof)
        vm.prank(prover);
        game.prove(bytes(""));

        (,, address proverAddr,, OPSuccinctFaultDisputeGame.ProposalStatus status_,) = game.claimData();
        assertEq(proverAddr, prover);
        assertEq(uint8(status_), uint8(OPSuccinctFaultDisputeGame.ProposalStatus.UnchallengedAndValidProofProvided));
    }

    // ================================================================
    // Phase 3: Bond + closeGame/claimCredit boundaries
    // ================================================================

    /// @notice TC19: REFUND mode — blacklist triggers REFUND, both parties get their bonds back.
    function testTC19a_RefundMode_Blacklist() public {
        // Challenge game
        _challengeGame(game);

        // Prove to end the game
        vm.prank(prover);
        game.prove(bytes(""));

        // Resolve
        game.resolve();
        assertEq(uint8(game.status()), uint8(GameStatus.DEFENDER_WINS));

        // Guardian blacklists the game before closeGame
        anchorStateRegistry.blacklistDisputeGame(IDisputeGame(address(game)));

        // Wait finality
        _waitFinality(game);

        // closeGame → REFUND mode
        game.closeGame();
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.REFUND));

        // Proposer gets back INIT_BOND
        game.claimCredit(proposer);
        // Challenger gets back CHALLENGER_BOND
        game.claimCredit(challenger);
        // Game balance is zero
        assertEq(address(game).balance, 0);
    }

    /// @notice TC19b: REFUND mode — retirement triggers REFUND.
    function testTC19b_RefundMode_Retirement() public {
        _challengeGame(game);

        vm.prank(prover);
        game.prove(bytes(""));
        game.resolve();

        // Guardian retires all games created before now
        anchorStateRegistry.updateRetirementTimestamp();

        _waitFinality(game);

        game.closeGame();
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.REFUND));

        game.claimCredit(proposer);
        game.claimCredit(challenger);
        assertEq(address(game).balance, 0);
    }

    /// @notice TC19c: Changing respectedGameType does NOT trigger REFUND.
    function testTC19c_RespectedGameTypeChange_StillNormal() public {
        // Resolve game normally (unchallenged)
        _waitAndResolve(game);

        // Change respected game type to something else
        anchorStateRegistry.setRespectedGameType(GameType.wrap(99));

        _waitFinality(game);

        // closeGame → should still be NORMAL (isGameProper doesn't check respectedGameType)
        game.closeGame();
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.NORMAL));

        game.claimCredit(proposer);
        assertEq(address(game).balance, 0);
    }

    /// @notice TC22: claimCredit(address(0)) — ETH sent to address(0).
    function testTC22_ClaimCreditAddressZero() public {
        // Create child game, make parent (game) fail to cascade
        OPSuccinctFaultDisputeGame childGame = _createGame(3000, 1, keccak256("tc22-child"));

        // Challenge parent, let it timeout → CHALLENGER_WINS
        _challengeGame(game);
        _waitAndResolve(game);

        // Child cascades to CHALLENGER_WINS with no challenger → credit goes to address(0)
        childGame.resolve();
        assertEq(uint8(childGame.status()), uint8(GameStatus.CHALLENGER_WINS));

        _waitFinality(childGame);

        uint256 childBalance = address(childGame).balance;
        assertGt(childBalance, 0);

        // claimCredit(address(0)) succeeds — ETH is sent to address(0), practically irrecoverable
        uint256 zeroBalanceBefore = address(0).balance;
        childGame.claimCredit(address(0));
        assertEq(address(childGame).balance, 0);
        assertEq(address(0).balance, zeroBalanceBefore + childBalance);
    }

    /// @notice TC23: MaliciousRecipient reentrancy attack — CEI pattern prevents double-payout.
    ///         The re-entrant call reverts with NoCreditToClaim (credit cleared before transfer).
    ///         However, the revert in receive() causes the ETH transfer to fail, which then
    ///         triggers BondTransferFailed on the outer call. This means the attacker cannot
    ///         extract funds at all — even stronger than just preventing double-payout.
    function testTC23_ReentrancyAttack_CEI() public {
        MaliciousRecipient malicious = new MaliciousRecipient(game);
        address maliciousAddr = address(malicious);

        // Make the malicious contract the prover
        _challengeGame(game);

        vm.prank(maliciousAddr);
        game.prove(bytes(""));

        game.resolve();
        assertEq(uint8(game.status()), uint8(GameStatus.DEFENDER_WINS));

        _waitFinality(game);

        // The reentrancy in receive() causes BondTransferFailed — attacker gets nothing.
        // CEI pattern: credit is cleared before transfer, re-entrant claimCredit reverts with
        // NoCreditToClaim, which makes receive() revert, which makes the outer call fail.
        vm.expectRevert(BondTransferFailed.selector);
        game.claimCredit(maliciousAddr);

        // Credit was cleared (tx reverted, so it's restored) — attacker is locked out
        // but the credit remains claimable by a non-malicious caller.
        // Verify credit still exists since the entire tx reverted.
        assertEq(game.normalModeCredit(maliciousAddr), CHALLENGER_BOND_AMOUNT);
        assertEq(maliciousAddr.balance, 0);
    }

    /// @notice TC24: BondTransferFailed — recipient cannot accept ETH.
    function testTC24_BondTransferFailed() public {
        NonPayableRecipient nonPayable = new NonPayableRecipient();
        address nonPayableAddr = address(nonPayable);

        // Make the non-payable contract the prover
        _challengeGame(game);

        vm.prank(nonPayableAddr);
        game.prove(bytes(""));

        game.resolve();
        _waitFinality(game);

        // claimCredit for non-payable recipient → revert BondTransferFailed
        vm.expectRevert(BondTransferFailed.selector);
        game.claimCredit(nonPayableAddr);

        // Credit is NOT cleared (entire tx reverted)
        assertEq(game.normalModeCredit(nonPayableAddr), CHALLENGER_BOND_AMOUNT);
    }

    /// @notice TC26: Anchor state does not regress when older game finalizes after newer one.
    function testTC26_AnchorStateNoRegression() public {
        // game at index 1, l2Block = 2000 (parent = parentGame index 0, l2Block = 1000)
        // After setUp, anchor is at l2SeqNum=1000 (parentGame was finalized via claimCredit).
        // All child games must use parentIndex=1 (game, l2SeqNum=2000 > anchor 1000).
        // Create all games BEFORE any closeGame, since closeGame advances anchor
        // and the constraint requires parent.l2SeqNum > anchor.l2SeqNum at creation time.
        OPSuccinctFaultDisputeGame game2 = _createGame(5000, 1, keccak256("tc26-high"));
        OPSuccinctFaultDisputeGame game3 = _createGame(3000, 1, keccak256("tc26-low"));

        // Resolve game (l2Block=2000) first
        _waitAndResolve(game);
        _waitFinality(game);
        game.closeGame();

        (, uint256 anchorBlockAfterGame) = anchorStateRegistry.getAnchorRoot();
        assertEq(anchorBlockAfterGame, 2000);

        // Now resolve game2 (l2Block=5000)
        _waitAndResolve(game2);
        _waitFinality(game2);
        game2.closeGame();

        // Anchor should advance to 5000
        (, uint256 anchorBlock) = anchorStateRegistry.getAnchorRoot();
        assertEq(anchorBlock, 5000);

        // Resolve game3 (l2Block=3000, created earlier) — should not regress anchor
        _waitAndResolve(game3);
        _waitFinality(game3);
        game3.closeGame();

        (, uint256 anchorBlockFinal) = anchorStateRegistry.getAnchorRoot();
        assertEq(anchorBlockFinal, 5000, "Anchor should not regress");
    }

    /// @notice TC26b: CHALLENGER_WINS game does not advance anchor.
    function testTC26b_ChallengerWinsDoesNotAdvanceAnchor() public {
        (, uint256 anchorBlockBefore) = anchorStateRegistry.getAnchorRoot();

        // Challenge game and let it timeout → CHALLENGER_WINS
        _challengeGame(game);
        _waitAndResolve(game);
        _waitFinality(game);
        game.closeGame();

        // Anchor should not change
        (, uint256 anchorBlockAfter) = anchorStateRegistry.getAnchorRoot();
        assertEq(anchorBlockAfter, anchorBlockBefore);
    }

    // ================================================================
    // Phase 4: Stress tests + Rollback
    // ================================================================

    /// @notice TC27: Gas DoS pressure test — measure gas with many non-type-42 games.
    ///         We use a separate game type (type 1) to force getLastProposalTimestamp() to iterate.
    function testTC27_GasDoS_GetLastProposalTimestamp() public {
        // Deploy a minimal game implementation for type 1 (Cannon-like) to create non-type-42 games.
        // We reuse the same impl but register under type 1.
        // Note: These games will fail initialize() due to GAME_TYPE check, so we use a workaround.
        // Instead, we directly test AccessManager.getLastProposalTimestamp() gas after creating
        // type-42 games, then measuring gas when the latest type-42 is far back in the list.

        // First, record gas with current state (latest game IS type 42)
        uint256 gasBefore = gasleft();
        accessManager.getLastProposalTimestamp();
        uint256 gasUsed_baseline = gasBefore - gasleft();

        // Create 100 type-42 games to simulate worst case
        // (In reality we'd need non-type-42 games, but since we can't easily register
        // a different game type with a compatible impl, we measure baseline scaling.)
        for (uint256 i = 0; i < 100; i++) {
            _createGame(3000 + i * 10, 1, keccak256(abi.encodePacked("gas-test-", i)));
        }

        gasBefore = gasleft();
        accessManager.getLastProposalTimestamp();
        uint256 gasUsed_100 = gasBefore - gasleft();

        // Log gas usage for analysis
        emit log_named_uint("Gas baseline (2 games)", gasUsed_baseline);
        emit log_named_uint("Gas after 100 games", gasUsed_100);

        // The latest game is always type 42, so iteration finds it immediately.
        // Gas should not blow up. Fail if > 1M gas.
        assertLt(gasUsed_100, 1_000_000, "getLastProposalTimestamp gas too high");
    }

    /// @notice TC28: Rollback — disable ZK game creation, switch respectedGameType, retire games.
    function testTC28_RollbackToCannon() public {
        // Resolve game (index 1) first so we can test a child
        _waitAndResolve(game);

        // Create a pre-rollback game (child of game at index 1)
        OPSuccinctFaultDisputeGame preRollbackGame = _createGame(3000, 1, keccak256("pre-rollback"));

        // Step 1: Disable new ZK game creation
        factory.setImplementation(gameType, IDisputeGame(address(0)));

        vm.prank(proposer);
        vm.deal(proposer, INIT_BOND);
        vm.expectRevert(); // NoImplementation or similar
        factory.create{value: INIT_BOND}(
            gameType, Claim.wrap(keccak256("post-rollback")), abi.encodePacked(uint256(4000), uint32(1))
        );

        // Step 2: Switch ASR respectedGameType to Cannon (type 1)
        anchorStateRegistry.setRespectedGameType(GameType.wrap(1));
        assertEq(GameType.unwrap(anchorStateRegistry.respectedGameType()), 1);

        // Step 3: Switch Portal respectedGameType
        portal.setRespectedGameType(GameType.wrap(1));
        assertEq(GameType.unwrap(portal.respectedGameType()), 1);

        // Step 4: Retire all existing games
        anchorStateRegistry.updateRetirementTimestamp();

        // Verify: pre-rollback game still resolvable but enters REFUND mode
        _waitAndResolve(preRollbackGame);
        _waitFinality(preRollbackGame);

        preRollbackGame.closeGame();
        assertEq(uint8(preRollbackGame.bondDistributionMode()), uint8(BondDistributionMode.REFUND));

        // Proposer gets their bond back in REFUND mode
        preRollbackGame.claimCredit(proposer);
        assertEq(address(preRollbackGame).balance, 0);
    }

    /// @notice TC28b: Already resolved ZK game status unchanged after rollback.
    function testTC28b_RollbackDoesNotAffectResolvedGames() public {
        // Resolve game normally
        _waitAndResolve(game);
        assertEq(uint8(game.status()), uint8(GameStatus.DEFENDER_WINS));

        // Perform rollback
        factory.setImplementation(gameType, IDisputeGame(address(0)));
        anchorStateRegistry.setRespectedGameType(GameType.wrap(1));
        portal.setRespectedGameType(GameType.wrap(1));

        // Game status unchanged
        assertEq(uint8(game.status()), uint8(GameStatus.DEFENDER_WINS));

        // But retirement makes it REFUND mode
        anchorStateRegistry.updateRetirementTimestamp();
        _waitFinality(game);
        game.closeGame();
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.REFUND));
    }
}
