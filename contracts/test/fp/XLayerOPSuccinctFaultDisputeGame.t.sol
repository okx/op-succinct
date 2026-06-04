// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Testing
import "forge-std/Test.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ProxyAdmin} from "@optimism/src/universal/ProxyAdmin.sol";

// Libraries
import {Claim, Duration, GameStatus, GameType, Hash, Proposal, Timestamp} from "src/dispute/lib/Types.sol";
import {BadAuth, IncorrectBondAmount} from "src/dispute/lib/Errors.sol";
import {ClaimAlreadyChallenged} from "src/fp/lib/Errors.sol";

// Contracts
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {XLayerOPSuccinctFaultDisputeGame} from "src/fp/XLayerOPSuccinctFaultDisputeGame.sol";
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

struct XLayerAggregationOutputs {
    bytes32 l1Head;
    bytes32 l2PreRoot;
    bytes32 claimRoot;
    uint256 claimBlockNum;
    bytes32 rollupConfigHash;
    bytes32 rangeProgramCommitment;
    address proverAddress;
}

contract XLayerExpectedVerifier is ISP1Verifier {
    bytes32 public immutable teeProofHash;
    bytes32 public immutable zkProofHash;
    bytes32 public immutable expectedRangeVkeyCommitment;
    bytes32 public immutable expectedTeePcrCommitment;

    constructor(bytes memory teeProof, bytes memory zkProof, bytes32 rangeVkeyCommitment, bytes32 teePcrCommitment) {
        teeProofHash = keccak256(teeProof);
        zkProofHash = keccak256(zkProof);
        expectedRangeVkeyCommitment = rangeVkeyCommitment;
        expectedTeePcrCommitment = teePcrCommitment;
    }

    function verifyProof(bytes32, bytes calldata publicValues, bytes calldata proofBytes) external view {
        XLayerAggregationOutputs memory outputs = abi.decode(publicValues, (XLayerAggregationOutputs));
        bytes32 proofHash = keccak256(proofBytes);

        if (proofHash == teeProofHash) {
            require(outputs.rangeProgramCommitment == expectedTeePcrCommitment, "unexpected tee pcr");
        } else if (proofHash == zkProofHash) {
            require(outputs.rangeProgramCommitment == expectedRangeVkeyCommitment, "unexpected zk range vkey");
        } else {
            revert("unexpected proof bytes");
        }
    }
}

contract XLayerOPSuccinctFaultDisputeGameTest is Test {
    event Challenged(address indexed challenger, XLayerOPSuccinctFaultDisputeGame.ProofType proofType);

    DisputeGameFactory factory;
    Proxy factoryProxy;
    ProxyAdmin proxyAdmin;

    XLayerOPSuccinctFaultDisputeGame gameImpl;
    XLayerOPSuccinctFaultDisputeGame parentGame;
    XLayerOPSuccinctFaultDisputeGame game;

    AnchorStateRegistry anchorStateRegistry;
    AccessManager accessManager;

    address proposer = address(0x123);
    address challenger = address(0x456);
    address prover = address(0x789);

    MockOptimismPortal2 portal;

    bytes internal teeProof = hex"c0ffee";
    bytes internal zkProof = hex"deadbeef";
    bytes32 internal rollupConfigHash = keccak256("rollup-config");
    bytes32 internal aggregationVkey = keccak256("aggregation-vkey");
    bytes32 internal rangeVkeyCommitment = keccak256("range-vkey");
    bytes32 internal teePcrCommitment = keccak256("tee-pcr");

    uint256 disputeGameFinalityDelaySeconds = 1000;

    GameType gameType = GameType.wrap(42);
    Duration maxChallengeDuration = Duration.wrap(12 hours);
    Duration maxProveDuration = Duration.wrap(3 days);
    Claim rootClaim = Claim.wrap(keccak256("rootClaim"));

    uint256 l2BlockNumber = 2000;
    uint32 parentIndex = 0;

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

        XLayerExpectedVerifier sp1Verifier =
            new XLayerExpectedVerifier(teeProof, zkProof, rangeVkeyCommitment, teePcrCommitment);
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

        accessManager = new AccessManager(2 weeks, IDisputeGameFactory(address(factory)), gameType);
        accessManager.setProposer(proposer, true);
        accessManager.setChallenger(challenger, true);

        gameImpl = new XLayerOPSuccinctFaultDisputeGame(
            maxChallengeDuration,
            maxProveDuration,
            gameType,
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            rollupConfigHash,
            aggregationVkey,
            rangeVkeyCommitment,
            teePcrCommitment,
            1 ether,
            IAnchorStateRegistry(address(anchorStateRegistry)),
            accessManager
        );

        factory.setInitBond(gameType, 1 ether);
        factory.setImplementation(gameType, IDisputeGame(address(gameImpl)));

        vm.startPrank(proposer);
        vm.deal(proposer, 2 ether);
        vm.warp(block.timestamp + 1000);

        parentGame = XLayerOPSuccinctFaultDisputeGame(
            address(
                factory.create{value: 1 ether}(
                    gameType, Claim.wrap(keccak256("genesis")), abi.encodePacked(uint256(1000), type(uint32).max)
                )
            )
        );

        (,,,,, Timestamp parentGameDeadline) = parentGame.claimData();
        vm.warp(parentGameDeadline.raw() + 1 seconds);
        parentGame.resolve();

        vm.warp(parentGame.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1 seconds);

        game = XLayerOPSuccinctFaultDisputeGame(
            address(factory.create{value: 1 ether}(gameType, rootClaim, abi.encodePacked(l2BlockNumber, parentIndex)))
        );

        parentGame.claimCredit(proposer);

        vm.stopPrank();
    }

    function testChallengeStoresAndEmitsProofType() public {
        vm.startPrank(challenger);
        vm.deal(challenger, 1 ether);

        vm.expectEmit(true, false, false, true, address(game));
        emit Challenged(challenger, XLayerOPSuccinctFaultDisputeGame.ProofType.ZK);

        game.challenge{value: 1 ether}(XLayerOPSuccinctFaultDisputeGame.ProofType.ZK);
        vm.stopPrank();

        assertEq(uint8(game.challengedProofType()), uint8(XLayerOPSuccinctFaultDisputeGame.ProofType.ZK));

        (, address counteredBy_,,, XLayerOPSuccinctFaultDisputeGame.ProposalStatus status_,) = game.claimData();
        assertEq(counteredBy_, challenger);
        assertEq(uint8(status_), uint8(XLayerOPSuccinctFaultDisputeGame.ProposalStatus.Challenged));
    }

    function testProveReadsProofTypePrefixAndStripsItBeforeVerification() public {
        vm.startPrank(challenger);
        vm.deal(challenger, 1 ether);
        game.challenge{value: 1 ether}(XLayerOPSuccinctFaultDisputeGame.ProofType.TEE);
        vm.stopPrank();

        bytes memory typedProof = bytes.concat(bytes1(uint8(XLayerOPSuccinctFaultDisputeGame.ProofType.TEE)), teeProof);

        vm.prank(prover);
        game.prove(typedProof);

        (,, address prover_,, XLayerOPSuccinctFaultDisputeGame.ProposalStatus status_,) = game.claimData();
        assertEq(prover_, prover);
        assertEq(uint8(status_), uint8(XLayerOPSuccinctFaultDisputeGame.ProposalStatus.ChallengedAndValidProofProvided));
    }

    function testProveUsesConfiguredRangeVkeyCommitmentForZKProof() public {
        vm.startPrank(challenger);
        vm.deal(challenger, 1 ether);
        game.challenge{value: 1 ether}(XLayerOPSuccinctFaultDisputeGame.ProofType.ZK);
        vm.stopPrank();

        bytes memory typedProof = bytes.concat(bytes1(uint8(XLayerOPSuccinctFaultDisputeGame.ProofType.ZK)), zkProof);

        vm.prank(prover);
        game.prove(typedProof);

        (,, address prover_,, XLayerOPSuccinctFaultDisputeGame.ProposalStatus status_,) = game.claimData();
        assertEq(prover_, prover);
        assertEq(uint8(status_), uint8(XLayerOPSuccinctFaultDisputeGame.ProposalStatus.ChallengedAndValidProofProvided));
    }

    function testProveRevertsWhenProofTypeDoesNotMatchChallenge() public {
        vm.startPrank(challenger);
        vm.deal(challenger, 1 ether);
        game.challenge{value: 1 ether}(XLayerOPSuccinctFaultDisputeGame.ProofType.ZK);
        vm.stopPrank();

        bytes memory typedProof = bytes.concat(bytes1(uint8(XLayerOPSuccinctFaultDisputeGame.ProofType.TEE)), teeProof);

        vm.expectRevert(
            abi.encodeWithSelector(
                XLayerOPSuccinctFaultDisputeGame.UnexpectedProofType.selector,
                XLayerOPSuccinctFaultDisputeGame.ProofType.ZK,
                XLayerOPSuccinctFaultDisputeGame.ProofType.TEE
            )
        );

        vm.prank(prover);
        game.prove(typedProof);
    }

    function testProveRevertsWhenProofTypePrefixIsInvalid() public {
        bytes memory typedProof = bytes.concat(bytes1(0x02), teeProof);

        vm.expectRevert(
            abi.encodeWithSelector(XLayerOPSuccinctFaultDisputeGame.InvalidProofType.selector, bytes1(0x02))
        );

        vm.prank(prover);
        game.prove(typedProof);
    }

    function testProveRevertsWhenTypedProofIsEmpty() public {
        vm.expectRevert(XLayerOPSuccinctFaultDisputeGame.EmptyTypedProof.selector);

        vm.prank(prover);
        game.prove(bytes(""));
    }

    function testChallengeKeepsExistingAccessAndBondChecks() public {
        vm.deal(challenger, 2 ether);

        vm.prank(challenger);
        vm.expectRevert(IncorrectBondAmount.selector);
        game.challenge{value: 0.5 ether}(XLayerOPSuccinctFaultDisputeGame.ProofType.TEE);

        vm.deal(address(0x999), 1 ether);
        vm.prank(address(0x999));
        vm.expectRevert(BadAuth.selector);
        game.challenge{value: 1 ether}(XLayerOPSuccinctFaultDisputeGame.ProofType.TEE);

        vm.startPrank(challenger);
        game.challenge{value: 1 ether}(XLayerOPSuccinctFaultDisputeGame.ProofType.TEE);

        vm.expectRevert(ClaimAlreadyChallenged.selector);
        game.challenge{value: 1 ether}(XLayerOPSuccinctFaultDisputeGame.ProofType.TEE);
        vm.stopPrank();
    }
}
