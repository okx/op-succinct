// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ProxyAdmin} from "@optimism/src/universal/ProxyAdmin.sol";

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
import {BadExtraData} from "src/dispute/lib/Errors.sol";
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {AnchorStateRegistry} from "src/dispute/AnchorStateRegistry.sol";
import {OPSuccinctFaultDisputeGame} from "src/fp/OPSuccinctFaultDisputeGame.sol";
import {AccessManager} from "src/fp/AccessManager.sol";
import {InvalidRootClaimPreimage, RootClaimPreimageDisabled} from "src/fp/lib/Errors.sol";
import {OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE} from "src/lib/Types.sol";
import {MockOptimismPortal2} from "src/utils/MockOptimismPortal2.sol";
import {MockSystemConfig} from "src/utils/MockSystemConfig.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {ISystemConfig} from "interfaces/L1/ISystemConfig.sol";
import {ISP1Verifier} from "src/fp/interfaces/ISP1Verifier.sol";
import {SP1MockVerifier} from "src/utils/SP1MockVerifier.sol";

contract Stage5PostAnchorProbe {
    enum Mode {
        Success,
        Revert,
        BurnGas
    }

    Mode public mode;
    uint256 public calls;
    mapping(uint256 => uint256) internal gasBurner;

    function setMode(Mode mode_) external {
        mode = mode_;
    }

    function push() external {
        calls++;
        if (mode == Mode.Revert) revert("probe revert");
        if (mode == Mode.BurnGas) {
            uint256 i;
            while (true) {
                gasBurner[i] = i + calls;
                i++;
            }
        }
    }
}

contract OPSuccinctFaultDisputeGameStage5Test is Test {
    event PostAnchorFailed(address indexed game);
    event GameClosed(BondDistributionMode mode);

    DisputeGameFactory internal factory;
    ProxyAdmin internal proxyAdmin;
    AnchorStateRegistry internal anchorStateRegistry;
    AccessManager internal accessManager;
    MockOptimismPortal2 internal portal;
    SP1MockVerifier internal verifier;
    Stage5PostAnchorProbe internal postAnchorProbe;

    GameType internal gameType = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);
    Duration internal maxChallengeDuration = Duration.wrap(12 hours);
    Duration internal maxProveDuration = Duration.wrap(3 days);

    address internal proposer = address(0x123);
    uint256 internal constant INIT_BOND = 1 ether;
    uint256 internal constant CHALLENGER_BOND = 1 ether;
    uint256 internal constant FINALITY_DELAY = 1000;

    bytes32 internal constant BLOCK_HASH = bytes32(uint256(0x1111));
    bytes32 internal constant APP_HASH = bytes32(uint256(0x2222));
    bytes32 internal constant WITHDRAWAL_ROOT = bytes32(uint256(0x3333));
    bytes32 internal constant FORCE_ROOT = bytes32(uint256(0x4444));

    function setUp() public {
        proxyAdmin = new ProxyAdmin(address(this));

        DisputeGameFactory factoryImpl = new DisputeGameFactory();
        Proxy factoryProxy = new Proxy(address(proxyAdmin));
        proxyAdmin.upgradeAndCall(
            payable(address(factoryProxy)),
            address(factoryImpl),
            abi.encodeWithSelector(DisputeGameFactory.initialize.selector, address(this))
        );
        factory = DisputeGameFactory(address(factoryProxy));

        MockSystemConfig mockSystemConfig = new MockSystemConfig(address(this));
        portal = new MockOptimismPortal2(gameType, FINALITY_DELAY);
        Proposal memory startingAnchorRoot = Proposal({root: Hash.wrap(keccak256("genesis")), l2SequenceNumber: 0});

        AnchorStateRegistry registryImpl = new AnchorStateRegistry(FINALITY_DELAY);
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

        verifier = new SP1MockVerifier();
        postAnchorProbe = new Stage5PostAnchorProbe();

        factory.setInitBond(gameType, INIT_BOND);
        vm.deal(proposer, 100 ether);
        vm.warp(block.timestamp + 1000);
    }

    function _deployImpl(bool hasPreimage, address postAnchor) internal returns (OPSuccinctFaultDisputeGame) {
        return new OPSuccinctFaultDisputeGame(
            maxChallengeDuration,
            maxProveDuration,
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(verifier)),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            CHALLENGER_BOND,
            IAnchorStateRegistry(address(anchorStateRegistry)),
            accessManager,
            hasPreimage,
            postAnchor
        );
    }

    function _registerImpl(bool hasPreimage, address postAnchor) internal returns (OPSuccinctFaultDisputeGame impl) {
        impl = _deployImpl(hasPreimage, postAnchor);
        factory.setImplementation(gameType, IDisputeGame(address(impl)));
    }

    function _root(bytes32 blockHash_, bytes32 appHash_, bytes32 withdrawalRoot_, bytes32 forceRoot_)
        internal
        pure
        returns (Claim)
    {
        return Claim.wrap(keccak256(abi.encodePacked(blockHash_, appHash_, withdrawalRoot_, forceRoot_)));
    }

    function _extendedExtraData(
        uint256 l2SequenceNumber,
        uint32 parentIndex,
        bytes32 blockHash_,
        bytes32 appHash_,
        bytes32 withdrawalRoot_,
        bytes32 forceRoot_
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(l2SequenceNumber, parentIndex, blockHash_, appHash_, withdrawalRoot_, forceRoot_);
    }

    function _createGame(Claim claim, bytes memory extraData) internal returns (OPSuccinctFaultDisputeGame created) {
        vm.prank(proposer);
        created = OPSuccinctFaultDisputeGame(address(factory.create{value: INIT_BOND}(gameType, claim, extraData)));
    }

    function _createExtendedGame(
        uint256 l2SequenceNumber,
        bytes32 blockHash_,
        bytes32 appHash_,
        bytes32 withdrawalRoot_,
        bytes32 forceRoot_
    ) internal returns (OPSuccinctFaultDisputeGame created) {
        created = _createGame(
            _root(blockHash_, appHash_, withdrawalRoot_, forceRoot_),
            _extendedExtraData(l2SequenceNumber, type(uint32).max, blockHash_, appHash_, withdrawalRoot_, forceRoot_)
        );
    }

    function _resolveAndFinalize(OPSuccinctFaultDisputeGame game) internal {
        (,,,,, Timestamp deadline) = game.claimData();
        vm.warp(deadline.raw() + 1);
        game.resolve();
        vm.warp(game.resolvedAt().raw() + FINALITY_DELAY + 1);
    }

    function _assertClosedNormal(OPSuccinctFaultDisputeGame game) internal view {
        assertEq(uint8(game.status()), uint8(GameStatus.DEFENDER_WINS));
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.NORMAL));
    }

    function test_extendedGameCreation_commitsPreimagesAndReturnsFullExtraData() public {
        _registerImpl(true, address(postAnchorProbe));

        OPSuccinctFaultDisputeGame game = _createExtendedGame(1000, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        bytes memory expected =
            _extendedExtraData(1000, type(uint32).max, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);

        assertEq(game.blockHash(), BLOCK_HASH);
        assertEq(game.appHash(), APP_HASH);
        assertEq(game.withdrawalRoot(), WITHDRAWAL_ROOT);
        assertEq(game.forceRoot(), FORCE_ROOT);
        assertEq(game.extraData(), expected);
        (GameType returnedType, Claim returnedClaim, bytes memory returnedExtraData) = game.gameData();
        assertEq(GameType.unwrap(returnedType), GameType.unwrap(gameType));
        assertEq(returnedClaim.raw(), _root(BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT).raw());
        assertEq(returnedExtraData, expected);
    }

    function test_legacyGameCreation_keeps36ByteExtraDataAndGetterReverts() public {
        _registerImpl(false, address(0));

        Claim claim = Claim.wrap(keccak256("legacy-root"));
        bytes memory expected = abi.encodePacked(uint256(1000), type(uint32).max);
        OPSuccinctFaultDisputeGame game = _createGame(claim, expected);

        assertEq(game.extraData(), expected);
        (, Claim returnedClaim, bytes memory returnedExtraData) = game.gameData();
        assertEq(returnedClaim.raw(), claim.raw());
        assertEq(returnedExtraData, expected);

        vm.expectRevert(RootClaimPreimageDisabled.selector);
        game.blockHash();
        vm.expectRevert(RootClaimPreimageDisabled.selector);
        game.appHash();
        vm.expectRevert(RootClaimPreimageDisabled.selector);
        game.withdrawalRoot();
        vm.expectRevert(RootClaimPreimageDisabled.selector);
        game.forceRoot();
    }

    function test_extendedGameRejectsSwappedWithdrawalAndForceRoots() public {
        _registerImpl(true, address(postAnchorProbe));

        Claim original = _root(BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        bytes memory swapped =
            _extendedExtraData(1000, type(uint32).max, BLOCK_HASH, APP_HASH, FORCE_ROOT, WITHDRAWAL_ROOT);

        uint256 beforeCount = factory.gameCount();
        vm.prank(proposer);
        vm.expectRevert(InvalidRootClaimPreimage.selector);
        factory.create{value: INIT_BOND}(gameType, original, swapped);
        assertEq(factory.gameCount(), beforeCount);
    }

    function test_extendedGameRejectsMissingExtraPreimageBytes() public {
        _registerImpl(true, address(postAnchorProbe));

        bytes memory missingForceRoot =
            abi.encodePacked(uint256(1000), type(uint32).max, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT);

        vm.prank(proposer);
        vm.expectRevert(BadExtraData.selector);
        factory.create{value: INIT_BOND}(
            gameType, _root(BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT), missingForceRoot
        );
    }

    function test_extendedGameRejectsExtraPreimageBytes() public {
        _registerImpl(true, address(postAnchorProbe));

        bytes memory extra = abi.encodePacked(
            _extendedExtraData(1000, type(uint32).max, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT), bytes1(0x01)
        );

        vm.prank(proposer);
        vm.expectRevert(BadExtraData.selector);
        factory.create{value: INIT_BOND}(gameType, _root(BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT), extra);
    }

    function testFuzz_extendedGameRejectsAnyMutatedPreimage(
        bytes32 blockHash_,
        bytes32 appHash_,
        bytes32 withdrawalRoot_,
        bytes32 forceRoot_,
        bytes32 mutatedValue,
        uint8 field
    ) public {
        vm.assume(withdrawalRoot_ != forceRoot_);
        _registerImpl(true, address(postAnchorProbe));

        bytes32 mutatedBlockHash = blockHash_;
        bytes32 mutatedAppHash = appHash_;
        bytes32 mutatedWithdrawalRoot = withdrawalRoot_;
        bytes32 mutatedForceRoot = forceRoot_;

        uint8 selected = field % 4;
        if (selected == 0) {
            vm.assume(mutatedValue != blockHash_);
            mutatedBlockHash = mutatedValue;
        } else if (selected == 1) {
            vm.assume(mutatedValue != appHash_);
            mutatedAppHash = mutatedValue;
        } else if (selected == 2) {
            vm.assume(mutatedValue != withdrawalRoot_);
            mutatedWithdrawalRoot = mutatedValue;
        } else {
            vm.assume(mutatedValue != forceRoot_);
            mutatedForceRoot = mutatedValue;
        }

        Claim original = _root(blockHash_, appHash_, withdrawalRoot_, forceRoot_);
        bytes memory mutated = _extendedExtraData(
            1000, type(uint32).max, mutatedBlockHash, mutatedAppHash, mutatedWithdrawalRoot, mutatedForceRoot
        );

        vm.prank(proposer);
        vm.expectRevert(InvalidRootClaimPreimage.selector);
        factory.create{value: INIT_BOND}(gameType, original, mutated);
    }

    function test_closeGame_successCallsPostAnchorOnce() public {
        _registerImpl(true, address(postAnchorProbe));
        OPSuccinctFaultDisputeGame game = _createExtendedGame(1000, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);

        _resolveAndFinalize(game);
        game.closeGame();

        assertEq(postAnchorProbe.calls(), 1);
        assertEq(address(anchorStateRegistry.anchorGame()), address(game));
        _assertClosedNormal(game);

        game.closeGame();
        assertEq(postAnchorProbe.calls(), 1, "repeat close must not resend");
    }

    function test_closeGame_anchorSetByAnotherCallerStillPushesLatest() public {
        _registerImpl(true, address(postAnchorProbe));
        OPSuccinctFaultDisputeGame game = _createExtendedGame(1000, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);

        _resolveAndFinalize(game);
        vm.prank(address(0xBEEF));
        anchorStateRegistry.setAnchorState(IDisputeGame(address(game)));

        assertEq(postAnchorProbe.calls(), 0, "direct ASR update must not call forwarder");
        game.closeGame();

        assertEq(address(anchorStateRegistry.anchorGame()), address(game));
        assertEq(postAnchorProbe.calls(), 1, "close must sync an anchor advanced by another caller");
        _assertClosedNormal(game);
    }

    function test_closeGame_postAnchorRevertEmitsFailureButCloses() public {
        _registerImpl(true, address(postAnchorProbe));
        OPSuccinctFaultDisputeGame game = _createExtendedGame(1000, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        postAnchorProbe.setMode(Stage5PostAnchorProbe.Mode.Revert);

        _resolveAndFinalize(game);
        vm.expectEmit(false, false, false, true, address(game));
        emit GameClosed(BondDistributionMode.NORMAL);
        vm.expectEmit(true, false, false, true, address(game));
        emit PostAnchorFailed(address(game));
        game.closeGame();

        assertEq(address(anchorStateRegistry.anchorGame()), address(game));
        _assertClosedNormal(game);
    }

    function test_closeGame_postAnchorOogEmitsFailureButCloses() public {
        _registerImpl(true, address(postAnchorProbe));
        OPSuccinctFaultDisputeGame game = _createExtendedGame(1000, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        postAnchorProbe.setMode(Stage5PostAnchorProbe.Mode.BurnGas);

        _resolveAndFinalize(game);
        vm.expectEmit(false, false, false, true, address(game));
        emit GameClosed(BondDistributionMode.NORMAL);
        vm.expectEmit(true, false, false, true, address(game));
        emit PostAnchorFailed(address(game));
        game.closeGame();

        assertEq(address(anchorStateRegistry.anchorGame()), address(game));
        _assertClosedNormal(game);
    }

    function test_closeGame_asrRejectsGameSkipsPostAnchor() public {
        _registerImpl(true, address(postAnchorProbe));
        OPSuccinctFaultDisputeGame game = _createExtendedGame(1000, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);

        _resolveAndFinalize(game);
        anchorStateRegistry.blacklistDisputeGame(IDisputeGame(address(game)));
        game.closeGame();

        assertEq(postAnchorProbe.calls(), 0);
        assertEq(address(anchorStateRegistry.anchorGame()), address(0));
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.REFUND));
    }

    function test_claimCredit_postAnchorRevertStillPaysCredit() public {
        _registerImpl(true, address(postAnchorProbe));
        OPSuccinctFaultDisputeGame game = _createExtendedGame(1000, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        postAnchorProbe.setMode(Stage5PostAnchorProbe.Mode.Revert);

        _resolveAndFinalize(game);
        uint256 beforeBalance = proposer.balance;
        vm.expectEmit(false, false, false, true, address(game));
        emit GameClosed(BondDistributionMode.NORMAL);
        vm.expectEmit(true, false, false, true, address(game));
        emit PostAnchorFailed(address(game));
        game.claimCredit(proposer);

        assertEq(game.credit(proposer), 0);
        assertEq(address(game).balance, 0);
        assertEq(proposer.balance, beforeBalance + INIT_BOND);
        _assertClosedNormal(game);
    }

    function test_closeGame_degradedConfigDoesNotCallPostAnchor() public {
        _registerImpl(true, address(0));
        OPSuccinctFaultDisputeGame game = _createExtendedGame(1000, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);

        _resolveAndFinalize(game);
        game.closeGame();

        assertEq(postAnchorProbe.calls(), 0);
        assertEq(address(anchorStateRegistry.anchorGame()), address(game));
        _assertClosedNormal(game);
    }
}
