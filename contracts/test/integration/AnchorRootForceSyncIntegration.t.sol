// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ProxyAdmin} from "@optimism/src/universal/ProxyAdmin.sol";
import {AddressAliasHelper} from "@optimism/src/vendor/AddressAliasHelper.sol";

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
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {AnchorStateRegistry} from "src/dispute/AnchorStateRegistry.sol";

import {OPSuccinctFaultDisputeGame} from "src/fp/OPSuccinctFaultDisputeGame.sol";
import {AccessManager} from "src/fp/AccessManager.sol";
import {PostAnchor} from "src/fp/PostAnchor.sol";
import {TZRootManager} from "src/fp/TZRootManager.sol";
import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {InvalidRoot, Unauthorized, StaleRoot, RootClaimPreimageDisabled} from "src/fp/lib/Errors.sol";
import {OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE} from "src/lib/Types.sol";

import {MockOptimismPortal2} from "src/utils/MockOptimismPortal2.sol";
import {MockSystemConfig} from "src/utils/MockSystemConfig.sol";
import {TZBootstrapExtraData} from "../helpers/TZBootstrapExtraData.sol";

import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {IOptimismPortal2} from "interfaces/L1/IOptimismPortal2.sol";
import {ISystemConfig} from "interfaces/L1/ISystemConfig.sol";
import {ISP1Verifier} from "src/fp/interfaces/ISP1Verifier.sol";
import {SP1MockVerifier} from "src/utils/SP1MockVerifier.sol";

/// @notice Cross-chain deposit surface stand-in for the OptimismPortal. It records the exact
///         deposit arguments the forwarder emits so an integration test can replay the message on
///         the target chain, and can be forced to revert to model a portal outage. It never fakes
///         any behavior of the system under test (game, forwarder, root manager).
contract IntegrationRecordingPortal {
    address public lastTo;
    uint256 public lastValue;
    uint64 public lastGasLimit;
    bool public lastIsCreation;
    bytes public lastData;
    uint256 public callCount;
    bool internal shouldRevert;

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function depositTransaction(address _to, uint256 _value, uint64 _gasLimit, bool _isCreation, bytes memory _data)
        external
        payable
    {
        if (shouldRevert) revert("portal down");
        lastTo = _to;
        lastValue = _value;
        lastGasLimit = _gasLimit;
        lastIsCreation = _isCreation;
        lastData = _data;
        callCount++;
    }
}

/// @notice End-to-end integration: drives the real dispute-game lifecycle into the real
///         PostAnchor forwarder and the real TZRootManager sink across the full
///         closeGame -> setAnchorState -> push -> portal deposit -> (aliased) record path.
contract AnchorRootForceSyncIntegrationTest is Test {
    // Events under observation (mirrors of the production declarations).
    event RootsEnqueued(address indexed game, uint256 indexed l2BlockNumber, bytes32 withdrawalRoot, bytes32 forceRoot);
    event RootsRecorded(bytes32 withdrawalRoot, bytes32 forceRoot, uint256 l2BlockNumber);
    event PostAnchorFailed(address indexed game);
    event GameClosed(BondDistributionMode bondDistributionMode);

    // Real dispute-game system.
    DisputeGameFactory internal factory;
    ProxyAdmin internal proxyAdmin;
    AnchorStateRegistry internal anchorStateRegistry;
    AccessManager internal accessManager;
    MockOptimismPortal2 internal finalityPortal;
    SP1MockVerifier internal verifier;

    // Systems under test on the forwarding path.
    IntegrationRecordingPortal internal depositPortal;
    PostAnchor internal postAnchor;
    TZRootManager internal rootManager;
    OPSuccinctFaultDisputeGame internal extendedImpl;
    address internal predictedRootManager;
    address internal aliasedForwarder;

    GameType internal gameType = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);
    Duration internal maxChallengeDuration = Duration.wrap(12 hours);
    Duration internal maxProveDuration = Duration.wrap(3 days);

    address internal proposer = address(0x123);
    address internal relayer = address(0xBEEF);
    uint256 internal constant INIT_BOND = 1 ether;
    uint256 internal constant CHALLENGER_BOND = 1 ether;
    uint256 internal constant FINALITY_DELAY = 1000;
    uint64 internal constant PUSH_GAS = 150_000;

    // Four mutually distinct roots so a withdrawal/force swap cannot pass unnoticed.
    bytes32 internal constant BLOCK_HASH = bytes32(uint256(0x1111));
    bytes32 internal constant APP_HASH = bytes32(uint256(0x2222));
    bytes32 internal constant WITHDRAWAL_ROOT = bytes32(uint256(0x3333));
    bytes32 internal constant FORCE_ROOT = bytes32(uint256(0x4444));
    uint256 internal constant SEQ_1 = 1000;
    uint256 internal constant SEQ_2 = 2000;

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
        finalityPortal = new MockOptimismPortal2(gameType, FINALITY_DELAY);
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
        depositPortal = new IntegrationRecordingPortal();

        // Deploy-time cross-chain address precomputation: the forwarder must know the target-chain
        // sink address before it exists, and the sink must authorize the forwarder's alias. Deploy
        // the forwarder with the predicted sink address, then deploy the sink and confirm the
        // prediction holds. This mirrors production's precompute-and-assert deployment step.
        uint256 nonce = vm.getNonce(address(this));
        predictedRootManager = vm.computeCreateAddress(address(this), nonce + 1);
        postAnchor = new PostAnchor(
            IAnchorStateRegistry(address(anchorStateRegistry)),
            IOptimismPortal2(payable(address(depositPortal))),
            predictedRootManager,
            PUSH_GAS
        );
        rootManager = new TZRootManager(address(postAnchor));
        require(address(rootManager) == predictedRootManager, "cross-chain address precompute drift");
        aliasedForwarder = AddressAliasHelper.applyL1ToL2Alias(address(postAnchor));

        extendedImpl = _registerImpl(true, address(postAnchor));

        factory.setInitBond(gameType, INIT_BOND);
        vm.deal(proposer, 100 ether);
        vm.warp(block.timestamp + 1000);
    }

    // ---------------------------------------------------------------------------------------------
    // Harness helpers (real system deployment + real extended-game lifecycle).
    // ---------------------------------------------------------------------------------------------

    function _deployImpl(bool hasPreimage, address postAnchor_) internal returns (OPSuccinctFaultDisputeGame) {
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
            postAnchor_
        );
    }

    function _registerImpl(bool hasPreimage, address postAnchor_) internal returns (OPSuccinctFaultDisputeGame impl) {
        impl = _deployImpl(hasPreimage, postAnchor_);
        factory.setImplementation(gameType, IDisputeGame(address(impl)));
    }

    // Build the game-creation payloads through the canonical producer encoder (the single source of
    // truth the TradeZone bootstrap producer / deploy script uses), so the integration path consumes
    // exactly the producer-shaped rootClaim and extraData that reach the chain in production.
    function _root(bytes32 bh, bytes32 ah, bytes32 wr, bytes32 fr) internal pure returns (Claim) {
        return Claim.wrap(TZBootstrapExtraData.commitRootClaim(bh, ah, wr, fr));
    }

    function _extendedExtraData(uint256 seq, bytes32 bh, bytes32 ah, bytes32 wr, bytes32 fr)
        internal
        pure
        returns (bytes memory)
    {
        return TZBootstrapExtraData.encodeExtended(seq, type(uint32).max, bh, ah, wr, fr);
    }

    function _createExtendedGame(uint256 seq, bytes32 bh, bytes32 ah, bytes32 wr, bytes32 fr)
        internal
        returns (OPSuccinctFaultDisputeGame created)
    {
        vm.prank(proposer);
        created = OPSuccinctFaultDisputeGame(
            address(
                factory.create{value: INIT_BOND}(
                    gameType, _root(bh, ah, wr, fr), _extendedExtraData(seq, bh, ah, wr, fr)
                )
            )
        );
    }

    function _resolveAndFinalize(OPSuccinctFaultDisputeGame game) internal {
        (,,,,, Timestamp deadline) = game.claimData();
        vm.warp(deadline.raw() + 1);
        game.resolve();
        vm.warp(game.resolvedAt().raw() + FINALITY_DELAY + 1);
    }

    /// @dev Delivers the exact deposit calldata the portal captured to the real sink, from the
    ///      aliased forwarder identity, exactly as the target-chain rollup would after derivation.
    function _deliverCapturedDeposit() internal returns (bool ok) {
        bytes memory data = depositPortal.lastData();
        vm.prank(aliasedForwarder);
        (ok,) = address(rootManager).call(data);
    }

    function _assertCheckpointRoots(uint256 height, bytes32 expectedW, bytes32 expectedF) internal view {
        (bytes32 withdrawalRoot, bytes32 forceTxRoot) = rootManager.getRoots(height);
        assertEq(withdrawalRoot, expectedW, "checkpoint withdrawal root");
        assertEq(forceTxRoot, expectedF, "checkpoint force root");
    }

    function _assertLatestRoots(uint256 expectedHeight, bytes32 expectedW, bytes32 expectedF) internal view {
        (uint256 height, bytes32 withdrawalRoot, bytes32 forceTxRoot) = rootManager.getLatestRoots();
        assertEq(height, expectedHeight, "latest checkpoint height");
        assertEq(withdrawalRoot, expectedW, "latest withdrawal root");
        assertEq(forceTxRoot, expectedF, "latest force root");
    }

    // ---------------------------------------------------------------------------------------------
    // Deployment / initialization.
    // ---------------------------------------------------------------------------------------------

    function test_deployment_wiresCrossChainImmutablesAndInitState() public view {
        // Forwarder immutables point at the real dependencies.
        assertEq(address(postAnchor.ASR()), address(anchorStateRegistry), "ASR wiring");
        assertEq(address(postAnchor.XL_PORTAL()), address(depositPortal), "portal wiring");
        assertEq(postAnchor.XL_ROOT_MANAGER(), address(rootManager), "sink target wiring");
        assertEq(postAnchor.PUSH_GAS_LIMIT(), PUSH_GAS, "push gas wiring");

        // Sink authorizes exactly the deployed forwarder and starts empty.
        assertEq(rootManager.L1_POST_ANCHOR(), address(postAnchor), "sink forwarder wiring");
        _assertLatestRoots(0, bytes32(0), bytes32(0));

        // Precomputed cross-chain address matched the deployed sink.
        assertEq(address(rootManager), predictedRootManager, "precompute match");

        // Extended implementation carries the auto-delivery configuration.
        assertEq(extendedImpl.POST_ANCHOR(), address(postAnchor), "impl POST_ANCHOR");
        assertTrue(extendedImpl.HAS_ROOT_CLAIM_PREIMAGE(), "impl extended layout");
        assertEq(extendedImpl.version(), "2.1.0", "impl version");
    }

    function test_reinitialize_revertsAfterFactoryInit() public {
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        // A game created by the factory is already initialized; a second initialize must revert.
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        game.initialize();
    }

    // ---------------------------------------------------------------------------------------------
    // End-to-end happy round-trip.
    // ---------------------------------------------------------------------------------------------

    function test_e2e_closeGamePushDepositAndTargetChainRecord() public {
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game);

        // closeGame finalizes its own state before making the best-effort forwarder call.
        vm.expectEmit(false, false, false, true, address(game));
        emit GameClosed(BondDistributionMode.NORMAL);
        vm.expectEmit(true, true, false, true, address(postAnchor));
        emit RootsEnqueued(address(game), SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
        game.closeGame();

        // The anchor really advanced to this game and bonds distribute normally.
        assertEq(address(anchorStateRegistry.anchorGame()), address(game), "anchor set");
        assertEq(uint8(game.status()), uint8(GameStatus.DEFENDER_WINS), "defender wins");
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.NORMAL), "normal bonds");

        // The forwarder produced exactly one fixed deposit: right target, zero value, fixed gas,
        // not a creation, and the frozen record(W, F, height) calldata built from the game's roots.
        assertEq(depositPortal.callCount(), 1, "one deposit");
        assertEq(depositPortal.lastTo(), address(rootManager), "deposit target is sink");
        assertEq(depositPortal.lastValue(), 0, "deposit carries no value");
        assertEq(depositPortal.lastGasLimit(), PUSH_GAS, "deposit gas");
        assertFalse(depositPortal.lastIsCreation(), "not a creation deposit");
        assertEq(
            depositPortal.lastData(),
            abi.encodeCall(ITZRootManager.record, (WITHDRAWAL_ROOT, FORCE_ROOT, SEQ_1)),
            "deposit calldata is record(W,F,seq)"
        );
        // Forwarder holds no funds.
        assertEq(address(postAnchor).balance, 0, "forwarder holds no ETH");

        // Deliver the captured message on the target chain from the aliased forwarder identity.
        vm.expectEmit(false, false, false, true, address(rootManager));
        emit RootsRecorded(WITHDRAWAL_ROOT, FORCE_ROOT, SEQ_1);
        assertTrue(_deliverCapturedDeposit(), "record delivery");

        // The exact-height and latest queries both mirror the anchor game's committed tuple.
        _assertCheckpointRoots(SEQ_1, game.withdrawalRoot(), game.forceRoot());
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);

        // Credit remains claimable and pays exactly the bond; no value is stranded.
        uint256 beforeBalance = proposer.balance;
        game.claimCredit(proposer);
        assertEq(proposer.balance, beforeBalance + INIT_BOND, "bond paid");
        assertEq(address(game).balance, 0, "game drained");
    }

    // ---------------------------------------------------------------------------------------------
    // Multi-game monotonic continuity across transactions.
    // ---------------------------------------------------------------------------------------------

    function test_e2e_multiGameMonotonicContinuity() public {
        bytes32 w2 = bytes32(uint256(0x5555));
        bytes32 f2 = bytes32(uint256(0x6666));

        // First game closes and syncs its roots at height SEQ_1.
        OPSuccinctFaultDisputeGame game1 = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game1);
        game1.closeGame();
        assertTrue(_deliverCapturedDeposit(), "record #1");
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);

        // Second, higher game re-anchors and advances the sink monotonically.
        OPSuccinctFaultDisputeGame game2 = _createExtendedGame(SEQ_2, BLOCK_HASH, APP_HASH, w2, f2);
        _resolveAndFinalize(game2);
        game2.closeGame();
        assertEq(address(anchorStateRegistry.anchorGame()), address(game2), "anchor advanced to game2");
        assertEq(depositPortal.callCount(), 2, "second deposit enqueued");
        assertEq(
            depositPortal.lastData(),
            abi.encodeCall(ITZRootManager.record, (w2, f2, SEQ_2)),
            "second deposit carries game2 roots"
        );
        assertTrue(_deliverCapturedDeposit(), "record #2");

        // Checkpoints may be sparse: latest advances, while exact-height history remains intact.
        _assertCheckpointRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
        _assertCheckpointRoots(SEQ_1 + 1, bytes32(0), bytes32(0));
        _assertCheckpointRoots(SEQ_2, w2, f2);
        _assertLatestRoots(SEQ_2, w2, f2);
    }

    function test_e2e_externalAnchorAdvanceBeforeCloseStillPushesLatest() public {
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game);

        // setAnchorState is permissionless. Simulate another caller advancing the ASR before the
        // game's close hook executes.
        vm.prank(address(0xBEEF));
        anchorStateRegistry.setAnchorState(IDisputeGame(address(game)));
        assertEq(address(anchorStateRegistry.anchorGame()), address(game), "anchor pre-advanced");
        assertEq(depositPortal.callCount(), 0, "direct ASR advance does not enqueue");

        game.closeGame();

        assertEq(depositPortal.callCount(), 1, "close catches up latest anchor");
        assertEq(
            depositPortal.lastData(),
            abi.encodeCall(ITZRootManager.record, (WITHDRAWAL_ROOT, FORCE_ROOT, SEQ_1)),
            "latest roots enqueued"
        );
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.NORMAL), "closed normal");
    }

    function test_e2e_multipleExternalAnchorAdvancesPushOnlyCurrentLatest() public {
        bytes32 w2 = bytes32(uint256(0x5555));
        bytes32 f2 = bytes32(uint256(0x6666));
        OPSuccinctFaultDisputeGame game1 = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        OPSuccinctFaultDisputeGame game2 = _createExtendedGame(SEQ_2, BLOCK_HASH, APP_HASH, w2, f2);

        // Finalize both before an external caller advances through both anchors.
        (,,,,, Timestamp deadline1) = game1.claimData();
        (,,,,, Timestamp deadline2) = game2.claimData();
        uint64 latestDeadline = deadline1.raw() > deadline2.raw() ? deadline1.raw() : deadline2.raw();
        vm.warp(latestDeadline + 1);
        game1.resolve();
        game2.resolve();
        vm.warp(block.timestamp + FINALITY_DELAY + 1);

        vm.startPrank(address(0xBEEF));
        anchorStateRegistry.setAnchorState(IDisputeGame(address(game1)));
        anchorStateRegistry.setAnchorState(IDisputeGame(address(game2)));
        vm.stopPrank();

        // Closing the older game catches up directly to the current ASR anchor. Since only the
        // latest checkpoint matters, game1 is intentionally not enqueued.
        game1.closeGame();
        assertEq(uint8(game1.bondDistributionMode()), uint8(BondDistributionMode.NORMAL), "older game closed normally");
        assertEq(depositPortal.callCount(), 1, "only current latest enqueued");
        assertEq(
            depositPortal.lastData(), abi.encodeCall(ITZRootManager.record, (w2, f2, SEQ_2)), "game2 roots enqueued"
        );

        // Closing game2 enqueues the current anchor again. The target-chain sink, rather than an
        // L1 enqueue watermark, is responsible for making the duplicate harmless.
        game2.closeGame();
        assertEq(depositPortal.callCount(), 2, "latest anchor remains retryable");
    }

    // ---------------------------------------------------------------------------------------------
    // Best-effort hook failure isolation, then permissionless retry convergence.
    // ---------------------------------------------------------------------------------------------

    function test_e2e_postAnchorFailureIsolatedThenPermissionlessRetryConverges() public {
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game);

        // Portal is down: the hook fails but the game must still close cleanly.
        depositPortal.setShouldRevert(true);
        vm.expectEmit(false, false, false, true, address(game));
        emit GameClosed(BondDistributionMode.NORMAL);
        vm.expectEmit(true, false, false, true, address(game));
        emit PostAnchorFailed(address(game));
        game.closeGame();

        // Anchor update and bond mode survived the hook failure; the sink was not touched.
        assertEq(address(anchorStateRegistry.anchorGame()), address(game), "anchor set despite hook failure");
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.NORMAL), "closed normal");
        assertEq(depositPortal.callCount(), 0, "no deposit captured while portal down");
        _assertLatestRoots(0, bytes32(0), bytes32(0));

        // Credit is still payable even though the cross-chain delivery failed.
        uint256 beforeBalance = proposer.balance;
        game.claimCredit(proposer);
        assertEq(proposer.balance, beforeBalance + INIT_BOND, "bond paid despite hook failure");

        // Portal recovers; an arbitrary relayer converges the sink through the same entry point.
        depositPortal.setShouldRevert(false);
        vm.expectEmit(true, true, false, true, address(postAnchor));
        emit RootsEnqueued(address(game), SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
        vm.prank(relayer);
        postAnchor.push();

        assertEq(depositPortal.callCount(), 1, "retry enqueued one deposit");
        assertTrue(_deliverCapturedDeposit(), "retry record delivery");
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
    }

    function test_e2e_enqueuedButUndeliveredMessageCanBeRetried() public {
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game);

        // The close hook successfully enqueues, but simulate that the captured message has not
        // executed on the target chain.
        game.closeGame();
        assertEq(depositPortal.callCount(), 1, "initial enqueue");
        _assertLatestRoots(0, bytes32(0), bytes32(0));

        // Any relayer can enqueue the same current anchor again, and the retry can land.
        vm.prank(relayer);
        postAnchor.push();
        assertEq(depositPortal.callCount(), 2, "same-height retry enqueued");
        assertTrue(_deliverCapturedDeposit(), "retry delivery succeeds");
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);

        // If the original delivery later lands too, strict monotonicity rejects the duplicate.
        assertFalse(_deliverCapturedDeposit(), "late duplicate is stale");
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
    }

    function test_e2e_currentAnchorRemainsRetryableAfterRetirement() public {
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game);

        game.closeGame();
        assertEq(depositPortal.callCount(), 1, "initial enqueue");

        // Retirement affects whether a game may become a new anchor, but ASR intentionally keeps
        // the existing anchor as its recovery starting point.
        anchorStateRegistry.updateRetirementTimestamp();
        assertEq(address(anchorStateRegistry.anchorGame()), address(game), "current anchor retained");
        assertFalse(anchorStateRegistry.isGameClaimValid(IDisputeGame(address(game))), "candidate validity changed");

        // PostAnchor trusts the ASR's stored anchor and can still retry its missed delivery.
        vm.prank(relayer);
        postAnchor.push();
        assertEq(depositPortal.callCount(), 2, "retired current anchor remains retryable");
        assertTrue(_deliverCapturedDeposit(), "retirement retry delivery succeeds");
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
    }

    // ---------------------------------------------------------------------------------------------
    // Target-chain failure / no-partial-effect paths.
    // ---------------------------------------------------------------------------------------------

    function test_targetChain_rejectsUnauthorizedCallerNoStateChange() public {
        // Build a real producer-shaped message via the full close+push path first.
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game);
        game.closeGame();
        bytes memory data = depositPortal.lastData();

        // The raw (un-aliased) forwarder address is not authorized.
        vm.prank(address(postAnchor));
        (bool ok1,) = address(rootManager).call(data);
        assertFalse(ok1, "raw forwarder address must be rejected");

        // An arbitrary account is not authorized either.
        vm.prank(relayer);
        (bool ok2,) = address(rootManager).call(data);
        assertFalse(ok2, "arbitrary caller must be rejected");

        // Direct typed call surfaces the specific error.
        vm.prank(relayer);
        vm.expectRevert(Unauthorized.selector);
        rootManager.record(WITHDRAWAL_ROOT, FORCE_ROOT, SEQ_1);

        // No partial effect: the sink is still empty.
        _assertLatestRoots(0, bytes32(0), bytes32(0));

        // The legitimate aliased delivery still works afterwards.
        assertTrue(_deliverCapturedDeposit(), "aliased delivery still works");
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
    }

    function test_targetChain_rejectsEitherZeroRootNoStateChange() public {
        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedForwarder);
        rootManager.record(bytes32(0), FORCE_ROOT, SEQ_1);

        vm.expectRevert(InvalidRoot.selector);
        vm.prank(aliasedForwarder);
        rootManager.record(WITHDRAWAL_ROOT, bytes32(0), SEQ_1);

        _assertCheckpointRoots(SEQ_1, bytes32(0), bytes32(0));
        _assertLatestRoots(0, bytes32(0), bytes32(0));
    }

    function test_targetChain_exactReplayAndLowerHeightRevert() public {
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game);
        game.closeGame();

        // First delivery records the roots.
        assertTrue(_deliverCapturedDeposit(), "first record");
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);

        // Replaying the identical message is not strictly newer and therefore reverts.
        vm.prank(aliasedForwarder);
        vm.expectRevert(StaleRoot.selector);
        rootManager.record(WITHDRAWAL_ROOT, FORCE_ROOT, SEQ_1);

        // A strictly lower height also reverts as stale.
        vm.prank(aliasedForwarder);
        vm.expectRevert(StaleRoot.selector);
        rootManager.record(WITHDRAWAL_ROOT, FORCE_ROOT, SEQ_1 - 1);

        // Neither rejected delivery changes state.
        _assertCheckpointRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
    }

    function test_targetChain_sameHeightDifferentRootsRevert() public {
        OPSuccinctFaultDisputeGame game = _createExtendedGame(SEQ_1, BLOCK_HASH, APP_HASH, WITHDRAWAL_ROOT, FORCE_ROOT);
        _resolveAndFinalize(game);
        game.closeGame();
        assertTrue(_deliverCapturedDeposit(), "initial record");

        // A differing same-height tuple is not strictly newer and therefore reverts.
        bytes32 correctedW = bytes32(uint256(0x7777));
        bytes32 correctedF = bytes32(uint256(0x8888));
        vm.expectRevert(StaleRoot.selector);
        vm.prank(aliasedForwarder);
        rootManager.record(correctedW, correctedF, SEQ_1);

        _assertCheckpointRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
        _assertLatestRoots(SEQ_1, WITHDRAWAL_ROOT, FORCE_ROOT);
    }

    // ---------------------------------------------------------------------------------------------
    // Legacy game path exerts no target-chain effect.
    // ---------------------------------------------------------------------------------------------

    function test_legacyGame_closeDoesNotPushNoTargetChainEffect() public {
        // Register a legacy implementation (no preimage layout, no forwarder) for this scenario.
        OPSuccinctFaultDisputeGame legacyImpl = _registerImpl(false, address(0));

        Claim claim = Claim.wrap(keccak256("legacy-root"));
        bytes memory legacyExtraData = TZBootstrapExtraData.encodeLegacy(SEQ_1, type(uint32).max);
        vm.prank(proposer);
        OPSuccinctFaultDisputeGame game =
            OPSuccinctFaultDisputeGame(address(factory.create{value: INIT_BOND}(gameType, claim, legacyExtraData)));

        _resolveAndFinalize(game);
        vm.expectEmit(false, false, false, true, address(game));
        emit GameClosed(BondDistributionMode.NORMAL);
        game.closeGame();

        // Legacy game closes normally but never enqueues a deposit and never touches the sink.
        assertEq(uint8(game.bondDistributionMode()), uint8(BondDistributionMode.NORMAL), "legacy closed normal");
        assertEq(depositPortal.callCount(), 0, "no deposit from legacy game");
        _assertLatestRoots(0, bytes32(0), bytes32(0));
        assertEq(legacyImpl.POST_ANCHOR(), address(0), "legacy impl has no forwarder");

        // Four-preimage getters are disabled on the legacy game.
        vm.expectRevert(RootClaimPreimageDisabled.selector);
        game.withdrawalRoot();
    }
}
