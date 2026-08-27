// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Libraries
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Claim, Duration, GameType} from "src/dispute/lib/Types.sol";

// Interfaces
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {ISP1Verifier} from "src/fp/interfaces/ISP1Verifier.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";

// Contracts
import {AccessManager} from "../../src/fp/AccessManager.sol";
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {OPSuccinctFaultDisputeGame} from "../../src/fp/OPSuccinctFaultDisputeGame.sol";
import {SP1MockVerifier} from "src/utils/SP1MockVerifier.sol";
import {Transactor} from "@optimism/src/periphery/Transactor.sol";

// Utils
import {Utils} from "../../test/helpers/Utils.sol";
import {TZBootstrapExtraData} from "../../test/helpers/TZBootstrapExtraData.sol";

/// @title DeployOPSuccinctLiteTz
/// @notice TradeZone (tz) variant of DeployOPSuccinctLite.
///
/// Steps:
///   1. Deploy a *bootstrap* OPSuccinctFaultDisputeGame impl with zero challenge /
///      prove windows so the game is closable as soon as a single block passes
///      after creation.
///   2. Register it on the factory.
///   3. Optionally create a single bootstrap game that will become the new anchor
///      once it is resolved and closed. This variant registers an extended
///      (HAS_ROOT_CLAIM_PREIMAGE = true) implementation, which accepts only a
///      164-byte four-preimage extraData bound to
///      rootClaim = keccak256(blockHash . appHash . withdrawalRoot . forceRoot).
///      The bootstrap game is created only when all four preimages are supplied via
///      env; otherwise it is intentionally skipped (the approved design forbids
///      creating an extended game with a legacy payload before activation).
///   4. Deploy the *production* impl (durations come from JSON) and swap the
///      factory implementation to point at it, so subsequent games use the real
///      challenge window.
///
/// `resolve()` and `closeGame()` for the bootstrap game are intentionally NOT
/// done here — anvil advances block.timestamp by exactly 1s per block, which is
/// too tight to be reliable inside a single forge broadcast, and on production
/// chains `closeGame()` also needs `disputeGameFinalityDelaySeconds` to elapse.
/// Use `contracts/close-games.sh` afterwards to advance the bootstrap game.
///
/// Required environment variables:
///   FACTORY_ADDRESS                     — DisputeGameFactory
///   ANCHOR_STATE_REGISTRY               — AnchorStateRegistry
///   TRANSACTOR                          — Transactor owning the factory
///   BOOTSTRAP_L2_BLOCK_NUMBER (uint256) — l2 block number for the bootstrap game
///
/// Optional bootstrap-game preimages (all four required to create the bootstrap game;
/// omit them before activation to skip creation):
///   BOOTSTRAP_BLOCK_HASH (bytes32)      — committed block hash
///   BOOTSTRAP_APP_HASH (bytes32)        — committed app hash
///   BOOTSTRAP_WITHDRAWAL_ROOT (bytes32) — committed withdrawal root
///   BOOTSTRAP_FORCE_ROOT (bytes32)      — committed force root
///   BOOTSTRAP_ROOT_CLAIM (bytes32)      — optional; if set, must equal
///                                         keccak256(blockHash.appHash.withdrawalRoot.forceRoot)
///
/// PostAnchor configuration:
///   - `config/tz/opsuccinctfdgconfig.json` is the sole source of the implementation's
///     `hasRootClaimPreimage` and `postAnchorAddress` constructor arguments.
///   - A zero `postAnchorAddress` is rejected by default. Set
///     `ALLOW_DEGRADED_POST_ANCHOR=true` only when intentionally deploying without automatic
///     anchor synchronization.
///
/// Caller requirements:
///   - The broadcasting EOA must be whitelisted as a proposer in AccessManager
///     (or AccessManager must be in permissionless mode), otherwise initialize()
///     reverts with BadAuth.
///   - The broadcasting EOA must hold at least config.initialBondWei to fund
///     factory.create{value: ...}().
contract DeployOPSuccinctLiteTz is Script, Utils {
    /// @notice Resolved constructor configuration shared by bootstrap and production implementations.
    struct ImplementationConfig {
        bool hasRootClaimPreimage;
        address postAnchor;
    }

    /// @notice Bundle returned by run() for downstream tooling.
    struct DeployResult {
        address bootstrapImpl;
        address productionImpl;
        address bootstrapGame;
        address sp1Verifier;
        address accessManager;
    }

    function run() public returns (DeployResult memory result) {
        // -----------------------------------------------------------------
        // 1. Load config + env
        // -----------------------------------------------------------------
        FDGConfig memory config = readFDGJson("config/tz/opsuccinctfdgconfig.json");
        ImplementationConfig memory implementationConfig = _resolveImplementationConfig(config);

        address factoryAddress = vm.envAddress("FACTORY_ADDRESS");
        address registryAddress = vm.envAddress("ANCHOR_STATE_REGISTRY");

        // Optional now: for the extended TradeZone implementation the bootstrap rootClaim is derived
        // from the four preimages (see _createBootstrapGame). When supplied it is cross-checked.
        bytes32 bootstrapRoot = vm.envOr("BOOTSTRAP_ROOT_CLAIM", bytes32(0));
        uint256 bootstrapBlock = vm.envUint("BOOTSTRAP_L2_BLOCK_NUMBER");

        vm.startBroadcast();

        // -----------------------------------------------------------------
        // 2. AccessManager + SP1 verifier (same as Lite)
        // -----------------------------------------------------------------
        AccessManager accessManagerContract = deployAccessManager(
            config.fallbackTimeoutFpSecs,
            factoryAddress,
            config.permissionlessMode,
            config.proposerAddresses,
            config.challengerAddresses
        );

        SP1Config memory sp1Config = deploySP1Verifier(
            config.useSp1MockVerifier,
            config.verifierAddress,
            config.rollupConfigHash,
            config.aggregationVkey,
            config.rangeVkeyCommitment
        );

        // -----------------------------------------------------------------
        // 3. Deploy + register BOOTSTRAP impl with zero challenge window
        // -----------------------------------------------------------------
        // Zero-second windows: deadline = block.timestamp at create. One block
        // later, gameOver() returns true, so close-games.sh can resolve()
        // immediately without waiting on a challenge clock.
        OPSuccinctFaultDisputeGame bootstrapImpl = deployGameImplementation(
            0,
            0,
            DisputeGameFactory(factoryAddress),
            sp1Config,
            IAnchorStateRegistry(registryAddress),
            accessManagerContract,
            config.challengerBondWei,
            implementationConfig
        );
        console.log("Bootstrap impl deployed at:", address(bootstrapImpl));

        configureFactory(factoryAddress, config.gameType, config.initialBondWei, address(bootstrapImpl));

        // -----------------------------------------------------------------
        // 4. Create bootstrap game (resolve + close handled by close-games.sh)
        // -----------------------------------------------------------------
        address bootstrapGameAddr =
            _createBootstrapGame(factoryAddress, config.gameType, config.initialBondWei, bootstrapRoot, bootstrapBlock);

        // -----------------------------------------------------------------
        // 5. Deploy + register PRODUCTION impl (using JSON durations)
        // -----------------------------------------------------------------
        OPSuccinctFaultDisputeGame productionImpl = deployGameImplementation(
            config.maxChallengeDuration,
            config.maxProveDuration,
            DisputeGameFactory(factoryAddress),
            sp1Config,
            IAnchorStateRegistry(registryAddress),
            accessManagerContract,
            config.challengerBondWei,
            implementationConfig
        );
        console.log("Production impl deployed at:", address(productionImpl));

        configureFactory(factoryAddress, config.gameType, config.initialBondWei, address(productionImpl));

        vm.stopBroadcast();

        console.log("");
        console.log("Next step: run ./close-games.sh to resolve + close the bootstrap game.");

        return DeployResult({
            bootstrapImpl: address(bootstrapImpl),
            productionImpl: address(productionImpl),
            bootstrapGame: bootstrapGameAddr,
            sp1Verifier: sp1Config.verifierAddress,
            accessManager: address(accessManagerContract)
        });
    }

    // ---------------------------------------------------------------------
    // Bootstrap helpers
    // ---------------------------------------------------------------------

    /// @dev Creates the bootstrap dispute game. Extracted from run() to keep
    /// the local-variable count down (avoids "stack too deep").
    function _createBootstrapGame(
        address factoryAddress,
        uint32 gameTypeValue,
        uint256 bondWei,
        bytes32 rootClaim,
        uint256 l2BlockNumber
    ) internal returns (address gameAddr) {
        GameType gt = GameType.wrap(gameTypeValue);

        // The game's constructor records `wasRespectedGameTypeWhenCreated` by
        // comparing GAME_TYPE to AnchorStateRegistry.respectedGameType() at
        // creation time. close-games.sh later requires this flag to be true
        // (so the anchor advances on closeGame), so flip the registry first.
        // Broadcasting EOA must be the guardian — true on the xlayer devnet
        // where DEPLOYER_PRIVATE_KEY == systemConfig.guardian().
        address registryAddress = vm.envAddress("ANCHOR_STATE_REGISTRY");
        IAnchorStateRegistry(registryAddress).setRespectedGameType(gt);
        console.log("Set respected game type to:", uint256(gameTypeValue));

        // This TradeZone deploy path registers an extended implementation
        // (HAS_ROOT_CLAIM_PREIMAGE == true), which accepts only a 164-byte four-preimage
        // extraData whose rootClaim equals keccak256(blockHash . appHash . withdrawalRoot .
        // forceRoot). The four preimages are produced off-chain by the fault-proof backend, which
        // is the activation gate and is not available at bootstrap/deploy time. The approved design
        // forbids creating an extended Game with a legacy payload before activation, so this
        // producer creates the bootstrap Game only when all four preimages are supplied via env;
        // otherwise it intentionally does NOT create one (no silent legacy payload) and leaves the
        // first valid extended Game to the backend at activation.
        bytes32 bootBlockHash = vm.envOr("BOOTSTRAP_BLOCK_HASH", bytes32(0));
        bytes32 bootAppHash = vm.envOr("BOOTSTRAP_APP_HASH", bytes32(0));
        bytes32 bootWithdrawalRoot = vm.envOr("BOOTSTRAP_WITHDRAWAL_ROOT", bytes32(0));
        bytes32 bootForceRoot = vm.envOr("BOOTSTRAP_FORCE_ROOT", bytes32(0));

        if (
            bootBlockHash == bytes32(0) || bootAppHash == bytes32(0) || bootWithdrawalRoot == bytes32(0)
                || bootForceRoot == bytes32(0)
        ) {
            console.log("Bootstrap game skipped: extended implementation requires four preimages.");
            console.log("Set BOOTSTRAP_BLOCK_HASH / BOOTSTRAP_APP_HASH / BOOTSTRAP_WITHDRAWAL_ROOT /");
            console.log("BOOTSTRAP_FORCE_ROOT to create it; before activation, skipping is expected.");
            return address(0);
        }

        // Bind the rootClaim to the four preimages exactly as the Game verifies on-chain, using the
        // shared encoder that the deterministic tests also exercise.
        bytes32 committedRootClaim =
            TZBootstrapExtraData.commitRootClaim(bootBlockHash, bootAppHash, bootWithdrawalRoot, bootForceRoot);
        require(
            rootClaim == bytes32(0) || rootClaim == committedRootClaim,
            "BOOTSTRAP_ROOT_CLAIM must equal keccak256(blockHash.appHash.withdrawalRoot.forceRoot)"
        );

        // First game in the chain: parent index is uint32.max so the game starts from the current
        // anchor root in the registry. The extended 164-byte payload is built by the shared encoder.
        bytes memory extraData = TZBootstrapExtraData.encodeExtended(
            l2BlockNumber, type(uint32).max, bootBlockHash, bootAppHash, bootWithdrawalRoot, bootForceRoot
        );

        IDisputeGame created =
            DisputeGameFactory(factoryAddress).create{value: bondWei}(gt, Claim.wrap(committedRootClaim), extraData);
        gameAddr = address(created);
        console.log("Bootstrap game created at:", gameAddr);
        console.log("  l2BlockNumber:", l2BlockNumber);
        console.logBytes32(committedRootClaim);
    }

    // ---------------------------------------------------------------------
    // Everything below is unchanged from DeployOPSuccinctLite.s.sol
    // ---------------------------------------------------------------------

    function configureFactory(
        address factoryAddress,
        uint32 gameTypeValue,
        uint256 initialBondWei,
        address gameImplAddress
    ) internal {
        address transactorAddress = vm.envAddress("TRANSACTOR");

        Transactor transactor = Transactor(transactorAddress);
        GameType gameType = GameType.wrap(gameTypeValue);

        bytes memory setInitBondData =
            abi.encodeWithSelector(DisputeGameFactory.setInitBond.selector, gameType, initialBondWei);

        try transactor.CALL(factoryAddress, setInitBondData, 0) returns (bool success1, bytes memory) {
            require(success1, "Transactor.CALL returned false for setInitBond");
        } catch Error(string memory reason) {
            revert(string.concat("Failed to set initial bond via Transactor: ", reason));
        } catch (bytes memory) {
            revert("Failed to set initial bond via Transactor: low-level call reverted");
        }

        bytes memory setImplementationData =
            abi.encodeWithSignature("setImplementation(uint32,address)", GameType.unwrap(gameType), gameImplAddress);

        try transactor.CALL(factoryAddress, setImplementationData, 0) returns (bool success2, bytes memory) {
            require(success2, "Transactor.CALL returned false for setImplementation");
        } catch Error(string memory reason) {
            revert(string.concat("Failed to set implementation via Transactor: ", reason));
        } catch (bytes memory) {
            revert("Failed to set implementation via Transactor: low-level call reverted");
        }

        console.log("Factory configured with game type:", uint256(gameTypeValue));
    }

    function deployAccessManager(
        uint256 fallbackTimeoutFpSecs,
        address factoryAddress,
        bool permissionlessMode,
        address[] memory proposerAddresses,
        address[] memory challengerAddresses
    ) internal returns (AccessManager) {
        AccessManager accessManager = new AccessManager(fallbackTimeoutFpSecs, IDisputeGameFactory(factoryAddress));
        console.log("Access manager deployed at:", address(accessManager));
        console.log("Permissionless fallback timeout (seconds):", fallbackTimeoutFpSecs);

        if (permissionlessMode) {
            accessManager.setProposer(address(0), true);
            accessManager.setChallenger(address(0), true);
            console.log("Access Manager configured for permissionless mode");
        } else {
            for (uint256 i = 0; i < proposerAddresses.length; i++) {
                if (proposerAddresses[i] != address(0)) {
                    accessManager.setProposer(proposerAddresses[i], true);
                    console.log("Added proposer:", proposerAddresses[i]);
                }
            }
            for (uint256 i = 0; i < challengerAddresses.length; i++) {
                if (challengerAddresses[i] != address(0)) {
                    accessManager.setChallenger(challengerAddresses[i], true);
                    console.log("Added challenger:", challengerAddresses[i]);
                }
            }
        }

        return accessManager;
    }

    function deploySP1Verifier(
        bool useSp1MockVerifier,
        address verifierAddress,
        bytes32 rollupConfigHash,
        bytes32 aggregationVkey,
        bytes32 rangeVkeyCommitment
    ) internal returns (SP1Config memory) {
        SP1Config memory sp1Config;
        sp1Config.rollupConfigHash = rollupConfigHash;
        sp1Config.aggregationVkey = aggregationVkey;
        sp1Config.rangeVkeyCommitment = rangeVkeyCommitment;

        if (useSp1MockVerifier) {
            SP1MockVerifier sp1Verifier = new SP1MockVerifier();
            sp1Config.verifierAddress = address(sp1Verifier);
            console.log("Using SP1 Mock Verifier:", address(sp1Verifier));
        } else {
            require(verifierAddress != address(0), "Missing SP1 verifier address");
            sp1Config.verifierAddress = verifierAddress;
            console.log("Using SP1 Verifier Gateway:", verifierAddress);
        }

        return sp1Config;
    }

    function deployGameImplementation(
        uint256 maxChallengeDuration,
        uint256 maxProveDuration,
        DisputeGameFactory factory,
        SP1Config memory sp1Config,
        IAnchorStateRegistry registry,
        AccessManager accessManager,
        uint256 challengerBondWei,
        ImplementationConfig memory implementationConfig
    ) internal returns (OPSuccinctFaultDisputeGame) {
        OPSuccinctFaultDisputeGame implementation = new OPSuccinctFaultDisputeGame(
            Duration.wrap(uint64(maxChallengeDuration)),
            Duration.wrap(uint64(maxProveDuration)),
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(sp1Config.verifierAddress),
            sp1Config.rollupConfigHash,
            sp1Config.aggregationVkey,
            sp1Config.rangeVkeyCommitment,
            challengerBondWei,
            registry,
            accessManager,
            implementationConfig.hasRootClaimPreimage,
            implementationConfig.postAnchor
        );

        require(
            implementation.HAS_ROOT_CLAIM_PREIMAGE() == implementationConfig.hasRootClaimPreimage,
            "HAS_ROOT_CLAIM_PREIMAGE mismatch"
        );
        require(implementation.POST_ANCHOR() == implementationConfig.postAnchor, "POST_ANCHOR mismatch");

        return implementation;
    }

    /// @dev Resolves the immutable implementation configuration before broadcasting any transaction.
    ///      TradeZone always requires the extended 164-byte claim layout. Automatic synchronization
    ///      may be disabled only through an explicit degraded-mode opt-in.
    function _resolveImplementationConfig(FDGConfig memory config)
        internal
        view
        returns (ImplementationConfig memory implementationConfig)
    {
        bool allowDegradedPostAnchor = vm.envOr("ALLOW_DEGRADED_POST_ANCHOR", false);
        return _validateImplementationConfig(config, allowDegradedPostAnchor);
    }

    function _validateImplementationConfig(FDGConfig memory config, bool allowDegradedPostAnchor)
        internal
        pure
        returns (ImplementationConfig memory implementationConfig)
    {
        require(config.hasRootClaimPreimage, "TradeZone requires root-claim preimages");
        require(
            config.postAnchorAddress != address(0) || allowDegradedPostAnchor,
            "postAnchorAddress is zero; explicitly enable degraded mode"
        );

        implementationConfig = ImplementationConfig({
            hasRootClaimPreimage: config.hasRootClaimPreimage, postAnchor: config.postAnchorAddress
        });
    }
}
