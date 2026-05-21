// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Libraries
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Claim, Duration, GameStatus, GameType} from "src/dispute/lib/Types.sol";

// Interfaces
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {ISP1Verifier} from "@sp1-contracts/src/ISP1Verifier.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";

// Contracts
import {AccessManager} from "../../src/fp/AccessManager.sol";
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {OPSuccinctFaultDisputeGame} from "../../src/fp/OPSuccinctFaultDisputeGame.sol";
import {SP1MockVerifier} from "@sp1-contracts/src/SP1MockVerifier.sol";
import {Transactor} from "@optimism/src/periphery/Transactor.sol";

// Utils
import {Utils} from "../../test/helpers/Utils.sol";
import {SP1Verifier as SP1VerifierPlonk} from "../../lib/sp1-contracts/contracts/src/v6.1.0/SP1VerifierPlonk.sol";
import {SP1Verifier as SP1VerifierGroth16} from "../../lib/sp1-contracts/contracts/src/v6.1.0/SP1VerifierGroth16.sol";
import {SP1VerifierGateway} from "../../lib/sp1-contracts/contracts/src/SP1VerifierGateway.sol";

/// @title DeployOPSuccinctLiteTz
/// @notice TradeZone (tz) variant of DeployOPSuccinctLite.
///
/// In addition to the standard Lite deployment flow, this script bootstraps the
/// AnchorStateRegistry by:
///   1. Deploying a *bootstrap* OPSuccinctFaultDisputeGame implementation with very
///      short challenge / prove durations (default 1s / 1s).
///   2. Registering it on the factory.
///   3. Creating a single bootstrap game with a known root + l2BlockNumber.
///   4. Letting the challenge deadline lapse (next broadcast block) and calling
///      `resolve()` so the game becomes DEFENDER_WINS.
///   5. Best-effort calling `closeGame()` — this triggers `setAnchorState()` and
///      updates the anchor root. NOTE: this only succeeds if
///      `OptimismPortal2.disputeGameFinalityDelaySeconds()` has elapsed since
///      `resolvedAt`. On chains with a long portal finality delay you must call
///      `closeGame()` separately later.
///   6. Deploying the *production* implementation (durations come from JSON) and
///      swapping the factory implementation to point at it, so subsequent games use
///      the real challenge window.
///
/// Required environment variables:
///   FACTORY_ADDRESS                     — DisputeGameFactory
///   ANCHOR_STATE_REGISTRY               — AnchorStateRegistry
///   TRANSACTOR                          — Transactor owning the factory
///   BOOTSTRAP_ROOT_CLAIM (bytes32)      — root claim for the bootstrap game
///   BOOTSTRAP_L2_BLOCK_NUMBER (uint256) — l2 block number for the bootstrap game
///
/// Caller requirements:
///   - The broadcasting EOA must be whitelisted as a proposer in AccessManager
///     (or AccessManager must be in permissionless mode), otherwise initialize()
///     reverts with BadAuth.
///   - The broadcasting EOA must hold at least config.initialBondWei to fund
///     factory.create{value: ...}().
contract DeployOPSuccinctLiteTz is Script, Utils {
    /// @notice Bundle returned by run() for downstream tooling.
    struct DeployResult {
        address bootstrapImpl;
        address productionImpl;
        address bootstrapGame;
        address sp1Verifier;
        address accessManager;
        bool resolved;
        bool closed;
    }

    function run() public returns (DeployResult memory result) {
        // -----------------------------------------------------------------
        // 1. Load config + env
        // -----------------------------------------------------------------
        FDGConfig memory config = readFDGJson("config/tz/opsuccinctfdgconfig.json");

        address factoryAddress = vm.envAddress("FACTORY_ADDRESS");
        address registryAddress = vm.envAddress("ANCHOR_STATE_REGISTRY");

        bytes32 bootstrapRoot = vm.envBytes32("BOOTSTRAP_ROOT_CLAIM");
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
            config.useSp1MockVerifier, config.rollupConfigHash, config.aggregationVkey, config.rangeVkeyCommitment
        );

        // -----------------------------------------------------------------
        // 3. Deploy + register BOOTSTRAP impl with tiny challenge window
        // -----------------------------------------------------------------
        // 1-second windows: long enough that on any chain with >=1s blocktime the
        // deadline will have passed by the next broadcast tx, short enough that the
        // single bootstrap game finalizes immediately.
        OPSuccinctFaultDisputeGame bootstrapImpl = deployGameImplementation(
            1,
            1,
            DisputeGameFactory(factoryAddress),
            sp1Config,
            IAnchorStateRegistry(registryAddress),
            accessManagerContract,
            config.challengerBondWei
        );
        console.log("Bootstrap impl deployed at:", address(bootstrapImpl));

        configureFactory(factoryAddress, config.gameType, config.initialBondWei, address(bootstrapImpl));

        // -----------------------------------------------------------------
        // 4. Create bootstrap game and try to resolve + close it
        // -----------------------------------------------------------------
        (address bootstrapGameAddr, bool didResolve, bool didClose) = _bootstrapAnchor(
            factoryAddress, config.gameType, config.initialBondWei, bootstrapRoot, bootstrapBlock
        );

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
            config.challengerBondWei
        );
        console.log("Production impl deployed at:", address(productionImpl));

        configureFactory(factoryAddress, config.gameType, config.initialBondWei, address(productionImpl));

        vm.stopBroadcast();

        return DeployResult({
            bootstrapImpl: address(bootstrapImpl),
            productionImpl: address(productionImpl),
            bootstrapGame: bootstrapGameAddr,
            sp1Verifier: sp1Config.verifierAddress,
            accessManager: address(accessManagerContract),
            resolved: didResolve,
            closed: didClose
        });
    }

    // ---------------------------------------------------------------------
    // Bootstrap helpers
    // ---------------------------------------------------------------------

    /// @dev Creates one bootstrap game, then best-effort resolves and closes it.
    /// Splits the work into a helper so the outer run() stays readable and avoids
    /// "stack too deep".
    function _bootstrapAnchor(
        address factoryAddress,
        uint32 gameTypeValue,
        uint256 bondWei,
        bytes32 rootClaim,
        uint256 l2BlockNumber
    ) internal returns (address gameAddr, bool didResolve, bool didClose) {
        GameType gt = GameType.wrap(gameTypeValue);

        // First game in the chain: parent index is uint32.max so the game starts
        // from the current anchor root in the registry.
        bytes memory extraData = abi.encodePacked(l2BlockNumber, type(uint32).max);

        IDisputeGame created = DisputeGameFactory(factoryAddress).create{value: bondWei}(
            gt, Claim.wrap(rootClaim), extraData
        );
        gameAddr = address(created);
        OPSuccinctFaultDisputeGame game = OPSuccinctFaultDisputeGame(gameAddr);
        console.log("Bootstrap game created at:", gameAddr);
        console.log("  l2BlockNumber:", l2BlockNumber);
        console.logBytes32(rootClaim);

        // Try to resolve. With the hardcoded 1s challenge window, the next
        // broadcast tx is in a later block on any chain with >=1s blocktime, so
        // gameOver() returns true. We still wrap in try/catch so the deploy
        // doesn't abort on faster chains; the caller can resolve manually.
        try game.resolve() returns (GameStatus s) {
            didResolve = true;
            console.log("Bootstrap game resolved, status:", uint256(uint8(s)));
        } catch Error(string memory reason) {
            console.log("resolve() reverted:", reason);
        } catch (bytes memory) {
            console.log("resolve() reverted (low-level). Likely deadline not yet passed.");
            console.log("Re-run resolve() in a follow-up tx; deadline is now+BOOTSTRAP_CHALLENGE_DURATION.");
        }

        // Best-effort closeGame() — only succeeds once
        // AnchorStateRegistry.isGameFinalized() is true, which requires
        // resolvedAt + portal.disputeGameFinalityDelaySeconds() < block.timestamp.
        // If the portal uses a long delay, this will revert here; that's fine,
        // the caller just needs to call closeGame() later.
        if (didResolve) {
            try game.closeGame() {
                didClose = true;
                console.log("Bootstrap game closed -- anchor state updated.");
            } catch Error(string memory reason) {
                console.log("closeGame() reverted:", reason);
                console.log("Re-run game.closeGame() after the portal finality delay elapses.");
            } catch (bytes memory) {
                console.log("closeGame() reverted (low-level) -- most likely GameNotFinalized.");
                console.log("Re-run game.closeGame() after the portal finality delay elapses.");
            }
        }
    }

    // ---------------------------------------------------------------------
    // Everything below is unchanged from DeployOPSuccinctLite.s.sol
    // ---------------------------------------------------------------------

    function configureFactory(address factoryAddress, uint32 gameTypeValue, uint256 initialBondWei, address gameImplAddress)
        internal
    {
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
            SP1VerifierPlonk sp1VerifierPlonk = new SP1VerifierPlonk();
            SP1VerifierGroth16 sp1VerifierGroth16 = new SP1VerifierGroth16();
            SP1VerifierGateway sp1VerifierGateway = new SP1VerifierGateway(tx.origin);
            sp1VerifierGateway.addRoute(address(sp1VerifierPlonk));
            sp1VerifierGateway.addRoute(address(sp1VerifierGroth16));
            sp1Config.verifierAddress = address(sp1VerifierGateway);
            console.log("Using SP1 Verifier Gateway:", address(sp1VerifierGateway));
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
        uint256 challengerBondWei
    ) internal returns (OPSuccinctFaultDisputeGame) {
        return new OPSuccinctFaultDisputeGame(
            Duration.wrap(uint64(maxChallengeDuration)),
            Duration.wrap(uint64(maxProveDuration)),
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(sp1Config.verifierAddress),
            sp1Config.rollupConfigHash,
            sp1Config.aggregationVkey,
            sp1Config.rangeVkeyCommitment,
            challengerBondWei,
            registry,
            accessManager
        );
    }
}
