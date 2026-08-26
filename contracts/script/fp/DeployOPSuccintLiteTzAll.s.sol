// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import { Script, console2 } from "forge-std/Script.sol";
import { Proxy } from "src/universal/Proxy.sol";
import { DisputeGameFactory } from "src/dispute/DisputeGameFactory.sol";
import { AnchorStateRegistry } from "src/dispute/AnchorStateRegistry.sol";
import { IDisputeGameFactory } from "interfaces/dispute/IDisputeGameFactory.sol";
import { IDisputeGame } from "interfaces/dispute/IDisputeGame.sol";
import { IAnchorStateRegistry } from "interfaces/dispute/IAnchorStateRegistry.sol";
import { ISystemConfig } from "interfaces/L1/ISystemConfig.sol";
import { MockSystemConfig } from "src/utils/MockSystemConfig.sol";
import {AccessManager} from "../../src/fp/AccessManager.sol";
import {SP1MockVerifier} from "src/utils/SP1MockVerifier.sol";
import {ISP1Verifier} from "src/fp/interfaces/ISP1Verifier.sol";
import {OPSuccinctFaultDisputeGame} from "../../src/fp/OPSuccinctFaultDisputeGame.sol";
import { Duration, GameType, Hash, Proposal } from "src/dispute/lib/Types.sol";
import { OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE } from "src/lib/Types.sol";

contract DeployOPSuccinctLiteTzAll is Script {
    struct DeployResult {
        address factory;
        address anchorStateRegistry;
        address accessManager;
        address gameImpl;
    }
    GameType internal constant OP_SUCCINCT_GAME_TYPE = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);

    bytes32 internal constant DEFAULT_ANCHOR_BLOCK_HASH = keccak256("genesis-block");
    bytes32 internal constant DEFAULT_ANCHOR_STATE_HASH = keccak256("genesis-state");
    uint256 internal constant DEFAULT_ANCHOR_L2_BLOCK = 0;

    function run() external returns (DeployResult memory result) {
        uint256 deployerKey = vm.envUint("DEPLOYER_SK");
        address deployer = vm.addr(deployerKey);
        address proposer_ = vm.envAddress("PROPOSER");
        address challenger_ = vm.envAddress("CHALLENGER");

        vm.startBroadcast(deployerKey);

        bytes32 anchorBlockHash = vm.envOr("ANCHOR_BLOCK_HASH", DEFAULT_ANCHOR_BLOCK_HASH);
        bytes32 anchorStateHash = vm.envOr("ANCHOR_STATE_HASH", DEFAULT_ANCHOR_STATE_HASH);
        uint256 anchorL2Block = vm.envOr("ANCHOR_L2_BLOCK", DEFAULT_ANCHOR_L2_BLOCK);
        uint256 fallbackTimeoutFpSecs = vm.envOr("FALLBACK_TIMEOUT_FP_SECS", type(uint256).max);

        DisputeGameFactory factory = _deployFactory(deployer);

        AnchorStateRegistry asr = _deployASR(deployer, factory, anchorBlockHash, anchorStateHash, anchorL2Block);

        AccessManager accessManager = _deployAccessManager(fallbackTimeoutFpSecs, address(factory), proposer_, challenger_);

        OPSuccinctFaultDisputeGame gameImpl = _deployGameImpl(factory, asr, accessManager);

        configureFactory(deployer, address(factory), OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE, 1000, address(gameImpl));

        vm.stopBroadcast();

        console2.log("=== Deployed (fork mode) ===");
        console2.log("DisputeGameFactory   :", address(factory));
        console2.log("AnchorStateRegistry  :", address(asr));
        console2.log("AccessManager        :", address(accessManager));
        console2.log("GameImpl             :", address(gameImpl));

        result = DeployResult({
            factory: address(factory),
            anchorStateRegistry: address(asr),
            accessManager: address(accessManager),
            gameImpl: address(gameImpl)
        });
    }

    function configureFactory(address, address factoryAddress, uint32 gameTypeValue, uint256 initialBondWei, address gameImplAddress)
        internal
    {
        DisputeGameFactory factory = DisputeGameFactory(factoryAddress);
        GameType gameType = GameType.wrap(gameTypeValue);

        factory.setInitBond(gameType, initialBondWei);
        factory.setImplementation(gameType, IDisputeGame(gameImplAddress));

        console2.log("Factory configured with game type:", uint256(gameTypeValue));
    }


    function _deployGameImpl(
        DisputeGameFactory factory,
        AnchorStateRegistry asr,
        AccessManager accessManager
    ) internal returns (OPSuccinctFaultDisputeGame) {
        SP1MockVerifier sp1Verifier = new SP1MockVerifier();
        bytes32 rollupConfigHash = vm.envOr("ROLLUP_CONFIG_HASH", bytes32(0));
        // in ci, sp1 proof is mocked. So we donot concern the AGGREGATION_VKEY correctness. So leave it zero. 
        bytes32 aggregationVkey = vm.envOr("AGGREGATION_VKEY", bytes32(0)); 
        bytes32 rangeVkeyCommitment = vm.envOr("RANGE_VKEY_COMMITMENT", bytes32(0));
        return new OPSuccinctFaultDisputeGame(
            Duration.wrap(3600),
            Duration.wrap(3600),
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            rollupConfigHash,
            aggregationVkey,
            rangeVkeyCommitment,
            100000,
            IAnchorStateRegistry(address(asr)),
            accessManager,
            true,
            vm.envOr("POST_ANCHOR_ADDRESS", address(0))
        );
    }

    function _deployFactory(address deployer) internal returns (DisputeGameFactory) {
        DisputeGameFactory factoryImpl = new DisputeGameFactory();
        Proxy p = new Proxy(deployer);
        p.upgradeToAndCall(address(factoryImpl), abi.encodeCall(factoryImpl.initialize, (deployer)));
        return DisputeGameFactory(address(p));
    }

    function _deployAccessManager(
        uint256 fallbackTimeoutFpSecs,
        address factoryAddress,
        address proposerAddress,
        address challengerAddress
    ) internal returns (AccessManager) {
        AccessManager accessManager = new AccessManager(fallbackTimeoutFpSecs, IDisputeGameFactory(factoryAddress));
        console2.log("Access manager deployed at:", address(accessManager));
        console2.log("Permissionless fallback timeout (seconds):", fallbackTimeoutFpSecs);

        accessManager.setProposer(proposerAddress, true);
        console2.log("Added proposer:", proposerAddress);
        accessManager.setChallenger(challengerAddress, true);
        console2.log("Added challenger:", challengerAddress);

        return accessManager;
    }

    function _deployASR(
        address deployer,
        DisputeGameFactory factory,
        bytes32 anchorBlockHash,
        bytes32 anchorStateHash,
        uint256 anchorL2Block
    )
        internal
        returns (AnchorStateRegistry)
    {
        MockSystemConfig sc = new MockSystemConfig(deployer);
        AnchorStateRegistry asrImpl = new AnchorStateRegistry(0);
        Proxy p = new Proxy(deployer);
        p.upgradeToAndCall(
            address(asrImpl),
            abi.encodeCall(
                asrImpl.initialize,
                (
                    ISystemConfig(address(sc)),
                    IDisputeGameFactory(address(factory)),
                    Proposal({
                        root: Hash.wrap(keccak256(abi.encode(anchorBlockHash, anchorStateHash))),
                        l2SequenceNumber: anchorL2Block
                    }),
                    OP_SUCCINCT_GAME_TYPE
                )
            )
        );
        return AnchorStateRegistry(address(p));
    }
}
