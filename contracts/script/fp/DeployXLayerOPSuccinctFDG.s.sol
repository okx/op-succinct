// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Libraries
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Duration, GameType} from "src/dispute/lib/Types.sol";

// Interfaces
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {ISP1Verifier} from "../../src/fp/interfaces/ISP1Verifier.sol";

// Contracts
import {AccessManager} from "../../src/fp/AccessManager.sol";
import {XLayerOPSuccinctFaultDisputeGame} from "../../src/fp/XLayerOPSuccinctFaultDisputeGame.sol";

contract DeployXLayerOPSuccinctFDG is Script {
    function run() public returns (address gameImpl) {
        vm.startBroadcast();

        address factoryAddress = vm.envAddress("FACTORY_ADDRESS");
        XLayerOPSuccinctFaultDisputeGame newImpl = deployImplementation(factoryAddress);

        console.log("XLayerOPSuccinctFaultDisputeGame implementation deployed at:", address(newImpl));
        console.log("Factory:", factoryAddress);

        vm.stopBroadcast();

        return address(newImpl);
    }

    function deployImplementation(address factoryAddress) internal returns (XLayerOPSuccinctFaultDisputeGame) {
        return new XLayerOPSuccinctFaultDisputeGame(
            Duration.wrap(uint64(vm.envUint("MAX_CHALLENGE_DURATION"))),
            Duration.wrap(uint64(vm.envUint("MAX_PROVE_DURATION"))),
            GameType.wrap(uint32(vm.envUint("GAME_TYPE"))),
            IDisputeGameFactory(factoryAddress),
            ISP1Verifier(vm.envAddress("VERIFIER_ADDRESS")),
            vm.envBytes32("ROLLUP_CONFIG_HASH"),
            vm.envBytes32("AGGREGATION_VKEY"),
            vm.envBytes32("RANGE_VKEY_COMMITMENT"),
            vm.envBytes32("TEE_PCR_COMMITMENT"),
            vm.envUint("CHALLENGER_BOND_WEI"),
            IAnchorStateRegistry(vm.envAddress("ANCHOR_STATE_REGISTRY")),
            AccessManager(vm.envAddress("ACCESS_MANAGER"))
        );
    }
}
