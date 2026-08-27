// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import {SP1MockVerifier} from "src/utils/SP1MockVerifier.sol";

contract DeployMockVerifier is Script {
    function run() external returns (address) {
        vm.startBroadcast();
        SP1MockVerifier verifier = new SP1MockVerifier();
        vm.stopBroadcast();
        console.log("Deployed SP1MockVerifier at:", address(verifier));
        return address(verifier);
    }
}
