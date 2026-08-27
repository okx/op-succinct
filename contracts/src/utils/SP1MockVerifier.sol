// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {ISP1Verifier} from "src/fp/interfaces/ISP1Verifier.sol";

/// @title SP1 Mock Verifier
/// @author Succinct Labs
/// @notice Accepts only an empty proof, for local deployments and tests.
contract SP1MockVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata proofBytes) external pure {
        assert(proofBytes.length == 0);
    }
}
