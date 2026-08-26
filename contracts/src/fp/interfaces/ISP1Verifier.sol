// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title SP1 Verifier Interface
/// @author Succinct Labs
/// @notice Compatibility interface for verifier contracts used by the Solidity 0.8.15 dispute-game graph.
interface ISP1Verifier {
    /// @notice Verifies a proof with the given program verification key and public values.
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

interface ISP1VerifierWithHash is ISP1Verifier {
    /// @notice Returns the verifier implementation hash.
    function VERIFIER_HASH() external pure returns (bytes32);
}
