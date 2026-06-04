// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @notice Local SP1 verifier interface kept on Solidity 0.8.15 so OP Stack contracts
///         pinned to 0.8.15 do not import the upstream 0.8.20 interface into the same
///         compilation unit.
interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}
