// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title TZBootstrapExtraData
/// @notice Shared, pure encoder for the TradeZone extended dispute-game creation payload. It is the
///         single source of truth for the four-preimage `extraData` byte layout and for the
///         `rootClaim` commitment, and it is used by BOTH the TradeZone deploy script (the bootstrap
///         game producer) and the deterministic encoder tests, so the producer and its verification
///         cannot drift apart.
/// @dev An extended `OPSuccinctFaultDisputeGame` implementation (constructed with
///      `hasRootClaimPreimage_ == true`) accepts only a 164-byte `extraData` laid out as:
///
///        offset  size  field
///        0x00    32    l2SequenceNumber
///        0x20    4     parentIndex
///        0x24    32    blockHash
///        0x44    32    appHash
///        0x64    32    withdrawalRoot
///        0x84    32    forceRoot
///
///      and it binds `rootClaim == keccak256(blockHash . appHash . withdrawalRoot . forceRoot)`.
///      A legacy implementation (`hasRootClaimPreimage_ == false`) accepts only the 36-byte
///      `l2SequenceNumber . parentIndex` layout. Both layouts and the commitment field order mirror
///      the on-chain `initialize()` length guard and commitment check exactly, and the four preimage
///      offsets match the on-chain getters (blockHash, appHash, withdrawalRoot, forceRoot at CWIA
///      offsets 0x78, 0x98, 0xB8, 0xD8, i.e. extraData offsets 0x24, 0x44, 0x64, 0x84).
library TZBootstrapExtraData {
    /// @notice Byte length of the legacy (non-four-preimage) `extraData` payload.
    uint256 internal constant LEGACY_EXTRA_DATA_LEN = 36;

    /// @notice Byte length of the extended (four-preimage) `extraData` payload.
    uint256 internal constant EXTENDED_EXTRA_DATA_LEN = 164;

    /// @notice Encodes the legacy 36-byte `extraData` (`l2SequenceNumber . parentIndex`).
    /// @param l2SequenceNumber The proposed L2 sequence (block) number.
    /// @param parentIndex The parent game index; `type(uint32).max` starts from the current anchor.
    /// @return payload The 36-byte legacy payload.
    function encodeLegacy(uint256 l2SequenceNumber, uint32 parentIndex) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(l2SequenceNumber, parentIndex);
    }

    /// @notice Encodes the extended 164-byte four-preimage `extraData`.
    /// @param l2SequenceNumber The proposed L2 sequence (block) number.
    /// @param parentIndex The parent game index; `type(uint32).max` starts from the current anchor.
    /// @param blockHash The committed block hash preimage.
    /// @param appHash The committed app hash preimage.
    /// @param withdrawalRoot The committed withdrawal root preimage.
    /// @param forceRoot The committed force root preimage.
    /// @return payload The 164-byte extended payload, laid out to match the on-chain preimage getters.
    function encodeExtended(
        uint256 l2SequenceNumber,
        uint32 parentIndex,
        bytes32 blockHash,
        bytes32 appHash,
        bytes32 withdrawalRoot,
        bytes32 forceRoot
    ) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(l2SequenceNumber, parentIndex, blockHash, appHash, withdrawalRoot, forceRoot);
    }

    /// @notice Computes the extended `rootClaim` exactly as the on-chain game verifies it.
    /// @dev Fixed field order: blockHash, appHash, withdrawalRoot, forceRoot.
    /// @param blockHash The committed block hash preimage.
    /// @param appHash The committed app hash preimage.
    /// @param withdrawalRoot The committed withdrawal root preimage.
    /// @param forceRoot The committed force root preimage.
    /// @return rootClaim `keccak256(blockHash . appHash . withdrawalRoot . forceRoot)`.
    function commitRootClaim(bytes32 blockHash, bytes32 appHash, bytes32 withdrawalRoot, bytes32 forceRoot)
        internal
        pure
        returns (bytes32 rootClaim)
    {
        rootClaim = keccak256(abi.encodePacked(blockHash, appHash, withdrawalRoot, forceRoot));
    }
}
