// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { UniversalMultiSig } from "../../src/UniversalMultiSig.sol";

/// @notice Certora-only harness exposing the internal keccak key helper so CVL
/// can address `_isOwner` storage across owners versions (CVL has no abi.encode).
contract UniversalMultiSigHarness is UniversalMultiSig {
    constructor(address[] memory owners) UniversalMultiSig(owners) {}

    function ownerHashFor(address owner, uint256 ownerVersion) external pure returns (bytes32) {
        return _getOwnerHash(owner, ownerVersion);
    }
}
