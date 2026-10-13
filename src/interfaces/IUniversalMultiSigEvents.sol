// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUniversalMultiSigEvents {
    /// @notice `owner` approved `txHash`; `executor` is the account that registered the approval
    /// (the owner itself, or the caller submitting a delegated approval).
    event TxApproved(address indexed owner, address indexed executor, bytes32 txHash);

    /// @notice `owner` revoked its approval of `txHash`.
    event TxRevoked(address indexed owner, bytes32 txHash);

    /// @notice The owner set was replaced by `owners`, moving to version `ownersVersion`.
    event OwnersUpdated(address[] owners, uint256 ownersVersion);

    /// @notice A batch was executed by `caller` at transaction nonce `txNonce`.
    event TxExecuted(address indexed caller, bytes32 txHash, uint256 txNonce);
}
