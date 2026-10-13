// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUniversalMultiSigErrors {
    /// @notice The provided owner count is below `MIN_OWNER_COUNT`.
    error InvalidOwnersCount();

    /// @notice An owner address is zero, this contract, or already an owner.
    error InvalidOwner();

    /// @notice A delegated approval signature is invalid for the claimed owner.
    error InvalidSignature();

    /// @notice The owner has already approved this transaction.
    error AlreadyApproved();

    /// @notice The caller has no approval to revoke for this transaction.
    error NotApproved();

    /// @notice A batch target is the zero address.
    error InvalidTarget();

    /// @notice The caller is not authorized to perform this action.
    error UnauthorizedCaller();

    /// @notice The transaction has not reached the approval threshold.
    error UnauthorizedTx();

    /// @notice A call in the batch reverted.
    /// @param reason The revert data of the failed call.
    error TxFailed(bytes reason);

    /// @notice Batch arrays are empty or have mismatched lengths.
    error InvalidArguments();

    /// @notice The address is already an owner of the current version.
    error AlreadyOwner();
}
