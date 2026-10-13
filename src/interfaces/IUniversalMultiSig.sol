// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IUniversalMultiSigErrors } from "./IUniversalMultiSigErrors.sol";
import { IUniversalMultiSigEvents } from "./IUniversalMultiSigEvents.sol";

interface IUniversalMultiSig is IUniversalMultiSigErrors, IUniversalMultiSigEvents {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Minimum number of owners.
    function MIN_OWNER_COUNT() external pure returns (uint256);

    /// @notice EIP-712 struct hash used for delegated approvals.
    /// @dev Struct: `DelegatedApproval(address owner,bytes32 txHash,address executor,uint256 nonce)`.
    /// - `txHash`: from `getTxHash(targets, values, datas, txNonce)`.
    /// - `executor`: the address that will call `universalTx`.
    /// - `nonce`: the owner's delegation nonce, from `getOwnerDelegationNonce(owner)`.
    /// Validated against the claimed owner: ECDSA for EOA owners, ERC-1271 for contract owners.
    function DELEGATED_APPROVAL_STRUCT_HASH() external pure returns (bytes32);

    /* -------------------------------------------------------------------------- */
    /*                                   OWNERS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Approves `txHash` on behalf of the caller.
    /// @dev Owner-only. Approval is scoped to the current owners version.
    function approveTx(bytes32 txHash) external;

    /// @notice Revokes the caller's approval of `txHash`.
    /// @dev Callable by any address that has approved `txHash` under the current owners version.
    function revokeTx(bytes32 txHash) external;

    /// @notice Replaces the owner set.
    /// @dev Only callable by this contract itself, i.e. through a `universalTx` self-call.
    /// Owners must be unique, non-zero, and cannot be this contract.
    /// All approvals recorded under previous owners versions are voided: pending
    /// transactions must be re-approved by the new owners.
    /// @param owners The new owner set.
    function updateOwners(address[] calldata owners) external;

    /// @notice Executes a batch of calls once `txHash` holds enough approvals.
    /// @dev Approvals can come from `approveTx` and/or EIP-712 delegations passed in
    /// `delegations` (encoded `(address owner, bytes signature)` pairs). The transaction
    /// nonce is consumed before the calls are made.
    /// @param targets Destination of each call.
    /// @param values ETH value (wei) sent with each call.
    /// @param datas Calldata of each call.
    /// @param delegations Encoded `(owner, signature)` pairs to register as approvals.
    /// @return txHash_ The hash of the executed batch.
    function universalTx(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes[] calldata delegations
    ) external payable returns (bytes32 txHash_);

    /* -------------------------------------------------------------------------- */
    /*                               VIEW FUNCTIONS                               */
    /* -------------------------------------------------------------------------- */

    /// @notice Current owners version; incremented on every ownership update.
    function getOwnersVersion() external view returns (uint256);

    /// @notice Current number of owners.
    function getOwnersCount() external view returns (uint256);

    /// @notice Nonce of the next batch to be executed by `universalTx`.
    function getTxNonce() external view returns (uint256);

    /// @notice Current delegation nonce of `owner`, mixed into its EIP-712 digests.
    function getOwnerDelegationNonce(address owner) external view returns (uint256);

    /// @notice Number of approvals recorded for `txHash` under the current owners version.
    function getOwnersTxApprovalsCount(bytes32 txHash) external view returns (uint256);

    /// @notice Computes the hash identifying a batch at a given transaction nonce.
    /// @dev Approvals are keyed by this hash; use the current `getTxNonce()` value as `txCount`.
    /// @param targets Destination of each call.
    /// @param values ETH value (wei) sent with each call.
    /// @param datas Calldata of each call.
    /// @param txCount The transaction nonce the batch will execute at.
    /// @return The batch hash.
    function getTxHash(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        uint256 txCount
    ) external pure returns (bytes32);

    /// @notice Whether `owner` is part of the current owner set.
    function isOwner(address owner) external view returns (bool isOwner_);

    /// @notice Whether `txHash` has reached the approval threshold (strict majority).
    function isAuthorizedTx(bytes32 txHash) external view returns (bool approved_);

    /// @notice Whether `owner` has approved `txHash` under the current owners version.
    function isOwnerTxApproved(bytes32 txHash, address owner) external view returns (bool);

    /// @notice EIP-712 domain separator of this contract.
    function domainSeparatorV4() external view returns (bytes32);
}
