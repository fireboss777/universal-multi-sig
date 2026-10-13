// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IUniversalMultiSigErrors } from "./IUniversalMultiSigErrors.sol";
import { IUniversalMultiSigEvents } from "./IUniversalMultiSigEvents.sol";

interface IUniversalMultiSig is IUniversalMultiSigErrors, IUniversalMultiSigEvents {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice The minimum number of owners required for the multisig contract.
    /// @dev The minimum owner count ensures an acceptable threshold for transaction approvals.
    function MIN_OWNER_COUNT() external pure returns (uint256);

    /// @notice The struct hash for the delegated approval.
    /// @dev This hash is used for validating the structure in signatures.
    /// The struct includes the following fields:
    /// - address owner: The address of the owner granting approval.
    /// - bytes32 txHash: The hash of the transaction being approved.
    ///   This can be retrieved using the `getTxHash(address to, uint256 value, bytes calldata data)` function.
    ///   The `txHash` uniquely represents the transaction based on its target address, value, and data.
    /// - address executor: The address that will execute the transaction.
    /// - uint256 nonce: A unique identifier to prevent replay attacks.
    ///   This can be retrieved using the `getNonce(address owner)` function.
    function DELEGATED_APPROVAL_STRUCT_HASH() external pure returns (bytes32);

    /* -------------------------------------------------------------------------- */
    /*                                   OWNERS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Approves a transaction identified by its hash.
    /// @dev This function can only be called by an owner of the contract. When a transaction is approved,
    /// it allows the transaction to be executed if the required number of approvals is met.
    /// @param txHash The hash of the transaction to be approved.
    function approveTx(bytes32 txHash) external;

    /// @notice Revokes approval for a transaction identified by its hash.
    /// @dev Owners of the contract can call this function to revoke their approval
    /// for a specific transaction. Revoking approval will reduce the count of approvals for
    /// that transaction, which may prevent it from being executed if the required approvals
    /// are not met.
    /// @param txHash The hash of the transaction whose approval is to be revoked.
    function revokeTx(bytes32 txHash) external;

    /// @notice Updates the list of owners for the multi-signature wallet.
    /// @dev This function can only be called by a owner of the contract through `universalTx` as
    /// any external transaction. It replaces the existing owners with a new set of owner addresses provided
    /// in the `owners` array. Care must be taken to ensure that the new list of owner addresses is valid, as it will
    /// determine the new approval authority for future transactions.
    /// All transaction approvals recorded under previous owners versions are implicitly revoked:
    /// pending transactions must be re-approved by the new owners before they can be executed.
    /// @param owners An array of addresses representing the new owners of the contract.
    /// It must not be empty, and all addresses must be unique.
    function updateOwners(address[] calldata owners) external;

    /// @notice Executes a multi-call transaction to multiple target addresses.
    /// @dev This function allows owners to aggregate multiple calls into a single transaction. The
    /// function will execute each target with the corresponding value and data provided in the
    /// `values` and `datas` arrays. The `delegations` parameter is used to provide EIP-712 delegation
    /// signatures, allowing owners to delegate authority for specific calls securely.
    /// This function requires either approvals majority threshold is already reached or that it receives
    /// majority approvals along with EIP-712 delegation signatures to authorize the execution of the transaction.
    /// @param targets An array of target addresses to which the calls will be sent.
    /// @param values An array of ETH values (in wei) to be sent to each target address.
    /// @param datas An array of byte arrays containing the encoded function calls for each target.
    /// @param delegations An array of EIP-712 delegation signature data for authorization.
    /// @return txHash_ The hash of the executed transaction, which can be used for tracking and
    /// further approvals if necessary.
    function universalTx(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes[] calldata delegations
    ) external payable returns (bytes32 txHash_);

    /* -------------------------------------------------------------------------- */
    /*                               VIEW FUNCTIONS                               */
    /* -------------------------------------------------------------------------- */

    /// @notice Retrieves the current version of the owners in the multi-signature wallet.
    /// @dev This version value is incremented each time the list of owners is updated. It helps track
    /// changes to the ownership structure over time, allowing external parties to ensure compatibility
    /// with updates in the contract's logic or to verify the current configuration of owners.
    /// @return The current version of owners.
    function getOwnersVersion() external view returns (uint256);

    /// @notice Retrieves the total number of owners in the multi-signature wallet.
    /// @dev This function returns a uint256 representing the count of current owners. This is useful
    /// for understanding the ownership structure and can help in managing approval thresholds
    /// and transaction authorizations.
    /// @return The total number of owners in the wallet.
    function getOwnersCount() external view returns (uint256);

    /// @notice Retrieves the current transaction nonce of the multi-signature wallet.
    /// @dev The transaction nonce is a uint256 value that represents the number of transactions
    /// that have been executed by the wallet. This is used to ensure the uniqueness of each
    /// transaction and prevent replay attacks. It is particularly useful for tracking the order
    /// of transactions and managing state within the contract.
    /// @return The current transaction nonce of the wallet.
    function getTxNonce() external view returns (uint256);

    /// @notice Retrieves the current delegation nonce for a specific owner.
    /// @dev The delegation nonce is a uint256 value that represents the number of times
    /// the specified `owner` has delegated authority using EIP-712 signatures. This nonce
    /// is used to prevent replay attacks on delegated signatures and ensures that each
    /// delegation is unique. It is useful for tracking the number of delegations an owner
    /// has made and managing delegation validation processes.
    /// @param owner The address of the owner whose delegation nonce is being retrieved.
    /// @return The current delegation nonce for the specified owner.
    function getOwnerDelegationNonce(address owner) external view returns (uint256);

    /// @notice Retrieves the count of approvals for a specific transaction hash.
    /// @dev This function takes a `txHash` as input and returns the number of owner approvals
    /// that have been recorded for the transaction associated with that hash. This is useful
    /// for determining if a transaction has received the required number of approvals to execute
    /// or if it is still pending approval.
    /// @param txHash The unique hash of the transaction for which approvals are being counted.
    /// @return The total number of approvals from owners for the specified transaction hash.
    function getOwnersTxApprovalsCount(bytes32 txHash) external view returns (uint256);

    /// @notice Computes the transaction hash for a proposed multi-call transaction.
    /// @dev This function takes the target addresses, ETH values, data for function calls,
    /// and the transaction count as inputs and returns a unique hash representing the
    /// proposed transaction. This hash can be used for tracking and verifying transactions
    /// before executing them, ensuring that the requested actions match the intended transaction.
    /// @param targets An array of target addresses for the function calls.
    /// @param values An array of ETH values (in wei) to be sent to each corresponding target address.
    /// @param datas An array of byte arrays containing the encoded function calls for each target.
    /// @param txCount A uint256 representing the transaction count, which helps differentiate
    /// between multiple transactions.
    /// @return A bytes32 hash that uniquely identifies the constructed transaction.
    function getTxHash(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        uint256 txCount
    ) external pure returns (bytes32);

    /// @notice Checks if a given address is an owner of the multi-signature wallet.
    /// @dev This function verifies whether the specified `owner` address is part of the current
    /// list of owners in the wallet. It returns a boolean value indicating the ownership status.
    /// This is useful for access control and ensuring that only authorized addresses can perform
    /// certain actions within the wallet.
    /// @param owner The address to check for ownership status.
    /// @return isOwner_ A boolean indicating whether the specified address is an owner (true)
    /// or not (false).
    function isOwner(address owner) external view returns (bool isOwner_);

    /// @notice Checks if a specific transaction hash has been authorized.
    /// @dev This function verifies whether the provided `txHash` has received the necessary
    /// approvals from the owners of the multi-signature wallet. The function returns a boolean
    /// value indicating whether the transaction is approved (true) or not (false). This is
    /// crucial for confirming the authorization status of a transaction before it is executed.
    /// @param txHash The unique hash of the transaction to check for authorization status.
    /// @return approved_ A boolean indicating whether the specified transaction hash is authorized
    /// (true) or not (false).
    function isAuthorizedTx(bytes32 txHash) external view returns (bool approved_);

    /// @notice Checks if a specific owner has approved a transaction.
    /// @dev This function verifies whether the given `owner` has provided approval for the
    /// transaction identified by the `txHash`. It returns a boolean indicating whether the
    /// specified owner has approved the transaction (true) or not (false). This is useful
    /// for determining the approval status of a transaction by individual owners before execution.
    /// @param txHash The unique hash of the transaction for which approval is being checked.
    /// @param owner The address of the owner whose approval status is being verified.
    /// @return A boolean indicating whether the specified owner has approved the transaction
    /// (true) or not (false).
    function isOwnerTxApproved(bytes32 txHash, address owner) external view returns (bool);

    /// @notice Retrieves the domain separator for EIP-712 typed data signing.
    /// @dev This function returns a bytes32 value representing the domain separator used
    /// in conjunction with EIP-712 to prevent replay attacks across different domains.
    /// The domain separator is a critical component in generating unique signatures
    /// for typed data, ensuring that the data being signed is associated with a specific
    /// contract and context.
    /// @return A bytes32 value representing the domain separator for the contract.
    function domainSeparatorV4() external view returns (bytes32);
}
