# Universal Multi-Signature Wallet

## Overview

The Universal Multi-Sig contract is a secure multi-signature wallet implementation that operates on the Ethereum blockchain. This contract allows multiple owners to manage funds, approve transactions, and delegate approvals, ensuring that no single owner can unilaterally control the wallet's assets. It employs a structured approach to governance with clear rules and mechanisms for transaction approval.

## Features

- **Multi-Signature Approval**: Requires consensus from multiple owners to approve and execute transactions.
- **Delegated Approvals**: Owners can delegate their approval rights to others, allowing flexibility in managing approvals. Delegated signatures are validated via `SignatureChecker`, supporting both EOA owners (ECDSA) and contract owners (ERC-1271).
- **Reversible Transaction Approval**: Owners can revoke their approval for a specific transaction.
- **Secure Ownership Management**: Only recognized owners can execute transactions or modify ownership. The contract itself (`address(this)`) can never be set as an owner.
- **Version-Scoped Approvals**: Transaction approvals are scoped to the owners version that granted them. Any ownership update implicitly revokes every pending approval; the new owners must re-approve from scratch.
- **Event Logging**: All key actions are logged with events for transparency and accountability.

## Smart Contract Details

- **Contract Name**: `UniversalMultiSig`
- **License**: MIT
- **Version**: 1.0

### Constants

- **MIN_OWNER_COUNT**: Minimum number of owners required to initialize the contract (set to 3).
- **DELEGATED_APPROVAL_STRUCT_HASH**: The hash structure used for EIP-712 typed data signatures for delegated approvals.

### State Variables
- **_isOwner**: Mapping to track recognized owners.
- **_isOwnerTxApproved**: Mapping to track transaction approvals by per-owner, scoped by owners version.
- **_ownersTxApprovalsCount**: Mapping to count approvals for each transaction hash, scoped by owners version.
- **_ownerDelegationNonce**: Mapping to prevent replay attacks on delegated approvals.
- **_ownersVersion**: Keeps track of the version number for the ownership list.
- **_ownersCount**: Total count of current owners.
- **_txNonce**: Ensures each transaction is unique. Consumed before external calls to prevent replay via reentrancy.

### Events
- **OwnersUpdated(address[] owners, uint256 version)**: Emits when the list of owners is updated.
- **TxApproved(address indexed owner, address indexed executor, bytes32 txHash)**: Emits when a transaction is approved.
- **TxRevoked(address indexed owner, bytes32 txHash)**: Emits when a transaction is revoked.
- **TxExecuted(address indexed executor, bytes32 txHash, uint256 txNonce)**: Emits when a transaction is executed.

## Functions

### Core Functions

- **Constructor**: Initializes the owners of the multi-signature wallet.
- **approveTx(bytes32 txHash)**: Approves a transaction by the sender if they are an owner.
- **revokeTx(bytes32 txHash)**: Revokes approval for a transaction.
- **updateOwners(address[] calldata owners)**: Updates the list of owners (can only be called by the contract itself).
- **universalTx(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas, bytes[] calldata delegations)**: Executes transactions and requires approval based on multi-signature rules.

### View Functions

- **getOwnersVersion()**: Returns the current version number of the owners.
- **getOwnersCount()**: Returns the total count of current owners.
- **getTxNonce()**: Returns the current transaction nonce.
- **getOwnerDelegationNonce(address owner)**: Returns the delegation nonce for a specified owner.
- **getOwnersTxApprovalsCount(bytes32 txHash)**: Returns the number of approvals for a specific transaction.

### Utility Functions

- **isOwner(address owner)**: Checks if an address is a recognized owner.
- **isAuthorizedTx(bytes32 txHash)**: Checks if a transaction has received sufficient approvals.
- **isOwnerTxApproved(bytes32 txHash, address owner)**: Checks if a specific owner has approved a transaction.
- **getTxHash(...)**: Calculates the hash of a proposed transaction.

### EIP-712 Support
- **domainSeparatorV4()**: Returns the domain separator for EIP-712.

## Instructions for Deployment and Usage

1. **Deployment**: Deploy the `UniversalMultiSig` contract, passing an array of owner addresses at the constructor. Ensure that the count of owners is at least the defined minimum (`MIN_OWNER_COUNT`).

2. **Approving Transactions**: Owners can call the `approveTx(txHash)` function to approve a transaction hash generated using `getTxHash()`.

3. **Revoking Approvals**: If an owner wishes to revoke their approval for a transaction, they can call `revokeTx(txHash)`.

4. **Executing Transactions**: To execute a batch of transactions, owners call `universalTx(...)` with required parameters, ensuring all conditions for approval are met.

5. **Updating Owners**: To change the list of owners, the `updateOwners()` function can be called, but it can only be invoked internally by the contract itself. Rotating the owner set invalidates all pending approvals made under the previous version.

## Important Notes

- Always conduct thorough testing before deploying the contract on the mainnet.
- Be aware of security implications when handling private keys and signatures.
- Consider integrating further mechanisms for transparency, such as off-chain audits or governance processes.

## Conclusion

The Universal Multi-Signature Wallet is designed to facilitate secure and flexible management of digital assets in a collaborative environment, ensuring that a high standard of safety and governance is applied to transactions.