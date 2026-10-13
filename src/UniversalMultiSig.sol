// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC1155Holder } from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { IUniversalMultiSig } from "./interfaces/IUniversalMultiSig.sol";

contract UniversalMultiSig is IUniversalMultiSig, ERC1155Holder, IERC721Receiver, EIP712 {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IUniversalMultiSig
    uint256 public constant MIN_OWNER_COUNT = 3;

    /// @inheritdoc IUniversalMultiSig
    bytes32 public constant DELEGATED_APPROVAL_STRUCT_HASH =
        keccak256("DelegatedApproval(address owner,bytes32 txHash,address executor,uint256 nonce)");

    /* -------------------------------------------------------------------------- */
    /*                               STATE VARIABLES                              */
    /* -------------------------------------------------------------------------- */

    /// @notice A mapping that tracks whether a given owner is recognized in the multi-signature wallet.
    /// @dev The mapping uses a bytes32 key (typically a hash of the owner's address) to indicate
    /// if the corresponding address is an owner (true) or not (false).
    mapping(bytes32 => bool) internal _isOwner;

    /// @notice A mapping that tracks whether a specific transaction has been approved by any owner.
    /// @dev Keys are scoped by owners version: an ownership update implicitly revokes every
    /// approval made under previous versions, as the old version entries are never read again.
    mapping(uint256 => mapping(bytes32 => bool)) internal _isOwnerTxApproved;

    /// @notice A mapping that counts the number of approvals for each transaction hash.
    /// @dev Keys are scoped by owners version, see `_isOwnerTxApproved`.
    mapping(uint256 => mapping(bytes32 => uint256)) internal _ownersTxApprovalsCount;

    /// @notice A mapping that maintains a delegation nonce for each owner address.
    /// @dev This mapping tracks the number of times an owner has delegated their authority.
    /// Each owner’s delegation nonce prevents replay attacks on delegated signatures.
    mapping(address => uint256) internal _ownerDelegationNonce;

    /// @notice A version number that increments whenever the list of owners is updated.
    /// @dev This variable helps track changes to the ownership structure over time, providing
    /// information about the current version of the owners.
    uint256 internal _ownersVersion;

    /// @notice The total count of current owners in the multi-signature wallet.
    /// @dev This variable records how many active owners are authorized to approve transactions
    /// within the wallet.
    uint256 internal _ownersCount;

    /// @notice A nonce that tracks the number of transactions initiated by the wallet.
    /// @dev This variable ensures that each transaction is unique and is used to prevent
    /// replay attacks, making it vital for the integrity of the wallet's transaction mechanism.
    uint256 internal _txNonce;

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIER                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Modifier that restricts function access to contract owners only.
    /// @dev This modifier checks if the caller of the function is an owner of the contract.
    /// If the caller is not an owner, it reverts the transaction with an `UnauthorizedCaller` error.
    /// Functions using this modifier will enforce ownership checks and ensure that only designated owners
    /// can execute certain actions.
    modifier onlyOwners() {
        if (!isOwner(msg.sender)) {
            revert UnauthorizedCaller();
        }
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /// @notice Constructor of the UniversalMultiSig contract and initializes the owners.
    /// @param owners An array of addresses that represent the owners of the multisig contract.
    /// @dev This constructor requires a minimum number of owners as defined by the `MIN_OWNER_COUNT`.
    /// It checks that the provided owners array is not empty, that none of the addresses are zero,
    /// and that the contract itself is not set as an owner.
    /// If the validation checks fail, it reverts the transaction with the respective error.
    /// Finally, it registers the provided owners under version 0 and emits the `OwnersUpdated` event.
    constructor(address[] memory owners) EIP712("UniversalMultiSig", "1") {
        if (owners.length < MIN_OWNER_COUNT) {
            revert InvalidOwnersCount();
        }

        for (uint256 i; i < owners.length;) {
            if (owners[i] == address(0) || owners[i] == address(this)) {
                revert InvalidOwner();
            }

            bytes32 ownerHash = _getOwnerHash(owners[i], 0);

            if (_isOwner[ownerHash]) {
                revert AlreadyOwner();
            }

            _isOwner[ownerHash] = true;

            unchecked {
                ++i;
            }
        }

        _ownersCount = owners.length;

        emit OwnersUpdated(owners, 0);
    }

    /// @notice This function is invoked when the contract receives Ether.
    /// @dev Allows the contract to accept plain Ether transfers without any data.
    /// Any incoming Ether sent to the contract will be received and added
    /// to the contract's balance.
    receive() external payable { }

    /* -------------------------------------------------------------------------- */
    /*                                   OWNERS                                   */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IUniversalMultiSig
    function approveTx(bytes32 txHash) external onlyOwners {
        _approveTx(txHash, msg.sender);
    }

    /// @inheritdoc IUniversalMultiSig
    function revokeTx(bytes32 txHash) external {
        uint256 version = _ownersVersion;
        bytes32 ownerTxApprovalHash = _getOwnerTxApprovalHash(txHash, msg.sender);
        bool isTxApproved = _isOwnerTxApproved[version][ownerTxApprovalHash];

        if (!isTxApproved) {
            revert NotApproved();
        }

        delete _isOwnerTxApproved[version][ownerTxApprovalHash];
        unchecked {
            _ownersTxApprovalsCount[version][txHash] -= 1;
        }

        emit TxRevoked(msg.sender, txHash);
    }

    /// @inheritdoc IUniversalMultiSig
    function updateOwners(address[] calldata owners) external {
        if (msg.sender != address(this)) {
            revert UnauthorizedCaller();
        }

        if (owners.length < MIN_OWNER_COUNT) {
            revert InvalidOwnersCount();
        }

        uint256 version = _ownersVersion + 1;

        for (uint256 i; i < owners.length;) {
            if (owners[i] == address(0) || owners[i] == address(this)) {
                revert InvalidOwner();
            }

            bytes32 ownerHash = _getOwnerHash(owners[i], version);

            if (_isOwner[ownerHash]) {
                revert AlreadyOwner();
            }

            _isOwner[ownerHash] = true;

            unchecked {
                ++i;
            }
        }

        _ownersVersion = version;
        _ownersCount = owners.length;

        emit OwnersUpdated(owners, version);
    }

    /// @inheritdoc IUniversalMultiSig
    function universalTx(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes[] calldata delegations
    ) external payable onlyOwners returns (bytes32 txHash_) {
        // Check transactions datas length
        if (
            targets.length == 0 || targets.length != values.length || targets.length != datas.length
        ) {
            revert InvalidArguments();
        }

        uint256 txNonce = _txNonce;

        txHash_ = getTxHash(targets, values, datas, txNonce);

        // Check if approval delegations are included
        if (delegations.length > 0) {
            _registerDelegatedApprovals(txHash_, delegations);
        }

        // Check if the transaction is authorized
        if (!isAuthorizedTx(txHash_)) {
            revert UnauthorizedTx();
        }

        // Effects before interactions: consume the nonce so a reentrant call made from a
        // target cannot recompute the same txHash and replay the recorded approvals.
        _txNonce = txNonce + 1;

        // Executes the transaction
        for (uint256 i; i < targets.length;) {
            if (targets[i] == address(0)) {
                revert InvalidTarget();
            }
            (bool success, bytes memory reason) = targets[i].call{ value: values[i] }(datas[i]);
            if (!success) {
                revert TxFailed(reason);
            }

            unchecked {
                ++i;
            }
        }

        emit TxExecuted(msg.sender, txHash_, txNonce);
    }

    /* -------------------------------------------------------------------------- */
    /*                               VIEW FUNCTIONS                               */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IUniversalMultiSig
    function getOwnersVersion() external view returns (uint256) {
        return _ownersVersion;
    }

    /// @inheritdoc IUniversalMultiSig
    function getOwnersCount() external view returns (uint256) {
        return _ownersCount;
    }

    /// @inheritdoc IUniversalMultiSig
    function getTxNonce() external view returns (uint256) {
        return _txNonce;
    }

    /// @inheritdoc IUniversalMultiSig
    function getOwnerDelegationNonce(address owner) external view returns (uint256) {
        return _ownerDelegationNonce[owner];
    }

    /// @inheritdoc IUniversalMultiSig
    function getOwnersTxApprovalsCount(bytes32 txHash) external view returns (uint256) {
        return _ownersTxApprovalsCount[_ownersVersion][txHash];
    }

    /// @inheritdoc IUniversalMultiSig
    function getTxHash(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        uint256 txCount
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(targets, values, datas, txCount));
    }

    /// @inheritdoc IUniversalMultiSig
    function isOwner(address owner) public view returns (bool isOwner_) {
        return _isOwner[_getOwnerHash(owner, _ownersVersion)];
    }

    /// @inheritdoc IUniversalMultiSig
    function isAuthorizedTx(bytes32 txHash) public view returns (bool approved_) {
        uint256 ownersCount = _ownersCount;
        uint256 ownersApprovalsCount = _ownersTxApprovalsCount[_ownersVersion][txHash];

        if (ownersCount % 2 == 0) {
            return ownersApprovalsCount > ownersCount / 2;
        } else {
            return ownersApprovalsCount >= (ownersCount + 1) / 2;
        }
    }

    /// @inheritdoc IUniversalMultiSig
    function isOwnerTxApproved(bytes32 txHash, address owner) external view returns (bool) {
        return _isOwnerTxApproved[_ownersVersion][_getOwnerTxApprovalHash(txHash, owner)];
    }
    /// @inheritdoc IUniversalMultiSig

    function domainSeparatorV4() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @inheritdoc IERC721Receiver
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /// @notice Registers delegated approvals for a given transaction.
    /// @dev This internal function processes an array of delegated signatures for a specific transaction hash.
    /// It allows owners of the contract to approve transactions via delegated signatures, providing increased
    /// flexibility in managing approvals. The function performs the following steps:
    ///
    /// 1. Iterates through each delegation provided in the `delegations` array.
    /// 2. Decodes each delegation into an owner's address and a corresponding signature.
    /// 3. Hashes the approval data into a digest format appropriate for EIP-712 using the `_hashTypedDataV4` method.
    /// 4. Recovers the signer address from the provided signature using ECDSA.
    /// 5. Checks if the recovered signer is not the `msg.sender` (the function caller) and if the signer is an owner of the contract.
    /// 6. If both conditions are satisfied, it calls `_approveTx` to register the transaction approval and increments the nonce for the owner.
    ///
    /// @param txHash The hash of the transaction for which approvals are being registered.
    /// @param delegations An array of encoded delegations containing pairs of owner addresses and signatures.
    function _registerDelegatedApprovals(bytes32 txHash, bytes[] calldata delegations) internal {
        for (uint256 i; i < delegations.length;) {
            (address owner, bytes memory signature) = abi.decode(delegations[i], (address, bytes));
            bytes32 digest = _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        DELEGATED_APPROVAL_STRUCT_HASH,
                        owner,
                        txHash,
                        msg.sender,
                        _ownerDelegationNonce[owner]
                    )
                )
            );
            address signer = ECDSA.recover(digest, signature);

            if (signer == owner && isOwner(signer)) {
                _approveTx(txHash, owner);
                _ownerDelegationNonce[owner] += 1;
            } else {
                revert InvalidSignature();
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Approves a transaction for a given transaction hash by a specified owner.
    /// @dev This internal function is responsible for recording approvals of a transaction.
    /// It first checks if the transaction has already been approved by the given owner using the
    /// `getTxApprovalsData` function. If the transaction has already been approved, it reverts with the
    /// `AlreadyApproved` error.
    ///
    /// If the transaction has not yet been approved, the function adds the owner's address to the list
    /// of approvers for that transaction hash and emits a `TxApproved` event.
    ///
    /// @param txHash The hash of the transaction to be approved.
    /// @param owner The address of the owner approving the transaction.
    function _approveTx(bytes32 txHash, address owner) internal {
        uint256 version = _ownersVersion;
        bytes32 ownerTxApprovalHash = _getOwnerTxApprovalHash(txHash, owner);
        bool isTxApproved = _isOwnerTxApproved[version][ownerTxApprovalHash];

        if (isTxApproved) {
            revert AlreadyApproved();
        }

        _isOwnerTxApproved[version][ownerTxApprovalHash] = true;
        _ownersTxApprovalsCount[version][txHash] += 1;

        emit TxApproved(owner, msg.sender, txHash);
    }

    /// @notice Calculates the hash of an owner address and its corresponding version.
    /// @dev This internal function takes an owner's address and a version number as input,
    /// and returns a bytes32 hash. The hash is generated using the keccak256 hashing algorithm
    /// combined with ABI encoding of the owner's address and version. This is useful for verifying
    /// ownership details in scenarios such as signatures and approvals.
    /// @param owner The address of the owner whose hash is being calculated.
    /// @param ownerVersion The current owners version number.
    /// @return A bytes32 value representing the hashed output of the owner's address and version.
    function _getOwnerHash(address owner, uint256 ownerVersion) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, ownerVersion));
    }

    /// @notice Calculates the hash of a transaction approval for a specific owner.
    /// @dev This internal function takes a transaction hash and an owner's address as inputs,
    /// and returns a bytes32 hash. The hash is generated using the keccak256 hashing algorithm
    /// combined with ABI encoding of the transaction hash and the owner's address. This is useful
    /// for verifying approvals of transactions by owners in a multi-signature setup.
    /// @param txHash The bytes32 hash of the transaction that is being approved.
    /// @param owner The address of the owner approving the transaction.
    /// @return A bytes32 value representing the hashed output of the transaction hash and owner address.
    function _getOwnerTxApprovalHash(bytes32 txHash, address owner)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(txHash, owner));
    }
}
