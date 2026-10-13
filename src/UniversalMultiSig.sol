// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC1155Holder } from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

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

    /// @notice Whether an address is an owner, keyed by (owner, owners version).
    mapping(bytes32 => bool) internal _isOwner;

    /// @notice Whether an owner has approved a transaction, keyed by (owners version, (txHash, owner)).
    /// @dev Scoped by owners version: an ownership update voids every prior approval.
    mapping(uint256 => mapping(bytes32 => bool)) internal _isOwnerTxApproved;

    /// @notice Number of approvals per transaction hash, keyed by (owners version, txHash).
    mapping(uint256 => mapping(bytes32 => uint256)) internal _ownersTxApprovalsCount;

    /// @notice Per-owner nonce mixed into delegated approval digests to prevent replays.
    mapping(address => uint256) internal _ownerDelegationNonce;

    /// @notice Incremented on every ownership update; scopes all approval state.
    uint256 internal _ownersVersion;

    /// @notice Current number of owners.
    uint256 internal _ownersCount;

    /// @notice Incremented on every executed transaction; binds approvals to a given batch.
    uint256 internal _txNonce;

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIER                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Reverts with `UnauthorizedCaller` unless the caller is an owner.
    modifier onlyOwners() {
        if (!isOwner(msg.sender)) {
            revert UnauthorizedCaller();
        }
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /// @notice Sets the initial owner set (owners version 0).
    /// @dev Owners must be unique, non-zero, and cannot be this contract.
    constructor(address[] memory owners) EIP712("UniversalMultiSig", "1") {
        if (owners.length < MIN_OWNER_COUNT) {
            revert InvalidOwnersCount();
        }

        for (uint256 i; i < owners.length; ++i) {
            if (owners[i] == address(0) || owners[i] == address(this)) {
                revert InvalidOwner();
            }

            bytes32 ownerHash = _getOwnerHash(owners[i], 0);

            if (_isOwner[ownerHash]) {
                revert AlreadyOwner();
            }

            _isOwner[ownerHash] = true;
        }

        _ownersCount = owners.length;

        emit OwnersUpdated(owners, 0);
    }

    /// @notice Accepts plain ETH transfers.
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

        for (uint256 i; i < owners.length; ++i) {
            if (owners[i] == address(0) || owners[i] == address(this)) {
                revert InvalidOwner();
            }

            bytes32 ownerHash = _getOwnerHash(owners[i], version);

            if (_isOwner[ownerHash]) {
                revert AlreadyOwner();
            }

            _isOwner[ownerHash] = true;
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
        if (
            targets.length == 0 || targets.length != values.length || targets.length != datas.length
        ) {
            revert InvalidArguments();
        }

        uint256 txNonce = _txNonce;

        txHash_ = getTxHash(targets, values, datas, txNonce);

        if (delegations.length > 0) {
            _registerDelegatedApprovals(txHash_, delegations);
        }

        if (!isAuthorizedTx(txHash_)) {
            revert UnauthorizedTx();
        }

        // Consume the nonce before the external calls: a reentrant call would recompute
        // a different txHash and find no approvals.
        _txNonce = txNonce + 1;

        for (uint256 i; i < targets.length; ++i) {
            if (targets[i] == address(0)) {
                revert InvalidTarget();
            }
            (bool success, bytes memory reason) = targets[i].call{ value: values[i] }(datas[i]);
            if (!success) {
                revert TxFailed(reason);
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

    /// @notice Registers approvals from EIP-712 delegated signatures.
    /// @dev Each delegation is an abi-encoded `(address owner, bytes signature)` pair, signed over
    /// the `DelegatedApproval` digest bound to `msg.sender` and the owner's delegation nonce.
    /// Signatures are validated via `SignatureChecker`: ECDSA for EOA owners, ERC-1271 for contract owners.
    /// @param txHash The transaction being approved.
    /// @param delegations Encoded `(owner, signature)` pairs.
    function _registerDelegatedApprovals(bytes32 txHash, bytes[] calldata delegations) internal {
        for (uint256 i; i < delegations.length; ++i) {
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

            if (SignatureChecker.isValidSignatureNow(owner, digest, signature) && isOwner(owner)) {
                _approveTx(txHash, owner);
                _ownerDelegationNonce[owner] += 1;
            } else {
                revert InvalidSignature();
            }
        }
    }

    /// @notice Records `owner`'s approval of `txHash` under the current owners version.
    /// @dev Reverts with `AlreadyApproved` if `owner` has already approved this transaction.
    /// @param txHash The transaction being approved.
    /// @param owner The owner granting the approval.
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

    /// @notice Keys an owner in `_isOwner` by address and owners version.
    function _getOwnerHash(address owner, uint256 ownerVersion) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, ownerVersion));
    }

    /// @notice Keys a per-owner approval in `_isOwnerTxApproved`.
    function _getOwnerTxApprovalHash(bytes32 txHash, address owner)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(txHash, owner));
    }
}
