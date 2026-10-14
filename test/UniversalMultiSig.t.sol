// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import { UniversalMultiSig } from "../src/UniversalMultiSig.sol";
import { IUniversalMultiSigEvents as Events } from "../src/interfaces/IUniversalMultiSig.sol";
import { IUniversalMultiSigErrors as Errors } from "../src/interfaces/IUniversalMultiSigErrors.sol";

import { UniversalMultiSigFixture } from "./utils/Fixture.sol";
import { UniversalMultiSigHandler } from "./utils/Handler.sol";

contract ERC1271Owner {
    mapping(bytes32 => bool) public approvedDigests;

    function approveDigest(bytes32 digest) external {
        approvedDigests[digest] = true;
    }

    function isValidSignature(bytes32 digest, bytes calldata) external view returns (bytes4) {
        if (approvedDigests[digest]) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

contract ERC1271ReentrantOwner {
    UniversalMultiSig public multisig;
    bytes public payload;

    receive() external payable { }

    function setMultisig(UniversalMultiSig multisig_) external {
        multisig = multisig_;
    }

    function setPayload(bytes memory payload_) external {
        payload = payload_;
    }

    function isValidSignature(bytes32, bytes calldata) external returns (bytes4) {
        // Reenter universalTx while the delegated approval is being validated.
        // A successful reentrant execution means the batch ran twice; surface it
        // as a failed signature so the outer call reverts loudly instead.
        (bool success,) = address(multisig).call(payload);
        if (success) {
            revert("reentrancy succeeded");
        }
        return IERC1271.isValidSignature.selector;
    }
}

contract ReentrantOwner {
    UniversalMultiSig public multisig;
    bytes public payload;
    bool public attempted;
    bytes public reentrancyError;

    function setMultisig(UniversalMultiSig multisig_) external {
        multisig = multisig_;
    }

    function setPayload(bytes memory payload_) external {
        payload = payload_;
    }

    function execute() external {
        (bool success, bytes memory reason) = address(multisig).call(payload);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(reason, 0x20), mload(reason))
            }
        }
    }

    receive() external payable {
        if (attempted) return;
        attempted = true;

        (bool success, bytes memory reason) = address(multisig).call(payload);
        if (success) {
            revert("reentrancy succeeded");
        } else {
            reentrancyError = reason;
        }
    }
}

contract UniversalMultiSigTest is UniversalMultiSigFixture {
    uint256 internal constant BASE_AMOUNT = 1 ether;

    function setUp() public {
        _setUp();
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    function test_constructor() external {
        vm.expectEmit();
        emit Events.OwnersUpdated(OWNERS, 0);
        multisig = new UniversalMultiSigHandler(OWNERS);

        assertEq(multisig.getOwnersCount(), OWNERS.length);
        assertEq(multisig.getOwnersVersion(), 0);

        for (uint256 i; i < OWNERS.length; i++) {
            assertTrue(multisig.isOwner(OWNERS[i]));
        }
    }

    function test_RevertWhen_constructorInvalidOwnersCount() external {
        OWNERS.pop();
        assertLt(OWNERS.length, multisig.MIN_OWNER_COUNT());
        vm.expectRevert(Errors.InvalidOwnersCount.selector);
        new UniversalMultiSigHandler(OWNERS);
    }

    function test_RevertWhen_constructorAlreadyOwner() external {
        OWNERS[0] = OWNERS[1];
        assertEq(OWNERS.length, multisig.MIN_OWNER_COUNT());
        vm.expectRevert(Errors.AlreadyOwner.selector);
        new UniversalMultiSigHandler(OWNERS);
    }

    function test_RevertWhen_constructorInvalidOwner() external {
        OWNERS[0] = address(0);
        assertEq(OWNERS.length, multisig.MIN_OWNER_COUNT());
        vm.expectRevert(Errors.InvalidOwner.selector);
        new UniversalMultiSigHandler(OWNERS);
    }

    function test_RevertWhen_constructorInvalidOwnerSelf() external {
        address predicted = computeCreateAddress(address(this), vm.getNonce(address(this)));

        address[] memory owners = new address[](3);
        owners[0] = USER_1;
        owners[1] = USER_2;
        owners[2] = predicted;

        vm.expectRevert(Errors.InvalidOwner.selector);
        new UniversalMultiSigHandler(owners);
    }

    function test_receive() external {
        vm.deal(address(this), BASE_AMOUNT);
        uint256 balanceBefore = address(multisig).balance;

        (bool success,) = address(multisig).call{ value: BASE_AMOUNT }("");

        assertTrue(success);
        assertEq(address(multisig).balance, balanceBefore + BASE_AMOUNT);
    }

    /* -------------------------------------------------------------------------- */
    /*                                 APPROVE_TX                                 */
    /* -------------------------------------------------------------------------- */

    function test_RevertWhen_approveTxNotOwner() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        vm.expectRevert(Errors.UnauthorizedCaller.selector);
        multisig.approveTx(txHash);
    }

    function test_approveTx() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());
        uint256 ownersTxApprovalsCountBefore = multisig.getOwnersTxApprovalsCount(txHash);

        vm.prank(OWNERS[0]);
        vm.expectEmit();
        emit Events.TxApproved(OWNERS[0], OWNERS[0], txHash);
        multisig.approveTx(txHash);

        assertTrue(multisig.isOwnerTxApproved(txHash, OWNERS[0]));
        assertEq(multisig.getOwnersTxApprovalsCount(txHash), ownersTxApprovalsCountBefore + 1);
    }

    function test_RevertWhen_approveTxAlreadyApproved() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());
        uint256 ownersTxApprovalsCountBefore = multisig.getOwnersTxApprovalsCount(txHash);

        vm.prank(OWNERS[0]);
        multisig.approveTx(txHash);

        assertTrue(multisig.isOwnerTxApproved(txHash, OWNERS[0]));
        assertEq(multisig.getOwnersTxApprovalsCount(txHash), ownersTxApprovalsCountBefore + 1);

        vm.prank(OWNERS[0]);
        vm.expectRevert(Errors.AlreadyApproved.selector);
        multisig.approveTx(txHash);
    }

    function test_approveTxForEvenOwners() external {
        /* --------------------------- update even owners --------------------------- */

        address[] memory newOwners = new address[](4);
        newOwners[0] = vm.addr(type(uint160).max);
        newOwners[1] = vm.addr(type(uint160).max - 1);
        newOwners[2] = vm.addr(type(uint160).max - 2);
        newOwners[3] = vm.addr(type(uint160).max - 3);

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getUpdateOwnersTx(newOwners);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                break;
            }
        }

        uint256 ownersVersion = multisig.getOwnersVersion();
        uint256 txNonce = multisig.getTxNonce();

        vm.prank(OWNERS[0]);
        vm.expectEmit();
        emit Events.OwnersUpdated(newOwners, ownersVersion + 1);
        vm.expectEmit();
        emit Events.TxExecuted(OWNERS[0], txHash, txNonce);
        multisig.universalTx(targets, values, datas, new bytes[](0));

        for (uint256 i; i < OWNERS.length; i++) {
            assertFalse(multisig.isOwner(OWNERS[i]));
        }

        for (uint256 i; i < newOwners.length; i++) {
            assertTrue(multisig.isOwner(newOwners[i]));
        }

        assertEq(multisig.getOwnersVersion(), ownersVersion + 1);
        assertEq(multisig.getTxNonce(), txNonce + 1);

        /* ------------------------------- approve tx ------------------------------- */

        (targets, values, datas) = _getTransferEthTx(address(this), BASE_AMOUNT);

        txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        for (uint256 i; i < newOwners.length; i++) {
            vm.prank(newOwners[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                assertEq(i, newOwners.length / 2);
                break;
            }
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                                  REVOKE_TX                                 */
    /* -------------------------------------------------------------------------- */

    function test_revokeTx() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());
        uint256 ownersTxApprovalsCountBefore = multisig.getOwnersTxApprovalsCount(txHash);

        vm.prank(OWNERS[0]);
        multisig.approveTx(txHash);

        assertTrue(multisig.isOwnerTxApproved(txHash, OWNERS[0]));
        assertEq(multisig.getOwnersTxApprovalsCount(txHash), ownersTxApprovalsCountBefore + 1);

        vm.prank(OWNERS[0]);
        vm.expectEmit();
        emit Events.TxRevoked(OWNERS[0], txHash);
        multisig.revokeTx(txHash);

        assertFalse(multisig.isOwnerTxApproved(txHash, OWNERS[0]));
        assertEq(multisig.getOwnersTxApprovalsCount(txHash), ownersTxApprovalsCountBefore);
    }

    function test_RevertWhen_revokeTxNotApproved() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        vm.prank(OWNERS[0]);
        vm.expectRevert(Errors.NotApproved.selector);
        multisig.revokeTx(txHash);
    }

    function test_RevertWhen_revokeTxAfterUpdateOwners() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        vm.prank(OWNERS[0]);
        multisig.approveTx(txHash);
        assertTrue(multisig.isOwnerTxApproved(txHash, OWNERS[0]));

        /* ------------------------------ rotate owners ------------------------------ */

        address[] memory newOwners = new address[](3);
        newOwners[0] = USER_4;
        newOwners[1] = vm.addr(type(uint160).max);
        newOwners[2] = vm.addr(type(uint160).max - 1);

        (address[] memory uTargets, uint256[] memory uValues, bytes[] memory uDatas) =
            _getUpdateOwnersTx(newOwners);
        bytes32 updateTxHash = multisig.getTxHash(uTargets, uValues, uDatas, multisig.getTxNonce());

        vm.prank(OWNERS[0]);
        multisig.approveTx(updateTxHash);
        vm.prank(OWNERS[1]);
        multisig.approveTx(updateTxHash);

        vm.prank(OWNERS[0]);
        multisig.universalTx(uTargets, uValues, uDatas, new bytes[](0));

        /* -------------------- ex-owner revoke is now a no-op --------------------- */

        assertFalse(multisig.isOwnerTxApproved(txHash, OWNERS[0]));

        vm.prank(OWNERS[0]);
        vm.expectRevert(Errors.NotApproved.selector);
        multisig.revokeTx(txHash);
    }

    /* -------------------------------------------------------------------------- */
    /*                                UPDATE_OWNERS                               */
    /* -------------------------------------------------------------------------- */

    function test_RevertWhen_updateOwnersUnauthorizedCaller() external {
        vm.expectRevert(Errors.UnauthorizedCaller.selector);
        multisig.updateOwners(new address[](0));
    }

    function test_updateOwners() external {
        address[] memory newOwners = new address[](3);
        newOwners[0] = vm.addr(type(uint160).max);
        newOwners[1] = vm.addr(type(uint160).max - 1);
        newOwners[2] = vm.addr(type(uint160).max - 2);

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getUpdateOwnersTx(newOwners);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                assertEq(i + 1, (newOwners.length + 1) / 2);

                break;
            }
        }

        uint256 ownersVersion = multisig.getOwnersVersion();
        uint256 txNonce = multisig.getTxNonce();

        vm.prank(OWNERS[0]);
        vm.expectEmit();
        emit Events.OwnersUpdated(newOwners, ownersVersion + 1);
        vm.expectEmit();
        emit Events.TxExecuted(OWNERS[0], txHash, txNonce);
        multisig.universalTx(targets, values, datas, new bytes[](0));

        for (uint256 i; i < OWNERS.length; i++) {
            assertFalse(multisig.isOwner(OWNERS[i]));
        }

        for (uint256 i; i < newOwners.length; i++) {
            assertTrue(multisig.isOwner(newOwners[i]));
        }

        assertEq(multisig.getOwnersVersion(), ownersVersion + 1);
        assertEq(multisig.getTxNonce(), txNonce + 1);
    }

    function test_updateOwnersInvalidOwner() external {
        address[] memory newOwners = new address[](multisig.MIN_OWNER_COUNT());

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getUpdateOwnersTx(newOwners);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                break;
            }
        }

        vm.prank(OWNERS[0]);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.TxFailed.selector, abi.encodePacked(Errors.InvalidOwner.selector)
            )
        );
        multisig.universalTx(targets, values, datas, new bytes[](0));
    }

    function test_RevertWhen_updateOwnersInvalidOwnersCount() external {
        address[] memory newOwners = new address[](multisig.MIN_OWNER_COUNT() - 1);

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getUpdateOwnersTx(newOwners);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                break;
            }
        }

        vm.prank(OWNERS[0]);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.TxFailed.selector, abi.encodePacked(Errors.InvalidOwnersCount.selector)
            )
        );
        multisig.universalTx(targets, values, datas, new bytes[](0));
    }

    function test_RevertWhen_updateOwnersAlreadyOwner() external {
        address[] memory newOwners = OWNERS;
        newOwners[0] = newOwners[1];

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getUpdateOwnersTx(newOwners);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                break;
            }
        }

        vm.prank(OWNERS[0]);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.TxFailed.selector, abi.encodePacked(Errors.AlreadyOwner.selector)
            )
        );
        multisig.universalTx(targets, values, datas, new bytes[](0));
    }

    function test_RevertWhen_updateOwnersInvalidOwnerSelf() external {
        address[] memory newOwners = new address[](3);
        newOwners[0] = USER_1;
        newOwners[1] = USER_2;
        newOwners[2] = address(multisig);

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getUpdateOwnersTx(newOwners);

        bytes32 txHash = multisig.getTxHash(targets, values, datas, multisig.getTxNonce());

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                break;
            }
        }

        vm.prank(OWNERS[0]);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.TxFailed.selector, abi.encodePacked(Errors.InvalidOwner.selector)
            )
        );
        multisig.universalTx(targets, values, datas, new bytes[](0));
    }

    function test_updateOwnersInvalidatesPreApprovedFutureTx() external {
        vm.deal(address(multisig), BASE_AMOUNT * 2);
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        // Pre-approve the payload for the NEXT nonce: the upcoming rotation will consume
        // the current nonce, making the future nonce predictable.
        uint256 futureNonce = multisig.getTxNonce() + 1;
        bytes32 futureTxHash = multisig.getTxHash(targets, values, datas, futureNonce);

        vm.prank(OWNERS[0]);
        multisig.approveTx(futureTxHash);
        vm.prank(OWNERS[1]);
        multisig.approveTx(futureTxHash);
        assertTrue(multisig.isAuthorizedTx(futureTxHash));

        /* ------------------------------ rotate owners ------------------------------ */

        address[] memory newOwners = new address[](3);
        newOwners[0] = USER_4;
        newOwners[1] = vm.addr(type(uint160).max);
        newOwners[2] = vm.addr(type(uint160).max - 1);

        (address[] memory uTargets, uint256[] memory uValues, bytes[] memory uDatas) =
            _getUpdateOwnersTx(newOwners);
        bytes32 updateTxHash = multisig.getTxHash(uTargets, uValues, uDatas, multisig.getTxNonce());

        vm.prank(OWNERS[0]);
        multisig.approveTx(updateTxHash);
        vm.prank(OWNERS[1]);
        multisig.approveTx(updateTxHash);

        vm.prank(OWNERS[0]);
        multisig.universalTx(uTargets, uValues, uDatas, new bytes[](0));

        /* ------------------ pre-approvals from removed owners are void ------------------ */

        assertFalse(multisig.isAuthorizedTx(futureTxHash));
        assertEq(multisig.getOwnersTxApprovalsCount(futureTxHash), 0);

        vm.prank(newOwners[0]);
        vm.expectRevert(Errors.UnauthorizedTx.selector);
        multisig.universalTx(targets, values, datas, new bytes[](0));

        /* ------------------- the new owners must re-approve from scratch ------------------- */

        vm.prank(newOwners[0]);
        multisig.approveTx(futureTxHash);
        assertFalse(multisig.isAuthorizedTx(futureTxHash));

        uint256 balanceBefore = address(this).balance;

        vm.prank(newOwners[1]);
        multisig.approveTx(futureTxHash);
        assertTrue(multisig.isAuthorizedTx(futureTxHash));

        vm.prank(newOwners[0]);
        multisig.universalTx(targets, values, datas, new bytes[](0));

        assertEq(address(this).balance, balanceBefore + BASE_AMOUNT);
        assertEq(multisig.getTxNonce(), futureNonce + 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                                UNIVERSAL_TX                                */
    /* -------------------------------------------------------------------------- */

    function test_universalTx() external {
        vm.deal(address(multisig), BASE_AMOUNT);
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        uint256 txNonce = multisig.getTxNonce();
        bytes32 txHash = multisig.getTxHash(targets, values, datas, txNonce);

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                break;
            }
        }

        uint256 balanceBefore = address(this).balance;

        vm.prank(OWNERS[0]);
        vm.expectEmit();
        emit Events.TxExecuted(OWNERS[0], txHash, txNonce);
        multisig.universalTx(targets, values, datas, new bytes[](0));

        txNonce = multisig.getTxNonce();
        txHash = multisig.getTxHash(targets, values, datas, txNonce);

        assertEq(multisig.getTxNonce(), txNonce);
        assertEq(address(this).balance, balanceBefore + BASE_AMOUNT);
        assertFalse(multisig.isAuthorizedTx(txHash));
    }

    function test_RevertWhen_universalTxUnauthorizedTxReplay() external {
        vm.deal(address(multisig), BASE_AMOUNT * 2);
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        uint256 txNonce = multisig.getTxNonce();
        bytes32 txHash = multisig.getTxHash(targets, values, datas, txNonce);

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                break;
            }
        }

        uint256 balanceBefore = address(this).balance;

        vm.prank(OWNERS[0]);
        multisig.universalTx(targets, values, datas, new bytes[](0));

        assertEq(multisig.getTxNonce(), txNonce + 1);
        assertEq(address(this).balance, balanceBefore + BASE_AMOUNT);

        vm.prank(OWNERS[0]);
        vm.expectRevert(Errors.UnauthorizedTx.selector);
        multisig.universalTx(targets, values, datas, new bytes[](0));
    }

    function test_universalTxBlocksReentrancy() external {
        ReentrantOwner attacker = new ReentrantOwner();

        address[] memory owners = new address[](3);
        owners[0] = USER_1;
        owners[1] = USER_2;
        owners[2] = address(attacker);

        UniversalMultiSigHandler localMultisig = new UniversalMultiSigHandler(owners);
        attacker.setMultisig(UniversalMultiSig(payable(address(localMultisig))));
        vm.deal(address(localMultisig), BASE_AMOUNT);

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(attacker), BASE_AMOUNT);

        uint256 txNonce = localMultisig.getTxNonce();
        bytes32 txHash = localMultisig.getTxHash(targets, values, datas, txNonce);

        vm.prank(USER_1);
        localMultisig.approveTx(txHash);
        vm.prank(USER_2);
        localMultisig.approveTx(txHash);
        assertTrue(localMultisig.isAuthorizedTx(txHash));

        attacker.setPayload(
            abi.encodeWithSignature(
                "universalTx(address[],uint256[],bytes[],bytes[])",
                targets,
                values,
                datas,
                new bytes[](0)
            )
        );

        uint256 balanceBefore = address(attacker).balance;

        attacker.execute();

        // The reentrant call was attempted and rejected: the nonce was consumed
        // before the external interaction, so the replayed payload hashes differently.
        assertTrue(attacker.attempted());
        assertEq(
            keccak256(attacker.reentrancyError()),
            keccak256(abi.encodeWithSelector(Errors.UnauthorizedTx.selector))
        );

        // Funds moved exactly once and the nonce advanced once.
        assertEq(address(attacker).balance, balanceBefore + BASE_AMOUNT);
        assertEq(localMultisig.getTxNonce(), txNonce + 1);
    }

    function test_universalTxBlocksERC1271Reentrancy() external {
        ERC1271ReentrantOwner attacker = new ERC1271ReentrantOwner();

        address[] memory owners = new address[](3);
        owners[0] = USER_1;
        owners[1] = USER_2;
        owners[2] = address(attacker);

        UniversalMultiSigHandler localMultisig = new UniversalMultiSigHandler(owners);
        attacker.setMultisig(UniversalMultiSig(payable(address(localMultisig))));
        vm.deal(address(localMultisig), BASE_AMOUNT);

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(attacker), BASE_AMOUNT);

        uint256 txNonce = localMultisig.getTxNonce();
        bytes32 txHash = localMultisig.getTxHash(targets, values, datas, txNonce);

        // Pre-approve so txHash is already authorized while isValidSignature runs:
        // the reentrant replay would otherwise die on UnauthorizedTx and prove nothing.
        vm.prank(USER_1);
        localMultisig.approveTx(txHash);
        vm.prank(USER_2);
        localMultisig.approveTx(txHash);
        assertTrue(localMultisig.isAuthorizedTx(txHash));

        attacker.setPayload(
            abi.encodeWithSignature(
                "universalTx(address[],uint256[],bytes[],bytes[])",
                targets,
                values,
                datas,
                new bytes[](0)
            )
        );

        bytes[] memory delegationList = new bytes[](1);
        delegationList[0] = abi.encode(address(attacker), bytes("checked-by-erc1271"));

        uint256 balanceBefore = address(attacker).balance;

        // Signature validation cannot execute the batch a second time: the nonce
        // is consumed before _registerDelegatedApprovals, so the replayed payload
        // hashes differently, and the static ERC-1271 call forbids state writes.
        vm.prank(USER_1);
        localMultisig.universalTx(targets, values, datas, delegationList);

        // Funds moved exactly once and the nonce advanced once.
        assertEq(address(attacker).balance, balanceBefore + BASE_AMOUNT);
        assertEq(localMultisig.getTxNonce(), txNonce + 1);
    }

    function test_universalTxWithDelegation() external {
        vm.deal(address(multisig), BASE_AMOUNT);
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        uint256 txNonce = multisig.getTxNonce();
        bytes32 txHash = multisig.getTxHash(targets, values, datas, txNonce);

        bytes[] memory delegationList = new bytes[](2);
        bytes memory user1Sig = _getSignature(USER_1_PK, txHash, OWNERS[0]);
        bytes memory user2Sig = _getSignature(USER_2_PK, txHash, OWNERS[0]);
        delegationList[0] = abi.encode(vm.addr(USER_1_PK), user1Sig);
        delegationList[1] = abi.encode(vm.addr(USER_2_PK), user2Sig);

        uint256 balanceBefore = address(this).balance;

        vm.prank(OWNERS[0]);
        vm.expectEmit();
        emit Events.TxApproved(vm.addr(USER_1_PK), OWNERS[0], txHash);
        vm.expectEmit();
        emit Events.TxApproved(vm.addr(USER_2_PK), OWNERS[0], txHash);
        vm.expectEmit();
        emit Events.TxExecuted(OWNERS[0], txHash, txNonce);
        multisig.universalTx(targets, values, datas, delegationList);

        assertEq(multisig.getTxNonce(), txNonce + 1);
        assertEq(address(this).balance, balanceBefore + BASE_AMOUNT);
    }

    function test_universalTxWithDelegationERC1271() external {
        ERC1271Owner contractOwner = new ERC1271Owner();

        address[] memory owners = new address[](3);
        owners[0] = USER_1;
        owners[1] = USER_2;
        owners[2] = address(contractOwner);

        UniversalMultiSigHandler localMultisig = new UniversalMultiSigHandler(owners);
        vm.deal(address(localMultisig), BASE_AMOUNT);

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        bytes32 txHash = localMultisig.getTxHash(targets, values, datas, localMultisig.getTxNonce());

        // USER_1 approves directly, the contract owner delegates via ERC-1271 (2/3)
        vm.prank(USER_1);
        localMultisig.approveTx(txHash);

        bytes32 structHash = keccak256(
            abi.encode(
                localMultisig.DELEGATED_APPROVAL_STRUCT_HASH(),
                address(contractOwner),
                txHash,
                USER_1,
                localMultisig.getOwnerDelegationNonce(address(contractOwner))
            )
        );
        bytes32 digest =
            MessageHashUtils.toTypedDataHash(localMultisig.domainSeparatorV4(), structHash);

        contractOwner.approveDigest(digest);

        bytes[] memory delegationList = new bytes[](1);
        delegationList[0] = abi.encode(address(contractOwner), bytes("ignored-by-erc1271"));

        uint256 balanceBefore = address(this).balance;

        vm.prank(USER_1);
        vm.expectEmit();
        emit Events.TxApproved(address(contractOwner), USER_1, txHash);
        vm.expectEmit();
        emit Events.TxExecuted(USER_1, txHash, 0);
        localMultisig.universalTx(targets, values, datas, delegationList);

        assertEq(address(this).balance, balanceBefore + BASE_AMOUNT);
        assertEq(localMultisig.getTxNonce(), 1);
        assertEq(localMultisig.getOwnerDelegationNonce(address(contractOwner)), 1);
    }

    function test_RevertWhen_universalTxInvalidSignatureERC1271() external {
        ERC1271Owner contractOwner = new ERC1271Owner();

        address[] memory owners = new address[](3);
        owners[0] = USER_1;
        owners[1] = USER_2;
        owners[2] = address(contractOwner);

        UniversalMultiSigHandler localMultisig = new UniversalMultiSigHandler(owners);

        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        bytes32 txHash = localMultisig.getTxHash(targets, values, datas, localMultisig.getTxNonce());

        vm.prank(USER_1);
        localMultisig.approveTx(txHash);

        // The contract owner never approved the digest: isValidSignature returns a wrong magic value.
        bytes[] memory delegationList = new bytes[](1);
        delegationList[0] = abi.encode(address(contractOwner), bytes("ignored-by-erc1271"));

        vm.prank(USER_1);
        vm.expectRevert(Errors.InvalidSignature.selector);
        localMultisig.universalTx(targets, values, datas, delegationList);
    }

    function test_RevertWhen_universalTxInvalidSignature() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        uint256 txNonce = multisig.getTxNonce();
        bytes32 txHash = multisig.getTxHash(targets, values, datas, txNonce);

        vm.prank(OWNERS[0]);
        multisig.approveTx(txHash);

        bytes[] memory delegationList = new bytes[](2);
        bytes memory user2Sig = _getSignature(USER_2_PK, txHash, OWNERS[0]);
        bytes memory user3Sig = _getSignature(USER_3_PK, txHash, OWNERS[0]);
        delegationList[0] = abi.encode(OWNERS[0], user2Sig);
        delegationList[1] = abi.encode(OWNERS[0], user3Sig);

        vm.prank(OWNERS[0]);
        vm.expectRevert(Errors.InvalidSignature.selector);
        multisig.universalTx(targets, values, datas, delegationList);
    }

    function test_RevertWhen_universalTxInvalidArguments() external {
        (address[] memory targets, uint256[] memory values,) =
            _getTransferEthTx(address(this), BASE_AMOUNT);

        vm.prank(OWNERS[0]);
        vm.expectRevert(Errors.InvalidArguments.selector);
        multisig.universalTx(targets, values, new bytes[](0), new bytes[](0));
    }

    function test_RevertWhen_universalTxInvalidTarget() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            _getTransferEthTx(address(0), BASE_AMOUNT);

        uint256 txNonce = multisig.getTxNonce();
        bytes32 txHash = multisig.getTxHash(targets, values, datas, txNonce);

        for (uint256 i; i < OWNERS.length; i++) {
            vm.prank(OWNERS[i]);
            multisig.approveTx(txHash);

            if (multisig.isAuthorizedTx(txHash)) {
                break;
            }
        }

        vm.prank(OWNERS[0]);
        vm.expectRevert(Errors.InvalidTarget.selector);
        multisig.universalTx(targets, values, datas, new bytes[](0));
    }

    /* -------------------------------------------------------------------------- */
    /*                             ON_ERC721_RECEIVED                             */
    /* -------------------------------------------------------------------------- */

    function test_onERC721Received() external view {
        assertEq(
            multisig.onERC721Received(address(0), address(0), 0, ""),
            IERC721Receiver.onERC721Received.selector
        );
    }

    /* -------------------------------------------------------------------------- */
    /*                                   HELPERS                                  */
    /* -------------------------------------------------------------------------- */

    function _getTransferEthTx(address to, uint256 value)
        internal
        pure
        returns (address[] memory targets_, uint256[] memory values_, bytes[] memory datas_)
    {
        targets_ = new address[](1);
        targets_[0] = to;

        values_ = new uint256[](1);
        values_[0] = value;

        datas_ = new bytes[](1);
    }

    function _getUpdateOwnersTx(address[] memory newOwners)
        internal
        view
        returns (address[] memory targets_, uint256[] memory values_, bytes[] memory datas_)
    {
        targets_ = new address[](1);
        targets_[0] = address(multisig);

        values_ = new uint256[](1);

        datas_ = new bytes[](1);
        datas_[0] = abi.encodeWithSignature("updateOwners(address[])", newOwners);
    }

    function _getSignature(uint256 signerPK, bytes32 txHash, address executor)
        internal
        view
        returns (bytes memory)
    {
        address signer = vm.addr(signerPK);

        bytes32 structHash = keccak256(
            abi.encode(
                multisig.DELEGATED_APPROVAL_STRUCT_HASH(),
                signer,
                txHash,
                executor,
                multisig.getOwnerDelegationNonce(signer)
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(multisig.domainSeparatorV4(), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPK, digest);

        return abi.encodePacked(r, s, v);
    }

    receive() external payable { }
}
