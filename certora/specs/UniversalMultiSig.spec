using UniversalMultiSigHarness as multisig;

methods {
    function ownerHashFor(address, uint256) external returns (bytes32) envfree;
}

/// A successful universalTx never drives _ownersCount below the minimum:
/// it writes only approval/nonce storage directly, and a payload call can
/// change owner state only via the self-call path into updateOwners,
/// which itself keeps the count >= 3.
rule minOwnerCountUniversalTx() {
    env e;
    address[] targets;
    uint256[] values;
    bytes[] datas;
    bytes[] delegations;
    // <=5 keeps the loops inside the loop_iter=6 unrolling (optimistic_loop
    // in conf); longer arrays would be over-approximated.
    require targets.length <= 5 && values.length <= 5
        && datas.length <= 5 && delegations.length <= 5;
    require to_mathint(multisig._ownersCount) >= 3;
    multisig.universalTx@withrevert(e, targets, values, datas, delegations);
    assert !lastReverted => to_mathint(multisig._ownersCount) >= 3;
}

/// _ownersCount stays >= 3 across every method except universalTx
/// (covered by minOwnerCountUniversalTx above).
rule minOwnerCountOtherMethods(method f) filtered {
    f -> f.selector != sig:universalTx(address[], uint256[], bytes[], bytes[]).selector
        && f.contract == multisig
        && !f.isView
} {
    env e;
    calldataarg args;
    require to_mathint(multisig._ownersCount) >= 3;
    multisig.f(e, args);
    assert to_mathint(multisig._ownersCount) >= 3;
}

/// A successful updateOwners keeps self out of the new version: the
/// contract rejects address(this) at runtime, and the require assumes the
/// future-version key is still clear (a reachable state never writes
/// key(self, ·), but an arbitrary havoced pre-state may set it).
rule notSelfOwnerUpdateOwners() {
    env e;
    address[] owners;
    // 3 = runtime minimum; <=5 keeps the rebuild loops inside the loop_iter=6 unrolling.
    require 3 <= owners.length && owners.length <= 5;
    require !multisig.isOwner(e, currentContract);
    require !multisig._isOwner[
        multisig.ownerHashFor(currentContract, require_uint256(multisig._ownersVersion + 1))
    ];
    multisig.updateOwners(e, owners);
    assert !multisig.isOwner(e, currentContract);
}

/// A successful universalTx never makes self an owner: it writes no owner
/// storage directly, and a payload self-call into updateOwners is covered
/// by notSelfOwnerUpdateOwners.
rule notSelfOwnerUniversalTx() {
    env e;
    address[] targets;
    uint256[] values;
    bytes[] datas;
    bytes[] delegations;
    require targets.length <= 5 && values.length <= 5
        && datas.length <= 5 && delegations.length <= 5;
    require !multisig.isOwner(e, currentContract);
    multisig.universalTx@withrevert(e, targets, values, datas, delegations);
    assert !lastReverted => !multisig.isOwner(e, currentContract);
}

/// The current contract is never an owner, across every method except
/// updateOwners and universalTx (dedicated rules above).
rule notSelfOwnerOtherMethods(method f) filtered {
    f -> f.selector != sig:universalTx(address[], uint256[], bytes[], bytes[]).selector
        && f.selector != sig:updateOwners(address[]).selector
        && f.contract == multisig
        && !f.isView
} {
    env e;
    calldataarg args;
    require !multisig.isOwner(e, currentContract);
    multisig.f(e, args);
    assert !multisig.isOwner(e, currentContract);
}

/// A successful updateOwners keeps zero out of the new version (same
/// future-version-key argument as notSelfOwnerUpdateOwners).
rule notZeroOwnerUpdateOwners() {
    env e;
    address[] owners;
    require 3 <= owners.length && owners.length <= 5;
    require !multisig.isOwner(e, 0);
    require !multisig._isOwner[
        multisig.ownerHashFor(0, require_uint256(multisig._ownersVersion + 1))
    ];
    multisig.updateOwners(e, owners);
    assert !multisig.isOwner(e, 0);
}

/// A successful universalTx never makes zero an owner (same argument as
/// notSelfOwnerUniversalTx).
rule notZeroOwnerUniversalTx() {
    env e;
    address[] targets;
    uint256[] values;
    bytes[] datas;
    bytes[] delegations;
    require targets.length <= 5 && values.length <= 5
        && datas.length <= 5 && delegations.length <= 5;
    require !multisig.isOwner(e, 0);
    multisig.universalTx@withrevert(e, targets, values, datas, delegations);
    assert !lastReverted => !multisig.isOwner(e, 0);
}

/// The zero address is never an owner, across every method except
/// updateOwners and universalTx (dedicated rules above).
rule notZeroOwnerOtherMethods(method f) filtered {
    f -> f.selector != sig:universalTx(address[], uint256[], bytes[], bytes[]).selector
        && f.selector != sig:updateOwners(address[]).selector
        && f.contract == multisig
        && !f.isView
} {
    env e;
    calldataarg args;
    require !multisig.isOwner(e, 0);
    multisig.f(e, args);
    assert !multisig.isOwner(e, 0);
}


/// updateOwners is reachable only through a self-call.
rule updateOwnersOnlySelf() {
    env e;
    address[] owners;
    require e.msg.sender != currentContract;
    multisig.updateOwners@withrevert(e, owners);
    assert lastReverted;
}

/// A successful updateOwners bumps the version by exactly one.
rule updateOwnersBumpsVersion() {
    env e;
    address[] owners;
    require e.msg.sender == currentContract;
    require 3 <= owners.length && owners.length <= 5;
    uint256 versionBefore = multisig._ownersVersion;
    multisig.updateOwners(e, owners);
    assert multisig._ownersVersion == versionBefore + 1;
}

/// No method other than updateOwners (directly or through a universalTx
/// self-call) touches _ownersVersion.
rule versionUnchangedByOtherMethods(method f) filtered {
    f -> f.selector != sig:updateOwners(address[]).selector
        && f.selector != sig:universalTx(address[], uint256[], bytes[], bytes[]).selector
        && f.contract == multisig
        && !f.isView
} {
    env e;
    calldataarg args;
    uint256 versionBefore = multisig._ownersVersion;
    multisig.f(e, args);
    assert multisig._ownersVersion == versionBefore;
}

/// A successful universalTx consumes exactly one nonce.
rule txNonceConsumedByOne() {
    env e;
    address[] targets;
    uint256[] values;
    bytes[] datas;
    bytes[] delegations;
    require targets.length <= 5 && values.length <= 5
        && datas.length <= 5 && delegations.length <= 5;
    uint256 nonceBefore = multisig._txNonce;
    multisig.universalTx@withrevert(e, targets, values, datas, delegations);
    assert !lastReverted => multisig._txNonce == nonceBefore + 1;
}

/// No method other than universalTx touches _txNonce.
rule txNonceUnchangedByOtherMethods(method f) filtered {
    f -> f.selector != sig:universalTx(address[], uint256[], bytes[], bytes[]).selector
        && f.contract == multisig
        && !f.isView
} {
    env e;
    calldataarg args;
    uint256 nonceBefore = multisig._txNonce;
    multisig.f(e, args);
    assert multisig._txNonce == nonceBefore;
}

/// approveTx reverts for non-owners.
rule approveTxRequiresOwner() {
    env e;
    bytes32 txHash;
    require !multisig.isOwner(e, e.msg.sender);
    multisig.approveTx@withrevert(e, txHash);
    assert lastReverted;
}

/// universalTx reverts for non-owners.
rule universalTxRequiresOwner() {
    env e;
    address[] targets;
    uint256[] values;
    bytes[] datas;
    bytes[] delegations;
    require !multisig.isOwner(e, e.msg.sender);
    multisig.universalTx@withrevert(e, targets, values, datas, delegations);
    assert lastReverted;
}

/// approveTx sets the caller's flag and increments the count by one;
/// a second approval from the same owner reverts.
rule approveTxSemantics() {
    env e;
    bytes32 txHash;
    require multisig.isOwner(e, e.msg.sender);
    bool already = multisig.isOwnerTxApproved(e, txHash, e.msg.sender);
    uint256 countBefore = multisig.getOwnersTxApprovalsCount(e, txHash);
    multisig.approveTx@withrevert(e, txHash);
    assert already => lastReverted;
    assert !lastReverted =>
        multisig.isOwnerTxApproved(e, txHash, e.msg.sender) &&
        multisig.getOwnersTxApprovalsCount(e, txHash) == countBefore + 1;
}

/// revokeTx clears the caller's flag and decrements the count by one;
/// an unapproved caller reverts.
rule revokeTxSemantics() {
    env e;
    bytes32 txHash;
    bool had = multisig.isOwnerTxApproved(e, txHash, e.msg.sender);
    uint256 countBefore = multisig.getOwnersTxApprovalsCount(e, txHash);
    // Reachable states pair the flag with the count (approveTx increments
    // on first approval); an arbitrary havoced pre-state may set the flag
    // with a zero count, which the unchecked decrement would wrap.
    require had => countBefore > 0;
    multisig.revokeTx@withrevert(e, txHash);
    assert !had => lastReverted;
    assert had => !lastReverted
        && !multisig.isOwnerTxApproved(e, txHash, e.msg.sender)
        && to_mathint(multisig.getOwnersTxApprovalsCount(e, txHash))
            == to_mathint(countBefore) - 1;
}

/// No method other than universalTx moves any delegation nonce.
rule delegationNonceUntouchedOutsideUniversalTx(method f) filtered {
    f -> f.selector != sig:universalTx(address[], uint256[], bytes[], bytes[]).selector
        && f.contract == multisig
        && !f.isView
} {
    env e;
    calldataarg args;
    address a;
    uint256 nonceBefore = multisig._ownerDelegationNonce[a];
    multisig.f(e, args);
    assert multisig._ownerDelegationNonce[a] == nonceBefore;
}

