// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    IBatchValidityVerifierV4,
    IFraudProofVerifierV4,
    ITallyProofVerifierV4
} from "../../v4/IV4ProofVerifiers.sol";

contract MockBatchValidityVerifierV4 is IBatchValidityVerifierV4 {
    mapping(bytes32 publicInputsHash => bool accepted) public accepted;

    function setAccepted(bytes32 publicInputsHash, bool value) external {
        accepted[publicInputsHash] = value;
    }

    function verify(
        bytes calldata,
        bytes32 publicInputsHash
    ) external view returns (bool) {
        return accepted[publicInputsHash];
    }
}

contract MockFraudProofVerifierV4 is IFraudProofVerifierV4 {
    mapping(bytes32 challengeKey => bool accepted) public accepted;

    function setAccepted(
        bytes32 challengeType,
        bytes32 batchPublicInputsHash,
        bool value
    ) external {
        accepted[keccak256(abi.encode(challengeType, batchPublicInputsHash))] =
            value;
    }

    function verifyChallenge(
        bytes32 challengeType,
        bytes calldata,
        bytes32 batchPublicInputsHash
    ) external view returns (bool) {
        return
            accepted[
                keccak256(abi.encode(challengeType, batchPublicInputsHash))
            ];
    }
}

contract MockTallyProofVerifierV4 is ITallyProofVerifierV4 {
    bool public accept;

    function setAccept(bool value) external {
        accept = value;
    }

    function verify(
        bytes calldata,
        bytes32
    ) external view returns (bool) {
        return accept;
    }
}
