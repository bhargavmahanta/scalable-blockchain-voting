// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IBatchValidityVerifierV4 {
    function verify(
        bytes calldata proof,
        bytes32 publicInputsHash
    ) external view returns (bool);
}

interface IFraudProofVerifierV4 {
    function verifyChallenge(
        bytes32 challengeType,
        bytes calldata evidence,
        bytes32 batchPublicInputsHash
    ) external view returns (bool);
}

interface ITallyProofVerifierV4 {
    function verify(
        bytes calldata proof,
        bytes32 publicInputsHash
    ) external view returns (bool);
}
