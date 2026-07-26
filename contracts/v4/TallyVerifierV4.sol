// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BatchCommitmentV4} from "./BatchCommitmentV4.sol";
import {ElectionConfigV4} from "./ElectionConfigV4.sol";
import {ITallyProofVerifierV4} from "./IV4ProofVerifiers.sol";
import {VerifierRegistryV4} from "./VerifierRegistryV4.sol";

/// @notice Permissionless, proof-gated and immutable constituency tally.
contract TallyVerifierV4 {
    bytes32 public constant TALLY_VERIFIER_TYPE =
        keccak256("SVB_TALLY_VALIDITY_V4");
    bytes32 private constant TALLY_INPUT_DOMAIN =
        keccak256("SVB_TALLY_PUBLIC_INPUTS_V4");

    error InvalidCandidateCounts();
    error InvalidResult();
    error ProofRejected();
    error ResultAlreadyPublished();
    error SettlementIncomplete();

    ElectionConfigV4 public immutable electionConfig;
    BatchCommitmentV4 public immutable batchCommitment;
    VerifierRegistryV4 public immutable verifierRegistry;

    bytes32 public resultHash;
    bytes32 public tallyArtifactDigest;
    bytes32 public publicInputsHash;
    address public publisher;
    bool public resultPublished;

    event TallyPublished(
        bytes32 indexed resultHash,
        bytes32 indexed tallyArtifactDigest,
        bytes32 indexed publicInputsHash,
        uint64 acceptedBallotCount,
        address publisher
    );

    constructor(
        ElectionConfigV4 electionConfig_,
        BatchCommitmentV4 batchCommitment_
    ) {
        if (
            address(electionConfig_) == address(0) ||
            address(batchCommitment_) == address(0) ||
            address(batchCommitment_.electionConfig()) !=
            address(electionConfig_)
        ) revert InvalidResult();
        electionConfig = electionConfig_;
        batchCommitment = batchCommitment_;
        verifierRegistry = electionConfig_.verifierRegistry();
    }

    function publishTally(
        bytes32 resultHash_,
        bytes32 tallyArtifactDigest_,
        uint64[] calldata candidateCounts,
        bytes calldata proof
    ) external {
        if (resultPublished) revert ResultAlreadyPublished();
        if (block.timestamp <= electionConfig.votingEndsAt()) {
            revert SettlementIncomplete();
        }
        if (
            resultHash_ == bytes32(0) ||
            tallyArtifactDigest_ == bytes32(0) ||
            proof.length == 0
        ) revert InvalidResult();
        if (candidateCounts.length != electionConfig.candidateProfile()) {
            revert InvalidCandidateCounts();
        }

        uint256 total;
        for (uint256 index = 0; index < candidateCounts.length; ++index) {
            total += candidateCounts[index];
        }
        uint64 acceptedCount = batchCommitment.acceptedBallotCount();
        if (total != acceptedCount) revert InvalidCandidateCounts();

        bytes32 electionBinding = keccak256(
            abi.encode(
                TALLY_INPUT_DOMAIN,
                electionConfig.nationalElectionId(),
                electionConfig.constituencyId(),
                electionConfig.trusteeKeysetHash(),
                electionConfig.dkgTranscriptHash()
            )
        );
        bytes32 inputsHash = keccak256(
            abi.encode(
                electionBinding,
                batchCommitment.finalizedBatchAccumulator(),
                acceptedCount,
                resultHash_,
                tallyArtifactDigest_,
                candidateCounts,
                electionConfig.tallyVerifierVersion()
            )
        );
        address verifierAddress = verifierRegistry.getVerifier(
            TALLY_VERIFIER_TYPE,
            electionConfig.tallyVerifierVersion()
        );
        if (!ITallyProofVerifierV4(verifierAddress).verify(proof, inputsHash)) {
            revert ProofRejected();
        }

        resultPublished = true;
        resultHash = resultHash_;
        tallyArtifactDigest = tallyArtifactDigest_;
        publicInputsHash = inputsHash;
        publisher = msg.sender;
        emit TallyPublished(
            resultHash_,
            tallyArtifactDigest_,
            inputsHash,
            acceptedCount,
            msg.sender
        );
    }
}
