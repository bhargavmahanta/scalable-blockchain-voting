// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ElectionConfigV4} from "../../v4/ElectionConfigV4.sol";

contract MockAcceptedBallotsV4 {
    uint64 public immutable acceptedBallotCount;

    constructor(uint64 acceptedBallotCount_) {
        acceptedBallotCount = acceptedBallotCount_;
    }
}

contract MockPublishedTallyV4 {
    ElectionConfigV4 public immutable electionConfig;
    MockAcceptedBallotsV4 public immutable batchCommitment;
    bytes32 public immutable resultHash;
    bytes32 public immutable tallyArtifactDigest;
    bytes32 public immutable publicInputsHash;
    bool public immutable resultPublished;

    constructor(
        ElectionConfigV4 electionConfig_,
        MockAcceptedBallotsV4 batchCommitment_,
        bytes32 resultHash_,
        bytes32 tallyArtifactDigest_,
        bytes32 publicInputsHash_,
        bool resultPublished_
    ) {
        electionConfig = electionConfig_;
        batchCommitment = batchCommitment_;
        resultHash = resultHash_;
        tallyArtifactDigest = tallyArtifactDigest_;
        publicInputsHash = publicInputsHash_;
        resultPublished = resultPublished_;
    }
}
