// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {VerifierRegistryV4} from "./VerifierRegistryV4.sol";

/// @notice Immutable production parameters for one constituency election.
/// @dev A changed parameter requires a new deployment; active elections are
/// never upgraded in place.
contract ElectionConfigV4 {
    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    error InvalidConfiguration();
    error InvalidVotingWindow();
    error UnsupportedCandidateProfile();

    struct ElectionParameters {
        bytes32 nationalElectionId;
        bytes32 constituencyId;
        bytes32 eligibilityRoot;
        uint64 eligibilityRootVersion;
        uint8 candidateProfile;
        bytes32 candidateListHash;
        bytes32 trusteeKeysetHash;
        bytes32 dkgTranscriptHash;
        uint32 eligibilityVerifierVersion;
        uint32 batchVerifierVersion;
        uint32 tallyVerifierVersion;
        uint64 votingStartsAt;
        uint64 votingEndsAt;
        uint64 settlementEndsAt;
    }

    bytes32 public immutable nationalElectionId;
    bytes32 public immutable constituencyId;
    bytes32 public immutable eligibilityRoot;
    uint64 public immutable eligibilityRootVersion;
    uint8 public immutable candidateProfile;
    bytes32 public immutable candidateListHash;
    bytes32 public immutable trusteeKeysetHash;
    bytes32 public immutable dkgTranscriptHash;
    VerifierRegistryV4 public immutable verifierRegistry;
    uint32 public immutable eligibilityVerifierVersion;
    uint32 public immutable batchVerifierVersion;
    uint32 public immutable tallyVerifierVersion;
    uint64 public immutable votingStartsAt;
    uint64 public immutable votingEndsAt;
    uint64 public immutable settlementEndsAt;

    constructor(
        ElectionParameters memory parameters,
        VerifierRegistryV4 verifierRegistry_
    ) {
        if (
            parameters.nationalElectionId == bytes32(0) ||
            parameters.constituencyId == bytes32(0) ||
            parameters.eligibilityRoot == bytes32(0) ||
            uint256(parameters.eligibilityRoot) >= SNARK_SCALAR_FIELD ||
            parameters.eligibilityRootVersion == 0 ||
            parameters.candidateListHash == bytes32(0) ||
            parameters.trusteeKeysetHash == bytes32(0) ||
            parameters.dkgTranscriptHash == bytes32(0) ||
            address(verifierRegistry_) == address(0) ||
            parameters.eligibilityVerifierVersion == 0 ||
            parameters.batchVerifierVersion == 0 ||
            parameters.tallyVerifierVersion == 0
        ) revert InvalidConfiguration();
        if (
            parameters.candidateProfile != 4 &&
            parameters.candidateProfile != 16
        ) {
            revert UnsupportedCandidateProfile();
        }
        if (
            parameters.votingStartsAt >= parameters.votingEndsAt ||
            parameters.votingEndsAt >= parameters.settlementEndsAt
        ) revert InvalidVotingWindow();

        nationalElectionId = parameters.nationalElectionId;
        constituencyId = parameters.constituencyId;
        eligibilityRoot = parameters.eligibilityRoot;
        eligibilityRootVersion = parameters.eligibilityRootVersion;
        candidateProfile = parameters.candidateProfile;
        candidateListHash = parameters.candidateListHash;
        trusteeKeysetHash = parameters.trusteeKeysetHash;
        dkgTranscriptHash = parameters.dkgTranscriptHash;
        verifierRegistry = verifierRegistry_;
        eligibilityVerifierVersion = parameters.eligibilityVerifierVersion;
        batchVerifierVersion = parameters.batchVerifierVersion;
        tallyVerifierVersion = parameters.tallyVerifierVersion;
        votingStartsAt = parameters.votingStartsAt;
        votingEndsAt = parameters.votingEndsAt;
        settlementEndsAt = parameters.settlementEndsAt;
    }

    function isVotingOpen() external view returns (bool) {
        return
            block.timestamp >= votingStartsAt &&
            block.timestamp <= votingEndsAt;
    }
}
