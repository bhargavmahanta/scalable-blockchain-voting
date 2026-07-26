// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {VoterRegistry} from "./VoterRegistry.sol";

interface IBallotProofVerifier {
    function verify(
        bytes calldata proof,
        bytes32 publicInputsHash,
        bytes32 electionId,
        bytes32 candidateListHash,
        bytes32 ballotNullifier,
        bytes32 votePackageDigest
    ) external view returns (bool);
}

/// @notice Direct ballot-commitment path used for local contract testing.
/// @dev The scalable demo path will commit batches instead of one transaction
/// per ballot.
contract VotingContract is Ownable {
    error InvalidDigest();
    error InvalidBallotNullifier();
    error InvalidBallotPublicInputs();
    error NonCanonicalBallotNullifier();
    error NoBallotVerifier();
    error BallotProofRejected();
    error NullifierAlreadyUsed(bytes32 ballotNullifier);
    error UnauthorizedVotingKey();

    bytes32 public immutable electionId;
    bytes32 public immutable candidateListHash;
    VoterRegistry public immutable voterRegistry;
    IBallotProofVerifier public ballotProofVerifier;

    mapping(bytes32 ballotNullifier => bool used) public isNullifierUsed;
    mapping(bytes32 ballotNullifier => bytes32 publicInputsHash)
        public ballotPublicInputsHashOf;

    event BallotCommitted(
        bytes32 indexed ballotNullifier,
        bytes32 indexed identityNullifier,
        bytes32 votePackageDigest
    );
    event BallotProofVerifierChanged(address indexed verifier);

    constructor(
        bytes32 electionId_,
        bytes32 candidateListHash_,
        VoterRegistry voterRegistry_,
        address initialOwner,
        IBallotProofVerifier initialBallotProofVerifier
    ) Ownable(initialOwner) {
        electionId = electionId_;
        candidateListHash = candidateListHash_;
        voterRegistry = voterRegistry_;
        ballotProofVerifier = initialBallotProofVerifier;
        emit BallotProofVerifierChanged(address(initialBallotProofVerifier));
    }

    function setBallotProofVerifier(
        IBallotProofVerifier verifier
    ) external onlyOwner {
        ballotProofVerifier = verifier;
        emit BallotProofVerifierChanged(address(verifier));
    }

    /// @notice Trusted/reference path for local tests.
    /// @dev The scalable path should use package proofs and batch proofs.
    function submitBallot(
        bytes32 identityNullifier,
        bytes32 ballotNullifier,
        bytes32 votePackageDigest
    ) external {
        _commitBallot(
            identityNullifier,
            ballotNullifier,
            votePackageDigest,
            bytes32(0)
        );
    }

    /// @notice Proof-gated direct ballot path used to exercise the ballot
    /// verifier seam before the batch circuit is ready.
    /// @dev The verifier statement is built off-chain and represented here by
    /// `ballotPublicInputsHash`; the real circuit must bind election,
    /// candidate list, ciphertext, and ballot nullifier.
    function submitBallotWithProof(
        bytes32 identityNullifier,
        bytes32 ballotNullifier,
        bytes32 votePackageDigest,
        bytes32 ballotPublicInputsHash,
        bytes calldata proof
    ) external {
        if (ballotPublicInputsHash == bytes32(0)) {
            revert InvalidBallotPublicInputs();
        }
        if (
            uint256(ballotNullifier) >=
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        ) {
            revert NonCanonicalBallotNullifier();
        }
        IBallotProofVerifier verifier = ballotProofVerifier;
        if (address(verifier) == address(0)) revert NoBallotVerifier();
        if (!verifier.verify(
            proof,
            ballotPublicInputsHash,
            electionId,
            candidateListHash,
            ballotNullifier,
            votePackageDigest
        )) {
            revert BallotProofRejected();
        }
        _commitBallot(
            identityNullifier,
            ballotNullifier,
            votePackageDigest,
            ballotPublicInputsHash
        );
    }

    function _commitBallot(
        bytes32 identityNullifier,
        bytes32 ballotNullifier,
        bytes32 votePackageDigest,
        bytes32 ballotPublicInputsHash
    ) private {
        if (ballotNullifier == bytes32(0)) revert InvalidBallotNullifier();
        if (votePackageDigest == bytes32(0)) revert InvalidDigest();
        if (isNullifierUsed[ballotNullifier]) {
            revert NullifierAlreadyUsed(ballotNullifier);
        }
        if (voterRegistry.votingKeyOf(identityNullifier) != msg.sender) {
            revert UnauthorizedVotingKey();
        }

        isNullifierUsed[ballotNullifier] = true;
        ballotPublicInputsHashOf[ballotNullifier] = ballotPublicInputsHash;
        emit BallotCommitted(
            ballotNullifier,
            identityNullifier,
            votePackageDigest
        );
    }
}
