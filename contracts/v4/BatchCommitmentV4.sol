// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {ElectionConfigV4} from "./ElectionConfigV4.sol";
import {
    IBatchValidityVerifierV4,
    IFraudProofVerifierV4
} from "./IV4ProofVerifiers.sol";
import {VerifierRegistryV4} from "./VerifierRegistryV4.sol";

/// @notice Permissionless bonded batch settlement for V4.
/// @dev Optimistic finalization is explicitly the interim security mode.
/// Recursive finalization uses a registered proof verifier and may occur
/// before the challenge window closes.
contract BatchCommitmentV4 is ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant BATCH_VERIFIER_TYPE =
        keccak256("SVB_BATCH_VALIDITY_V4");
    bytes32 public constant FRAUD_VERIFIER_TYPE =
        keccak256("SVB_BATCH_FRAUD_V4");
    bytes32 private constant BATCH_INPUT_DOMAIN =
        keccak256("SVB_BATCH_PUBLIC_INPUTS_V4");
    bytes32 private constant ACCUMULATOR_DOMAIN =
        keccak256("SVB_FINALIZED_BATCH_ACCUMULATOR_V4");

    enum BatchState {
        None,
        Proposed,
        Challenged,
        Finalized,
        Reverted
    }

    struct BatchProposal {
        BatchState state;
        address batcher;
        bytes32 packageRoot;
        bytes32 previousNullifierRoot;
        bytes32 nullifierRoot;
        bytes32 manifestDigest;
        bytes32 aggregateCiphertextDigest;
        bytes32 availabilityCertificateHash;
        bytes32 batchPublicInputsHash;
        uint64 ballotCount;
        uint64 proposedAt;
        uint64 challengeDeadline;
        uint32 batchVerifierVersion;
        uint32 fraudVerifierVersion;
        uint256 bond;
    }

    struct BatchInput {
        bytes32 packageRoot;
        bytes32 previousNullifierRoot;
        bytes32 nullifierRoot;
        bytes32 manifestDigest;
        bytes32 aggregateCiphertextDigest;
        bytes32 availabilityCertificateHash;
        uint64 ballotCount;
    }

    error BatchAlreadyProposed();
    error BatchNotFinalizable();
    error BatchNotProposed();
    error ChallengeWindowClosed();
    error ChallengeWindowOpen();
    error InvalidBatch();
    error InvalidBondConfiguration();
    error InvalidProof();
    error ProposalWindowClosed();
    error SettlementWindowClosed();
    error StaleNullifierTransition();

    ElectionConfigV4 public immutable electionConfig;
    VerifierRegistryV4 public immutable verifierRegistry;
    IERC20 public immutable bondToken;
    uint256 public immutable batcherBond;
    uint256 public immutable challengerBond;
    uint64 public immutable challengePeriod;
    uint32 public immutable fraudVerifierVersion;

    bytes32 public finalizedNullifierRoot;
    bytes32 public finalizedBatchAccumulator;
    uint64 public finalizedBatchCount;
    uint64 public acceptedBallotCount;

    mapping(bytes32 proposalId => BatchProposal proposal) private proposals;
    mapping(bytes32 manifestDigest => bool proposed) public isManifestProposed;
    mapping(address batcher => uint256 nonce) public batcherNonces;

    event BatchProposed(
        bytes32 indexed proposalId,
        address indexed batcher,
        bytes32 indexed manifestDigest,
        bytes32 previousNullifierRoot,
        bytes32 nullifierRoot,
        bytes32 packageRoot,
        uint64 ballotCount,
        uint64 challengeDeadline
    );
    event BatchChallengeResolved(
        bytes32 indexed proposalId,
        address indexed challenger,
        bytes32 indexed challengeType,
        bool fraudProven
    );
    event BatchFinalized(
        bytes32 indexed proposalId,
        uint64 indexed finalizedBatchIndex,
        bool recursivelyProved,
        bytes32 finalizedBatchAccumulator,
        uint64 acceptedBallotCount
    );
    event BatchReverted(bytes32 indexed proposalId, bytes32 indexed reason);

    constructor(
        ElectionConfigV4 electionConfig_,
        IERC20 bondToken_,
        uint256 batcherBond_,
        uint256 challengerBond_,
        uint64 challengePeriod_,
        uint32 fraudVerifierVersion_
    ) {
        if (
            address(electionConfig_) == address(0) ||
            address(bondToken_) == address(0) ||
            batcherBond_ == 0 ||
            challengerBond_ == 0 ||
            challengePeriod_ == 0 ||
            fraudVerifierVersion_ == 0
        ) revert InvalidBondConfiguration();
        electionConfig = electionConfig_;
        verifierRegistry = electionConfig_.verifierRegistry();
        bondToken = bondToken_;
        batcherBond = batcherBond_;
        challengerBond = challengerBond_;
        challengePeriod = challengePeriod_;
        fraudVerifierVersion = fraudVerifierVersion_;
    }

    function proposeBatch(
        BatchInput calldata batch
    ) external nonReentrant returns (bytes32 proposalId) {
        if (block.timestamp > electionConfig.votingEndsAt()) {
            revert ProposalWindowClosed();
        }
        if (
            batch.packageRoot == bytes32(0) ||
            batch.nullifierRoot == bytes32(0) ||
            batch.nullifierRoot == batch.previousNullifierRoot ||
            batch.manifestDigest == bytes32(0) ||
            batch.aggregateCiphertextDigest == bytes32(0) ||
            batch.availabilityCertificateHash == bytes32(0) ||
            batch.ballotCount == 0
        ) revert InvalidBatch();
        if (batch.previousNullifierRoot != finalizedNullifierRoot) {
            revert StaleNullifierTransition();
        }
        if (isManifestProposed[batch.manifestDigest]) {
            revert BatchAlreadyProposed();
        }

        uint256 nonce = batcherNonces[msg.sender]++;
        proposalId = keccak256(
            abi.encode(
                electionConfig.nationalElectionId(),
                electionConfig.constituencyId(),
                msg.sender,
                nonce,
                batch.manifestDigest
            )
        );
        uint64 challengeDeadline = uint64(block.timestamp) + challengePeriod;
        if (challengeDeadline > electionConfig.settlementEndsAt()) {
            revert SettlementWindowClosed();
        }
        uint32 batchVerifierVersion = electionConfig.batchVerifierVersion();
        bytes32 batchPublicInputsHash = computeBatchPublicInputsHash(
            batch,
            batchVerifierVersion
        );

        proposals[proposalId] = BatchProposal({
            state: BatchState.Proposed,
            batcher: msg.sender,
            packageRoot: batch.packageRoot,
            previousNullifierRoot: batch.previousNullifierRoot,
            nullifierRoot: batch.nullifierRoot,
            manifestDigest: batch.manifestDigest,
            aggregateCiphertextDigest: batch.aggregateCiphertextDigest,
            availabilityCertificateHash: batch.availabilityCertificateHash,
            batchPublicInputsHash: batchPublicInputsHash,
            ballotCount: batch.ballotCount,
            proposedAt: uint64(block.timestamp),
            challengeDeadline: challengeDeadline,
            batchVerifierVersion: batchVerifierVersion,
            fraudVerifierVersion: fraudVerifierVersion,
            bond: batcherBond
        });
        isManifestProposed[batch.manifestDigest] = true;
        bondToken.safeTransferFrom(msg.sender, address(this), batcherBond);

        emit BatchProposed(
            proposalId,
            msg.sender,
            batch.manifestDigest,
            batch.previousNullifierRoot,
            batch.nullifierRoot,
            batch.packageRoot,
            batch.ballotCount,
            challengeDeadline
        );
    }

    function challengeBatch(
        bytes32 proposalId,
        bytes32 challengeType,
        bytes calldata evidence
    ) external nonReentrant returns (bool fraudProven) {
        BatchProposal storage proposal = proposals[proposalId];
        if (proposal.state != BatchState.Proposed) revert BatchNotProposed();
        if (block.timestamp > proposal.challengeDeadline) {
            revert ChallengeWindowClosed();
        }
        if (challengeType == bytes32(0) || evidence.length == 0) {
            revert InvalidProof();
        }

        bondToken.safeTransferFrom(msg.sender, address(this), challengerBond);
        proposal.state = BatchState.Challenged;
        address verifierAddress = verifierRegistry.getVerifier(
            FRAUD_VERIFIER_TYPE,
            proposal.fraudVerifierVersion
        );
        fraudProven = IFraudProofVerifierV4(verifierAddress).verifyChallenge(
            challengeType,
            evidence,
            proposal.batchPublicInputsHash
        );

        if (fraudProven) {
            proposal.state = BatchState.Reverted;
            uint256 payout = proposal.bond + challengerBond;
            proposal.bond = 0;
            bondToken.safeTransfer(msg.sender, payout);
            emit BatchReverted(proposalId, challengeType);
        } else {
            proposal.state = BatchState.Proposed;
            bondToken.safeTransfer(proposal.batcher, challengerBond);
        }
        emit BatchChallengeResolved(
            proposalId,
            msg.sender,
            challengeType,
            fraudProven
        );
    }

    function finalizeOptimistic(bytes32 proposalId) external nonReentrant {
        BatchProposal storage proposal = proposals[proposalId];
        if (proposal.state != BatchState.Proposed) revert BatchNotFinalizable();
        if (block.timestamp <= proposal.challengeDeadline) {
            revert ChallengeWindowOpen();
        }
        _finalize(proposalId, proposal, false);
    }

    function finalizeWithProof(
        bytes32 proposalId,
        bytes calldata proof
    ) external nonReentrant {
        BatchProposal storage proposal = proposals[proposalId];
        if (proposal.state != BatchState.Proposed) revert BatchNotFinalizable();
        if (proof.length == 0) revert InvalidProof();
        address verifierAddress = verifierRegistry.getVerifier(
            BATCH_VERIFIER_TYPE,
            proposal.batchVerifierVersion
        );
        if (
            !IBatchValidityVerifierV4(verifierAddress).verify(
                proof,
                proposal.batchPublicInputsHash
            )
        ) revert InvalidProof();
        _finalize(proposalId, proposal, true);
    }

    function revertStaleProposal(bytes32 proposalId) external nonReentrant {
        BatchProposal storage proposal = proposals[proposalId];
        if (
            proposal.state != BatchState.Proposed ||
            proposal.previousNullifierRoot == finalizedNullifierRoot
        ) revert BatchNotFinalizable();
        proposal.state = BatchState.Reverted;
        uint256 refund = proposal.bond;
        proposal.bond = 0;
        bondToken.safeTransfer(proposal.batcher, refund);
        emit BatchReverted(proposalId, keccak256("STALE_TRANSITION"));
    }

    function getProposal(
        bytes32 proposalId
    ) external view returns (BatchProposal memory) {
        return proposals[proposalId];
    }

    function computeBatchPublicInputsHash(
        BatchInput memory batch,
        uint32 batchVerifierVersion
    ) public view returns (bytes32) {
        bytes32 electionBinding = keccak256(
            abi.encode(
                BATCH_INPUT_DOMAIN,
                electionConfig.nationalElectionId(),
                electionConfig.constituencyId(),
                electionConfig.eligibilityRoot(),
                electionConfig.eligibilityRootVersion(),
                electionConfig.candidateProfile()
            )
        );
        return keccak256(
            abi.encode(
                electionBinding,
                batch,
                batchVerifierVersion
            )
        );
    }

    function _finalize(
        bytes32 proposalId,
        BatchProposal storage proposal,
        bool recursivelyProved
    ) private {
        if (block.timestamp > electionConfig.settlementEndsAt()) {
            revert SettlementWindowClosed();
        }
        if (proposal.previousNullifierRoot != finalizedNullifierRoot) {
            revert StaleNullifierTransition();
        }

        proposal.state = BatchState.Finalized;
        finalizedNullifierRoot = proposal.nullifierRoot;
        finalizedBatchAccumulator = keccak256(
            abi.encode(
                ACCUMULATOR_DOMAIN,
                finalizedBatchAccumulator,
                proposal.batchPublicInputsHash
            )
        );
        uint64 finalizedIndex = finalizedBatchCount;
        finalizedBatchCount = finalizedIndex + 1;
        acceptedBallotCount += proposal.ballotCount;

        uint256 refund = proposal.bond;
        proposal.bond = 0;
        bondToken.safeTransfer(proposal.batcher, refund);
        emit BatchFinalized(
            proposalId,
            finalizedIndex,
            recursivelyProved,
            finalizedBatchAccumulator,
            acceptedBallotCount
        );
    }
}
