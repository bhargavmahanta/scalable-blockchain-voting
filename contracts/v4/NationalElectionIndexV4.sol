// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

import {ElectionConfigV4} from "./ElectionConfigV4.sol";
import {TallyVerifierV4} from "./TallyVerifierV4.sol";

/// @notice Canonical national index over independently processed constituency
/// elections. Ballots and proofs remain sharded; this contract stores only
/// verified tally references in the frozen registration order.
contract NationalElectionIndexV4 is AccessControl {
    bytes32 public constant CONSTITUENCY_REGISTRAR_ROLE =
        keccak256("CONSTITUENCY_REGISTRAR_ROLE");
    bytes32 private constant TALLY_LEAF_DOMAIN =
        keccak256("SVB_CONSTITUENCY_TALLY_LEAF_V4");
    bytes32 private constant INDEX_DOMAIN =
        keccak256("SVB_NATIONAL_TALLY_INDEX_V4");

    struct ConstituencyRecord {
        bytes32 constituencyId;
        ElectionConfigV4 electionConfig;
        TallyVerifierV4 tallyVerifier;
        bytes32 tallyLeaf;
        bool tallyRecorded;
    }

    error ConstituencyAlreadyRegistered();
    error ConstituencyNotRegistered();
    error InvalidConstituency();
    error InvalidGovernance();
    error NationalIndexIncomplete();
    error RegistrationAlreadyFrozen();
    error RegistrationNotFrozen();
    error TallyNotPublished();

    bytes32 public immutable nationalElectionId;
    uint32 public immutable expectedConstituencyCount;
    bool public registrationFrozen;
    bool public nationalIndexFinalized;
    uint32 public registeredConstituencyCount;
    uint32 public recordedTallyCount;
    uint32 public accumulatedTallyCount;
    uint64 public nationalAcceptedBallotCount;
    bytes32 public nationalTallyAccumulator;

    mapping(bytes32 constituencyId => uint256 indexPlusOne)
        public constituencyIndex;
    mapping(uint256 index => ConstituencyRecord record) private records;

    event ConstituencyRegistered(
        uint256 indexed index,
        bytes32 indexed constituencyId,
        address indexed electionConfig,
        address tallyVerifier
    );
    event ConstituencyRegistrationFrozen(uint32 constituencyCount);
    event ConstituencyTallyRecorded(
        uint256 indexed index,
        bytes32 indexed constituencyId,
        bytes32 indexed tallyLeaf,
        uint64 acceptedBallotCount
    );
    event ConstituencyTallyAccumulated(
        uint256 indexed index,
        bytes32 indexed constituencyId,
        bytes32 nationalTallyAccumulator
    );
    event NationalIndexFinalized(
        bytes32 indexed nationalTallyAccumulator,
        uint32 constituencyCount,
        uint64 acceptedBallotCount
    );

    constructor(
        bytes32 nationalElectionId_,
        uint32 expectedConstituencyCount_,
        address adminTimelock,
        address registrarMultisig
    ) {
        if (
            nationalElectionId_ == bytes32(0) ||
            expectedConstituencyCount_ == 0 ||
            adminTimelock == address(0) ||
            registrarMultisig == address(0) ||
            adminTimelock == registrarMultisig
        ) revert InvalidGovernance();
        nationalElectionId = nationalElectionId_;
        expectedConstituencyCount = expectedConstituencyCount_;
        _grantRole(DEFAULT_ADMIN_ROLE, adminTimelock);
        _grantRole(CONSTITUENCY_REGISTRAR_ROLE, registrarMultisig);
    }

    function registerConstituency(
        ElectionConfigV4 electionConfig,
        TallyVerifierV4 tallyVerifier
    ) external onlyRole(CONSTITUENCY_REGISTRAR_ROLE) {
        if (registrationFrozen) revert RegistrationAlreadyFrozen();
        if (
            address(electionConfig) == address(0) ||
            address(tallyVerifier) == address(0) ||
            electionConfig.nationalElectionId() != nationalElectionId ||
            address(tallyVerifier.electionConfig()) != address(electionConfig)
        ) revert InvalidConstituency();
        bytes32 constituencyId = electionConfig.constituencyId();
        if (constituencyIndex[constituencyId] != 0) {
            revert ConstituencyAlreadyRegistered();
        }
        uint32 count = registeredConstituencyCount;
        if (count >= expectedConstituencyCount) revert InvalidConstituency();
        records[count] = ConstituencyRecord({
            constituencyId: constituencyId,
            electionConfig: electionConfig,
            tallyVerifier: tallyVerifier,
            tallyLeaf: bytes32(0),
            tallyRecorded: false
        });
        constituencyIndex[constituencyId] = uint256(count) + 1;
        registeredConstituencyCount = count + 1;
        emit ConstituencyRegistered(
            count,
            constituencyId,
            address(electionConfig),
            address(tallyVerifier)
        );
    }

    function freezeRegistration() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (registrationFrozen) revert RegistrationAlreadyFrozen();
        if (registeredConstituencyCount != expectedConstituencyCount) {
            revert NationalIndexIncomplete();
        }
        registrationFrozen = true;
        emit ConstituencyRegistrationFrozen(registeredConstituencyCount);
    }

    function recordConstituencyTally(bytes32 constituencyId) external {
        if (!registrationFrozen) revert RegistrationNotFrozen();
        uint256 indexPlusOne = constituencyIndex[constituencyId];
        if (indexPlusOne == 0) revert ConstituencyNotRegistered();
        uint256 index = indexPlusOne - 1;
        ConstituencyRecord storage record = records[index];
        if (record.tallyRecorded) revert ConstituencyAlreadyRegistered();
        TallyVerifierV4 tally = record.tallyVerifier;
        if (!tally.resultPublished()) revert TallyNotPublished();
        uint64 acceptedCount = tally.batchCommitment().acceptedBallotCount();
        bytes32 tallyLeaf = keccak256(
            abi.encode(
                TALLY_LEAF_DOMAIN,
                nationalElectionId,
                constituencyId,
                address(record.electionConfig),
                address(tally),
                tally.resultHash(),
                tally.tallyArtifactDigest(),
                tally.publicInputsHash(),
                acceptedCount
            )
        );
        record.tallyLeaf = tallyLeaf;
        record.tallyRecorded = true;
        recordedTallyCount += 1;
        nationalAcceptedBallotCount += acceptedCount;
        emit ConstituencyTallyRecorded(
            index,
            constituencyId,
            tallyLeaf,
            acceptedCount
        );
    }

    /// @notice Accumulates the next registered constituency only after its
    /// proof-gated tally is recorded, making the national index deterministic
    /// regardless of the order in which constituencies finish.
    function accumulateNextTally() external {
        if (!registrationFrozen) revert RegistrationNotFrozen();
        uint32 index = accumulatedTallyCount;
        if (index >= expectedConstituencyCount) {
            revert NationalIndexIncomplete();
        }
        ConstituencyRecord storage record = records[index];
        if (!record.tallyRecorded) revert TallyNotPublished();
        nationalTallyAccumulator = keccak256(
            abi.encode(
                INDEX_DOMAIN,
                nationalTallyAccumulator,
                record.tallyLeaf
            )
        );
        accumulatedTallyCount = index + 1;
        emit ConstituencyTallyAccumulated(
            index,
            record.constituencyId,
            nationalTallyAccumulator
        );
    }

    function finalizeNationalIndex() external {
        if (
            !registrationFrozen ||
            accumulatedTallyCount != expectedConstituencyCount
        ) revert NationalIndexIncomplete();
        if (nationalIndexFinalized) revert RegistrationAlreadyFrozen();
        nationalIndexFinalized = true;
        emit NationalIndexFinalized(
            nationalTallyAccumulator,
            expectedConstituencyCount,
            nationalAcceptedBallotCount
        );
    }

    function getConstituency(
        uint256 index
    ) external view returns (ConstituencyRecord memory) {
        if (index >= registeredConstituencyCount) {
            revert ConstituencyNotRegistered();
        }
        return records[index];
    }
}
