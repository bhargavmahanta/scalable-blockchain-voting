// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IEligibilityVerifier {
    function verify(
        bytes calldata proof,
        bytes32 publicInputsHash,
        bytes32 electionId,
        bytes32 identityNullifier,
        address votingKey
    ) external view returns (bool);
}

/// @notice Registration seam for the first testnet demo.
/// @dev The owner-only path is still trusted. The proof path only becomes as
/// strong as the configured verifier contract.
contract VoterRegistry is Ownable {
    error IdentityAlreadyRegistered(bytes32 identityNullifier);
    error InvalidIdentityNullifier();
    error InvalidEligibilityProof();
    error NoEligibilityVerifier();
    error VotingKeyAlreadyRegistered(address votingKey);
    error InvalidVotingKey();
    error UnknownIdentity(bytes32 identityNullifier);

    bytes32 public immutable electionId;
    IEligibilityVerifier public eligibilityVerifier;

    mapping(bytes32 identityNullifier => address votingKey)
        private votingKeys;
    mapping(address votingKey => bool registered) public isVotingKeyRegistered;

    event VoterRegistered(
        bytes32 indexed identityNullifier,
        address indexed votingKey
    );
    event EligibilityVerifierChanged(address indexed verifier);

    constructor(
        bytes32 electionId_,
        address initialOwner,
        IEligibilityVerifier initialEligibilityVerifier
    )
        Ownable(initialOwner)
    {
        electionId = electionId_;
        eligibilityVerifier = initialEligibilityVerifier;
        emit EligibilityVerifierChanged(address(initialEligibilityVerifier));
    }

    /// @notice Trusted demo path. Useful before the anonymous verifier is ready.
    function register(
        bytes32 identityNullifier,
        address votingKey
    ) external onlyOwner {
        _register(identityNullifier, votingKey);
    }

    /// @notice Proof-based path for anonymous eligibility verification.
    /// @dev The statement is: this proof authorizes binding the
    /// election-scoped `identityNullifier` to `votingKey` for `electionId`.
    function registerWithProof(
        bytes32 identityNullifier,
        address votingKey,
        bytes calldata proof
    ) external {
        IEligibilityVerifier verifier = eligibilityVerifier;
        if (address(verifier) == address(0)) revert NoEligibilityVerifier();

        bytes32 publicInputsHash = registrationPublicInputsHash(
            identityNullifier,
            votingKey
        );
        if (!verifier.verify(
            proof,
            publicInputsHash,
            electionId,
            identityNullifier,
            votingKey
        )) {
            revert InvalidEligibilityProof();
        }

        _register(identityNullifier, votingKey);
    }

    function setEligibilityVerifier(
        IEligibilityVerifier verifier
    ) external onlyOwner {
        eligibilityVerifier = verifier;
        emit EligibilityVerifierChanged(address(verifier));
    }

    function registrationPublicInputsHash(
        bytes32 identityNullifier,
        address votingKey
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("SVB_REGISTRATION_PUBLIC_INPUTS_V1"),
                electionId,
                identityNullifier,
                votingKey
            )
        );
    }

    function _register(bytes32 identityNullifier, address votingKey) private {
        if (identityNullifier == bytes32(0)) {
            revert InvalidIdentityNullifier();
        }
        if (votingKey == address(0)) revert InvalidVotingKey();
        if (votingKeys[identityNullifier] != address(0)) {
            revert IdentityAlreadyRegistered(identityNullifier);
        }
        if (isVotingKeyRegistered[votingKey]) {
            revert VotingKeyAlreadyRegistered(votingKey);
        }

        votingKeys[identityNullifier] = votingKey;
        isVotingKeyRegistered[votingKey] = true;

        emit VoterRegistered(identityNullifier, votingKey);
    }

    function votingKeyOf(
        bytes32 identityNullifier
    ) external view returns (address) {
        address votingKey = votingKeys[identityNullifier];
        if (votingKey == address(0)) {
            revert UnknownIdentity(identityNullifier);
        }
        return votingKey;
    }
}
