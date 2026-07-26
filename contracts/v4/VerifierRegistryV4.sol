// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @notice Append-only registry for production verifier implementations.
/// @dev An election stores exact versions, so registering a newer verifier can
/// never change an active election.
contract VerifierRegistryV4 is AccessControl {
    bytes32 public constant VERIFIER_MANAGER_ROLE =
        keccak256("VERIFIER_MANAGER_ROLE");

    error InvalidGovernance();
    error InvalidVerifier();
    error InvalidVerifierVersion();
    error VerifierAlreadyRegistered(bytes32 verifierType, uint32 version);
    error VerifierTypeFrozen(bytes32 verifierType);
    error VerifierUnavailable(bytes32 verifierType, uint32 version);

    mapping(bytes32 verifierType => mapping(uint32 version => address verifier))
        private verifiers;
    mapping(bytes32 verifierType => bool frozen) public isVerifierTypeFrozen;

    event VerifierRegistered(
        bytes32 indexed verifierType,
        uint32 indexed version,
        address indexed verifier
    );
    event VerifierTypePermanentlyFrozen(bytes32 indexed verifierType);

    constructor(address adminTimelock, address verifierManagerMultisig) {
        if (
            adminTimelock == address(0) ||
            verifierManagerMultisig == address(0) ||
            adminTimelock == verifierManagerMultisig
        ) revert InvalidGovernance();
        _grantRole(DEFAULT_ADMIN_ROLE, adminTimelock);
        _grantRole(VERIFIER_MANAGER_ROLE, verifierManagerMultisig);
    }

    function registerVerifier(
        bytes32 verifierType,
        uint32 version,
        address verifier
    ) external onlyRole(VERIFIER_MANAGER_ROLE) {
        if (isVerifierTypeFrozen[verifierType]) {
            revert VerifierTypeFrozen(verifierType);
        }
        if (verifierType == bytes32(0) || version == 0) {
            revert InvalidVerifierVersion();
        }
        if (verifier == address(0) || verifier.code.length == 0) {
            revert InvalidVerifier();
        }
        if (verifiers[verifierType][version] != address(0)) {
            revert VerifierAlreadyRegistered(verifierType, version);
        }
        verifiers[verifierType][version] = verifier;
        emit VerifierRegistered(verifierType, version, verifier);
    }

    function freezeVerifierType(
        bytes32 verifierType
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (verifierType == bytes32(0)) revert InvalidVerifierVersion();
        isVerifierTypeFrozen[verifierType] = true;
        emit VerifierTypePermanentlyFrozen(verifierType);
    }

    function getVerifier(
        bytes32 verifierType,
        uint32 version
    ) external view returns (address verifier) {
        verifier = verifiers[verifierType][version];
        if (verifier == address(0)) {
            revert VerifierUnavailable(verifierType, version);
        }
    }
}
