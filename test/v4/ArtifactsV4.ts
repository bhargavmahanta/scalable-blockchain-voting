import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { keccak256, stringToHex, type Hex } from "viem";

import {
  TALLY_ARTIFACT_V4_SCHEMA,
  VOTE_PACKAGE_V4_SCHEMA,
  sealArtifact,
  validateTallyArtifactV4,
  verifyArtifactDigest,
  type TallyArtifactV4,
  type VotePackageV4,
} from "../../packages/crypto/src/index.js";

const hash = (value: string) => keccak256(stringToHex(value));

describe("V4 public artifact schemas", function () {
  it("creates a stable canonical vote-package digest without identity or choice", function () {
    const unsigned: Omit<VotePackageV4, "canonicalDigest"> = {
      schemaVersion: VOTE_PACKAGE_V4_SCHEMA,
      nationalElectionId: hash("national"),
      constituencyId: hash("constituency"),
      verifierVersion: 3,
      parentArtifactHashes: [hash("credential-root-artifact")],
      eligibilityRootVersion: 7,
      candidateProfile: 4,
      ballotNullifier: hash("national-nullifier"),
      ciphertextDigest: hash("ciphertext"),
      encryptedBallot: "0x1234",
      eligibilityAndBallotProof: "0xabcd",
      proofPublicInputsHash: hash("proof-inputs"),
    };
    const sealed = sealArtifact<VotePackageV4>(
      "SVB_VOTE_PACKAGE_V4",
      unsigned,
    );
    assert.equal(verifyArtifactDigest("SVB_VOTE_PACKAGE_V4", sealed), true);
    assert.equal("selectedCandidate" in sealed, false);
    assert.equal("identity" in sealed, false);
    assert.equal(
      verifyArtifactDigest("SVB_VOTE_PACKAGE_V4", {
        ...sealed,
        ciphertextDigest: hash("tampered"),
      }),
      false,
    );
  });

  it("requires bounded nonnegative totals and at least five shares", function () {
    const unsigned: Omit<TallyArtifactV4, "canonicalDigest"> = {
      schemaVersion: TALLY_ARTIFACT_V4_SCHEMA,
      nationalElectionId: hash("national"),
      constituencyId: hash("constituency"),
      verifierVersion: 5,
      parentArtifactHashes: [hash("batch-proof"), hash("dkg")],
      finalizedBatchAccumulator: hash("finalized-batches"),
      trusteeKeysetHash: hash("trustee-keyset"),
      dkgTranscriptHash: hash("dkg-transcript"),
      acceptedBallotCount: 10,
      candidateCounts: [4, 3, 2, 1],
      decryptionShareDigests: [
        hash("share-1"),
        hash("share-2"),
        hash("share-3"),
        hash("share-4"),
        hash("share-5"),
      ],
      tallyProof: "0x1234" as Hex,
      tallyPublicInputsHash: hash("tally-inputs"),
    };
    const artifact = sealArtifact<TallyArtifactV4>(
      "SVB_TALLY_ARTIFACT_V4",
      unsigned,
    );
    assert.equal(validateTallyArtifactV4(artifact), artifact);

    assert.throws(() =>
      validateTallyArtifactV4({
        ...artifact,
        acceptedBallotCount: 11,
      }),
    );
    assert.throws(() =>
      validateTallyArtifactV4({
        ...artifact,
        decryptionShareDigests: artifact.decryptionShareDigests.slice(0, 4),
      }),
    );
  });
});
