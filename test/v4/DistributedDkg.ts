import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { keccak256, stringToHex, zeroHash, type Hex } from "viem";

import {
  DkgTranscriptCoordinatorV1,
  deriveDkgSigningPublicKey,
  hashDkgContribution,
  signDkgContribution,
  verifyDkgContribution,
  type DkgContributionV1,
  type DkgTrusteeV1,
  type UnsignedDkgContributionV1,
} from "../../packages/crypto/src/index.js";

const hash = (value: string) => keccak256(stringToHex(value));
const privateKeys = Array.from(
  { length: 9 },
  (_, index) =>
    `0x${BigInt(index + 1).toString(16).padStart(64, "0")}` as Hex,
);
const trustees: readonly DkgTrusteeV1[] = privateKeys.map(
  (privateKey, index) => ({
    trusteeIndex: index + 1,
    signingPublicKey: deriveDkgSigningPublicKey(privateKey),
  }),
);

function unsignedContribution(
  trusteeIndex: number,
  round: 1 | 2,
  previousContributionHash: Hex,
  suffix = "",
): UnsignedDkgContributionV1 {
  return {
    ceremonyId: hash("ceremony-1"),
    nationalElectionId: hash("national-election"),
    constituencyId: hash("constituency"),
    trusteeIndex,
    round,
    pedersenCommitmentDigest: hash(
      `trustee-${trusteeIndex}-round-${round}-commitment-${suffix}`,
    ),
    encryptedShareBundleDigest: hash(
      `trustee-${trusteeIndex}-round-${round}-shares-${suffix}`,
    ),
    previousContributionHash,
  };
}

function signedRounds(trusteeIndex: number): readonly [
  DkgContributionV1,
  DkgContributionV1,
] {
  const roundOne = signDkgContribution(
    unsignedContribution(trusteeIndex, 1, zeroHash),
    privateKeys[trusteeIndex - 1]!,
  );
  const { signature: _signature, ...unsignedRoundOne } = roundOne;
  const roundTwo = signDkgContribution(
    unsignedContribution(
      trusteeIndex,
      2,
      hashDkgContribution(unsignedRoundOne),
    ),
    privateKeys[trusteeIndex - 1]!,
  );
  return [roundOne, roundTwo];
}

function coordinator() {
  return new DkgTranscriptCoordinatorV1({
    ceremonyId: hash("ceremony-1"),
    nationalElectionId: hash("national-election"),
    constituencyId: hash("constituency"),
    trustees,
  });
}

describe("signed 5-of-9 DKG transcript coordination", function () {
  it("finalizes with five survivors while four trustees are unavailable", function () {
    const ceremony = coordinator();
    for (let trusteeIndex = 1; trusteeIndex <= 5; trusteeIndex += 1) {
      const [roundOne, roundTwo] = signedRounds(trusteeIndex);
      ceremony.addContribution(roundOne);
      ceremony.addContribution(roundTwo);
    }
    const transcript = ceremony.finalize({
      electionPublicKey: "0x1234",
      trusteeKeysetHash: hash("keyset"),
    });
    assert.deepEqual(transcript.qualifiedTrusteeIndexes, [1, 2, 3, 4, 5]);
    assert.equal(transcript.contributionHashes.length, 10);
    assert.equal(JSON.stringify(transcript).includes("private"), false);
    assert.equal(JSON.stringify(transcript).includes("signature"), false);
  });

  it("detects signed equivocation and disqualifies the malicious trustee", function () {
    const ceremony = coordinator();
    for (let trusteeIndex = 1; trusteeIndex <= 6; trusteeIndex += 1) {
      const [roundOne, roundTwo] = signedRounds(trusteeIndex);
      ceremony.addContribution(roundOne);
      if (trusteeIndex === 1) {
        ceremony.addContribution(
          signDkgContribution(
            unsignedContribution(1, 1, zeroHash, "equivocation"),
            privateKeys[0]!,
          ),
        );
      } else {
        ceremony.addContribution(roundTwo);
      }
    }
    const transcript = ceremony.finalize({
      electionPublicKey: "0x1234",
      trusteeKeysetHash: hash("keyset"),
    });
    assert.deepEqual(transcript.disqualifiedTrusteeIndexes, [1]);
    assert.deepEqual(transcript.qualifiedTrusteeIndexes, [2, 3, 4, 5, 6]);
    assert.equal(transcript.equivocationEvidenceHashes.length, 1);
  });

  it("rejects forged or transcript-rebound contributions", function () {
    const [roundOne] = signedRounds(1);
    assert.equal(
      verifyDkgContribution(roundOne, trustees[0]!.signingPublicKey),
      true,
    );
    assert.equal(
      verifyDkgContribution(
        { ...roundOne, constituencyId: hash("other-constituency") },
        trustees[0]!.signingPublicKey,
      ),
      false,
    );
    assert.throws(() =>
      coordinator().addContribution({
        ...roundOne,
        signature: `0x${"00".repeat(64)}`,
      }),
    );
  });

  it("refuses to finalize with fewer than five qualified trustees", function () {
    const ceremony = coordinator();
    for (let trusteeIndex = 1; trusteeIndex <= 4; trusteeIndex += 1) {
      const [roundOne, roundTwo] = signedRounds(trusteeIndex);
      ceremony.addContribution(roundOne);
      ceremony.addContribution(roundTwo);
    }
    assert.throws(() =>
      ceremony.finalize({
        electionPublicKey: "0x1234",
        trusteeKeysetHash: hash("keyset"),
      }),
    );
  });
});
