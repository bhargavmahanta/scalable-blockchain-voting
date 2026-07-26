import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import { keccak256, stringToHex, zeroHash, type Hex } from "viem";

import { NullifierAccumulator } from "../packages/crypto/src/index.js";
import {
  hashProofCompatibleElectionPublicKey,
  type BabyJubPoint,
} from "../packages/crypto/src/proofCompatibleBallot.js";
import {
  PROOF_COMPATIBLE_BALLOT_PROOF_SYSTEM,
  PROOF_COMPATIBLE_VOTE_PACKAGE_VERSION,
  aggregateProofCompatibleCiphertexts,
  buildProofCompatibleBatchManifest,
  decryptProofCompatibleTally,
  digestProofCompatibleVotePackage,
  parseProofCompatibleVotePackageJson,
  serializeProofCompatibleVotePackage,
  validateProofCompatibleVotePackage,
  type ProofCompatibleVotePackageV2,
} from "../packages/crypto/src/proofCompatiblePipeline.js";
import {
  createProofCompatibleDecryptionShare,
  createProofCompatibleThresholdKeySet,
  decryptProofCompatibleTallyWithShares,
  verifyProofCompatibleDecryptionShare,
} from "../packages/crypto/src/proofCompatibleThreshold.js";

type CircuitInput = {
  electionPublicKey: readonly [string, string];
  c1: readonly (readonly [string, string])[];
  c2: readonly (readonly [string, string])[];
};

type ProofArtifact = {
  proof: Hex;
  publicSignals: readonly string[];
  publicInputsHash: Hex;
};

const electionId = keccak256(stringToHex("scalable-voting-demo-2026"));
const candidateListHash = keccak256(
  stringToHex("candidate-a,candidate-b,candidate-c,candidate-d"),
);

async function packageFromFixture(
  fixtureDirectory: string,
  ballotLabel: string,
): Promise<ProofCompatibleVotePackageV2> {
  const base = new URL(`./fixtures/${fixtureDirectory}/`, import.meta.url);
  const input = JSON.parse(
    await readFile(new URL("input.json", base), "utf8"),
  ) as CircuitInput;
  const artifact = JSON.parse(
    await readFile(new URL("ballot-proof-artifact.json", base), "utf8"),
  ) as ProofArtifact;
  const electionPublicKey = input.electionPublicKey.map(BigInt) as unknown as BabyJubPoint;

  return {
    version: PROOF_COMPATIBLE_VOTE_PACKAGE_VERSION,
    electionId,
    candidateListHash,
    ballotNullifier:
      `0x${BigInt(artifact.publicSignals[2]!).toString(16).padStart(64, "0")}`,
    packageCommitment:
      `0x${BigInt(artifact.publicSignals[3]!).toString(16).padStart(64, "0")}`,
    ciphertext: {
      scheme: "ec-elgamal-babyjubjub-affine-v1",
      electionPublicKeyHash: hashProofCompatibleElectionPublicKey(electionPublicKey),
      electionPublicKey: input.electionPublicKey,
      c1: input.c1,
      c2: input.c2,
    },
    ballotValidityProof: {
      system: PROOF_COMPATIBLE_BALLOT_PROOF_SYSTEM,
      proof: artifact.proof,
      publicInputsHash: artifact.publicInputsHash,
    },
  };
}

describe("proof-compatible package, batch, and tally pipeline", function () {
  it("validates and canonically serializes a real-proof vote package", async function () {
    const votePackage = await packageFromFixture("ballot-validity", "1");
    const validated = await validateProofCompatibleVotePackage(votePackage);
    const serialized = await serializeProofCompatibleVotePackage(validated);
    const parsed = await parseProofCompatibleVotePackageJson(serialized);

    assert.equal(serialized.endsWith("\n"), true);
    assert.equal(
      await digestProofCompatibleVotePackage(parsed),
      await digestProofCompatibleVotePackage(votePackage),
    );
    assert.equal(serialized.includes("selection"), false);
    assert.equal(serialized.includes("randomness"), false);
    assert.equal(serialized.includes("timestamp"), false);
  });

  it("rejects ciphertext or metadata changes not covered by the real proof", async function () {
    const votePackage = await packageFromFixture("ballot-validity", "1");
    const changedCiphertext = structuredClone(votePackage);
    changedCiphertext.ciphertext.c2 = [
      changedCiphertext.ciphertext.c2[1]!,
      ...changedCiphertext.ciphertext.c2.slice(1),
    ];
    await assert.rejects(validateProofCompatibleVotePackage(changedCiphertext));
    await assert.rejects(
      validateProofCompatibleVotePackage({
        ...votePackage,
        clientVersion: "fingerprinting-field",
      } as unknown as ProofCompatibleVotePackageV2),
    );
  });

  it("builds an aggregate-bound batch and decrypts the expected tally", async function () {
    const first = await packageFromFixture("ballot-validity", "1");
    const second = await packageFromFixture("ballot-validity-2", "2");
    const firstAccumulator = new NullifierAccumulator();
    const secondAccumulator = new NullifierAccumulator();
    const stored = [
      { contentId: "ipfs://proof-compatible-1", package: first },
      { contentId: "ipfs://proof-compatible-2", package: second },
    ];
    const manifest = await buildProofCompatibleBatchManifest(
      electionId,
      zeroHash,
      stored,
      firstAccumulator,
    );
    const reordered = await buildProofCompatibleBatchManifest(
      electionId,
      zeroHash,
      [...stored].reverse(),
      secondAccumulator,
    );

    assert.equal(manifest.version, 2);
    assert.equal(manifest.batchSize, 2n);
    assert.equal(manifest.manifestDigest, reordered.manifestDigest);
    assert.equal(manifest.aggregateCiphertextDigest, reordered.aggregateCiphertextDigest);
    assert.deepEqual(
      await decryptProofCompatibleTally({
        privateKey: 7n,
        ciphertext: manifest.aggregateCiphertext,
        maxVotes: 2,
      }),
      [0, 1, 1, 0],
    );

    const directAggregate = await aggregateProofCompatibleCiphertexts([
      first.ciphertext,
      second.ciphertext,
    ]);
    assert.deepEqual(directAggregate, manifest.aggregateCiphertext);
  });

  it("rejects duplicate proof-compatible nullifiers", async function () {
    const first = await packageFromFixture("ballot-validity", "1");
    await assert.rejects(
      buildProofCompatibleBatchManifest(
        electionId,
        zeroHash,
        [
          { contentId: "ipfs://duplicate-1", package: first },
          { contentId: "ipfs://duplicate-2", package: first },
        ],
        new NullifierAccumulator(),
      ),
    );
  });

  it("decrypts with five of nine BabyJubJub shares and rejects a tampered DLEQ proof", async function () {
    const first = await packageFromFixture("ballot-validity", "1");
    const second = await packageFromFixture("ballot-validity-2", "2");
    const aggregate = await aggregateProofCompatibleCiphertexts([
      first.ciphertext,
      second.ciphertext,
    ]);
    const keySet = await createProofCompatibleThresholdKeySet({
      privateKey: 7n,
      threshold: 5,
      trusteeCount: 9,
      coefficients: [11n, 13n, 17n, 19n],
    });
    assert.equal(keySet.publicKeyHash, aggregate.electionPublicKeyHash);
    const shares = await Promise.all(
      keySet.shares.slice(0, 5).map((share) =>
        createProofCompatibleDecryptionShare({
          trusteeIndex: share.trusteeIndex,
          privateShare: share.privateShare,
          ciphertext: aggregate,
          proofNonces: [0, 1, 2, 3].map(
            (offset) => BigInt(100 + share.trusteeIndex * 10 + offset),
          ),
        }),
      ),
    );
    for (const share of shares) {
      assert.equal(
        await verifyProofCompatibleDecryptionShare({ ciphertext: aggregate, share }),
        true,
      );
    }
    const tally = await decryptProofCompatibleTallyWithShares({
      ciphertext: aggregate,
      shares,
      threshold: 5,
      maxVotes: 2,
    });
    assert.deepEqual(tally, [0, 1, 1, 0]);
    assert.equal(tally.reduce((sum, count) => sum + count, 0), 2);
    assert.deepEqual(
      await decryptProofCompatibleTallyWithShares({
        ciphertext: aggregate,
        shares: [...shares].reverse(),
        threshold: 5,
        maxVotes: 2,
      }),
      tally,
    );
    await assert.rejects(
      decryptProofCompatibleTallyWithShares({
        ciphertext: aggregate,
        shares: shares.slice(0, 4),
        threshold: 5,
        maxVotes: 2,
      }),
    );
    await assert.rejects(
      decryptProofCompatibleTallyWithShares({
        ciphertext: aggregate,
        shares: [shares[0]!, shares[0]!, ...shares.slice(1, 4)],
        threshold: 5,
        maxVotes: 2,
      }),
    );

    const tampered = structuredClone(shares[0]!);
    tampered.proofs = [
      { ...tampered.proofs[0]!, response: (BigInt(tampered.proofs[0]!.response) + 1n).toString() },
      ...tampered.proofs.slice(1),
    ];
    assert.equal(
      await verifyProofCompatibleDecryptionShare({ ciphertext: aggregate, share: tampered }),
      false,
    );
    await assert.rejects(
      decryptProofCompatibleTallyWithShares({
        ciphertext: aggregate,
        shares: [tampered, ...shares.slice(1)],
        threshold: 5,
        maxVotes: 2,
      }),
    );

    const modifiedPartialDecryption = structuredClone(shares[0]!);
    modifiedPartialDecryption.decryptionSharePoints = [
      shares[1]!.decryptionSharePoints[0]!,
      ...modifiedPartialDecryption.decryptionSharePoints.slice(1),
    ];
    assert.equal(
      await verifyProofCompatibleDecryptionShare({
        ciphertext: aggregate,
        share: modifiedPartialDecryption,
      }),
      false,
    );

    const otherAggregate = await aggregateProofCompatibleCiphertexts([
      first.ciphertext,
    ]);
    const shareForOtherAggregate = await createProofCompatibleDecryptionShare({
      trusteeIndex: keySet.shares[0]!.trusteeIndex,
      privateShare: keySet.shares[0]!.privateShare,
      ciphertext: otherAggregate,
      proofNonces: [201n, 202n, 203n, 204n],
    });
    assert.equal(
      await verifyProofCompatibleDecryptionShare({
        ciphertext: aggregate,
        share: shareForOtherAggregate,
      }),
      false,
    );
  });
});
