import assert from "node:assert/strict";

import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  encodeAbiParameters,
  isHex,
  keccak256,
  parseAbiParameters,
  stringToHex,
  zeroHash,
} from "viem";

import type { Bytes32, Hex } from "./index.js";

export const DKG_TRANSCRIPT_VERSION = 1 as const;
export const DKG_THRESHOLD = 5 as const;
export const DKG_TRUSTEE_COUNT = 9 as const;

const contributionDomain = keccak256(
  stringToHex("SVB_PEDERSEN_DKG_CONTRIBUTION_V1"),
);
const equivocationDomain = keccak256(
  stringToHex("SVB_PEDERSEN_DKG_EQUIVOCATION_V1"),
);
const transcriptDomain = keccak256(
  stringToHex("SVB_PEDERSEN_DKG_TRANSCRIPT_V1"),
);

export type DkgTrusteeV1 = {
  trusteeIndex: number;
  signingPublicKey: Hex;
};

export type UnsignedDkgContributionV1 = {
  ceremonyId: Bytes32;
  nationalElectionId: Bytes32;
  constituencyId: Bytes32;
  trusteeIndex: number;
  round: 1 | 2;
  pedersenCommitmentDigest: Bytes32;
  encryptedShareBundleDigest: Bytes32;
  previousContributionHash: Bytes32;
};

export type DkgContributionV1 = UnsignedDkgContributionV1 & {
  signature: Hex;
};

export type DkgEquivocationEvidenceV1 = {
  trusteeIndex: number;
  round: 1 | 2;
  firstContributionHash: Bytes32;
  secondContributionHash: Bytes32;
  evidenceHash: Bytes32;
};

export type SignedDkgTranscriptV1 = {
  version: typeof DKG_TRANSCRIPT_VERSION;
  ceremonyId: Bytes32;
  nationalElectionId: Bytes32;
  constituencyId: Bytes32;
  threshold: typeof DKG_THRESHOLD;
  trusteeCount: typeof DKG_TRUSTEE_COUNT;
  qualifiedTrusteeIndexes: readonly number[];
  disqualifiedTrusteeIndexes: readonly number[];
  contributionHashes: readonly Bytes32[];
  equivocationEvidenceHashes: readonly Bytes32[];
  electionPublicKey: Hex;
  trusteeKeysetHash: Bytes32;
  transcriptHash: Bytes32;
};

function assertBytes32(value: string, label: string): asserts value is Bytes32 {
  assert.equal(
    isHex(value, { strict: true }) && value.length === 66,
    true,
    `${label} must be bytes32`,
  );
}

function normalizeHex<T extends Hex>(value: T): T {
  return value.toLowerCase() as T;
}

function privateKeyBytes(privateKey: Hex): Uint8Array {
  assertBytes32(privateKey, "privateKey");
  return hexToBytes(privateKey.slice(2));
}

export function deriveDkgSigningPublicKey(privateKey: Hex): Hex {
  return `0x${bytesToHex(
    secp256k1.getPublicKey(privateKeyBytes(privateKey), true),
  )}`;
}

export function hashDkgContribution(
  contribution: UnsignedDkgContributionV1,
): Bytes32 {
  assertBytes32(contribution.ceremonyId, "ceremonyId");
  assertBytes32(contribution.nationalElectionId, "nationalElectionId");
  assertBytes32(contribution.constituencyId, "constituencyId");
  assertBytes32(
    contribution.pedersenCommitmentDigest,
    "pedersenCommitmentDigest",
  );
  assertBytes32(
    contribution.encryptedShareBundleDigest,
    "encryptedShareBundleDigest",
  );
  assertBytes32(
    contribution.previousContributionHash,
    "previousContributionHash",
  );
  assert.equal(
    contribution.trusteeIndex >= 1 &&
      contribution.trusteeIndex <= DKG_TRUSTEE_COUNT,
    true,
    "trusteeIndex out of range",
  );
  assert.equal(
    contribution.round === 1 || contribution.round === 2,
    true,
    "unsupported DKG round",
  );
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 ceremonyId, bytes32 nationalElectionId, bytes32 constituencyId, uint8 trusteeIndex, uint8 round, bytes32 pedersenCommitmentDigest, bytes32 encryptedShareBundleDigest, bytes32 previousContributionHash",
      ),
      [
        contributionDomain,
        normalizeHex(contribution.ceremonyId),
        normalizeHex(contribution.nationalElectionId),
        normalizeHex(contribution.constituencyId),
        contribution.trusteeIndex,
        contribution.round,
        normalizeHex(contribution.pedersenCommitmentDigest),
        normalizeHex(contribution.encryptedShareBundleDigest),
        normalizeHex(contribution.previousContributionHash),
      ],
    ),
  );
}

export function signDkgContribution(
  contribution: UnsignedDkgContributionV1,
  signingPrivateKey: Hex,
): DkgContributionV1 {
  const digest = hashDkgContribution(contribution);
  const signature = secp256k1.sign(
    hexToBytes(digest.slice(2)),
    privateKeyBytes(signingPrivateKey),
  );
  return {
    ...contribution,
    signature: `0x${signature.toCompactHex()}`,
  };
}

export function verifyDkgContribution(
  contribution: DkgContributionV1,
  signingPublicKey: Hex,
): boolean {
  try {
    assert.equal(
      isHex(contribution.signature, { strict: true }) &&
        contribution.signature.length === 130,
      true,
      "signature must be 64 bytes",
    );
    assert.equal(
      isHex(signingPublicKey, { strict: true }) &&
        signingPublicKey.length === 68,
      true,
      "signingPublicKey must be compressed secp256k1",
    );
    const { signature, ...unsigned } = contribution;
    return secp256k1.verify(
      hexToBytes(signature.slice(2)),
      hexToBytes(hashDkgContribution(unsigned).slice(2)),
      hexToBytes(signingPublicKey.slice(2)),
    );
  } catch {
    return false;
  }
}

export class DkgTranscriptCoordinatorV1 {
  readonly #ceremonyId: Bytes32;
  readonly #nationalElectionId: Bytes32;
  readonly #constituencyId: Bytes32;
  readonly #trustees = new Map<number, Hex>();
  readonly #contributions = new Map<string, DkgContributionV1>();
  readonly #disqualified = new Set<number>();
  readonly #equivocations: DkgEquivocationEvidenceV1[] = [];
  #finalized = false;

  constructor(params: {
    ceremonyId: Bytes32;
    nationalElectionId: Bytes32;
    constituencyId: Bytes32;
    trustees: readonly DkgTrusteeV1[];
  }) {
    assertBytes32(params.ceremonyId, "ceremonyId");
    assertBytes32(params.nationalElectionId, "nationalElectionId");
    assertBytes32(params.constituencyId, "constituencyId");
    assert.equal(
      params.trustees.length,
      DKG_TRUSTEE_COUNT,
      "exactly nine trustees are required",
    );
    for (const trustee of params.trustees) {
      assert.equal(
        trustee.trusteeIndex >= 1 &&
          trustee.trusteeIndex <= DKG_TRUSTEE_COUNT,
        true,
      );
      assert.equal(this.#trustees.has(trustee.trusteeIndex), false);
      assert.equal(
        isHex(trustee.signingPublicKey, { strict: true }) &&
          trustee.signingPublicKey.length === 68,
        true,
      );
      this.#trustees.set(
        trustee.trusteeIndex,
        normalizeHex(trustee.signingPublicKey),
      );
    }
    this.#ceremonyId = normalizeHex(params.ceremonyId);
    this.#nationalElectionId = normalizeHex(params.nationalElectionId);
    this.#constituencyId = normalizeHex(params.constituencyId);
  }

  addContribution(contribution: DkgContributionV1): void {
    assert.equal(this.#finalized, false, "ceremony is already finalized");
    assert.equal(
      normalizeHex(contribution.ceremonyId),
      this.#ceremonyId,
      "wrong ceremony",
    );
    assert.equal(
      normalizeHex(contribution.nationalElectionId),
      this.#nationalElectionId,
      "wrong national election",
    );
    assert.equal(
      normalizeHex(contribution.constituencyId),
      this.#constituencyId,
      "wrong constituency",
    );
    const publicKey = this.#trustees.get(contribution.trusteeIndex);
    assert.notEqual(publicKey, undefined, "unknown trustee");
    assert.equal(
      verifyDkgContribution(contribution, publicKey!),
      true,
      "invalid trustee signature",
    );

    const key = `${contribution.trusteeIndex}:${contribution.round}`;
    const existing = this.#contributions.get(key);
    const contributionHash = hashDkgContribution(contribution);
    if (existing !== undefined) {
      const existingHash = hashDkgContribution(existing);
      if (existingHash === contributionHash) return;
      this.#disqualified.add(contribution.trusteeIndex);
      const evidenceHash = keccak256(
        encodeAbiParameters(
          parseAbiParameters(
            "bytes32 domain, uint8 trusteeIndex, uint8 round, bytes32 firstContributionHash, bytes32 secondContributionHash",
          ),
          [
            equivocationDomain,
            contribution.trusteeIndex,
            contribution.round,
            existingHash,
            contributionHash,
          ],
        ),
      );
      this.#equivocations.push({
        trusteeIndex: contribution.trusteeIndex,
        round: contribution.round,
        firstContributionHash: existingHash,
        secondContributionHash: contributionHash,
        evidenceHash,
      });
      return;
    }

    if (contribution.round === 1) {
      assert.equal(
        normalizeHex(contribution.previousContributionHash),
        zeroHash,
        "round one cannot have a parent contribution",
      );
    } else {
      const roundOne = this.#contributions.get(
        `${contribution.trusteeIndex}:1`,
      );
      assert.notEqual(roundOne, undefined, "round two requires round one");
      assert.equal(
        normalizeHex(contribution.previousContributionHash),
        hashDkgContribution(roundOne!),
        "round two parent does not match round one",
      );
    }
    this.#contributions.set(key, contribution);
  }

  finalize(params: {
    electionPublicKey: Hex;
    trusteeKeysetHash: Bytes32;
  }): SignedDkgTranscriptV1 {
    assert.equal(this.#finalized, false, "ceremony is already finalized");
    assert.equal(
      isHex(params.electionPublicKey, { strict: true }) &&
        params.electionPublicKey.length > 4,
      true,
      "invalid election public key",
    );
    assertBytes32(params.trusteeKeysetHash, "trusteeKeysetHash");

    const qualified = [...this.#trustees.keys()]
      .filter(
        (index) =>
          !this.#disqualified.has(index) &&
          this.#contributions.has(`${index}:1`) &&
          this.#contributions.has(`${index}:2`),
      )
      .sort((left, right) => left - right);
    assert.equal(
      qualified.length >= DKG_THRESHOLD,
      true,
      "fewer than five qualified trustees survived",
    );
    const disqualified = [...this.#disqualified].sort(
      (left, right) => left - right,
    );
    const contributionHashes = qualified.flatMap((index) => [
      hashDkgContribution(this.#contributions.get(`${index}:1`)!),
      hashDkgContribution(this.#contributions.get(`${index}:2`)!),
    ]);
    const evidenceHashes = this.#equivocations
      .map((evidence) => evidence.evidenceHash)
      .sort();
    const transcriptHash = keccak256(
      encodeAbiParameters(
        parseAbiParameters(
          "bytes32 domain, uint8 version, bytes32 ceremonyId, bytes32 nationalElectionId, bytes32 constituencyId, uint8 threshold, uint8 trusteeCount, uint8[] qualifiedTrusteeIndexes, uint8[] disqualifiedTrusteeIndexes, bytes32[] contributionHashes, bytes32[] evidenceHashes, bytes electionPublicKey, bytes32 trusteeKeysetHash",
        ),
        [
          transcriptDomain,
          DKG_TRANSCRIPT_VERSION,
          this.#ceremonyId,
          this.#nationalElectionId,
          this.#constituencyId,
          DKG_THRESHOLD,
          DKG_TRUSTEE_COUNT,
          qualified,
          disqualified,
          contributionHashes,
          evidenceHashes,
          normalizeHex(params.electionPublicKey),
          normalizeHex(params.trusteeKeysetHash),
        ],
      ),
    );
    this.#finalized = true;
    return {
      version: DKG_TRANSCRIPT_VERSION,
      ceremonyId: this.#ceremonyId,
      nationalElectionId: this.#nationalElectionId,
      constituencyId: this.#constituencyId,
      threshold: DKG_THRESHOLD,
      trusteeCount: DKG_TRUSTEE_COUNT,
      qualifiedTrusteeIndexes: qualified,
      disqualifiedTrusteeIndexes: disqualified,
      contributionHashes,
      equivocationEvidenceHashes: evidenceHashes,
      electionPublicKey: normalizeHex(params.electionPublicKey),
      trusteeKeysetHash: normalizeHex(params.trusteeKeysetHash),
      transcriptHash,
    };
  }
}
