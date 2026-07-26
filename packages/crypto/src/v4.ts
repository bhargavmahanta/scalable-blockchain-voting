import assert from "node:assert/strict";

import { isHex, keccak256, stringToHex } from "viem";

import type { Bytes32, Hex } from "./index.js";

export const VOTE_PACKAGE_V4_SCHEMA = 4 as const;
export const BATCH_MANIFEST_V4_SCHEMA = 4 as const;
export const BATCH_PROOF_ARTIFACT_V4_SCHEMA = 4 as const;
export const DKG_TRANSCRIPT_V1_SCHEMA = 1 as const;
export const DECRYPTION_SHARE_V4_SCHEMA = 4 as const;
export const TALLY_ARTIFACT_V4_SCHEMA = 4 as const;

export type CandidateProfileV4 = 4 | 16;

export type ArtifactHeaderV4<SchemaVersion extends number> = {
  schemaVersion: SchemaVersion;
  nationalElectionId: Bytes32;
  constituencyId: Bytes32;
  verifierVersion: number;
  canonicalDigest: Bytes32;
  parentArtifactHashes: readonly Bytes32[];
};

export type VotePackageV4 = ArtifactHeaderV4<
  typeof VOTE_PACKAGE_V4_SCHEMA
> & {
  eligibilityRootVersion: number;
  candidateProfile: CandidateProfileV4;
  ballotNullifier: Bytes32;
  ciphertextDigest: Bytes32;
  encryptedBallot: Hex;
  eligibilityAndBallotProof: Hex;
  proofPublicInputsHash: Bytes32;
};

export type BatchManifestV4 = ArtifactHeaderV4<
  typeof BATCH_MANIFEST_V4_SCHEMA
> & {
  packageRoot: Bytes32;
  previousNullifierRoot: Bytes32;
  nullifierRoot: Bytes32;
  aggregateCiphertextDigest: Bytes32;
  availabilityCertificateHash: Bytes32;
  ballotCount: number;
  packageDigests: readonly Bytes32[];
};

export type BatchProofArtifactV4 = ArtifactHeaderV4<
  typeof BATCH_PROOF_ARTIFACT_V4_SCHEMA
> & {
  manifestDigest: Bytes32;
  batchPublicInputsHash: Bytes32;
  proofSystem: "groth16-bn254" | "recursive-groth16-bn254";
  proof: Hex;
  recursivelyProved: boolean;
};

export type DkgTranscriptV1 = ArtifactHeaderV4<
  typeof DKG_TRANSCRIPT_V1_SCHEMA
> & {
  threshold: 5;
  trusteeCount: 9;
  qualifiedTrusteeIndexes: readonly number[];
  trusteePublicKeys: readonly Hex[];
  pedersenCommitmentDigests: readonly Bytes32[];
  complaintDigests: readonly Bytes32[];
  electionPublicKey: Hex;
  trusteeKeysetHash: Bytes32;
};

export type DecryptionShareV4 = ArtifactHeaderV4<
  typeof DECRYPTION_SHARE_V4_SCHEMA
> & {
  trusteeIndex: number;
  trusteeKeysetHash: Bytes32;
  dkgTranscriptHash: Bytes32;
  finalizedBatchAccumulator: Bytes32;
  aggregateCiphertextDigest: Bytes32;
  decryptionShare: Hex;
  dleqProof: Hex;
};

export type TallyArtifactV4 = ArtifactHeaderV4<
  typeof TALLY_ARTIFACT_V4_SCHEMA
> & {
  finalizedBatchAccumulator: Bytes32;
  trusteeKeysetHash: Bytes32;
  dkgTranscriptHash: Bytes32;
  acceptedBallotCount: number;
  candidateCounts: readonly number[];
  decryptionShareDigests: readonly Bytes32[];
  tallyProof: Hex;
  tallyPublicInputsHash: Bytes32;
};

type CanonicalJson =
  | null
  | boolean
  | number
  | string
  | readonly CanonicalJson[]
  | { readonly [key: string]: CanonicalJson };

type ArtifactWithoutDigest<T extends { canonicalDigest: Bytes32 }> = Omit<
  T,
  "canonicalDigest"
>;

function canonicalize(value: unknown): CanonicalJson {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return value;
  }
  if (typeof value === "number") {
    assert.equal(Number.isSafeInteger(value), true, "artifact numbers must be safe integers");
    assert.equal(value >= 0, true, "artifact numbers cannot be negative");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, entry]) => entry !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, canonicalize(entry)]),
    );
  }
  throw new TypeError(`unsupported artifact value: ${typeof value}`);
}

function assertBytes32(value: string, label: string): asserts value is Bytes32 {
  assert.equal(
    isHex(value, { strict: true }) && value.length === 66,
    true,
    `${label} must be bytes32`,
  );
}

function validateHeader(
  artifact: ArtifactHeaderV4<number>,
): void {
  assert.equal(
    Number.isSafeInteger(artifact.schemaVersion) && artifact.schemaVersion > 0,
    true,
    "schemaVersion must be positive",
  );
  assert.equal(
    Number.isSafeInteger(artifact.verifierVersion) &&
      artifact.verifierVersion > 0,
    true,
    "verifierVersion must be positive",
  );
  assertBytes32(artifact.nationalElectionId, "nationalElectionId");
  assertBytes32(artifact.constituencyId, "constituencyId");
  assertBytes32(artifact.canonicalDigest, "canonicalDigest");
  artifact.parentArtifactHashes.forEach((hash, index) =>
    assertBytes32(hash, `parentArtifactHashes[${index}]`),
  );
}

export function computeCanonicalArtifactDigest<
  T extends ArtifactHeaderV4<number>,
>(
  domain: string,
  artifact: ArtifactWithoutDigest<T>,
): Bytes32 {
  assert.equal(domain.startsWith("SVB_"), true, "artifact domain must be namespaced");
  const serialized = JSON.stringify(canonicalize({ domain, artifact }));
  return keccak256(stringToHex(serialized));
}

export function sealArtifact<
  T extends ArtifactHeaderV4<number>,
>(
  domain: string,
  artifact: ArtifactWithoutDigest<T>,
): T {
  const sealed = {
    ...artifact,
    canonicalDigest: computeCanonicalArtifactDigest<T>(domain, artifact),
  } as T;
  validateHeader(sealed);
  return sealed;
}

export function verifyArtifactDigest<
  T extends ArtifactHeaderV4<number>,
>(
  domain: string,
  artifact: T,
): boolean {
  validateHeader(artifact);
  const { canonicalDigest, ...unsignedArtifact } = artifact;
  return (
    computeCanonicalArtifactDigest(
      domain,
      unsignedArtifact as ArtifactWithoutDigest<T>,
    ) === canonicalDigest.toLowerCase()
  );
}

export function validateTallyArtifactV4(
  artifact: TallyArtifactV4,
): TallyArtifactV4 {
  validateHeader(artifact);
  assert.equal(
    artifact.schemaVersion,
    TALLY_ARTIFACT_V4_SCHEMA,
    "unsupported tally artifact schema",
  );
  assert.equal(
    artifact.candidateCounts.length === 4 ||
      artifact.candidateCounts.length === 16,
    true,
    "candidate count profile must be 4 or 16",
  );
  const total = artifact.candidateCounts.reduce((sum, count) => {
    assert.equal(Number.isSafeInteger(count) && count >= 0, true);
    return sum + count;
  }, 0);
  assert.equal(
    total,
    artifact.acceptedBallotCount,
    "candidate totals must equal accepted ballot count",
  );
  assert.equal(
    artifact.decryptionShareDigests.length >= 5,
    true,
    "at least five trustee shares are required",
  );
  return artifact;
}
