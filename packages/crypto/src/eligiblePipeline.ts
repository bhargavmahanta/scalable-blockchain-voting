import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildBabyjub } from "circomlibjs";
import {
  decodeAbiParameters,
  encodeAbiParameters,
  isHex,
  keccak256,
  parseAbiParameters,
  stringToHex,
  type Hex,
} from "viem";

import {
  ELIGIBLE_BALLOT_PROOF_SYSTEM,
  computeEligiblePackageCommitment,
  hashEligibleBallotPublicSignals,
  type EligibleBallotPublicSignals,
} from "./eligibleBallot.js";
import {
  PROOF_COMPATIBLE_BALLOT_SCHEME,
  PROOF_COMPATIBLE_CANDIDATE_COUNT,
  SNARK_SCALAR_FIELD,
  bytes32ToSnarkField,
  hashProofCompatibleElectionPublicKey,
  type BabyJubPoint,
} from "./proofCompatibleBallot.js";
import {
  aggregateProofCompatibleCiphertexts,
  digestProofCompatibleCiphertext,
  type ProofCompatibleCiphertextJson,
  type ProofCompatiblePointJson,
} from "./proofCompatiblePipeline.js";
import {
  NullifierAccumulator,
  digestContentId,
  merkleProof,
  merkleRoot,
  type Bytes32,
  type PackageInclusionReceipt,
} from "./index.js";

export const ELIGIBLE_VOTE_PACKAGE_VERSION = 3 as const;
export const ELIGIBLE_BATCH_MANIFEST_VERSION = 3 as const;
export const ELIGIBLE_BATCH_VERIFICATION_MODE =
  "off-chain-real-proof-validation-v1" as const;

export type EligibleBallotProofJson = {
  system: typeof ELIGIBLE_BALLOT_PROOF_SYSTEM;
  proof: Hex;
  publicInputsHash: Bytes32;
};

export type EligibleVotePackageV3 = {
  version: typeof ELIGIBLE_VOTE_PACKAGE_VERSION;
  electionId: Bytes32;
  candidateListHash: Bytes32;
  eligibilityRoot: Bytes32;
  ballotNullifier: Bytes32;
  packageCommitment: Bytes32;
  ciphertext: ProofCompatibleCiphertextJson;
  ballotValidityProof: EligibleBallotProofJson;
};

export type StoredEligibleVotePackageV3 = {
  contentId: string;
  package: EligibleVotePackageV3;
};

/**
 * A V3 manifest binds every real per-ballot proof and the eligibility root.
 * `verificationMode` deliberately states that this artifact is locally
 * validated. It is not a recursive batch proof and must not be presented as one.
 */
export type EligibleBatchManifestV3 = {
  version: typeof ELIGIBLE_BATCH_MANIFEST_VERSION;
  verificationMode: typeof ELIGIBLE_BATCH_VERIFICATION_MODE;
  electionId: Bytes32;
  candidateListHash: Bytes32;
  eligibilityRoot: Bytes32;
  electionPublicKeyHash: Bytes32;
  previousNullifierRoot: Bytes32;
  nullifierRoot: Bytes32;
  cidMerkleRoot: Bytes32;
  manifestDigest: Bytes32;
  batchPublicInputsHash: Bytes32;
  batchSize: bigint;
  aggregateCiphertext: ProofCompatibleCiphertextJson;
  aggregateCiphertextDigest: Bytes32;
  packageDigests: readonly Bytes32[];
  packageLeafHashes: readonly Bytes32[];
  ballotNullifiers: readonly Bytes32[];
  ballotProofPublicInputsHashes: readonly Bytes32[];
};

const domainHash = (domain: string): Bytes32 => keccak256(stringToHex(domain));
const normalizeBytes32 = (value: Bytes32): Bytes32 =>
  value.toLowerCase() as Bytes32;
const normalizeHex = (value: Hex): Hex => value.toLowerCase() as Hex;
const snarkjsCliPath = join(
  process.cwd(),
  "node_modules",
  "snarkjs",
  "build",
  "cli.cjs",
);

function assertBytes32(value: string, label: string): asserts value is Bytes32 {
  assert.equal(
    isHex(value, { strict: true }) && value.length === 66,
    true,
    `${label} must be a bytes32 hex string`,
  );
}

function assertCanonicalField(value: Bytes32, label: string): bigint {
  const fieldValue = BigInt(value);
  assert.equal(fieldValue < SNARK_SCALAR_FIELD, true, `${label} is not canonical`);
  return fieldValue;
}

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [...keys].sort(),
    `${label} contains unsupported or missing fields`,
  );
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, canonicalize(entry)]),
    );
  }
  return value;
}

function decimalToBigInt(value: string, label: string): bigint {
  assert.match(value, /^(0|[1-9][0-9]*)$/, `${label} must be decimal`);
  const result = BigInt(value);
  assert.equal(result < SNARK_SCALAR_FIELD, true, `${label} exceeds the field`);
  return result;
}

function normalizePoint(
  point: ProofCompatiblePointJson,
  label: string,
): ProofCompatiblePointJson {
  assert.equal(Array.isArray(point) && point.length === 2, true, `${label} must have x and y`);
  return [
    decimalToBigInt(point[0], `${label}.x`).toString(),
    decimalToBigInt(point[1], `${label}.y`).toString(),
  ];
}

function pointToBigInts(point: ProofCompatiblePointJson): BabyJubPoint {
  return [BigInt(point[0]), BigInt(point[1])];
}

function fieldToBytes32(value: bigint): Bytes32 {
  assert.equal(value >= 0n && value < SNARK_SCALAR_FIELD, true);
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function decodeProofPublicSignals(proof: Hex): EligibleBallotPublicSignals {
  const decoded = decodeAbiParameters(
    parseAbiParameters(
      "uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[23] publicSignals",
    ),
    proof,
  );
  return decoded[3] as EligibleBallotPublicSignals;
}

function decodeGroth16Proof(proofEnvelope: Hex): {
  publicSignals: EligibleBallotPublicSignals;
  proof: unknown;
} {
  const [pA, pB, pC, publicSignals] = decodeAbiParameters(
    parseAbiParameters(
      "uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[23] publicSignals",
    ),
    proofEnvelope,
  );
  return {
    publicSignals: publicSignals as EligibleBallotPublicSignals,
    proof: {
      pi_a: [pA[0].toString(), pA[1].toString(), "1"],
      // Solidity calldata reverses each Fq2 coordinate relative to snarkjs JSON.
      pi_b: [
        [pB[0][1].toString(), pB[0][0].toString()],
        [pB[1][1].toString(), pB[1][0].toString()],
        ["1", "0"],
      ],
      pi_c: [pC[0].toString(), pC[1].toString(), "1"],
      protocol: "groth16",
      curve: "bn128",
    },
  };
}

export async function validateEligibleVotePackage(
  input: EligibleVotePackageV3,
): Promise<EligibleVotePackageV3> {
  exactKeys(
    input as unknown as Record<string, unknown>,
    [
      "version",
      "electionId",
      "candidateListHash",
      "eligibilityRoot",
      "ballotNullifier",
      "packageCommitment",
      "ciphertext",
      "ballotValidityProof",
    ],
    "eligible vote package",
  );
  assert.equal(input.version, ELIGIBLE_VOTE_PACKAGE_VERSION);
  assertBytes32(input.electionId, "electionId");
  assertBytes32(input.candidateListHash, "candidateListHash");
  assertBytes32(input.eligibilityRoot, "eligibilityRoot");
  assertBytes32(input.ballotNullifier, "ballotNullifier");
  assertBytes32(input.packageCommitment, "packageCommitment");
  const eligibilityRoot = assertCanonicalField(input.eligibilityRoot, "eligibilityRoot");
  const ballotNullifier = assertCanonicalField(input.ballotNullifier, "ballotNullifier");
  assertCanonicalField(input.packageCommitment, "packageCommitment");

  exactKeys(
    input.ciphertext as unknown as Record<string, unknown>,
    ["scheme", "electionPublicKeyHash", "electionPublicKey", "c1", "c2"],
    "eligible ciphertext",
  );
  assert.equal(input.ciphertext.scheme, PROOF_COMPATIBLE_BALLOT_SCHEME);
  assertBytes32(input.ciphertext.electionPublicKeyHash, "electionPublicKeyHash");
  assert.equal(input.ciphertext.c1.length, PROOF_COMPATIBLE_CANDIDATE_COUNT);
  assert.equal(input.ciphertext.c2.length, PROOF_COMPATIBLE_CANDIDATE_COUNT);
  const electionPublicKey = normalizePoint(input.ciphertext.electionPublicKey, "electionPublicKey");
  const c1 = input.ciphertext.c1.map((point, index) => normalizePoint(point, `c1[${index}]`));
  const c2 = input.ciphertext.c2.map((point, index) => normalizePoint(point, `c2[${index}]`));
  const publicKeyBigInts = pointToBigInts(electionPublicKey);
  const c1BigInts = c1.map(pointToBigInts);
  const c2BigInts = c2.map(pointToBigInts);
  assert.equal(
    normalizeBytes32(input.ciphertext.electionPublicKeyHash),
    hashProofCompatibleElectionPublicKey(publicKeyBigInts),
    "election public key hash mismatch",
  );

  exactKeys(
    input.ballotValidityProof as unknown as Record<string, unknown>,
    ["system", "proof", "publicInputsHash"],
    "eligible ballot proof",
  );
  assert.equal(input.ballotValidityProof.system, ELIGIBLE_BALLOT_PROOF_SYSTEM);
  assert.equal(isHex(input.ballotValidityProof.proof, { strict: true }), true);
  assertBytes32(input.ballotValidityProof.publicInputsHash, "publicInputsHash");

  const expectedCommitment = await computeEligiblePackageCommitment({
    electionId: bytes32ToSnarkField(input.electionId),
    candidateListHash: bytes32ToSnarkField(input.candidateListHash),
    eligibilityRoot,
    ballotNullifier,
    electionPublicKey: publicKeyBigInts,
    c1: c1BigInts,
    c2: c2BigInts,
  });
  assert.equal(
    normalizeBytes32(input.packageCommitment),
    fieldToBytes32(expectedCommitment),
    "package commitment does not bind the eligibility root and ciphertext",
  );

  const proofSignals = decodeProofPublicSignals(input.ballotValidityProof.proof);
  const expectedSignals = [
    bytes32ToSnarkField(input.electionId),
    bytes32ToSnarkField(input.candidateListHash),
    eligibilityRoot,
    ballotNullifier,
    expectedCommitment,
    ...publicKeyBigInts,
    ...c1BigInts.flat(),
    ...c2BigInts.flat(),
  ] as unknown as EligibleBallotPublicSignals;
  assert.deepEqual(proofSignals, expectedSignals, "proof public signals do not match package");
  assert.equal(
    normalizeBytes32(input.ballotValidityProof.publicInputsHash),
    hashEligibleBallotPublicSignals(expectedSignals),
    "proof public-input hash does not match package",
  );

  const babyJub = await buildBabyjub();
  for (const [label, point] of [
    ["electionPublicKey", publicKeyBigInts],
    ...c1BigInts.map((point, index) => [`c1[${index}]`, point] as const),
    ...c2BigInts.map((point, index) => [`c2[${index}]`, point] as const),
  ] as const) {
    assert.equal(
      babyJub.inSubgroup(point.map((coordinate) => babyJub.F.e(coordinate))),
      true,
      `${label} is not in the BabyJubJub subgroup`,
    );
  }

  return {
    version: ELIGIBLE_VOTE_PACKAGE_VERSION,
    electionId: normalizeBytes32(input.electionId),
    candidateListHash: normalizeBytes32(input.candidateListHash),
    eligibilityRoot: normalizeBytes32(input.eligibilityRoot),
    ballotNullifier: normalizeBytes32(input.ballotNullifier),
    packageCommitment: normalizeBytes32(input.packageCommitment),
    ciphertext: {
      scheme: PROOF_COMPATIBLE_BALLOT_SCHEME,
      electionPublicKeyHash: normalizeBytes32(input.ciphertext.electionPublicKeyHash),
      electionPublicKey,
      c1,
      c2,
    },
    ballotValidityProof: {
      system: ELIGIBLE_BALLOT_PROOF_SYSTEM,
      proof: normalizeHex(input.ballotValidityProof.proof),
      publicInputsHash: normalizeBytes32(input.ballotValidityProof.publicInputsHash),
    },
  };
}

export async function serializeEligibleVotePackage(
  input: EligibleVotePackageV3,
): Promise<string> {
  return `${JSON.stringify(canonicalize(await validateEligibleVotePackage(input)))}\n`;
}

export async function parseEligibleVotePackageJson(
  json: string,
): Promise<EligibleVotePackageV3> {
  return validateEligibleVotePackage(JSON.parse(json) as EligibleVotePackageV3);
}

export async function digestEligibleVotePackage(
  input: EligibleVotePackageV3,
): Promise<Bytes32> {
  return keccak256(encodeAbiParameters(
    parseAbiParameters("bytes32 domain, bytes canonicalPackage"),
    [domainHash("SVB_ELIGIBLE_VOTE_PACKAGE_V3"), stringToHex(await serializeEligibleVotePackage(input))],
  ));
}

export async function verifyEligibleVotePackageProof(
  input: EligibleVotePackageV3,
  verificationKey: unknown,
): Promise<boolean> {
  const validated = await validateEligibleVotePackage(input);
  const decoded = decodeGroth16Proof(validated.ballotValidityProof.proof);
  // snarkjs' library verifier leaves its worker pool alive in short-lived CLI
  // processes. The official CLI performs the same verification and terminates
  // cleanly, so use an isolated temporary directory for deterministic tooling.
  const directory = await mkdtemp(join(tmpdir(), "svb-eligible-proof-"));
  try {
    const verificationKeyPath = join(directory, "verification-key.json");
    const publicSignalsPath = join(directory, "public.json");
    const proofPath = join(directory, "proof.json");
    await Promise.all([
      writeFile(verificationKeyPath, JSON.stringify(verificationKey)),
      writeFile(publicSignalsPath, JSON.stringify(decoded.publicSignals.map(String))),
      writeFile(proofPath, JSON.stringify(decoded.proof)),
    ]);
    const child = spawn(process.execPath, [
      snarkjsCliPath, "groth16", "verify", verificationKeyPath, publicSignalsPath, proofPath,
    ], { stdio: ["ignore", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    const [exitCode] = await once(child, "close") as [number];
    const output = `${Buffer.concat(stdout).toString()}\n${Buffer.concat(stderr).toString()}`;
    return exitCode === 0 && /OK!/.test(output);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function computeEligibleBatchPublicInputsHash(params: {
  electionId: Bytes32;
  candidateListHash: Bytes32;
  eligibilityRoot: Bytes32;
  electionPublicKeyHash: Bytes32;
  previousNullifierRoot: Bytes32;
  nullifierRoot: Bytes32;
  cidMerkleRoot: Bytes32;
  manifestDigest: Bytes32;
  aggregateCiphertextDigest: Bytes32;
  packageDigests: readonly Bytes32[];
  ballotNullifiers: readonly Bytes32[];
  ballotProofPublicInputsHashes: readonly Bytes32[];
}): Bytes32 {
  return keccak256(encodeAbiParameters(
    parseAbiParameters(
      "bytes32 domain, bytes32 electionId, bytes32 candidateListHash, bytes32 eligibilityRoot, bytes32 electionPublicKeyHash, bytes32 previousNullifierRoot, bytes32 nullifierRoot, bytes32 cidMerkleRoot, bytes32 manifestDigest, bytes32 aggregateCiphertextDigest, bytes32[] packageDigests, bytes32[] ballotNullifiers, bytes32[] ballotProofPublicInputsHashes",
    ),
    [
      domainHash("SVB_ELIGIBLE_BATCH_PUBLIC_INPUTS_V3"),
      params.electionId,
      params.candidateListHash,
      params.eligibilityRoot,
      params.electionPublicKeyHash,
      params.previousNullifierRoot,
      params.nullifierRoot,
      params.cidMerkleRoot,
      params.manifestDigest,
      params.aggregateCiphertextDigest,
      params.packageDigests,
      params.ballotNullifiers,
      params.ballotProofPublicInputsHashes,
    ],
  ));
}

export async function buildEligibleBatchManifest(
  electionId: Bytes32,
  eligibilityRoot: Bytes32,
  previousNullifierRoot: Bytes32,
  storedPackages: readonly StoredEligibleVotePackageV3[],
  accumulator: NullifierAccumulator,
  verificationKey: unknown,
): Promise<EligibleBatchManifestV3> {
  assertBytes32(electionId, "electionId");
  assertBytes32(eligibilityRoot, "eligibilityRoot");
  assertCanonicalField(eligibilityRoot, "eligibilityRoot");
  assertBytes32(previousNullifierRoot, "previousNullifierRoot");
  assert.equal(storedPackages.length > 0, true, "batch cannot be empty");
  assert.equal(accumulator.root, normalizeBytes32(previousNullifierRoot));

  const validated = await Promise.all(storedPackages.map(async (storedPackage) => ({
    contentId: storedPackage.contentId.trim(),
    package: await validateEligibleVotePackage(storedPackage.package),
    digest: await digestEligibleVotePackage(storedPackage.package),
  })));
  const first = validated[0]!.package;
  for (const entry of validated) {
    assert.equal(entry.contentId.length > 0, true, "content ID cannot be empty");
    assert.equal(entry.package.electionId, normalizeBytes32(electionId), "election mismatch");
    assert.equal(entry.package.eligibilityRoot, normalizeBytes32(eligibilityRoot), "eligibility root mismatch");
    assert.equal(entry.package.candidateListHash, first.candidateListHash, "candidate list mismatch");
    assert.equal(
      entry.package.ciphertext.electionPublicKeyHash,
      first.ciphertext.electionPublicKeyHash,
      "election encryption key mismatch",
    );
    assert.equal(
      await verifyEligibleVotePackageProof(entry.package, verificationKey),
      true,
      "eligible ballot Groth16 proof rejected",
    );
  }
  validated.sort((left, right) => left.digest.localeCompare(right.digest));
  const ballotNullifiers = validated.map((entry) => entry.package.ballotNullifier);
  accumulator.addMany(ballotNullifiers);
  const packageDigests = validated.map((entry) => entry.digest);
  const ballotProofPublicInputsHashes = validated.map(
    (entry) => entry.package.ballotValidityProof.publicInputsHash,
  );
  const packageLeafHashes = validated.map((entry) => keccak256(encodeAbiParameters(
    parseAbiParameters(
      "bytes32 domain, bytes32 contentIdDigest, bytes32 packageDigest, bytes32 eligibilityRoot, bytes32 ballotNullifier, bytes32 packageCommitment, bytes32 proofPublicInputsHash",
    ),
    [
      domainHash("SVB_ELIGIBLE_PACKAGE_LEAF_V3"),
      digestContentId(entry.contentId),
      entry.digest,
      entry.package.eligibilityRoot,
      entry.package.ballotNullifier,
      entry.package.packageCommitment,
      entry.package.ballotValidityProof.publicInputsHash,
    ],
  )));
  const aggregateCiphertext = await aggregateProofCompatibleCiphertexts(
    validated.map((entry) => entry.package.ciphertext),
  );
  const aggregateCiphertextDigest = digestProofCompatibleCiphertext(aggregateCiphertext);
  const cidMerkleRoot = merkleRoot(packageLeafHashes);
  const nullifierRoot = accumulator.root;
  const manifestDigest = keccak256(encodeAbiParameters(
    parseAbiParameters(
      "bytes32 domain, uint8 version, bytes32 verificationMode, bytes32 electionId, bytes32 candidateListHash, bytes32 eligibilityRoot, bytes32 electionPublicKeyHash, bytes32 previousNullifierRoot, bytes32 nullifierRoot, bytes32 cidMerkleRoot, uint64 batchSize, bytes32 aggregateCiphertextDigest, bytes32[] packageDigests, bytes32[] ballotNullifiers, bytes32[] ballotProofPublicInputsHashes",
    ),
    [
      domainHash("SVB_ELIGIBLE_BATCH_MANIFEST_V3"),
      ELIGIBLE_BATCH_MANIFEST_VERSION,
      domainHash(ELIGIBLE_BATCH_VERIFICATION_MODE),
      normalizeBytes32(electionId),
      first.candidateListHash,
      normalizeBytes32(eligibilityRoot),
      first.ciphertext.electionPublicKeyHash,
      normalizeBytes32(previousNullifierRoot),
      nullifierRoot,
      cidMerkleRoot,
      BigInt(validated.length),
      aggregateCiphertextDigest,
      packageDigests,
      ballotNullifiers,
      ballotProofPublicInputsHashes,
    ],
  ));
  const batchPublicInputsHash = computeEligibleBatchPublicInputsHash({
    electionId: normalizeBytes32(electionId),
    candidateListHash: first.candidateListHash,
    eligibilityRoot: normalizeBytes32(eligibilityRoot),
    electionPublicKeyHash: first.ciphertext.electionPublicKeyHash,
    previousNullifierRoot: normalizeBytes32(previousNullifierRoot),
    nullifierRoot,
    cidMerkleRoot,
    manifestDigest,
    aggregateCiphertextDigest,
    packageDigests,
    ballotNullifiers,
    ballotProofPublicInputsHashes,
  });

  return {
    version: ELIGIBLE_BATCH_MANIFEST_VERSION,
    verificationMode: ELIGIBLE_BATCH_VERIFICATION_MODE,
    electionId: normalizeBytes32(electionId),
    candidateListHash: first.candidateListHash,
    eligibilityRoot: normalizeBytes32(eligibilityRoot),
    electionPublicKeyHash: first.ciphertext.electionPublicKeyHash,
    previousNullifierRoot: normalizeBytes32(previousNullifierRoot),
    nullifierRoot,
    cidMerkleRoot,
    manifestDigest,
    batchPublicInputsHash,
    batchSize: BigInt(validated.length),
    aggregateCiphertext,
    aggregateCiphertextDigest,
    packageDigests,
    packageLeafHashes,
    ballotNullifiers,
    ballotProofPublicInputsHashes,
  };
}

export async function buildEligibleInclusionReceipt(
  manifest: EligibleBatchManifestV3,
  votePackage: EligibleVotePackageV3,
): Promise<PackageInclusionReceipt> {
  const packageDigest = await digestEligibleVotePackage(votePackage);
  const leafIndex = manifest.packageDigests.indexOf(packageDigest);
  assert.equal(leafIndex >= 0, true, "package digest is not in manifest");
  return {
    batchManifestDigest: manifest.manifestDigest,
    packageDigest,
    leafHash: manifest.packageLeafHashes[leafIndex]!,
    leafIndex,
    proof: merkleProof(manifest.packageLeafHashes, leafIndex),
  };
}

export function computeEligibleEncryptedTallyHash(params: {
  electionId: Bytes32;
  candidateListHash: Bytes32;
  eligibilityRoot: Bytes32;
  acceptedBatchManifestDigests: readonly Bytes32[];
  acceptedBatchPublicInputsHashes: readonly Bytes32[];
  aggregateCiphertext: ProofCompatibleCiphertextJson;
}): Bytes32 {
  assertBytes32(params.electionId, "electionId");
  assertBytes32(params.candidateListHash, "candidateListHash");
  assertBytes32(params.eligibilityRoot, "eligibilityRoot");
  assertCanonicalField(params.eligibilityRoot, "eligibilityRoot");
  assert.equal(
    params.acceptedBatchManifestDigests.length,
    params.acceptedBatchPublicInputsHashes.length,
  );
  assert.equal(params.acceptedBatchManifestDigests.length > 0, true);
  return keccak256(encodeAbiParameters(
    parseAbiParameters(
      "bytes32 domain, bytes32 electionId, bytes32 candidateListHash, bytes32 eligibilityRoot, bytes32[] acceptedBatchManifestDigests, bytes32[] acceptedBatchPublicInputsHashes, bytes32 aggregateCiphertextDigest",
    ),
    [
      domainHash("SVB_ELIGIBLE_ENCRYPTED_TALLY_INPUTS_V3"),
      normalizeBytes32(params.electionId),
      normalizeBytes32(params.candidateListHash),
      normalizeBytes32(params.eligibilityRoot),
      params.acceptedBatchManifestDigests.map(normalizeBytes32),
      params.acceptedBatchPublicInputsHashes.map(normalizeBytes32),
      digestProofCompatibleCiphertext(params.aggregateCiphertext),
    ],
  ));
}
