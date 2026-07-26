import assert from "node:assert/strict";

import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  encodeAbiParameters,
  isAddress,
  isHex,
  keccak256,
  parseAbiParameters,
  stringToHex,
  zeroHash,
} from "viem";

export * from "./proofCompatibleBallot.js";
export * from "./v4.js";

export type Hex = `0x${string}`;
export type Bytes32 = Hex;
export type Address = Hex;

export const VOTE_PACKAGE_VERSION = 1 as const;
export const BATCH_MANIFEST_VERSION = 1 as const;

export const BALLOT_CIPHERTEXT_SCHEME =
  "ec-elgamal-secp256k1-compressed-points-v1" as const;
export const BALLOT_PROOF_SYSTEM = "groth16-ballot-validity-v1" as const;
export const TALLY_DECRYPTION_SHARE_SCHEME =
  "threshold-ec-elgamal-decryption-share-v1" as const;

export type ElectionKeyPair = {
  privateKey: Hex;
  publicKey: Hex;
  publicKeyHash: Bytes32;
};

export type BallotCiphertextV1 = {
  scheme: typeof BALLOT_CIPHERTEXT_SCHEME;
  electionPublicKeyHash: Bytes32;
  points: readonly Hex[];
};

export type BallotValidityProofV1 = {
  system: typeof BALLOT_PROOF_SYSTEM;
  proof: Hex;
  publicInputsHash: Bytes32;
};

export type ThresholdKeyShareV1 = {
  trusteeIndex: number;
  privateShare: Hex;
  publicShare: Hex;
};

export type ThresholdElectionKeySetV1 = {
  threshold: number;
  trusteeCount: number;
  publicKey: Hex;
  publicKeyHash: Bytes32;
  shares: readonly ThresholdKeyShareV1[];
};

export type TallyDecryptionShareProofV1 = {
  commitmentToGenerator: Hex;
  commitmentToCiphertext: Hex;
  response: Hex;
};

export type TallyDecryptionShareV1 = {
  scheme: typeof TALLY_DECRYPTION_SHARE_SCHEME;
  trusteeIndex: number;
  trusteePublicShare: Hex;
  electionPublicKeyHash: Bytes32;
  decryptionSharePoints: readonly Hex[];
  proofs: readonly TallyDecryptionShareProofV1[];
};

export type VotePackageV1 = {
  version: typeof VOTE_PACKAGE_VERSION;
  electionId: Bytes32;
  candidateListHash: Bytes32;
  ballotNullifier: Bytes32;
  ciphertext: BallotCiphertextV1;
  ballotValidityProof: BallotValidityProofV1;
};

export type StoredVotePackageV1 = {
  contentId: string;
  package: VotePackageV1;
};

export type BatchManifestV1 = {
  version: typeof BATCH_MANIFEST_VERSION;
  electionId: Bytes32;
  previousNullifierRoot: Bytes32;
  nullifierRoot: Bytes32;
  cidMerkleRoot: Bytes32;
  manifestDigest: Bytes32;
  batchPublicInputsHash: Bytes32;
  batchSize: bigint;
  packageDigests: readonly Bytes32[];
  packageLeafHashes: readonly Bytes32[];
  ballotNullifiers: readonly Bytes32[];
};

type MerkleProofStep = {
  sibling: Bytes32;
  direction: "left" | "right";
};

export type PackageInclusionReceipt = {
  batchManifestDigest: Bytes32;
  packageDigest: Bytes32;
  leafHash: Bytes32;
  leafIndex: number;
  proof: readonly MerkleProofStep[];
};

type CanonicalJson =
  | null
  | boolean
  | number
  | string
  | readonly CanonicalJson[]
  | { readonly [key: string]: CanonicalJson };

const SECP256K1_ORDER = secp256k1.CURVE.n;

const exactKeys = <T extends Record<string, unknown>>(
  value: T,
  keys: readonly string[],
  label: string,
) => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  assert.deepEqual(
    actual,
    expected,
    `${label} must contain exactly: ${expected.join(", ")}`,
  );
};

function assertBytes32(value: string, label: string): asserts value is Bytes32 {
  assert.equal(
    isHex(value, { strict: true }) && value.length === 66,
    true,
    `${label} must be a 32-byte hex string`,
  );
}

function assertAddress(value: string, label: string): asserts value is Address {
  assert.equal(isAddress(value), true, `${label} must be an Ethereum address`);
}

function assertHexBytes(value: string, label: string): asserts value is Hex {
  assert.equal(
    isHex(value, { strict: true }) && value.length >= 4,
    true,
    `${label} must be non-empty hex bytes`,
  );
}

function assertCompressedPointHex(value: string, label: string): asserts value is Hex {
  assertHexBytes(value, label);
  assert.equal(value.length, 68, `${label} must be a compressed secp256k1 point`);
  const prefix = value.slice(2, 4).toLowerCase();
  assert.equal(
    prefix === "02" || prefix === "03",
    true,
    `${label} must use compressed point prefix 02 or 03`,
  );
}

const domainHash = (domain: string): Bytes32 => keccak256(stringToHex(domain));

const normalizeBytes32 = (value: Bytes32): Bytes32 =>
  value.toLowerCase() as Bytes32;

const normalizeHex = (value: Hex): Hex => value.toLowerCase() as Hex;

const normalizeAddress = (value: Address): Address =>
  value.toLowerCase() as Address;

const stripHexPrefix = (value: Hex): string => value.slice(2);

const bytesToPrefixedHex = (value: Uint8Array): Hex =>
  `0x${bytesToHex(value)}`;

function modOrder(value: bigint): bigint {
  const result = value % SECP256K1_ORDER;
  return result >= 0n ? result : result + SECP256K1_ORDER;
}

function scalarToHex(value: bigint): Hex {
  const scalar = modOrder(value);
  assert.notEqual(scalar, 0n, "scalar cannot be zero");
  return `0x${scalar.toString(16).padStart(64, "0")}`;
}

function canonicalizeJson(value: unknown): CanonicalJson {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return value;
  }
  if (typeof value === "number") {
    assert.equal(Number.isFinite(value), true, "JSON number must be finite");
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalizeJson);
  }
  if (typeof value === "object" && value !== null) {
    const sortedEntries = Object.entries(value)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entryValue]) => [key, canonicalizeJson(entryValue)] as const);
    return Object.fromEntries(sortedEntries);
  }
  throw new TypeError(`unsupported JSON value type: ${typeof value}`);
}

function canonicalStringify(value: unknown): string {
  return JSON.stringify(canonicalizeJson(value));
}

function scalarFromPrivateKey(privateKey: Hex, label = "privateKey"): bigint {
  assertBytes32(privateKey, label);
  const scalar = BigInt(privateKey);
  assert.equal(scalar > 0n && scalar < SECP256K1_ORDER, true, `${label} is not a valid scalar`);
  return scalar;
}

function scalarFromHex(value: Hex, label: string): bigint {
  return scalarFromPrivateKey(normalizeHex(value), label);
}

function pointFromHex(value: Hex, label: string): typeof secp256k1.ProjectivePoint.BASE {
  assertCompressedPointHex(value, label);
  return secp256k1.ProjectivePoint.fromHex(stripHexPrefix(value));
}

function pointToHex(point: typeof secp256k1.ProjectivePoint.BASE): Hex {
  return bytesToPrefixedHex(point.toRawBytes(true));
}

export function createElectionKeyPair(privateKey?: Hex): ElectionKeyPair {
  const normalizedPrivateKey = privateKey === undefined
    ? bytesToPrefixedHex(secp256k1.utils.randomPrivateKey())
    : normalizeHex(privateKey);
  const publicKey = deriveElectionPublicKey(normalizedPrivateKey);
  return {
    privateKey: normalizedPrivateKey,
    publicKey,
    publicKeyHash: hashElectionPublicKey(publicKey),
  };
}

export function deriveElectionPublicKey(privateKey: Hex): Hex {
  scalarFromPrivateKey(privateKey);
  return bytesToPrefixedHex(
    secp256k1.getPublicKey(hexToBytes(stripHexPrefix(privateKey)), true),
  );
}

export function createThresholdElectionKeyShares(params: {
  privateKey?: Hex;
  threshold: number;
  trusteeCount: number;
  coefficients?: readonly Hex[];
}): ThresholdElectionKeySetV1 {
  assert.equal(Number.isInteger(params.threshold), true, "threshold must be an integer");
  assert.equal(Number.isInteger(params.trusteeCount), true, "trusteeCount must be an integer");
  assert.equal(params.threshold >= 2, true, "threshold must be at least two");
  assert.equal(params.trusteeCount >= params.threshold, true, "trusteeCount must be at least threshold");
  const secret = params.privateKey === undefined
    ? scalarFromPrivateKey(bytesToPrefixedHex(secp256k1.utils.randomPrivateKey()), "privateKey")
    : scalarFromHex(params.privateKey, "privateKey");
  if (params.coefficients !== undefined) {
    assert.equal(
      params.coefficients.length,
      params.threshold - 1,
      "coefficients must include threshold - 1 scalar values",
    );
  }
  const coefficients = params.coefficients === undefined
    ? Array.from(
        { length: params.threshold - 1 },
        () => scalarFromPrivateKey(bytesToPrefixedHex(secp256k1.utils.randomPrivateKey()), "coefficient"),
      )
    : params.coefficients.map((coefficient, index) =>
        scalarFromHex(coefficient, `coefficients[${index}]`),
      );

  const shares: ThresholdKeyShareV1[] = [];
  for (let trusteeIndex = 1; trusteeIndex <= params.trusteeCount; trusteeIndex += 1) {
    const x = BigInt(trusteeIndex);
    let y = secret;
    let power = x;
    for (const coefficient of coefficients) {
      y = modOrder(y + coefficient * power);
      power = modOrder(power * x);
    }
    const privateShare = scalarToHex(y);
    shares.push({
      trusteeIndex,
      privateShare,
      publicShare: pointToHex(secp256k1.ProjectivePoint.BASE.multiply(y)),
    });
  }

  const publicKey = pointToHex(secp256k1.ProjectivePoint.BASE.multiply(secret));
  return {
    threshold: params.threshold,
    trusteeCount: params.trusteeCount,
    publicKey,
    publicKeyHash: hashElectionPublicKey(publicKey),
    shares,
  };
}

export function hashElectionPublicKey(publicKey: Hex): Bytes32 {
  assertCompressedPointHex(publicKey, "electionPublicKey");
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("bytes32 domain, bytes publicKey"),
      [domainHash("SVB_ELECTION_PUBLIC_KEY_V1"), publicKey],
    ),
  );
}

export function computeRegistrationPublicInputsHash(params: {
  electionId: Bytes32;
  identityNullifier: Bytes32;
  votingKey: Address;
}): Bytes32 {
  assertBytes32(params.electionId, "electionId");
  assertBytes32(params.identityNullifier, "identityNullifier");
  assertAddress(params.votingKey, "votingKey");

  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 electionId, bytes32 identityNullifier, address votingKey",
      ),
      [
        domainHash("SVB_REGISTRATION_PUBLIC_INPUTS_V1"),
        normalizeBytes32(params.electionId),
        normalizeBytes32(params.identityNullifier),
        normalizeAddress(params.votingKey),
      ],
    ),
  );
}

export function encryptBallotSelection(params: {
  electionPublicKey: Hex;
  candidateCount: number;
  selectedIndex: number;
  randomness?: readonly Hex[];
}): BallotCiphertextV1 {
  const electionPublicKey = normalizeHex(params.electionPublicKey);
  const publicKeyPoint = pointFromHex(electionPublicKey, "electionPublicKey");
  assert.equal(Number.isInteger(params.candidateCount), true, "candidateCount must be an integer");
  assert.equal(params.candidateCount > 1, true, "candidateCount must be greater than one");
  assert.equal(Number.isInteger(params.selectedIndex), true, "selectedIndex must be an integer");
  assert.equal(
    params.selectedIndex >= 0 && params.selectedIndex < params.candidateCount,
    true,
    "selectedIndex out of range",
  );
  if (params.randomness !== undefined) {
    assert.equal(
      params.randomness.length,
      params.candidateCount,
      "randomness must include one scalar per candidate",
    );
  }

  const points: Hex[] = [];
  for (let candidateIndex = 0; candidateIndex < params.candidateCount; candidateIndex += 1) {
    const randomScalar = params.randomness?.[candidateIndex] === undefined
      ? scalarFromPrivateKey(bytesToPrefixedHex(secp256k1.utils.randomPrivateKey()), "randomness")
      : scalarFromPrivateKey(normalizeHex(params.randomness[candidateIndex]!), `randomness[${candidateIndex}]`);
    const c1 = secp256k1.ProjectivePoint.BASE.multiply(randomScalar);
    const sharedSecret = publicKeyPoint.multiply(randomScalar);
    const c2 = candidateIndex === params.selectedIndex
      ? sharedSecret.add(secp256k1.ProjectivePoint.BASE)
      : sharedSecret;
    points.push(pointToHex(c1), pointToHex(c2));
  }

  return {
    scheme: BALLOT_CIPHERTEXT_SCHEME,
    electionPublicKeyHash: hashElectionPublicKey(electionPublicKey),
    points,
  };
}

export function decryptBallotSelection(params: {
  privateKey: Hex;
  ciphertext: BallotCiphertextV1;
}): readonly number[] {
  const privateScalar = scalarFromPrivateKey(normalizeHex(params.privateKey));
  const publicKeyHash = hashElectionPublicKey(deriveElectionPublicKey(params.privateKey));
  const ciphertext = validateCiphertext(params.ciphertext);
  assert.equal(
    ciphertext.electionPublicKeyHash,
    publicKeyHash,
    "ciphertext was encrypted for a different public key",
  );

  return decryptCiphertextCounts({
    privateScalar,
    ciphertext,
    maxCount: 1,
  });
}

export function aggregateBallotCiphertexts(
  ciphertexts: readonly BallotCiphertextV1[],
): BallotCiphertextV1 {
  assert.equal(ciphertexts.length > 0, true, "at least one ciphertext is required");
  const normalizedCiphertexts = ciphertexts.map(validateCiphertext);
  const first = normalizedCiphertexts[0]!;
  const candidateCount = first.points.length / 2;
  const aggregatedPoints: Hex[] = [];

  for (const ciphertext of normalizedCiphertexts) {
    assert.equal(
      ciphertext.electionPublicKeyHash,
      first.electionPublicKeyHash,
      "all ciphertexts must use the same election public key",
    );
    assert.equal(
      ciphertext.points.length,
      first.points.length,
      "all ciphertexts must have the same candidate count",
    );
  }

  for (let pairIndex = 0; pairIndex < candidateCount; pairIndex += 1) {
    let c1 = pointFromHex(first.points[pairIndex * 2]!, `ciphertext[0].points[${pairIndex * 2}]`);
    let c2 = pointFromHex(first.points[pairIndex * 2 + 1]!, `ciphertext[0].points[${pairIndex * 2 + 1}]`);

    for (let ciphertextIndex = 1; ciphertextIndex < normalizedCiphertexts.length; ciphertextIndex += 1) {
      const ciphertext = normalizedCiphertexts[ciphertextIndex]!;
      c1 = c1.add(pointFromHex(ciphertext.points[pairIndex * 2]!, `ciphertext[${ciphertextIndex}].points[${pairIndex * 2}]`));
      c2 = c2.add(pointFromHex(ciphertext.points[pairIndex * 2 + 1]!, `ciphertext[${ciphertextIndex}].points[${pairIndex * 2 + 1}]`));
    }

    aggregatedPoints.push(pointToHex(c1), pointToHex(c2));
  }

  return {
    scheme: BALLOT_CIPHERTEXT_SCHEME,
    electionPublicKeyHash: first.electionPublicKeyHash,
    points: aggregatedPoints,
  };
}

export function decryptAggregatedTally(params: {
  privateKey: Hex;
  ciphertext: BallotCiphertextV1;
  maxVotes: number;
}): readonly number[] {
  assert.equal(Number.isInteger(params.maxVotes), true, "maxVotes must be an integer");
  assert.equal(params.maxVotes >= 0, true, "maxVotes cannot be negative");
  const privateScalar = scalarFromPrivateKey(normalizeHex(params.privateKey));
  const publicKeyHash = hashElectionPublicKey(deriveElectionPublicKey(params.privateKey));
  const ciphertext = validateCiphertext(params.ciphertext);
  assert.equal(
    ciphertext.electionPublicKeyHash,
    publicKeyHash,
    "ciphertext was encrypted for a different public key",
  );

  return decryptCiphertextCounts({
    privateScalar,
    ciphertext,
    maxCount: params.maxVotes,
  });
}

export function createTallyDecryptionShare(params: {
  trusteeIndex: number;
  privateShare: Hex;
  ciphertext: BallotCiphertextV1;
  proofNonces?: readonly Hex[];
}): TallyDecryptionShareV1 {
  assert.equal(Number.isInteger(params.trusteeIndex), true, "trusteeIndex must be an integer");
  assert.equal(params.trusteeIndex > 0, true, "trusteeIndex must be positive");
  const privateShare = scalarFromHex(params.privateShare, "privateShare");
  const ciphertext = validateCiphertext(params.ciphertext);
  const candidateCount = ciphertext.points.length / 2;
  if (params.proofNonces !== undefined) {
    assert.equal(
      params.proofNonces.length,
      candidateCount,
      "proofNonces must include one scalar per candidate",
    );
  }

  const trusteePublicShare = pointToHex(
    secp256k1.ProjectivePoint.BASE.multiply(privateShare),
  );
  const decryptionSharePoints: Hex[] = [];
  const proofs: TallyDecryptionShareProofV1[] = [];

  for (let pairIndex = 0; pairIndex < candidateCount; pairIndex += 1) {
    const c1 = pointFromHex(ciphertext.points[pairIndex * 2]!, `ciphertext.points[${pairIndex * 2}]`);
    const sharePoint = c1.multiply(privateShare);
    const sharePointHex = pointToHex(sharePoint);
    const nonce = params.proofNonces?.[pairIndex] === undefined
      ? scalarFromPrivateKey(bytesToPrefixedHex(secp256k1.utils.randomPrivateKey()), "proofNonce")
      : scalarFromHex(params.proofNonces[pairIndex]!, `proofNonces[${pairIndex}]`);
    const commitmentToGeneratorPoint = secp256k1.ProjectivePoint.BASE.multiply(nonce);
    const commitmentToCiphertextPoint = c1.multiply(nonce);
    const commitmentToGenerator = pointToHex(commitmentToGeneratorPoint);
    const commitmentToCiphertext = pointToHex(commitmentToCiphertextPoint);
    const challenge = decryptionShareChallenge({
      electionPublicKeyHash: ciphertext.electionPublicKeyHash,
      trusteeIndex: params.trusteeIndex,
      trusteePublicShare,
      ciphertextPoint: ciphertext.points[pairIndex * 2]!,
      decryptionSharePoint: sharePointHex,
      commitmentToGenerator,
      commitmentToCiphertext,
    });
    const response = scalarToHex(nonce + challenge * privateShare);

    decryptionSharePoints.push(sharePointHex);
    proofs.push({
      commitmentToGenerator,
      commitmentToCiphertext,
      response,
    });
  }

  return {
    scheme: TALLY_DECRYPTION_SHARE_SCHEME,
    trusteeIndex: params.trusteeIndex,
    trusteePublicShare,
    electionPublicKeyHash: ciphertext.electionPublicKeyHash,
    decryptionSharePoints,
    proofs,
  };
}

export function verifyTallyDecryptionShare(params: {
  ciphertext: BallotCiphertextV1;
  share: TallyDecryptionShareV1;
}): boolean {
  try {
    const ciphertext = validateCiphertext(params.ciphertext);
    const share = validateTallyDecryptionShare(params.share, ciphertext);
    for (let pairIndex = 0; pairIndex < ciphertext.points.length / 2; pairIndex += 1) {
      const c1 = pointFromHex(ciphertext.points[pairIndex * 2]!, `ciphertext.points[${pairIndex * 2}]`);
      const trusteePublicShare = pointFromHex(share.trusteePublicShare, "trusteePublicShare");
      const decryptionSharePoint = pointFromHex(
        share.decryptionSharePoints[pairIndex]!,
        `decryptionSharePoints[${pairIndex}]`,
      );
      const proof = share.proofs[pairIndex]!;
      const response = scalarFromHex(proof.response, `proofs[${pairIndex}].response`);
      const challenge = decryptionShareChallenge({
        electionPublicKeyHash: ciphertext.electionPublicKeyHash,
        trusteeIndex: share.trusteeIndex,
        trusteePublicShare: share.trusteePublicShare,
        ciphertextPoint: ciphertext.points[pairIndex * 2]!,
        decryptionSharePoint: share.decryptionSharePoints[pairIndex]!,
        commitmentToGenerator: proof.commitmentToGenerator,
        commitmentToCiphertext: proof.commitmentToCiphertext,
      });

      const expectedGeneratorCommitment = secp256k1.ProjectivePoint.BASE
        .multiply(response)
        .subtract(trusteePublicShare.multiply(challenge));
      const expectedCiphertextCommitment = c1
        .multiply(response)
        .subtract(decryptionSharePoint.multiply(challenge));

      if (pointToHex(expectedGeneratorCommitment) !== proof.commitmentToGenerator) {
        return false;
      }
      if (pointToHex(expectedCiphertextCommitment) !== proof.commitmentToCiphertext) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

export function decryptAggregatedTallyWithShares(params: {
  ciphertext: BallotCiphertextV1;
  shares: readonly TallyDecryptionShareV1[];
  threshold: number;
  maxVotes: number;
}): readonly number[] {
  assert.equal(Number.isInteger(params.threshold), true, "threshold must be an integer");
  assert.equal(params.threshold >= 2, true, "threshold must be at least two");
  assert.equal(Number.isInteger(params.maxVotes), true, "maxVotes must be an integer");
  assert.equal(params.maxVotes >= 0, true, "maxVotes cannot be negative");
  assert.equal(params.shares.length >= params.threshold, true, "not enough decryption shares");
  const ciphertext = validateCiphertext(params.ciphertext);
  const selectedShares = params.shares
    .map((share) => validateTallyDecryptionShare(share, ciphertext))
    .sort((left, right) => left.trusteeIndex - right.trusteeIndex)
    .slice(0, params.threshold);
  const seenIndexes = new Set<number>();
  for (const share of selectedShares) {
    assert.equal(verifyTallyDecryptionShare({ ciphertext, share }), true, "invalid decryption share proof");
    assert.equal(seenIndexes.has(share.trusteeIndex), false, "duplicate trustee index");
    seenIndexes.add(share.trusteeIndex);
  }

  const lagrangeByTrustee = selectedShares.map((share) => ({
    share,
    coefficient: lagrangeCoefficientAtZero(
      BigInt(share.trusteeIndex),
      selectedShares.map((entry) => BigInt(entry.trusteeIndex)),
    ),
  }));

  const combinedPublicKey = lagrangeByTrustee.reduce(
    (accumulator, entry) =>
      accumulator.add(pointFromHex(entry.share.trusteePublicShare, "trusteePublicShare").multiply(entry.coefficient)),
    secp256k1.ProjectivePoint.ZERO,
  );
  assert.equal(
    hashElectionPublicKey(pointToHex(combinedPublicKey)),
    ciphertext.electionPublicKeyHash,
    "decryption shares do not reconstruct the election public key",
  );

  const lookup = buildTallyLookup(params.maxVotes);
  const counts: number[] = [];
  for (let pairIndex = 0; pairIndex < ciphertext.points.length / 2; pairIndex += 1) {
    const c2 = pointFromHex(ciphertext.points[pairIndex * 2 + 1]!, `ciphertext.points[${pairIndex * 2 + 1}]`);
    const sharedSecret = lagrangeByTrustee.reduce(
      (accumulator, entry) =>
        accumulator.add(pointFromHex(
          entry.share.decryptionSharePoints[pairIndex]!,
          `decryptionSharePoints[${pairIndex}]`,
        ).multiply(entry.coefficient)),
      secp256k1.ProjectivePoint.ZERO,
    );
    const messagePoint = c2.subtract(sharedSecret);
    const count = messagePoint.equals(secp256k1.ProjectivePoint.ZERO)
      ? lookup.get("zero")
      : lookup.get(pointToHex(messagePoint));
    assert.notEqual(count, undefined, "ciphertext does not decrypt to an expected small tally value");
    counts.push(count as number);
  }

  return counts;
}

function validateCiphertext(input: BallotCiphertextV1): BallotCiphertextV1 {
  exactKeys(
    input as unknown as Record<string, unknown>,
    ["scheme", "electionPublicKeyHash", "points"],
    "ciphertext",
  );
  assert.equal(
    input.scheme,
    BALLOT_CIPHERTEXT_SCHEME,
    "unsupported ciphertext scheme",
  );
  assertBytes32(input.electionPublicKeyHash, "electionPublicKeyHash");
  assert.equal(
    Array.isArray(input.points) && input.points.length >= 4 && input.points.length % 2 === 0,
    true,
    "ciphertext.points must contain c1/c2 pairs for at least two candidates",
  );
  for (const [index, point] of input.points.entries()) {
    assertCompressedPointHex(point, `ciphertext.points[${index}]`);
  }

  return {
    scheme: BALLOT_CIPHERTEXT_SCHEME,
    electionPublicKeyHash: normalizeBytes32(input.electionPublicKeyHash),
    points: input.points.map(normalizeHex),
  };
}

function decryptCiphertextCounts(params: {
  privateScalar: bigint;
  ciphertext: BallotCiphertextV1;
  maxCount: number;
}): readonly number[] {
  const lookup = buildTallyLookup(params.maxCount);

  const counts: number[] = [];
  for (let index = 0; index < params.ciphertext.points.length; index += 2) {
    const c1 = pointFromHex(params.ciphertext.points[index]!, `ciphertext.points[${index}]`);
    const c2 = pointFromHex(params.ciphertext.points[index + 1]!, `ciphertext.points[${index + 1}]`);
    const messagePoint = c2.subtract(c1.multiply(params.privateScalar));
    const count = messagePoint.equals(secp256k1.ProjectivePoint.ZERO)
      ? lookup.get("zero")
      : lookup.get(pointToHex(messagePoint));
    assert.notEqual(count, undefined, "ciphertext does not decrypt to an expected small tally value");
    counts.push(count as number);
  }

  return counts;
}

function buildTallyLookup(maxCount: number): Map<string, number> {
  const lookup = new Map<string, number>();
  lookup.set("zero", 0);
  for (let count = 1; count <= maxCount; count += 1) {
    lookup.set(
      pointToHex(secp256k1.ProjectivePoint.BASE.multiply(BigInt(count))),
      count,
    );
  }
  return lookup;
}

function decryptionShareChallenge(params: {
  electionPublicKeyHash: Bytes32;
  trusteeIndex: number;
  trusteePublicShare: Hex;
  ciphertextPoint: Hex;
  decryptionSharePoint: Hex;
  commitmentToGenerator: Hex;
  commitmentToCiphertext: Hex;
}): bigint {
  assertBytes32(params.electionPublicKeyHash, "electionPublicKeyHash");
  assert.equal(Number.isInteger(params.trusteeIndex), true, "trusteeIndex must be an integer");
  assert.equal(params.trusteeIndex > 0, true, "trusteeIndex must be positive");
  assertCompressedPointHex(params.trusteePublicShare, "trusteePublicShare");
  assertCompressedPointHex(params.ciphertextPoint, "ciphertextPoint");
  assertCompressedPointHex(params.decryptionSharePoint, "decryptionSharePoint");
  assertCompressedPointHex(params.commitmentToGenerator, "commitmentToGenerator");
  assertCompressedPointHex(params.commitmentToCiphertext, "commitmentToCiphertext");

  return modOrder(BigInt(keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 electionPublicKeyHash, uint32 trusteeIndex, bytes trusteePublicShare, bytes ciphertextPoint, bytes decryptionSharePoint, bytes commitmentToGenerator, bytes commitmentToCiphertext",
      ),
      [
        domainHash("SVB_TALLY_DECRYPTION_SHARE_DLEQ_V1"),
        normalizeBytes32(params.electionPublicKeyHash),
        params.trusteeIndex,
        normalizeHex(params.trusteePublicShare),
        normalizeHex(params.ciphertextPoint),
        normalizeHex(params.decryptionSharePoint),
        normalizeHex(params.commitmentToGenerator),
        normalizeHex(params.commitmentToCiphertext),
      ],
    ),
  )));
}

function lagrangeCoefficientAtZero(x: bigint, allX: readonly bigint[]): bigint {
  let numerator = 1n;
  let denominator = 1n;
  for (const otherX of allX) {
    if (otherX === x) continue;
    numerator = modOrder(numerator * -otherX);
    denominator = modOrder(denominator * (x - otherX));
  }
  return modOrder(numerator * modInverse(denominator));
}

function modInverse(value: bigint): bigint {
  let low = modOrder(value);
  let high = SECP256K1_ORDER;
  let lm = 1n;
  let hm = 0n;
  while (low > 1n) {
    const ratio = high / low;
    const next = high - low * ratio;
    const nextCoefficient = hm - lm * ratio;
    high = low;
    hm = lm;
    low = next;
    lm = nextCoefficient;
  }
  return modOrder(lm);
}

function validateTallyDecryptionShare(
  input: TallyDecryptionShareV1,
  ciphertext: BallotCiphertextV1,
): TallyDecryptionShareV1 {
  exactKeys(
    input as unknown as Record<string, unknown>,
    [
      "scheme",
      "trusteeIndex",
      "trusteePublicShare",
      "electionPublicKeyHash",
      "decryptionSharePoints",
      "proofs",
    ],
    "tally decryption share",
  );
  assert.equal(input.scheme, TALLY_DECRYPTION_SHARE_SCHEME, "unsupported decryption share scheme");
  assert.equal(Number.isInteger(input.trusteeIndex), true, "trusteeIndex must be an integer");
  assert.equal(input.trusteeIndex > 0, true, "trusteeIndex must be positive");
  assertCompressedPointHex(input.trusteePublicShare, "trusteePublicShare");
  assertBytes32(input.electionPublicKeyHash, "electionPublicKeyHash");
  assert.equal(
    normalizeBytes32(input.electionPublicKeyHash),
    ciphertext.electionPublicKeyHash,
    "decryption share is for a different election public key",
  );
  const candidateCount = ciphertext.points.length / 2;
  assert.equal(input.decryptionSharePoints.length, candidateCount, "wrong number of decryption share points");
  assert.equal(input.proofs.length, candidateCount, "wrong number of decryption share proofs");
  input.decryptionSharePoints.forEach((point, index) =>
    assertCompressedPointHex(point, `decryptionSharePoints[${index}]`),
  );
  input.proofs.forEach((proof, index) => {
    exactKeys(
      proof as unknown as Record<string, unknown>,
      ["commitmentToGenerator", "commitmentToCiphertext", "response"],
      `proofs[${index}]`,
    );
    assertCompressedPointHex(proof.commitmentToGenerator, `proofs[${index}].commitmentToGenerator`);
    assertCompressedPointHex(proof.commitmentToCiphertext, `proofs[${index}].commitmentToCiphertext`);
    scalarFromHex(proof.response, `proofs[${index}].response`);
  });

  return {
    scheme: TALLY_DECRYPTION_SHARE_SCHEME,
    trusteeIndex: input.trusteeIndex,
    trusteePublicShare: normalizeHex(input.trusteePublicShare),
    electionPublicKeyHash: normalizeBytes32(input.electionPublicKeyHash),
    decryptionSharePoints: input.decryptionSharePoints.map(normalizeHex),
    proofs: input.proofs.map((proof) => ({
      commitmentToGenerator: normalizeHex(proof.commitmentToGenerator),
      commitmentToCiphertext: normalizeHex(proof.commitmentToCiphertext),
      response: normalizeHex(proof.response),
    })),
  };
}

export function digestBallotCiphertext(input: BallotCiphertextV1): Bytes32 {
  const ciphertext = validateCiphertext(input);
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 ciphertextScheme, bytes32 electionPublicKeyHash, bytes[] ciphertextPoints",
      ),
      [
        domainHash("SVB_BALLOT_CIPHERTEXT_V1"),
        domainHash(ciphertext.scheme),
        ciphertext.electionPublicKeyHash,
        [...ciphertext.points],
      ],
    ),
  );
}

export function digestTallyDecryptionShare(params: {
  ciphertext: BallotCiphertextV1;
  share: TallyDecryptionShareV1;
}): Bytes32 {
  const ciphertext = validateCiphertext(params.ciphertext);
  const share = validateTallyDecryptionShare(params.share, ciphertext);
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 aggregateCiphertextDigest, uint32 trusteeIndex, bytes trusteePublicShare, bytes32 electionPublicKeyHash, bytes[] decryptionSharePoints",
      ),
      [
        domainHash("SVB_TALLY_DECRYPTION_SHARE_V1"),
        digestBallotCiphertext(ciphertext),
        share.trusteeIndex,
        share.trusteePublicShare,
        share.electionPublicKeyHash,
        [...share.decryptionSharePoints],
      ],
    ),
  );
}

export function computeTallyResultHash(params: {
  electionId: Bytes32;
  candidateListHash: Bytes32;
  electionPublicKeyHash: Bytes32;
  aggregateCiphertext: BallotCiphertextV1;
  tallyCounts: readonly number[];
  decryptionShareDigests: readonly Bytes32[];
}): Bytes32 {
  assertBytes32(params.electionId, "electionId");
  assertBytes32(params.candidateListHash, "candidateListHash");
  assertBytes32(params.electionPublicKeyHash, "electionPublicKeyHash");
  const aggregateCiphertext = validateCiphertext(params.aggregateCiphertext);
  assert.equal(
    aggregateCiphertext.electionPublicKeyHash,
    normalizeBytes32(params.electionPublicKeyHash),
    "aggregate ciphertext key does not match election public key hash",
  );
  assert.equal(params.tallyCounts.length > 1, true, "tallyCounts must include at least two candidates");
  const tallyCounts = params.tallyCounts.map((count, index) => {
    assert.equal(Number.isInteger(count), true, `tallyCounts[${index}] must be an integer`);
    assert.equal(count >= 0, true, `tallyCounts[${index}] cannot be negative`);
    assert.equal(count <= 0xffffffff, true, `tallyCounts[${index}] exceeds uint32`);
    return count;
  });
  const decryptionShareDigests = params.decryptionShareDigests.map((digest, index) => {
    assertBytes32(digest, `decryptionShareDigests[${index}]`);
    return normalizeBytes32(digest);
  });
  assert.equal(
    decryptionShareDigests.length > 0,
    true,
    "at least one decryption share digest is required",
  );

  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 electionId, bytes32 candidateListHash, bytes32 electionPublicKeyHash, bytes32 aggregateCiphertextDigest, uint32[] tallyCounts, bytes32[] decryptionShareDigests",
      ),
      [
        domainHash("SVB_TALLY_RESULT_V1"),
        normalizeBytes32(params.electionId),
        normalizeBytes32(params.candidateListHash),
        normalizeBytes32(params.electionPublicKeyHash),
        digestBallotCiphertext(aggregateCiphertext),
        tallyCounts,
        decryptionShareDigests,
      ],
    ),
  );
}

export function computeTallyProofPublicInputsHash(params: {
  electionId: Bytes32;
  candidateListHash: Bytes32;
  electionPublicKeyHash: Bytes32;
  acceptedBatchManifestDigests: readonly Bytes32[];
  acceptedBatchPublicInputsHashes: readonly Bytes32[];
  aggregateCiphertext: BallotCiphertextV1;
  tallyCounts: readonly number[];
  decryptionShareDigests: readonly Bytes32[];
  resultHash: Bytes32;
}): Bytes32 {
  assertBytes32(params.electionId, "electionId");
  assertBytes32(params.candidateListHash, "candidateListHash");
  assertBytes32(params.electionPublicKeyHash, "electionPublicKeyHash");
  assertBytes32(params.resultHash, "resultHash");
  const acceptedBatchManifestDigests = params.acceptedBatchManifestDigests.map((digest, index) => {
    assertBytes32(digest, `acceptedBatchManifestDigests[${index}]`);
    return normalizeBytes32(digest);
  });
  const acceptedBatchPublicInputsHashes = params.acceptedBatchPublicInputsHashes.map((hashValue, index) => {
    assertBytes32(hashValue, `acceptedBatchPublicInputsHashes[${index}]`);
    return normalizeBytes32(hashValue);
  });
  assert.equal(
    acceptedBatchManifestDigests.length,
    acceptedBatchPublicInputsHashes.length,
    "accepted batch digest arrays must have the same length",
  );
  assert.equal(
    acceptedBatchManifestDigests.length > 0,
    true,
    "at least one accepted batch is required",
  );

  const resultHash = computeTallyResultHash({
    electionId: params.electionId,
    candidateListHash: params.candidateListHash,
    electionPublicKeyHash: params.electionPublicKeyHash,
    aggregateCiphertext: params.aggregateCiphertext,
    tallyCounts: params.tallyCounts,
    decryptionShareDigests: params.decryptionShareDigests,
  });
  assert.equal(
    resultHash,
    normalizeBytes32(params.resultHash),
    "resultHash does not match tally result fields",
  );

  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 electionId, bytes32 candidateListHash, bytes32 electionPublicKeyHash, bytes32[] acceptedBatchManifestDigests, bytes32[] acceptedBatchPublicInputsHashes, bytes32 aggregateCiphertextDigest, uint32[] tallyCounts, bytes32[] decryptionShareDigests, bytes32 resultHash",
      ),
      [
        domainHash("SVB_TALLY_PROOF_PUBLIC_INPUTS_V1"),
        normalizeBytes32(params.electionId),
        normalizeBytes32(params.candidateListHash),
        normalizeBytes32(params.electionPublicKeyHash),
        acceptedBatchManifestDigests,
        acceptedBatchPublicInputsHashes,
        digestBallotCiphertext(params.aggregateCiphertext),
        params.tallyCounts,
        params.decryptionShareDigests.map(normalizeBytes32),
        normalizeBytes32(params.resultHash),
      ],
    ),
  );
}

export function computeEncryptedTallyPublicInputsHash(params: {
  electionId: Bytes32;
  candidateListHash: Bytes32;
  electionPublicKeyHash: Bytes32;
  acceptedBatchPublicInputsHashes: readonly Bytes32[];
  aggregateCiphertext: BallotCiphertextV1;
}): Bytes32 {
  assertBytes32(params.electionId, "electionId");
  assertBytes32(params.candidateListHash, "candidateListHash");
  assertBytes32(params.electionPublicKeyHash, "electionPublicKeyHash");
  const acceptedBatchPublicInputsHashes = params.acceptedBatchPublicInputsHashes.map(
    (hashValue, index) => {
      assertBytes32(hashValue, `acceptedBatchPublicInputsHashes[${index}]`);
      return normalizeBytes32(hashValue);
    },
  );
  const aggregateCiphertext = validateCiphertext(params.aggregateCiphertext);
  assert.equal(
    aggregateCiphertext.electionPublicKeyHash,
    normalizeBytes32(params.electionPublicKeyHash),
    "aggregate ciphertext key does not match election public key hash",
  );

  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 electionId, bytes32 candidateListHash, bytes32 electionPublicKeyHash, bytes32[] acceptedBatchPublicInputsHashes, bytes32 aggregateCiphertextDigest",
      ),
      [
        domainHash("SVB_ENCRYPTED_TALLY_PUBLIC_INPUTS_V1"),
        normalizeBytes32(params.electionId),
        normalizeBytes32(params.candidateListHash),
        normalizeBytes32(params.electionPublicKeyHash),
        acceptedBatchPublicInputsHashes,
        digestBallotCiphertext(aggregateCiphertext),
      ],
    ),
  );
}

export function computeBallotPublicInputsHash(params: {
  electionId: Bytes32;
  candidateListHash: Bytes32;
  ballotNullifier: Bytes32;
  ciphertext: BallotCiphertextV1;
}): Bytes32 {
  assertBytes32(params.electionId, "electionId");
  assertBytes32(params.candidateListHash, "candidateListHash");
  assertBytes32(params.ballotNullifier, "ballotNullifier");

  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 electionId, bytes32 candidateListHash, bytes32 ballotNullifier, bytes32 ciphertextDigest",
      ),
      [
        domainHash("SVB_BALLOT_PUBLIC_INPUTS_V1"),
        normalizeBytes32(params.electionId),
        normalizeBytes32(params.candidateListHash),
        normalizeBytes32(params.ballotNullifier),
        digestBallotCiphertext(params.ciphertext),
      ],
    ),
  );
}

export function validateVotePackage(input: VotePackageV1): VotePackageV1 {
  exactKeys(
    input as unknown as Record<string, unknown>,
    [
      "version",
      "electionId",
      "candidateListHash",
      "ballotNullifier",
      "ciphertext",
      "ballotValidityProof",
    ],
    "vote package",
  );
  assert.equal(input.version, VOTE_PACKAGE_VERSION, "unsupported vote package version");
  assertBytes32(input.electionId, "electionId");
  assertBytes32(input.candidateListHash, "candidateListHash");
  assertBytes32(input.ballotNullifier, "ballotNullifier");

  exactKeys(
    input.ciphertext as unknown as Record<string, unknown>,
    ["scheme", "electionPublicKeyHash", "points"],
    "ciphertext",
  );
  const ciphertext = validateCiphertext(input.ciphertext);

  exactKeys(
    input.ballotValidityProof as unknown as Record<string, unknown>,
    ["system", "proof", "publicInputsHash"],
    "ballot validity proof",
  );
  assert.equal(
    input.ballotValidityProof.system,
    BALLOT_PROOF_SYSTEM,
    "unsupported ballot proof system",
  );
  assertHexBytes(input.ballotValidityProof.proof, "ballotValidityProof.proof");
  assertBytes32(input.ballotValidityProof.publicInputsHash, "publicInputsHash");

  const expectedPublicInputsHash = computeBallotPublicInputsHash({
    electionId: input.electionId,
    candidateListHash: input.candidateListHash,
    ballotNullifier: input.ballotNullifier,
    ciphertext,
  });
  assert.equal(
    normalizeBytes32(input.ballotValidityProof.publicInputsHash),
    expectedPublicInputsHash,
    "ballot proof public inputs do not match vote package",
  );

  return {
    version: VOTE_PACKAGE_VERSION,
    electionId: normalizeBytes32(input.electionId),
    candidateListHash: normalizeBytes32(input.candidateListHash),
    ballotNullifier: normalizeBytes32(input.ballotNullifier),
    ciphertext,
    ballotValidityProof: {
      system: BALLOT_PROOF_SYSTEM,
      proof: normalizeHex(input.ballotValidityProof.proof),
      publicInputsHash: normalizeBytes32(input.ballotValidityProof.publicInputsHash),
    },
  };
}

export function serializeVotePackage(input: VotePackageV1): string {
  return `${canonicalStringify(validateVotePackage(input))}\n`;
}

export function parseVotePackageJson(json: string): VotePackageV1 {
  return validateVotePackage(JSON.parse(json) as VotePackageV1);
}

export function digestVotePackage(input: VotePackageV1): Bytes32 {
  const votePackage = validateVotePackage(input);

  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, uint8 version, bytes32 electionId, bytes32 candidateListHash, bytes32 ballotNullifier, bytes32 ciphertextScheme, bytes32 electionPublicKeyHash, bytes[] ciphertextPoints, bytes32 proofSystem, bytes proof, bytes32 publicInputsHash",
      ),
      [
        domainHash("SVB_VOTE_PACKAGE_V1"),
        votePackage.version,
        votePackage.electionId,
        votePackage.candidateListHash,
        votePackage.ballotNullifier,
        domainHash(votePackage.ciphertext.scheme),
        votePackage.ciphertext.electionPublicKeyHash,
        [...votePackage.ciphertext.points],
        domainHash(votePackage.ballotValidityProof.system),
        votePackage.ballotValidityProof.proof,
        votePackage.ballotValidityProof.publicInputsHash,
      ],
    ),
  );
}

export function digestContentId(contentId: string): Bytes32 {
  assert.equal(contentId.trim().length > 0, true, "contentId cannot be empty");
  return keccak256(stringToHex(contentId.trim()));
}

export function hashPackageLeaf(storedPackage: StoredVotePackageV1): Bytes32 {
  const normalizedPackage = validateVotePackage(storedPackage.package);
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 contentIdDigest, bytes32 packageDigest, bytes32 ballotNullifier",
      ),
      [
        domainHash("SVB_PACKAGE_LEAF_V1"),
        digestContentId(storedPackage.contentId),
        digestVotePackage(normalizedPackage),
        normalizedPackage.ballotNullifier,
      ],
    ),
  );
}

export function hashMerklePair(left: Bytes32, right: Bytes32): Bytes32 {
  assertBytes32(left, "left");
  assertBytes32(right, "right");
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("bytes32 domain, bytes32 left, bytes32 right"),
      [domainHash("SVB_MERKLE_PAIR_V1"), normalizeBytes32(left), normalizeBytes32(right)],
    ),
  );
}

export function merkleRoot(leaves: readonly Bytes32[]): Bytes32 {
  if (leaves.length === 0) return zeroHash;

  let level = leaves.map((leaf, index) => {
    assertBytes32(leaf, `leaf[${index}]`);
    return normalizeBytes32(leaf);
  });

  while (level.length > 1) {
    const nextLevel: Bytes32[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index]!;
      const right = level[index + 1] ?? left;
      nextLevel.push(hashMerklePair(left, right));
    }
    level = nextLevel;
  }

  return level[0]!;
}

export function merkleProof(
  leaves: readonly Bytes32[],
  leafIndex: number,
): readonly MerkleProofStep[] {
  assert.equal(Number.isInteger(leafIndex), true, "leafIndex must be an integer");
  assert.equal(leafIndex >= 0 && leafIndex < leaves.length, true, "leafIndex out of range");

  let index = leafIndex;
  let level = leaves.map(normalizeBytes32);
  const proof: MerkleProofStep[] = [];

  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    const sibling = level[siblingIndex] ?? level[index]!;
    proof.push({
      sibling,
      direction: index % 2 === 0 ? "right" : "left",
    });

    const nextLevel: Bytes32[] = [];
    for (let cursor = 0; cursor < level.length; cursor += 2) {
      const left = level[cursor]!;
      const right = level[cursor + 1] ?? left;
      nextLevel.push(hashMerklePair(left, right));
    }
    index = Math.floor(index / 2);
    level = nextLevel;
  }

  return proof;
}

export function verifyMerkleProof(
  leafHash: Bytes32,
  proof: readonly MerkleProofStep[],
  expectedRoot: Bytes32,
): boolean {
  let cursor = normalizeBytes32(leafHash);
  for (const step of proof) {
    assertBytes32(step.sibling, "proof sibling");
    cursor =
      step.direction === "left"
        ? hashMerklePair(step.sibling, cursor)
        : hashMerklePair(cursor, step.sibling);
  }
  return cursor === normalizeBytes32(expectedRoot);
}

export function nullifierSetRoot(nullifiers: readonly Bytes32[]): Bytes32 {
  const uniqueSorted = [...new Set(nullifiers.map(normalizeBytes32))].sort();
  return merkleRoot(
    uniqueSorted.map((nullifier) =>
      keccak256(
        encodeAbiParameters(
          parseAbiParameters("bytes32 domain, bytes32 ballotNullifier"),
          [domainHash("SVB_NULLIFIER_LEAF_V1"), nullifier],
        ),
      ),
    ),
  );
}

export function computeBatchPublicInputsHash(params: {
  electionId: Bytes32;
  previousNullifierRoot: Bytes32;
  nullifierRoot: Bytes32;
  cidMerkleRoot: Bytes32;
  manifestDigest: Bytes32;
  packageDigests: readonly Bytes32[];
  ballotNullifiers: readonly Bytes32[];
}): Bytes32 {
  assertBytes32(params.electionId, "electionId");
  assertBytes32(params.previousNullifierRoot, "previousNullifierRoot");
  assertBytes32(params.nullifierRoot, "nullifierRoot");
  assertBytes32(params.cidMerkleRoot, "cidMerkleRoot");
  assertBytes32(params.manifestDigest, "manifestDigest");

  const packageDigests = params.packageDigests.map((digest, index) => {
    assertBytes32(digest, `packageDigests[${index}]`);
    return normalizeBytes32(digest);
  });
  const ballotNullifiers = params.ballotNullifiers.map((nullifier, index) => {
    assertBytes32(nullifier, `ballotNullifiers[${index}]`);
    return normalizeBytes32(nullifier);
  });

  return keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, bytes32 electionId, bytes32 previousNullifierRoot, bytes32 nullifierRoot, bytes32 cidMerkleRoot, bytes32 manifestDigest, bytes32[] packageDigests, bytes32[] ballotNullifiers",
      ),
      [
        domainHash("SVB_BATCH_PUBLIC_INPUTS_V1"),
        normalizeBytes32(params.electionId),
        normalizeBytes32(params.previousNullifierRoot),
        normalizeBytes32(params.nullifierRoot),
        normalizeBytes32(params.cidMerkleRoot),
        normalizeBytes32(params.manifestDigest),
        packageDigests,
        ballotNullifiers,
      ],
    ),
  );
}

export class NullifierAccumulator {
  readonly #seen = new Set<Bytes32>();

  constructor(initialNullifiers: readonly Bytes32[] = []) {
    for (const nullifier of initialNullifiers) {
      this.add(nullifier);
    }
  }

  get root(): Bytes32 {
    return nullifierSetRoot([...this.#seen]);
  }

  has(nullifier: Bytes32): boolean {
    return this.#seen.has(normalizeBytes32(nullifier));
  }

  add(nullifier: Bytes32): void {
    assertBytes32(nullifier, "ballotNullifier");
    const normalized = normalizeBytes32(nullifier);
    assert.equal(this.#seen.has(normalized), false, "duplicate ballot nullifier");
    this.#seen.add(normalized);
  }

  addMany(nullifiers: readonly Bytes32[]): void {
    for (const nullifier of nullifiers) {
      this.add(nullifier);
    }
  }
}

export function buildBatchManifest(
  electionId: Bytes32,
  previousNullifierRoot: Bytes32,
  storedPackages: readonly StoredVotePackageV1[],
  accumulator: NullifierAccumulator,
): BatchManifestV1 {
  assertBytes32(electionId, "electionId");
  assertBytes32(previousNullifierRoot, "previousNullifierRoot");
  assert.equal(storedPackages.length > 0, true, "batch must include at least one package");
  assert.equal(
    accumulator.root,
    normalizeBytes32(previousNullifierRoot),
    "previousNullifierRoot does not match accumulator state",
  );

  const normalizedElectionId = normalizeBytes32(electionId);
  const normalizedPackages = storedPackages.map((storedPackage) => ({
    contentId: storedPackage.contentId.trim(),
    package: validateVotePackage(storedPackage.package),
  }));

  for (const [index, storedPackage] of normalizedPackages.entries()) {
    assert.equal(
      storedPackage.package.electionId,
      normalizedElectionId,
      `package[${index}] electionId mismatch`,
    );
  }

  const sortedPackages = [...normalizedPackages].sort((a, b) =>
    digestVotePackage(a.package).localeCompare(digestVotePackage(b.package)),
  );
  const batchNullifiers = sortedPackages.map(
    (storedPackage) => storedPackage.package.ballotNullifier,
  );
  accumulator.addMany(batchNullifiers);

  const packageDigests = sortedPackages.map((storedPackage) =>
    digestVotePackage(storedPackage.package),
  );
  const packageLeafHashes = sortedPackages.map(hashPackageLeaf);
  const cidMerkleRoot = merkleRoot(packageLeafHashes);
  const nullifierRoot = accumulator.root;
  const manifestDigest = keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        "bytes32 domain, uint8 version, bytes32 electionId, bytes32 previousNullifierRoot, bytes32 nullifierRoot, bytes32 cidMerkleRoot, uint64 batchSize, bytes32[] packageDigests, bytes32[] ballotNullifiers",
      ),
      [
        domainHash("SVB_BATCH_MANIFEST_V1"),
        BATCH_MANIFEST_VERSION,
        normalizedElectionId,
        normalizeBytes32(previousNullifierRoot),
        nullifierRoot,
        cidMerkleRoot,
        BigInt(sortedPackages.length),
        packageDigests,
        batchNullifiers,
      ],
    ),
  );
  const batchPublicInputsHash = computeBatchPublicInputsHash({
    electionId: normalizedElectionId,
    previousNullifierRoot: normalizeBytes32(previousNullifierRoot),
    nullifierRoot,
    cidMerkleRoot,
    manifestDigest,
    packageDigests,
    ballotNullifiers: batchNullifiers,
  });

  return {
    version: BATCH_MANIFEST_VERSION,
    electionId: normalizedElectionId,
    previousNullifierRoot: normalizeBytes32(previousNullifierRoot),
    nullifierRoot,
    cidMerkleRoot,
    manifestDigest,
    batchPublicInputsHash,
    batchSize: BigInt(sortedPackages.length),
    packageDigests,
    packageLeafHashes,
    ballotNullifiers: batchNullifiers,
  };
}

export function buildInclusionReceipt(
  manifest: BatchManifestV1,
  packageDigest: Bytes32,
): PackageInclusionReceipt {
  const leafIndex = manifest.packageDigests.indexOf(normalizeBytes32(packageDigest));
  assert.equal(leafIndex >= 0, true, "package digest is not in manifest");
  const leafHash = manifest.packageLeafHashes[leafIndex]!;
  return {
    batchManifestDigest: manifest.manifestDigest,
    packageDigest: normalizeBytes32(packageDigest),
    leafHash,
    leafIndex,
    proof: merkleProof(manifest.packageLeafHashes, leafIndex),
  };
}
