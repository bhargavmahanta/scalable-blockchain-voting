import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  encodeAbiParameters,
  parseAbiParameters,
  type Hex,
} from "viem";

import {
  hashProofCompatibleBallotPublicSignals,
  type ProofCompatibleBallotPublicSignals,
} from "../packages/crypto/src/proofCompatibleBallot.js";

type SolidityCallData = readonly [
  readonly [string, string],
  readonly [readonly [string, string], readonly [string, string]],
  readonly [string, string],
  readonly string[],
];

const inputPath = process.argv[2];
const outputDirectory = process.argv[3];
if (inputPath === undefined || outputDirectory === undefined) {
  throw new Error(
    "usage: npm run proof:ballot -- path/to/input.json path/to/output-directory",
  );
}

const root = process.cwd();
const snarkjsCliPath = path.join(root, "node_modules/snarkjs/build/cli.cjs");
const wasmPath = path.join(
  root,
  "circuits/build/ballot_validity/ballot_validity_js/ballot_validity.wasm",
);
const zkeyPath = path.join(
  root,
  "circuits/build/ballot_validity/ballot_validity_final.zkey",
);
const resolvedOutputDirectory = path.resolve(outputDirectory);
const proofPath = path.join(resolvedOutputDirectory, "proof.json");
const publicSignalsPath = path.join(resolvedOutputDirectory, "public.json");

await readFile(path.resolve(inputPath));
await readFile(wasmPath);
await readFile(zkeyPath);
await mkdir(resolvedOutputDirectory, { recursive: true });

const prove = spawnSync(
  process.execPath,
  [
    snarkjsCliPath,
    "groth16",
    "fullprove",
    path.resolve(inputPath),
    wasmPath,
    zkeyPath,
    proofPath,
    publicSignalsPath,
  ],
  { cwd: root, encoding: "utf8" },
);
if (prove.status !== 0) {
  throw new Error(prove.stderr || prove.stdout || "ballot proof generation failed");
}

const calldata = spawnSync(
  process.execPath,
  [snarkjsCliPath, "zkey", "export", "soliditycalldata", publicSignalsPath, proofPath],
  { cwd: root, encoding: "utf8" },
);
if (calldata.status !== 0) {
  throw new Error(calldata.stderr || calldata.stdout || "calldata export failed");
}

const parsed = JSON.parse(`[${calldata.stdout.trim()}]`) as SolidityCallData;
const publicSignals = parsed[3].map(BigInt);
if (publicSignals.length !== 22) {
  throw new Error(`expected 22 public signals, received ${publicSignals.length}`);
}
const typedPublicSignals =
  publicSignals as unknown as ProofCompatibleBallotPublicSignals;
const proofEnvelope = encodeAbiParameters(
  parseAbiParameters(
    "uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[22] publicSignals",
  ),
  [
    parsed[0].map(BigInt) as [bigint, bigint],
    parsed[1].map((row) => row.map(BigInt)) as [
      [bigint, bigint],
      [bigint, bigint],
    ],
    parsed[2].map(BigInt) as [bigint, bigint],
    typedPublicSignals,
  ],
);

const artifact = {
  system: "groth16-ballot-validity-babyjubjub-v1",
  proof: proofEnvelope as Hex,
  publicSignals: typedPublicSignals.map(String),
  publicInputsHash: hashProofCompatibleBallotPublicSignals(typedPublicSignals),
  proofJsonPath: path.relative(resolvedOutputDirectory, proofPath),
  publicSignalsJsonPath: path.relative(resolvedOutputDirectory, publicSignalsPath),
};
await writeFile(
  path.join(resolvedOutputDirectory, "ballot-proof-artifact.json"),
  `${JSON.stringify(artifact, null, 2)}\n`,
);

console.log(JSON.stringify(artifact, null, 2));
