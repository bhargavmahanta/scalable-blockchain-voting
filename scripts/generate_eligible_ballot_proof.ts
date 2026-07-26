import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { encodeAbiParameters, parseAbiParameters, type Hex } from "viem";

import {
  ELIGIBLE_BALLOT_PROOF_SYSTEM,
  hashEligibleBallotPublicSignals,
  type EligibleBallotPublicSignals,
} from "../packages/crypto/src/eligibleBallot.js";

type SolidityCallData = readonly [
  readonly [string, string],
  readonly [readonly [string, string], readonly [string, string]],
  readonly [string, string],
  readonly string[],
];

const inputPath = process.argv[2];
const outputDirectory = process.argv[3];
if (inputPath === undefined || outputDirectory === undefined) {
  throw new Error("usage: npm run proof:eligible-ballot -- input.json output-directory");
}
const root = process.cwd();
const snarkjsCliPath = path.join(root, "node_modules/snarkjs/build/cli.cjs");
const buildDirectory = path.join(root, "circuits/build/eligible_ballot");
const wasmPath = path.join(buildDirectory, "eligible_ballot_js/eligible_ballot.wasm");
const zkeyPath = path.join(buildDirectory, "eligible_ballot_final.zkey");
const resolvedOutputDirectory = path.resolve(outputDirectory);
const proofPath = path.join(resolvedOutputDirectory, "proof.json");
const publicSignalsPath = path.join(resolvedOutputDirectory, "public.json");

await Promise.all([readFile(path.resolve(inputPath)), readFile(wasmPath), readFile(zkeyPath)]);
await mkdir(resolvedOutputDirectory, { recursive: true });
const prove = spawnSync(process.execPath, [
  snarkjsCliPath, "groth16", "fullprove", path.resolve(inputPath), wasmPath,
  zkeyPath, proofPath, publicSignalsPath,
], { cwd: root, encoding: "utf8" });
if (prove.status !== 0) throw new Error(prove.stderr || prove.stdout || "eligible ballot proof failed");
const calldata = spawnSync(process.execPath, [
  snarkjsCliPath, "zkey", "export", "soliditycalldata", publicSignalsPath, proofPath,
], { cwd: root, encoding: "utf8" });
if (calldata.status !== 0) throw new Error(calldata.stderr || calldata.stdout || "calldata export failed");
const parsed = JSON.parse(`[${calldata.stdout.trim()}]`) as SolidityCallData;
const signals = parsed[3].map(BigInt);
if (signals.length !== 23) throw new Error(`expected 23 public signals, received ${signals.length}`);
const publicSignals = signals as unknown as EligibleBallotPublicSignals;
const proofEnvelope = encodeAbiParameters(
  parseAbiParameters(
    "uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[23] publicSignals",
  ),
  [
    parsed[0].map(BigInt) as [bigint, bigint],
    parsed[1].map((row) => row.map(BigInt)) as [[bigint, bigint], [bigint, bigint]],
    parsed[2].map(BigInt) as [bigint, bigint],
    publicSignals,
  ],
);
const artifact = {
  system: ELIGIBLE_BALLOT_PROOF_SYSTEM,
  proof: proofEnvelope as Hex,
  publicSignals: publicSignals.map(String),
  publicInputsHash: hashEligibleBallotPublicSignals(publicSignals),
  proofJsonPath: path.relative(resolvedOutputDirectory, proofPath),
  publicSignalsJsonPath: path.relative(resolvedOutputDirectory, publicSignalsPath),
};
await writeFile(
  path.join(resolvedOutputDirectory, "eligible-ballot-proof-artifact.json"),
  `${JSON.stringify(artifact, null, 2)}\n`,
);
console.log(JSON.stringify(artifact, null, 2));
