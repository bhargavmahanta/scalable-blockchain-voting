import { randomBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";

const repositoryRoot = process.cwd();
const circomCliPath = path.join(repositoryRoot, "node_modules/circom2/cli.js");
const snarkjsCliPath = path.join(
  repositoryRoot,
  "node_modules/snarkjs/build/cli.cjs",
);
const circuitBuildDirectory = path.join(
  repositoryRoot,
  "circuits/build/ballot_validity",
);
const ceremonyDirectory = path.join(
  repositoryRoot,
  "circuits/ceremony/ballot_validity",
);
const generatedContractsDirectory = path.join(repositoryRoot, "contracts/generated");
const r1csPath = path.join(circuitBuildDirectory, "ballot_validity.r1cs");
const initialPowersOfTauPath = path.join(ceremonyDirectory, "pot15_0000.ptau");
const contributedPowersOfTauPath = path.join(ceremonyDirectory, "pot15_0001.ptau");
const preparedPowersOfTauPath = path.join(ceremonyDirectory, "pot15_final.ptau");
const initialZkeyPath = path.join(circuitBuildDirectory, "ballot_validity_0000.zkey");
const finalZkeyPath = path.join(circuitBuildDirectory, "ballot_validity_final.zkey");
const verificationKeyPath = path.join(circuitBuildDirectory, "verification_key.json");
const generatedVerifierPath = path.join(
  generatedContractsDirectory,
  "BallotGroth16Verifier.sol",
);

function run(command: string, args: readonly string[]) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
}

await rm(circuitBuildDirectory, { recursive: true, force: true });
await rm(ceremonyDirectory, { recursive: true, force: true });
await mkdir(circuitBuildDirectory, { recursive: true });
await mkdir(ceremonyDirectory, { recursive: true });
await mkdir(generatedContractsDirectory, { recursive: true });

run(process.execPath, [
  circomCliPath,
  "circuits/ballot_validity.circom",
  "--r1cs",
  "--wasm",
  "--sym",
  "-o",
  "circuits/build/ballot_validity",
]);

run(process.execPath, [
  snarkjsCliPath,
  "powersoftau",
  "new",
  "bn128",
  "15",
  initialPowersOfTauPath,
]);
run(process.execPath, [
  snarkjsCliPath,
  "powersoftau",
  "contribute",
  initialPowersOfTauPath,
  contributedPowersOfTauPath,
  "--name=SVB local demo contribution",
  `--entropy=${randomBytes(64).toString("hex")}`,
]);
run(process.execPath, [
  snarkjsCliPath,
  "powersoftau",
  "prepare",
  "phase2",
  contributedPowersOfTauPath,
  preparedPowersOfTauPath,
]);
run(process.execPath, [
  snarkjsCliPath,
  "groth16",
  "setup",
  r1csPath,
  preparedPowersOfTauPath,
  initialZkeyPath,
]);
run(process.execPath, [
  snarkjsCliPath,
  "zkey",
  "contribute",
  initialZkeyPath,
  finalZkeyPath,
  "--name=SVB ballot circuit local contribution",
  `--entropy=${randomBytes(64).toString("hex")}`,
]);
run(process.execPath, [
  snarkjsCliPath,
  "zkey",
  "export",
  "verificationkey",
  finalZkeyPath,
  verificationKeyPath,
]);
run(process.execPath, [
  snarkjsCliPath,
  "zkey",
  "export",
  "solidityverifier",
  finalZkeyPath,
  generatedVerifierPath,
]);

const generatedVerifier = await readFile(generatedVerifierPath, "utf8");
await writeFile(
  generatedVerifierPath,
  generatedVerifier.replace(
    "contract Groth16Verifier",
    "contract BallotGroth16Verifier",
  ),
);

run(process.execPath, [
  "--import",
  "tsx",
  "scripts/build_ballot_circuit_input.ts",
  "test/fixtures/ballot-validity/input.json",
  "1",
]);
run(process.execPath, [
  "--import",
  "tsx",
  "scripts/generate_ballot_proof.ts",
  "test/fixtures/ballot-validity/input.json",
  "test/fixtures/ballot-validity",
]);
run(process.execPath, [
  "--import",
  "tsx",
  "scripts/build_ballot_circuit_input.ts",
  "test/fixtures/ballot-validity-2/input.json",
  "2",
  "2",
]);
run(process.execPath, [
  "--import",
  "tsx",
  "scripts/generate_ballot_proof.ts",
  "test/fixtures/ballot-validity-2/input.json",
  "test/fixtures/ballot-validity-2",
]);

console.log(`Ballot proving key: ${path.relative(repositoryRoot, finalZkeyPath)}`);
console.log(`Verification key: ${path.relative(repositoryRoot, verificationKeyPath)}`);
console.log(`Solidity verifier: ${path.relative(repositoryRoot, generatedVerifierPath)}`);
console.log("The committed proof fixture was refreshed for this verifier.");
console.log("The local ceremony is suitable for this testnet demo, not a production election.");
