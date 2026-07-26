import { randomBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";

const root = process.cwd();
const circomCliPath = path.join(root, "node_modules/circom2/cli.js");
const snarkjsCliPath = path.join(root, "node_modules/snarkjs/build/cli.cjs");
const buildDirectory = path.join(root, "circuits/build/eligible_ballot");
const ceremonyDirectory = path.join(root, "circuits/ceremony/eligible_ballot");
const generatedDirectory = path.join(root, "contracts/generated");
const r1csPath = path.join(buildDirectory, "eligible_ballot.r1cs");
const pot0 = path.join(ceremonyDirectory, "pot16_0000.ptau");
const pot1 = path.join(ceremonyDirectory, "pot16_0001.ptau");
const potFinal = path.join(ceremonyDirectory, "pot16_final.ptau");
const initialZkey = path.join(buildDirectory, "eligible_ballot_0000.zkey");
const finalZkey = path.join(buildDirectory, "eligible_ballot_final.zkey");
const verificationKey = path.join(buildDirectory, "verification_key.json");
const verifierPath = path.join(generatedDirectory, "EligibleBallotGroth16Verifier.sol");

function run(command: string, args: readonly string[]) {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8", stdio: "inherit" });
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed`);
}

await rm(buildDirectory, { recursive: true, force: true });
await rm(ceremonyDirectory, { recursive: true, force: true });
await mkdir(buildDirectory, { recursive: true });
await mkdir(ceremonyDirectory, { recursive: true });
await mkdir(generatedDirectory, { recursive: true });

run(process.execPath, [circomCliPath, "circuits/eligible_ballot.circom", "--r1cs", "--wasm", "--sym", "-o", "circuits/build/eligible_ballot"]);
run(process.execPath, [snarkjsCliPath, "powersoftau", "new", "bn128", "16", pot0]);
run(process.execPath, [snarkjsCliPath, "powersoftau", "contribute", pot0, pot1,
  "--name=SVB eligible ballot local contribution", `--entropy=${randomBytes(64).toString("hex")}`]);
run(process.execPath, [snarkjsCliPath, "powersoftau", "prepare", "phase2", pot1, potFinal]);
run(process.execPath, [snarkjsCliPath, "groth16", "setup", r1csPath, potFinal, initialZkey]);
run(process.execPath, [snarkjsCliPath, "zkey", "contribute", initialZkey, finalZkey,
  "--name=SVB eligible ballot zkey contribution", `--entropy=${randomBytes(64).toString("hex")}`]);
run(process.execPath, [snarkjsCliPath, "zkey", "export", "verificationkey", finalZkey, verificationKey]);
run(process.execPath, [snarkjsCliPath, "zkey", "export", "solidityverifier", finalZkey, verifierPath]);
const generatedVerifier = await readFile(verifierPath, "utf8");
await writeFile(
  verifierPath,
  generatedVerifier.replace("contract Groth16Verifier", "contract EligibleBallotGroth16Verifier"),
);

for (const [fixture, selection, credential] of [
  ["eligible-ballot", "1", "1"],
  ["eligible-ballot-2", "2", "2"],
] as const) {
  run(process.execPath, ["--import", "tsx", "scripts/build_eligible_ballot_input.ts", `test/fixtures/${fixture}/input.json`, selection, credential]);
  run(process.execPath, ["--import", "tsx", "scripts/generate_eligible_ballot_proof.ts", `test/fixtures/${fixture}/input.json`, `test/fixtures/${fixture}`]);
}

console.log(`Eligible ballot proving key: ${path.relative(root, finalZkey)}`);
console.log(`Eligible ballot verifier: ${path.relative(root, verifierPath)}`);
console.log("This is a local testnet ceremony, not a production multi-party setup.");
