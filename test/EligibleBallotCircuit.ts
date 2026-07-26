import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const wasmPath = path.resolve(
  "circuits/build/eligible_ballot/eligible_ballot_js/eligible_ballot.wasm",
);
const fixtureInputPath = path.resolve("test/fixtures/eligible-ballot/input.json");
const snarkjsCliPath = path.resolve("node_modules/snarkjs/build/cli.cjs");

function calculateWitness(inputPath: string, witnessPath: string) {
  return spawnSync(process.execPath, [snarkjsCliPath, "wtns", "calculate", wasmPath, inputPath, witnessPath], {
    cwd: process.cwd(), encoding: "utf8",
  });
}

type EligibleCircuitInput = {
  electionId: string;
  eligibilityRoot: string;
  ballotNullifier: string;
  packageCommitment: string;
  c2: string[][];
  credentialSecret: string;
  eligibilityPathElements: string[];
  selection: string[];
};

async function writeMutatedFixture(
  directory: string,
  label: string,
  mutate: (input: EligibleCircuitInput) => void,
): Promise<string> {
  const input = JSON.parse(
    await readFile(fixtureInputPath, "utf8"),
  ) as EligibleCircuitInput;
  mutate(input);
  const inputPath = path.join(directory, `${label}.json`);
  await writeFile(inputPath, `${JSON.stringify(input, null, 2)}\n`);
  return inputPath;
}

function assertWitnessRejected(
  result: ReturnType<typeof calculateWitness>,
): void {
  assert.equal(result.error, undefined, result.error?.message);
  assert.notEqual(
    result.status,
    0,
    "invalid eligible ballot unexpectedly satisfied the circuit",
  );
}

describe("unified eligibility and ballot circuit", function () {
  it("accepts a private eligibility membership and valid encrypted ballot", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-valid-"));
    const result = calculateWitness(fixtureInputPath, path.join(directory, "valid.wtns"));
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  });

  it("rejects a changed eligibility path", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-path-"));
    const inputPath = await writeMutatedFixture(
      directory,
      "changed-path",
      (input) => {
        input.eligibilityPathElements[0] =
          (BigInt(input.eligibilityPathElements[0]!) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects a nullifier not derived from the private credential", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-nullifier-"));
    const inputPath = await writeMutatedFixture(
      directory,
      "changed-nullifier",
      (input) => {
        input.ballotNullifier = (BigInt(input.ballotNullifier) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects a stale eligibility root", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-root-"));
    const inputPath = await writeMutatedFixture(
      directory,
      "stale-root",
      (input) => {
        input.eligibilityRoot = (BigInt(input.eligibilityRoot) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects a credential secret that is not present in the tree", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-secret-"));
    const inputPath = await writeMutatedFixture(
      directory,
      "wrong-secret",
      (input) => {
        input.credentialSecret = (BigInt(input.credentialSecret) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects a proof witness bound to another election", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-election-"));
    const inputPath = await writeMutatedFixture(
      directory,
      "wrong-election",
      (input) => {
        input.electionId = (BigInt(input.electionId) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects a changed encrypted ciphertext", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-ciphertext-"));
    const inputPath = await writeMutatedFixture(
      directory,
      "changed-ciphertext",
      (input) => {
        input.c2[0]![0] = (BigInt(input.c2[0]![0]!) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects a changed package commitment", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-package-"));
    const inputPath = await writeMutatedFixture(
      directory,
      "changed-package",
      (input) => {
        input.packageCommitment =
          (BigInt(input.packageCommitment) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects an invalid one-hot ballot", async function () {
    const directory = await mkdtemp(path.join(tmpdir(), "svb-eligible-selection-"));
    const inputPath = await writeMutatedFixture(
      directory,
      "invalid-selection",
      (input) => {
        input.selection = ["1", "1", "0", "0"];
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });
});
