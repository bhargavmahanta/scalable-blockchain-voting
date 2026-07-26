import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { keccak256, stringToHex } from "viem";

import {
  buildProofCompatibleBallotWitness,
  bytes32ToSnarkField,
  createProofCompatibleElectionKeyPair,
  encryptProofCompatibleBallot,
} from "../packages/crypto/src/proofCompatibleBallot.js";

const wasmPath = path.resolve(
  "circuits/build/ballot_validity/ballot_validity_js/ballot_validity.wasm",
);
const fixtureInputPath = path.resolve(
  "test/fixtures/ballot-validity/input.json",
);
const snarkjsCliPath = path.resolve("node_modules/snarkjs/build/cli.cjs");

function calculateWitness(inputPath: string, witnessPath: string) {
  return spawnSync(
    process.execPath,
    [snarkjsCliPath, "wtns", "calculate", wasmPath, inputPath, witnessPath],
    { cwd: process.cwd(), encoding: "utf8" },
  );
}

type BallotCircuitInput = {
  electionPublicKey: string[];
  c2: string[][];
  selection?: string[];
  randomness: string[];
};

async function writeValidInput(
  directory: string,
  selectedIndex: number,
): Promise<string> {
  const electionKey = await createProofCompatibleElectionKeyPair(7n);
  const encrypted = await encryptProofCompatibleBallot({
    electionPublicKey: electionKey.publicKey,
    selectedIndex,
    randomness: [17n, 18n, 19n, 20n],
  });
  const ballotNullifier =
    `0x${bytes32ToSnarkField(
      keccak256(stringToHex(`circuit-selection-${selectedIndex}`)),
    ).toString(16).padStart(64, "0")}` as const;
  const witness = await buildProofCompatibleBallotWitness({
    electionId: keccak256(stringToHex("scalable-voting-demo-2026")),
    candidateListHash: keccak256(
      stringToHex("candidate-a,candidate-b,candidate-c,candidate-d"),
    ),
    ballotNullifier,
    electionPublicKey: electionKey.publicKey,
    ciphertext: encrypted.ciphertext,
    selection: encrypted.selection,
    randomness: encrypted.randomness,
  });
  const inputPath = path.join(directory, `selection-${selectedIndex}.json`);
  await writeFile(
    inputPath,
    `${JSON.stringify(
      witness,
      (_, value) => typeof value === "bigint" ? value.toString() : value,
      2,
    )}\n`,
  );
  return inputPath;
}

async function writeMutatedFixture(
  directory: string,
  label: string,
  mutate: (input: BallotCircuitInput) => void,
): Promise<string> {
  const input = JSON.parse(
    await readFile(fixtureInputPath, "utf8"),
  ) as BallotCircuitInput;
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
    "invalid ballot unexpectedly satisfied the circuit",
  );
}

describe("ballot validity circuit constraints", function () {
  for (const [selectedIndex, selection] of [
    [0, "[1, 0, 0, 0]"],
    [1, "[0, 1, 0, 0]"],
    [2, "[0, 0, 1, 0]"],
    [3, "[0, 0, 0, 1]"],
  ] as const) {
    it(`accepts one-hot selection ${selection}`, async function () {
      const directory = await mkdtemp(
        path.join(tmpdir(), "svb-ballot-circuit-valid-"),
      );
      const inputPath = await writeValidInput(directory, selectedIndex);
      const result = calculateWitness(
        inputPath,
        path.join(directory, "valid.wtns"),
      );
      assert.equal(result.error, undefined, result.error?.message);
      assert.equal(result.status, 0, result.stderr || result.stdout);
    });
  }

  for (const selection of [
    ["0", "0", "0", "0"],
    ["1", "1", "0", "0"],
    ["2", "0", "0", "0"],
    ["-1", "1", "0", "1"],
  ]) {
    it(`rejects invalid selection [${selection.join(", ")}]`, async function () {
      const directory = await mkdtemp(
        path.join(tmpdir(), "svb-ballot-circuit-selection-"),
      );
      const inputPath = await writeMutatedFixture(
        directory,
        "invalid-selection",
        (input) => {
          input.selection = selection;
        },
      );
      assertWitnessRejected(
        calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
      );
    });
  }

  it("rejects a selection that does not match the ciphertext", async function () {
    const directory = await mkdtemp(
      path.join(tmpdir(), "svb-ballot-circuit-ciphertext-"),
    );
    const inputPath = await writeMutatedFixture(
      directory,
      "selection-mismatch",
      (input) => {
        input.selection = ["1", "0", "0", "0"];
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects modified encryption randomness", async function () {
    const directory = await mkdtemp(
      path.join(tmpdir(), "svb-ballot-circuit-randomness-"),
    );
    const inputPath = await writeMutatedFixture(
      directory,
      "changed-randomness",
      (input) => {
        input.randomness[0] = (BigInt(input.randomness[0]!) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects a wrong election public key", async function () {
    const directory = await mkdtemp(
      path.join(tmpdir(), "svb-ballot-circuit-key-"),
    );
    const inputPath = await writeMutatedFixture(
      directory,
      "changed-public-key",
      (input) => {
        input.electionPublicKey[0] =
          (BigInt(input.electionPublicKey[0]!) + 1n).toString();
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });

  it("rejects a changed ciphertext coordinate", async function () {
    const directory = await mkdtemp(
      path.join(tmpdir(), "svb-ballot-circuit-coordinate-"),
    );
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

  it("rejects malformed witness input", async function () {
    const directory = await mkdtemp(
      path.join(tmpdir(), "svb-ballot-circuit-malformed-"),
    );
    const inputPath = await writeMutatedFixture(
      directory,
      "missing-selection",
      (input) => {
        delete input.selection;
      },
    );
    assertWitnessRejected(
      calculateWitness(inputPath, path.join(directory, "invalid.wtns")),
    );
  });
});
