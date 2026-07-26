import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { keccak256, stringToHex } from "viem";

import {
  BALLOT_PROOF_SYSTEM,
  VOTE_PACKAGE_VERSION,
  computeBallotPublicInputsHash,
  createElectionKeyPair,
  digestVotePackage,
  encryptBallotSelection,
  serializeVotePackage,
  type VotePackageV1,
} from "../packages/crypto/src/index.js";

const hash = (value: string) => keccak256(stringToHex(value));
const electionId = hash("data-availability-election");
const candidateListHash = hash("candidate-list");
const electionKey = createElectionKeyPair(
  "0x0000000000000000000000000000000000000000000000000000000000000001",
);

function votePackage(label: string): VotePackageV1 {
  const ballotNullifier = hash(`data-availability-nullifier-${label}`);
  const ciphertext = encryptBallotSelection({
    electionPublicKey: electionKey.publicKey,
    candidateCount: 3,
    selectedIndex: 1,
    randomness: [
      "0x0000000000000000000000000000000000000000000000000000000000000011",
      "0x0000000000000000000000000000000000000000000000000000000000000012",
      "0x0000000000000000000000000000000000000000000000000000000000000013",
    ],
  });

  return {
    version: VOTE_PACKAGE_VERSION,
    electionId,
    candidateListHash,
    ballotNullifier,
    ciphertext,
    ballotValidityProof: {
      system: BALLOT_PROOF_SYSTEM,
      proof: "0x1234",
      publicInputsHash: computeBallotPublicInputsHash({
        electionId,
        candidateListHash,
        ballotNullifier,
        ciphertext,
      }),
    },
  };
}

async function runDataAvailabilityCheck(inputPath: string) {
  const child = spawn(
    process.execPath,
    ["--import", "tsx", "scripts/check_data_availability.ts", inputPath],
    {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk));

  const [exitCode] = await once(child, "close") as [number];
  assert.equal(Buffer.concat(stderrChunks).toString(), "");
  return {
    exitCode,
    output: JSON.parse(Buffer.concat(stdoutChunks).toString()) as {
      allAvailable: boolean;
      checks: readonly { ok: boolean; error?: string; digest?: string }[];
    },
  };
}

describe("data availability script", function () {
  it("passes available package preflight checks", async function () {
    const tempDir = await mkdtemp(join(tmpdir(), "svb-da-test-"));
    try {
      const vote = votePackage("ok");
      await writeFile(join(tempDir, "vote.json"), serializeVotePackage(vote), "utf8");
      const inputPath = join(tempDir, "batch-input.json");
      await writeFile(
        inputPath,
        JSON.stringify({
          electionId,
          packages: [{
            contentId: "ipfs://bafy-demo-ok",
            path: "vote.json",
            expectedDigest: digestVotePackage(vote),
          }],
        }),
        "utf8",
      );

      const result = await runDataAvailabilityCheck(inputPath);

      assert.equal(result.exitCode, 0);
      assert.equal(result.output.allAvailable, true);
      assert.equal(result.output.checks[0]?.ok, true);
      assert.match(result.output.checks[0]?.digest ?? "", /^0x[0-9a-f]{64}$/);
    } finally {
      await rm(tempDir, { force: true, recursive: true });
    }
  });

  it("fails when a package is missing or digest does not match", async function () {
    const tempDir = await mkdtemp(join(tmpdir(), "svb-da-test-"));
    try {
      const vote = votePackage("bad-digest");
      await writeFile(join(tempDir, "vote.json"), serializeVotePackage(vote), "utf8");
      const inputPath = join(tempDir, "batch-input.json");
      await writeFile(
        inputPath,
        JSON.stringify({
          electionId,
          packages: [
            {
              contentId: "ipfs://bafy-demo-bad",
              path: "vote.json",
              expectedDigest: hash("wrong-digest"),
            },
            {
              contentId: "ipfs://bafy-demo-missing",
              path: "missing.json",
            },
          ],
        }),
        "utf8",
      );

      const result = await runDataAvailabilityCheck(inputPath);

      assert.equal(result.exitCode, 1);
      assert.equal(result.output.allAvailable, false);
      assert.equal(result.output.checks.every((check) => check.ok === false), true);
      assert.match(result.output.checks[0]?.error ?? "", /expectedDigest/);
      assert.match(result.output.checks[1]?.error ?? "", /no such file/i);
    } finally {
      await rm(tempDir, { force: true, recursive: true });
    }
  });

  it("fails for malformed package JSON and an invalid content identifier", async function () {
    const tempDir = await mkdtemp(join(tmpdir(), "svb-da-test-"));
    try {
      await writeFile(join(tempDir, "malformed.json"), "{not-json", "utf8");
      const inputPath = join(tempDir, "batch-input.json");
      await writeFile(
        inputPath,
        JSON.stringify({
          electionId,
          packages: [
            {
              contentId: "ipfs://bafy-malformed-json",
              path: "malformed.json",
            },
            {
              contentId: "https://gateway.example/not-an-ipfs-id",
              path: "malformed.json",
            },
          ],
        }),
        "utf8",
      );

      const result = await runDataAvailabilityCheck(inputPath);

      assert.equal(result.exitCode, 1);
      assert.equal(result.output.allAvailable, false);
      assert.match(result.output.checks[0]?.error ?? "", /JSON|position|property/i);
      assert.match(result.output.checks[1]?.error ?? "", /invalid IPFS content ID/i);
    } finally {
      await rm(tempDir, { force: true, recursive: true });
    }
  });

  it("rejects duplicate package references in one availability input", async function () {
    const tempDir = await mkdtemp(join(tmpdir(), "svb-da-test-"));
    try {
      const vote = votePackage("duplicate-reference");
      await writeFile(join(tempDir, "vote.json"), serializeVotePackage(vote), "utf8");
      const duplicateEntry = {
        contentId: "ipfs://bafy-duplicate-reference",
        path: "vote.json",
        expectedDigest: digestVotePackage(vote),
      };
      const inputPath = join(tempDir, "batch-input.json");
      await writeFile(
        inputPath,
        JSON.stringify({
          electionId,
          packages: [duplicateEntry, duplicateEntry],
        }),
        "utf8",
      );

      const result = await runDataAvailabilityCheck(inputPath);

      assert.equal(result.exitCode, 1);
      assert.equal(result.output.allAvailable, false);
    } finally {
      await rm(tempDir, { force: true, recursive: true });
    }
  });
});
