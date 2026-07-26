import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

describe("complete V3 dashboard artifact generation", function () {
  it("generates only public unified-proof and threshold evidence", async function () {
    const outputDirectory = await mkdtemp(path.join(tmpdir(), "svb-complete-v3-"));
    try {
      const child = spawn(process.execPath, [
        "--import", "tsx", "scripts/generate_complete_demo_v3.ts", outputDirectory,
      ], { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
      const stderr: Buffer[] = [];
      child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
      const timeout = setTimeout(() => child.kill("SIGTERM"), 180_000);
      const [exitCode] = await once(child, "close") as [number];
      clearTimeout(timeout);
      assert.equal(exitCode, 0, Buffer.concat(stderr).toString());

      const files = await readdir(outputDirectory);
      assert.equal(files.some((name) => /private-share|ceremony-config/.test(name)), false);
      for (const required of [
        "vote-1-package-v3.json",
        "vote-2-package-v3.json",
        "batch-artifact-v3.json",
        "encrypted-tally-v3.json",
        "threshold-public-keyset-v3.json",
        "tally-result-v3.json",
        "demo-summary.json",
      ]) assert.equal(files.includes(required), true, `${required} is missing`);

      const publicArtifacts = await Promise.all(files
        .filter((name) => name.endsWith(".json"))
        .map((name) => readFile(path.join(outputDirectory, name), "utf8")));
      const publicText = publicArtifacts.join("\n");
      assert.equal(publicText.includes('"privateShare"'), false);
      assert.equal(publicText.includes('"credentialSecret"'), false);
      assert.equal(publicText.includes('"credentialNonce"'), false);
      assert.equal(publicText.includes('"selection"'), false);
      assert.equal(publicText.includes('"randomness"'), false);

      const summary = JSON.parse(await readFile(
        path.join(outputDirectory, "demo-summary.json"), "utf8",
      )) as {
        version: number;
        ballotCount: number;
        tallyCounts: number[];
        verification: { eligibleProofsChecked: number };
      };
      assert.equal(summary.version, 3);
      assert.equal(summary.ballotCount, 2);
      assert.deepEqual(summary.tallyCounts, [0, 1, 1, 0]);
      assert.equal(summary.verification.eligibleProofsChecked, 2);
    } finally {
      await rm(outputDirectory, { recursive: true, force: true });
    }
  });
});
