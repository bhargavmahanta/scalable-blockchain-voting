import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
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
  encryptBallotSelection,
  serializeVotePackage,
  type VotePackageV1,
} from "../packages/crypto/src/index.js";

const hash = (value: string) => keccak256(stringToHex(value));

function votePackage(): VotePackageV1 {
  const electionKey = createElectionKeyPair(
    "0x0000000000000000000000000000000000000000000000000000000000000001",
  );
  const electionId = hash("ipfs-test-election");
  const candidateListHash = hash("candidate-list");
  const ballotNullifier = hash("ipfs-test-ballot-nullifier");
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

describe("IPFS vote package upload script", function () {
  it(
    "uploads canonical vote package JSON to a configured IPFS HTTP API",
    async function () {
    const receivedChunks: Buffer[] = [];
    const server = createServer((request, response) => {
      assert.equal(request.method, "POST");
      assert.equal(request.url?.startsWith("/api/v0/add?"), true);

      request.on("data", (chunk: Buffer) => receivedChunks.push(chunk));
      request.on("end", () => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({
          Name: "vote-package.json",
          Hash: "bafybeigdyrztfakecidforlocaltestonly",
          Size: String(Buffer.concat(receivedChunks).byteLength),
        }));
      });
    });

    server.listen(0, "127.0.0.1");
    await once(server, "listening");

    const address = server.address() as AddressInfo;

    const tempDir = await mkdtemp(join(tmpdir(), "svb-ipfs-test-"));
    try {
      const inputPath = join(tempDir, "vote-package.json");
      const serializedPackage = serializeVotePackage(votePackage());
      await writeFile(inputPath, serializedPackage, "utf8");

      const child = spawn(
        process.execPath,
        ["--import", "tsx", "scripts/upload_vote_package.ts", inputPath],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            IPFS_API_URL: `http://127.0.0.1:${address.port}`,
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );

      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      child.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
      child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk));

      const [exitCode] = await once(child, "close") as [number];
      assert.equal(Buffer.concat(stderrChunks).toString(), "");
      assert.equal(exitCode, 0);

      const result = JSON.parse(Buffer.concat(stdoutChunks).toString()) as {
        contentId: string;
        cid: string;
        votePackageDigest: string;
      };

      assert.equal(result.contentId, "ipfs://bafybeigdyrztfakecidforlocaltestonly");
      assert.equal(result.cid, "bafybeigdyrztfakecidforlocaltestonly");
      assert.match(result.votePackageDigest, /^0x[0-9a-f]{64}$/);
      assert.match(Buffer.concat(receivedChunks).toString(), /"version":1/);
    } finally {
      server.close();
      await rm(tempDir, { force: true, recursive: true });
    }
  });
});
