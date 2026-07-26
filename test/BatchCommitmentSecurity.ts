import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import {
  keccak256,
  stringToHex,
  zeroAddress,
  zeroHash,
  type Address,
} from "viem";

const hash = (value: string) => keccak256(stringToHex(value));
const electionId = hash("batch-security-election");

describe("batch commitment rejection behavior", async function () {
  const { viem } = await network.create();
  const [owner, batcher, outsider] = await viem.getWalletClients();

  async function deploy(verifier: Address = zeroAddress) {
    return viem.deployContract("BatchCommitment", [
      electionId,
      owner.account.address,
      batcher.account.address,
      verifier,
    ]);
  }

  it("rejects an unauthorized batcher without changing batch state", async function () {
    const commitment = await deploy();

    await assert.rejects(commitment.write.submitBatch([
      hash("unauthorized-cid-root"),
      zeroHash,
      hash("unauthorized-nullifier-root"),
      hash("unauthorized-manifest"),
      1n,
    ], { account: outsider.account }));
    assert.equal(await commitment.read.batchCount(), 0n);
    assert.equal(await commitment.read.latestNullifierRoot(), zeroHash);
  });

  it("rejects submitting the same batch root twice without advancing state", async function () {
    const commitment = await deploy();
    const cidRoot = hash("duplicate-cid-root");
    const nullifierRoot = hash("duplicate-nullifier-root");
    await commitment.write.submitBatch([
      cidRoot,
      zeroHash,
      nullifierRoot,
      hash("duplicate-manifest"),
      2n,
    ], { account: batcher.account });

    await assert.rejects(commitment.write.submitBatch([
      cidRoot,
      nullifierRoot,
      hash("duplicate-nullifier-root-2"),
      hash("duplicate-manifest-2"),
      2n,
    ], { account: batcher.account }));
    assert.equal(await commitment.read.batchCount(), 1n);
    assert.equal(await commitment.read.latestNullifierRoot(), nullifierRoot);
  });

  it("rejects an incorrect previous nullifier root without advancing state", async function () {
    const commitment = await deploy();

    await assert.rejects(commitment.write.submitBatch([
      hash("continuity-cid-root"),
      hash("incorrect-previous-root"),
      hash("continuity-nullifier-root"),
      hash("continuity-manifest"),
      1n,
    ], { account: batcher.account }));
    assert.equal(await commitment.read.batchCount(), 0n);
    assert.equal(await commitment.read.latestNullifierRoot(), zeroHash);
  });

  for (const [scenario, values] of [
    ["zero CID root", [zeroHash, hash("n-1"), hash("m-1"), 1n]],
    ["zero nullifier root", [hash("c-2"), zeroHash, hash("m-2"), 1n]],
    ["zero manifest digest", [hash("c-3"), hash("n-3"), zeroHash, 1n]],
    ["zero batch size", [hash("c-4"), hash("n-4"), hash("m-4"), 0n]],
  ] as const) {
    it(`rejects a batch with ${scenario} without changing state`, async function () {
      const commitment = await deploy();

      await assert.rejects(commitment.write.submitBatch([
        values[0],
        zeroHash,
        values[1],
        values[2],
        values[3],
      ], { account: batcher.account }));
      assert.equal(await commitment.read.batchCount(), 0n);
      assert.equal(await commitment.read.latestNullifierRoot(), zeroHash);
    });
  }

  it("rejects a proof-gated batch when the verifier returns false", async function () {
    const verifier = await viem.deployContract("MockBatchProofVerifier");
    const commitment = await deploy(verifier.address);

    await assert.rejects(commitment.write.submitBatchWithProof([
      hash("rejected-proof-cid-root"),
      zeroHash,
      hash("rejected-proof-nullifier-root"),
      hash("rejected-proof-manifest"),
      hash("rejected-proof-public-inputs"),
      1n,
      "0x1234",
    ], { account: outsider.account }));
    assert.equal(await commitment.read.batchCount(), 0n);
    assert.equal(await commitment.read.latestNullifierRoot(), zeroHash);
  });

  it("rejects a proof-gated batch when no verifier is configured", async function () {
    const commitment = await deploy();

    await assert.rejects(commitment.write.submitBatchWithProof([
      hash("unconfigured-cid-root"),
      zeroHash,
      hash("unconfigured-nullifier-root"),
      hash("unconfigured-manifest"),
      hash("unconfigured-public-inputs"),
      1n,
      "0x1234",
    ], { account: outsider.account }));
    assert.equal(await commitment.read.batchCount(), 0n);
    assert.equal(await commitment.read.latestNullifierRoot(), zeroHash);
  });
});
