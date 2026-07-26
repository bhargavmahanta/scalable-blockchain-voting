import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { keccak256, stringToHex, type Hex, zeroAddress } from "viem";

type EligibleProofArtifact = {
  proof: Hex;
  publicSignals: readonly string[];
  publicInputsHash: Hex;
};

const artifact = JSON.parse(await readFile(
  path.resolve("test/fixtures/eligible-ballot/eligible-ballot-proof-artifact.json"),
  "utf8",
)) as EligibleProofArtifact;
const signalBytes32 = (index: number) =>
  `0x${BigInt(artifact.publicSignals[index]!).toString(16).padStart(64, "0")}` as Hex;

describe("real unified eligibility and ballot proof", async function () {
  const { viem } = await network.create();
  const [owner, relayer] = await viem.getWalletClients();

  async function deploy() {
    const generated = await viem.deployContract("EligibleBallotGroth16Verifier");
    const adapter = await viem.deployContract("EligibleBallotGroth16VerifierAdapter", [generated.address]);
    const electionId = signalBytes32(0);
    const candidateListHash = signalBytes32(1);
    const eligibilityRoot = signalBytes32(2);
    const roots = await viem.deployContract("EligibilityRootRegistry", [
      electionId, eligibilityRoot, owner.account.address,
    ]);
    await roots.write.freezeRoot();
    const voting = await viem.deployContract("EligibleVotingContract", [
      electionId,
      candidateListHash,
      roots.address,
      adapter.address,
      owner.account.address,
    ]);
    return { adapter, voting, electionId, candidateListHash, eligibilityRoot };
  }

  it("verifies membership, nullifier derivation and encrypted ballot as one proof", async function () {
    const { adapter, electionId, candidateListHash, eligibilityRoot } = await deploy();
    assert.equal(await adapter.read.verify([
      artifact.proof,
      artifact.publicInputsHash,
      electionId,
      candidateListHash,
      eligibilityRoot,
      signalBytes32(3),
      signalBytes32(4),
    ]), true);
    assert.equal(await adapter.read.verify([
      artifact.proof,
      artifact.publicInputsHash,
      electionId,
      candidateListHash,
      `0x${(BigInt(eligibilityRoot) + 1n).toString(16).padStart(64, "0")}`,
      signalBytes32(3),
      signalBytes32(4),
    ]), false);
  });

  it("rejects a valid proof when the election ID is modified", async function () {
    const { adapter, candidateListHash, eligibilityRoot } = await deploy();

    assert.equal(await adapter.read.verify([
      artifact.proof,
      artifact.publicInputsHash,
      keccak256(stringToHex("another-election")),
      candidateListHash,
      eligibilityRoot,
      signalBytes32(3),
      signalBytes32(4),
    ]), false);
  });

  it("rejects a valid proof when the eligibility root is modified", async function () {
    const { adapter, electionId, candidateListHash, eligibilityRoot } = await deploy();
    const changedRoot =
      `0x${(BigInt(eligibilityRoot) + 1n).toString(16).padStart(64, "0")}` as Hex;

    assert.equal(await adapter.read.verify([
      artifact.proof,
      artifact.publicInputsHash,
      electionId,
      candidateListHash,
      changedRoot,
      signalBytes32(3),
      signalBytes32(4),
    ]), false);
  });

  it("rejects a valid proof when the ballot nullifier is modified", async function () {
    const { adapter, electionId, candidateListHash, eligibilityRoot } = await deploy();
    const changedNullifier =
      `0x${(BigInt(signalBytes32(3)) + 1n).toString(16).padStart(64, "0")}` as Hex;

    assert.equal(await adapter.read.verify([
      artifact.proof,
      artifact.publicInputsHash,
      electionId,
      candidateListHash,
      eligibilityRoot,
      changedNullifier,
      signalBytes32(4),
    ]), false);
  });

  it("rejects a valid proof when the package commitment is modified", async function () {
    const { adapter, electionId, candidateListHash, eligibilityRoot } = await deploy();
    const changedPackage =
      `0x${(BigInt(signalBytes32(4)) + 1n).toString(16).padStart(64, "0")}` as Hex;

    assert.equal(await adapter.read.verify([
      artifact.proof,
      artifact.publicInputsHash,
      electionId,
      candidateListHash,
      eligibilityRoot,
      signalBytes32(3),
      changedPackage,
    ]), false);
  });

  it("rejects a valid proof when the public-input hash is modified", async function () {
    const { adapter, electionId, candidateListHash, eligibilityRoot } = await deploy();

    assert.equal(await adapter.read.verify([
      artifact.proof,
      keccak256(stringToHex("changed-eligible-public-inputs")),
      electionId,
      candidateListHash,
      eligibilityRoot,
      signalBytes32(3),
      signalBytes32(4),
    ]), false);
  });

  it("rejects modified proof bytes", async function () {
    const { adapter, electionId, candidateListHash, eligibilityRoot } = await deploy();
    const changedProof =
      `0x${"00".repeat(32)}${artifact.proof.slice(66)}` as Hex;

    assert.equal(await adapter.read.verify([
      changedProof,
      artifact.publicInputsHash,
      electionId,
      candidateListHash,
      eligibilityRoot,
      signalBytes32(3),
      signalBytes32(4),
    ]), false);
  });

  it("rejects empty proof bytes without consuming the nullifier", async function () {
    const { voting, eligibilityRoot } = await deploy();
    const nullifier = signalBytes32(3);

    await assert.rejects(voting.write.submitEligibleBallot([
      eligibilityRoot,
      nullifier,
      signalBytes32(4),
      artifact.publicInputsHash,
      "0x",
    ], { account: relayer.account }));
    assert.equal(await voting.read.isNullifierUsed([nullifier]), false);
  });

  it("rejects random proof bytes without consuming the nullifier", async function () {
    const { voting, eligibilityRoot } = await deploy();
    const nullifier = signalBytes32(3);

    await assert.rejects(voting.write.submitEligibleBallot([
      eligibilityRoot,
      nullifier,
      signalBytes32(4),
      artifact.publicInputsHash,
      "0x1234",
    ], { account: relayer.account }));
    assert.equal(await voting.read.isNullifierUsed([nullifier]), false);
  });

  it("rejects proof submission when no verifier is configured", async function () {
    const { electionId, candidateListHash, eligibilityRoot } = await deploy();
    const roots = await viem.deployContract("EligibilityRootRegistry", [
      electionId, eligibilityRoot, owner.account.address,
    ]);
    await roots.write.freezeRoot();
    const voting = await viem.deployContract("EligibleVotingContract", [
      electionId,
      candidateListHash,
      roots.address,
      zeroAddress,
      owner.account.address,
    ]);
    const nullifier = signalBytes32(3);

    await assert.rejects(voting.write.submitEligibleBallot([
      eligibilityRoot,
      nullifier,
      signalBytes32(4),
      artifact.publicInputsHash,
      artifact.proof,
    ], { account: relayer.account }));
    assert.equal(await voting.read.isNullifierUsed([nullifier]), false);
  });

  it("rejects a valid proof reused with a different package", async function () {
    const { voting, eligibilityRoot } = await deploy();
    const nullifier = signalBytes32(3);
    const changedPackage =
      `0x${(BigInt(signalBytes32(4)) + 1n).toString(16).padStart(64, "0")}` as Hex;

    await assert.rejects(voting.write.submitEligibleBallot([
      eligibilityRoot,
      nullifier,
      changedPackage,
      artifact.publicInputsHash,
      artifact.proof,
    ], { account: relayer.account }));
    assert.equal(await voting.read.isNullifierUsed([nullifier]), false);
  });

  it("rejects a valid proof reused with a different nullifier", async function () {
    const { voting, eligibilityRoot } = await deploy();
    const changedNullifier =
      `0x${(BigInt(signalBytes32(3)) + 1n).toString(16).padStart(64, "0")}` as Hex;

    await assert.rejects(voting.write.submitEligibleBallot([
      eligibilityRoot,
      changedNullifier,
      signalBytes32(4),
      artifact.publicInputsHash,
      artifact.proof,
    ], { account: relayer.account }));
    assert.equal(await voting.read.isNullifierUsed([changedNullifier]), false);
  });

  it("allows an unrelated relayer to submit without registering the voter on-chain", async function () {
    const { voting, eligibilityRoot } = await deploy();
    await voting.write.submitEligibleBallot([
      eligibilityRoot,
      signalBytes32(3),
      signalBytes32(4),
      artifact.publicInputsHash,
      artifact.proof,
    ], { account: relayer.account });
    assert.equal(await voting.read.isNullifierUsed([signalBytes32(3)]), true);
    await assert.rejects(voting.write.submitEligibleBallot([
      eligibilityRoot,
      signalBytes32(3),
      signalBytes32(4),
      artifact.publicInputsHash,
      artifact.proof,
    ], { account: relayer.account }));
  });
});
