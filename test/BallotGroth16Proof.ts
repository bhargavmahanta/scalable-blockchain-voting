import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { keccak256, stringToHex, zeroAddress, type Hex } from "viem";

type BallotProofFixture = {
  proof: Hex;
  publicSignals: readonly string[];
  publicInputsHash: Hex;
};

const fixture = JSON.parse(
  await readFile(
    new URL("./fixtures/ballot-validity/ballot-proof-artifact.json", import.meta.url),
    "utf8",
  ),
) as BallotProofFixture;
const electionId = keccak256(stringToHex("scalable-voting-demo-2026"));
const candidateListHash = keccak256(
  stringToHex("candidate-a,candidate-b,candidate-c,candidate-d"),
);
const ballotNullifier =
  `0x${BigInt(fixture.publicSignals[2]!).toString(16).padStart(64, "0")}` as Hex;
const packageCommitment =
  `0x${BigInt(fixture.publicSignals[3]!).toString(16).padStart(64, "0")}` as Hex;

describe("real Groth16 ballot validity proof", async function () {
  const { viem } = await network.create();
  const [owner, voter, outsider] = await viem.getWalletClients();

  async function deployVoting() {
    const groth16Verifier = await viem.deployContract("BallotGroth16Verifier");
    const adapter = await viem.deployContract("BallotGroth16VerifierAdapter", [
      groth16Verifier.address,
    ]);
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      zeroAddress,
    ]);
    const voting = await viem.deployContract("VotingContract", [
      electionId,
      candidateListHash,
      registry.address,
      owner.account.address,
      adapter.address,
    ]);
    const identityNullifier = keccak256(stringToHex("groth16-proof-identity"));
    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );
    return { voting, identityNullifier };
  }

  it("verifies the generated proof and rejects changed bindings", async function () {
    const groth16Verifier = await viem.deployContract("BallotGroth16Verifier");
    const adapter = await viem.deployContract("BallotGroth16VerifierAdapter", [
      groth16Verifier.address,
    ]);

    assert.equal(
      await adapter.read.verify([
        fixture.proof,
        fixture.publicInputsHash,
        electionId,
        candidateListHash,
        ballotNullifier,
        packageCommitment,
      ]),
      true,
    );
    assert.equal(
      await adapter.read.verify([
        fixture.proof,
        fixture.publicInputsHash,
        electionId,
        keccak256(stringToHex("different-candidate-list")),
        ballotNullifier,
        packageCommitment,
      ]),
      false,
    );
    assert.equal(
      await adapter.read.verify([
        fixture.proof,
        fixture.publicInputsHash,
        electionId,
        candidateListHash,
        `0x${"01".padStart(64, "0")}`,
        packageCommitment,
      ]),
      false,
    );
    assert.equal(
      await adapter.read.verify([
        fixture.proof,
        fixture.publicInputsHash,
        electionId,
        candidateListHash,
        ballotNullifier,
        keccak256(stringToHex("different-package")),
      ]),
      false,
    );

    const changedProof =
      `0x${"0".repeat(64)}${fixture.proof.slice(66)}` as Hex;
    assert.equal(
      await adapter.read.verify([
        changedProof,
        fixture.publicInputsHash,
        electionId,
        candidateListHash,
        ballotNullifier,
        packageCommitment,
      ]),
      false,
    );
  });

  it("accepts the real proof through VotingContract", async function () {
    const groth16Verifier = await viem.deployContract("BallotGroth16Verifier");
    const adapter = await viem.deployContract("BallotGroth16VerifierAdapter", [
      groth16Verifier.address,
    ]);
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      zeroAddress,
    ]);
    const voting = await viem.deployContract("VotingContract", [
      electionId,
      candidateListHash,
      registry.address,
      owner.account.address,
      adapter.address,
    ]);
    const identityNullifier = keccak256(stringToHex("groth16-proof-identity"));

    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );
    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          `0x${"ff".repeat(32)}`,
          packageCommitment,
          fixture.publicInputsHash,
          fixture.proof,
        ],
        { account: voter.account },
      ),
    );
    await voting.write.submitBallotWithProof(
      [
        identityNullifier,
        ballotNullifier,
        packageCommitment,
        fixture.publicInputsHash,
        fixture.proof,
      ],
      { account: voter.account },
    );

    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), true);
    assert.equal(
      await voting.read.ballotPublicInputsHashOf([ballotNullifier]),
      fixture.publicInputsHash,
    );
  });

  it("rejects an empty proof without consuming the ballot nullifier", async function () {
    const { voting, identityNullifier } = await deployVoting();

    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          ballotNullifier,
          packageCommitment,
          fixture.publicInputsHash,
          "0x",
        ],
        { account: voter.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), false);
  });

  it("rejects random proof bytes without consuming the ballot nullifier", async function () {
    const { voting, identityNullifier } = await deployVoting();

    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          ballotNullifier,
          packageCommitment,
          fixture.publicInputsHash,
          "0x1234",
        ],
        { account: voter.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), false);
  });

  it("rejects a valid proof when the public-input hash is modified", async function () {
    const { voting, identityNullifier } = await deployVoting();

    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          ballotNullifier,
          packageCommitment,
          keccak256(stringToHex("modified-ballot-public-inputs")),
          fixture.proof,
        ],
        { account: voter.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), false);
  });

  it("rejects a valid proof reused with a different package", async function () {
    const { voting, identityNullifier } = await deployVoting();

    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          ballotNullifier,
          keccak256(stringToHex("different-proof-package")),
          fixture.publicInputsHash,
          fixture.proof,
        ],
        { account: voter.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), false);
  });

  it("rejects a valid proof reused with a different nullifier", async function () {
    const { voting, identityNullifier } = await deployVoting();
    const changedNullifier =
      `0x${(BigInt(ballotNullifier) + 1n).toString(16).padStart(64, "0")}` as Hex;

    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          changedNullifier,
          packageCommitment,
          fixture.publicInputsHash,
          fixture.proof,
        ],
        { account: voter.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([changedNullifier]), false);
  });

  it("rejects a valid proof submitted by a different voting key", async function () {
    const { voting, identityNullifier } = await deployVoting();

    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          ballotNullifier,
          packageCommitment,
          fixture.publicInputsHash,
          fixture.proof,
        ],
        { account: outsider.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), false);
  });
});
