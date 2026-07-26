import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import {
  encodeAbiParameters,
  keccak256,
  parseAbiParameters,
  stringToHex,
  zeroHash,
  type Address,
  type Hex,
} from "viem";

const hash = (value: string) => keccak256(stringToHex(value));
const fieldRoot =
  "0x0000000000000000000000000000000000000000000000000000000000001234";
const batchVerifierType = hash("SVB_BATCH_VALIDITY_V4");
const fraudVerifierType = hash("SVB_BATCH_FRAUD_V4");
const tallyVerifierType = hash("SVB_TALLY_VALIDITY_V4");

type Proposal = {
  state: number;
  batcher: Address;
  packageRoot: Hex;
  previousNullifierRoot: Hex;
  nullifierRoot: Hex;
  manifestDigest: Hex;
  aggregateCiphertextDigest: Hex;
  availabilityCertificateHash: Hex;
  batchPublicInputsHash: Hex;
  ballotCount: bigint;
  proposedAt: bigint;
  challengeDeadline: bigint;
  batchVerifierVersion: number;
  fraudVerifierVersion: number;
  bond: bigint;
};

describe("V4 production proof-only settlement", async function () {
  const { viem, networkHelpers } = await network.create();
  const [timelock, verifierManager, batcher, challenger, outsider] =
    await viem.getWalletClients();

  async function deploy() {
    const registry = await viem.deployContract("VerifierRegistryV4", [
      timelock.account.address,
      verifierManager.account.address,
    ]);
    const batchVerifier = await viem.deployContract(
      "MockBatchValidityVerifierV4",
    );
    const fraudVerifier = await viem.deployContract(
      "MockFraudProofVerifierV4",
    );
    const tallyVerifier = await viem.deployContract(
      "MockTallyProofVerifierV4",
    );

    await registry.write.registerVerifier(
      [batchVerifierType, 1, batchVerifier.address],
      { account: verifierManager.account },
    );
    await registry.write.registerVerifier(
      [fraudVerifierType, 1, fraudVerifier.address],
      { account: verifierManager.account },
    );
    await registry.write.registerVerifier(
      [tallyVerifierType, 1, tallyVerifier.address],
      { account: verifierManager.account },
    );

    const now = BigInt(await networkHelpers.time.latest());
    const nationalElectionId = hash(`national-election-${now}`);
    const constituencyId = hash(`constituency-${now}`);
    const votingEndsAt = now + 1_000n;
    const settlementEndsAt = now + 10_000n;
    const config = await viem.deployContract("ElectionConfigV4", [
      {
        nationalElectionId,
        constituencyId,
        eligibilityRoot: fieldRoot,
        eligibilityRootVersion: 7n,
        candidateProfile: 4,
        candidateListHash: hash("four-candidates"),
        trusteeKeysetHash: hash("five-of-nine-keyset"),
        dkgTranscriptHash: hash("dkg-transcript"),
        eligibilityVerifierVersion: 1,
        batchVerifierVersion: 1,
        tallyVerifierVersion: 1,
        votingStartsAt: now - 10n,
        votingEndsAt,
        settlementEndsAt,
      },
      registry.address,
    ]);
    const token = await viem.deployContract("MockBondTokenV4");
    const batcherBond = 1_000n;
    const challengerBond = 100n;
    const batches = await viem.deployContract("BatchCommitmentV4", [
      config.address,
      token.address,
      batcherBond,
      challengerBond,
      100n,
      1,
    ]);
    const tally = await viem.deployContract("TallyVerifierV4", [
      config.address,
      batches.address,
    ]);

    for (const wallet of [batcher, challenger]) {
      await token.write.mint([wallet.account.address, 20_000n]);
      await token.write.approve([batches.address, 20_000n], {
        account: wallet.account,
      });
    }

    return {
      registry,
      batchVerifier,
      fraudVerifier,
      tallyVerifier,
      config,
      token,
      batches,
      tally,
      nationalElectionId,
      constituencyId,
      votingEndsAt,
      batcherBond,
      challengerBond,
    };
  }

  function input(label: string, ballotCount = 8n) {
    return {
      packageRoot: hash(`${label}-packages`),
      previousNullifierRoot: zeroHash,
      nullifierRoot: hash(`${label}-nullifiers`),
      manifestDigest: hash(`${label}-manifest`),
      aggregateCiphertextDigest: hash(`${label}-aggregate`),
      availabilityCertificateHash: hash(`${label}-availability`),
      ballotCount,
    };
  }

  function proposalId(
    nationalElectionId: Hex,
    constituencyId: Hex,
    batcherAddress: Address,
    manifestDigest: Hex,
  ) {
    return keccak256(
      encodeAbiParameters(
        parseAbiParameters(
          "bytes32 nationalElectionId, bytes32 constituencyId, address batcher, uint256 nonce, bytes32 manifestDigest",
        ),
        [
          nationalElectionId,
          constituencyId,
          batcherAddress,
          0n,
          manifestDigest,
        ],
      ),
    );
  }

  it("keeps verifier versions append-only and rejects EOAs", async function () {
    const { registry, batchVerifier } = await deploy();
    await assert.rejects(
      registry.write.registerVerifier(
        [batchVerifierType, 2, outsider.account.address],
        { account: verifierManager.account },
      ),
    );
    await assert.rejects(
      registry.write.registerVerifier(
        [batchVerifierType, 1, batchVerifier.address],
        { account: verifierManager.account },
      ),
    );
    await registry.write.freezeVerifierType([batchVerifierType], {
      account: timelock.account,
    });
    await assert.rejects(
      registry.write.registerVerifier(
        [batchVerifierType, 2, batchVerifier.address],
        { account: verifierManager.account },
      ),
    );
  });

  it("slashes a fraudulent batch and rewards the challenger", async function () {
    const {
      fraudVerifier,
      token,
      batches,
      nationalElectionId,
      constituencyId,
      batcherBond,
    } = await deploy();
    const batch = input("fraud");
    const id = proposalId(
      nationalElectionId,
      constituencyId,
      batcher.account.address,
      batch.manifestDigest,
    );
    await batches.write.proposeBatch([batch], { account: batcher.account });
    const proposed = (await batches.read.getProposal([id])) as Proposal;
    assert.equal(proposed.state, 1);
    assert.equal(await token.read.balanceOf([batches.address]), batcherBond);

    const challengeType = hash("DUPLICATE_NULLIFIER");
    await fraudVerifier.write.setAccepted(
      [challengeType, proposed.batchPublicInputsHash, true],
      { account: outsider.account },
    );
    const challengerBefore = (await token.read.balanceOf([
      challenger.account.address,
    ])) as bigint;
    await batches.write.challengeBatch(
      [id, challengeType, "0x1234"],
      { account: challenger.account },
    );

    const reverted = (await batches.read.getProposal([id])) as Proposal;
    assert.equal(reverted.state, 4);
    assert.equal(
      await token.read.balanceOf([challenger.account.address]),
      challengerBefore + batcherBond,
    );
    assert.equal(await batches.read.acceptedBallotCount(), 0n);
  });

  it("penalizes an unsuccessful challenger without blocking finalization", async function () {
    const {
      token,
      batches,
      nationalElectionId,
      constituencyId,
      challengerBond,
    } = await deploy();
    const batch = input("honest-challenge");
    const id = proposalId(
      nationalElectionId,
      constituencyId,
      batcher.account.address,
      batch.manifestDigest,
    );
    await batches.write.proposeBatch([batch], { account: batcher.account });
    const batcherBefore = (await token.read.balanceOf([
      batcher.account.address,
    ])) as bigint;
    await batches.write.challengeBatch(
      [id, hash("BAD_AGGREGATION"), "0x1234"],
      { account: challenger.account },
    );
    assert.equal(
      await token.read.balanceOf([batcher.account.address]),
      batcherBefore + challengerBond,
    );
    assert.equal(
      ((await batches.read.getProposal([id])) as Proposal).state,
      1,
    );
  });

  it("finalizes a valid recursive proof and returns the batcher bond", async function () {
    const {
      batchVerifier,
      token,
      batches,
      nationalElectionId,
      constituencyId,
    } = await deploy();
    const batch = input("proved", 32n);
    const id = proposalId(
      nationalElectionId,
      constituencyId,
      batcher.account.address,
      batch.manifestDigest,
    );
    const balanceBefore = (await token.read.balanceOf([
      batcher.account.address,
    ])) as bigint;
    await batches.write.proposeBatch([batch], { account: batcher.account });
    const proposal = (await batches.read.getProposal([id])) as Proposal;
    await batchVerifier.write.setAccepted([
      proposal.batchPublicInputsHash,
      true,
    ]);
    await batches.write.finalizeWithProof([id, "0x1234"], {
      account: outsider.account,
    });

    assert.equal(
      ((await batches.read.getProposal([id])) as Proposal).state,
      3,
    );
    assert.equal(await batches.read.acceptedBallotCount(), 32n);
    assert.equal(
      await token.read.balanceOf([batcher.account.address]),
      balanceBefore,
    );
  });

  it("publishes one permissionless tally only when counts and proof agree", async function () {
    const {
      batchVerifier,
      tallyVerifier,
      batches,
      tally,
      nationalElectionId,
      constituencyId,
      votingEndsAt,
    } = await deploy();
    const batch = input("tally", 8n);
    const id = proposalId(
      nationalElectionId,
      constituencyId,
      batcher.account.address,
      batch.manifestDigest,
    );
    await batches.write.proposeBatch([batch], { account: batcher.account });
    const proposal = (await batches.read.getProposal([id])) as Proposal;
    await batchVerifier.write.setAccepted([
      proposal.batchPublicInputsHash,
      true,
    ]);
    await batches.write.finalizeWithProof([id, "0x1234"]);
    await networkHelpers.time.increaseTo(votingEndsAt + 1n);

    await assert.rejects(
      tally.write.publishTally(
        [hash("wrong-sum"), hash("wrong-artifact"), [3n, 2n, 1n, 1n], "0x12"],
        { account: outsider.account },
      ),
    );
    await tallyVerifier.write.setAccept([true]);
    await tally.write.publishTally(
      [hash("result"), hash("artifact"), [3n, 2n, 2n, 1n], "0x1234"],
      { account: outsider.account },
    );
    assert.equal(await tally.read.resultPublished(), true);
    assert.equal(
      ((await tally.read.publisher()) as Address).toLowerCase(),
      outsider.account.address.toLowerCase(),
    );
    await assert.rejects(
      tally.write.publishTally(
        [hash("second"), hash("second-artifact"), [3n, 2n, 2n, 1n], "0x1234"],
        { account: timelock.account },
      ),
    );
  });
});
