import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import {
  encodeAbiParameters,
  keccak256,
  parseAbiParameters,
  stringToHex,
  type Address,
  zeroAddress,
  zeroHash,
} from "viem";

import {
  bytes32ToSnarkField,
  computeRegistrationPublicInputsHash,
} from "../packages/crypto/src/index.js";

const electionId = keccak256(stringToHex("test-election"));
const candidateListHash = keccak256(stringToHex("test-candidate-list"));
const canonicalProofNullifier = (label: string) =>
  `0x${bytes32ToSnarkField(keccak256(stringToHex(label))).toString(16).padStart(64, "0")}` as const;

describe("Voting system foundation", async function () {
  const { viem } = await network.create();
  const [owner, voter, outsider] = await viem.getWalletClients();

  it("registers an ephemeral voting key and accepts one ballot nullifier", async function () {
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
      zeroAddress,
    ]);

    const identityNullifier = keccak256(stringToHex("identity-nullifier"));
    const ballotNullifier = keccak256(stringToHex("ballot-nullifier"));
    const packageDigest = keccak256(stringToHex("ipfs-package"));

    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );
    await voting.write.submitBallot(
      [identityNullifier, ballotNullifier, packageDigest],
      { account: voter.account },
    );

    assert.equal(
      await voting.read.isNullifierUsed([ballotNullifier]),
      true,
    );

    await assert.rejects(
      voting.write.submitBallot(
        [identityNullifier, ballotNullifier, packageDigest],
        { account: voter.account },
      ),
    );
    await assert.rejects(
      voting.write.submitBallot(
        [
          identityNullifier,
          keccak256(stringToHex("another-nullifier")),
          packageDigest,
        ],
        { account: outsider.account },
      ),
    );
  });

  it("rejects trusted registration by a non-owner and leaves the identity unregistered", async function () {
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      zeroAddress,
    ]);
    const identityNullifier = keccak256(stringToHex("unauthorized-registration"));

    await assert.rejects(
      registry.write.register(
        [identityNullifier, voter.account.address],
        { account: outsider.account },
      ),
    );
    await assert.rejects(registry.read.votingKeyOf([identityNullifier]));
    assert.equal(
      await registry.read.isVotingKeyRegistered([voter.account.address]),
      false,
    );
  });

  it("rejects duplicate identity-nullifier registration and preserves the original voting key", async function () {
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      zeroAddress,
    ]);
    const identityNullifier = keccak256(stringToHex("duplicate-identity"));
    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );

    await assert.rejects(
      registry.write.register(
        [identityNullifier, outsider.account.address],
        { account: owner.account },
      ),
    );
    assert.equal(
      ((await registry.read.votingKeyOf([identityNullifier])) as Address).toLowerCase(),
      voter.account.address.toLowerCase(),
    );
    assert.equal(
      await registry.read.isVotingKeyRegistered([outsider.account.address]),
      false,
    );
  });

  it("rejects the zero identity nullifier", async function () {
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      zeroAddress,
    ]);

    await assert.rejects(
      registry.write.register(
        [zeroHash, voter.account.address],
        { account: owner.account },
      ),
    );
    await assert.rejects(registry.read.votingKeyOf([zeroHash]));
  });

  it("rejects the zero voting address and leaves the identity unregistered", async function () {
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      zeroAddress,
    ]);
    const identityNullifier = keccak256(stringToHex("zero-voting-address"));

    await assert.rejects(
      registry.write.register(
        [identityNullifier, zeroAddress],
        { account: owner.account },
      ),
    );
    await assert.rejects(registry.read.votingKeyOf([identityNullifier]));
  });

  it("rejects reusing one voting key for another identity", async function () {
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      zeroAddress,
    ]);
    const firstIdentity = keccak256(stringToHex("first-key-owner"));
    const secondIdentity = keccak256(stringToHex("second-key-owner"));
    await registry.write.register(
      [firstIdentity, voter.account.address],
      { account: owner.account },
    );

    await assert.rejects(
      registry.write.register(
        [secondIdentity, voter.account.address],
        { account: owner.account },
      ),
    );
    await assert.rejects(registry.read.votingKeyOf([secondIdentity]));
    assert.equal(
      ((await registry.read.votingKeyOf([firstIdentity])) as Address).toLowerCase(),
      voter.account.address.toLowerCase(),
    );
  });

  it("rejects a direct ballot from an unregistered identity without consuming its nullifier", async function () {
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
      zeroAddress,
    ]);
    const ballotNullifier = keccak256(stringToHex("unregistered-ballot"));

    await assert.rejects(
      voting.write.submitBallot(
        [
          keccak256(stringToHex("unknown-identity")),
          ballotNullifier,
          keccak256(stringToHex("unregistered-package")),
        ],
        { account: voter.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), false);
  });

  it("rejects a wallet submitting for another voter without consuming the nullifier", async function () {
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
      zeroAddress,
    ]);
    const identityNullifier = keccak256(stringToHex("wallet-bound-identity"));
    const ballotNullifier = keccak256(stringToHex("wallet-bound-ballot"));
    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );

    await assert.rejects(
      voting.write.submitBallot(
        [
          identityNullifier,
          ballotNullifier,
          keccak256(stringToHex("wallet-bound-package")),
        ],
        { account: outsider.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), false);
  });

  it("rejects a duplicate ballot nullifier submitted by a different registered voter", async function () {
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
      zeroAddress,
    ]);
    const firstIdentity = keccak256(stringToHex("duplicate-ballot-first"));
    const secondIdentity = keccak256(stringToHex("duplicate-ballot-second"));
    const ballotNullifier = keccak256(stringToHex("shared-ballot-nullifier"));
    const packageDigest = keccak256(stringToHex("shared-nullifier-package"));
    await registry.write.register(
      [firstIdentity, voter.account.address],
      { account: owner.account },
    );
    await registry.write.register(
      [secondIdentity, outsider.account.address],
      { account: owner.account },
    );
    await voting.write.submitBallot(
      [firstIdentity, ballotNullifier, packageDigest],
      { account: voter.account },
    );

    await assert.rejects(
      voting.write.submitBallot(
        [secondIdentity, ballotNullifier, packageDigest],
        { account: outsider.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), true);
  });

  it("rejects a zero ballot nullifier without changing ballot state", async function () {
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
      zeroAddress,
    ]);
    const identityNullifier = keccak256(stringToHex("zero-ballot-nullifier-identity"));
    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );

    await assert.rejects(
      voting.write.submitBallot(
        [identityNullifier, zeroHash, keccak256(stringToHex("zero-nullifier-package"))],
        { account: voter.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([zeroHash]), false);
  });

  it("rejects a zero package digest without consuming the ballot nullifier", async function () {
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
      zeroAddress,
    ]);
    const identityNullifier = keccak256(stringToHex("zero-package-identity"));
    const ballotNullifier = keccak256(stringToHex("zero-package-ballot"));
    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );

    await assert.rejects(
      voting.write.submitBallot(
        [identityNullifier, ballotNullifier, zeroHash],
        { account: voter.account },
      ),
    );
    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), false);
  });

  it("accepts direct ballots through the ballot verifier seam", async function () {
    const verifier = await viem.deployContract("MockBallotProofVerifier");
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
      verifier.address,
    ]);

    const identityNullifier = keccak256(stringToHex("proof-ballot-identity"));
    const ballotNullifier = canonicalProofNullifier("proof-ballot-nullifier");
    const packageDigest = keccak256(stringToHex("proof-ballot-package"));
    const ballotPublicInputsHash = keccak256(stringToHex("proof-ballot-public-inputs"));

    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );
    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          ballotNullifier,
          packageDigest,
          ballotPublicInputsHash,
          "0x1234",
        ],
        { account: voter.account },
      ),
    );

    await verifier.write.setAccepted([ballotPublicInputsHash, true], {
      account: owner.account,
    });
    await voting.write.submitBallotWithProof(
      [
        identityNullifier,
        ballotNullifier,
        packageDigest,
        ballotPublicInputsHash,
        "0x1234",
      ],
      { account: voter.account },
    );

    assert.equal(await voting.read.isNullifierUsed([ballotNullifier]), true);
    assert.equal(
      await voting.read.ballotPublicInputsHashOf([ballotNullifier]),
      ballotPublicInputsHash,
    );
  });

  it("rejects proof ballots without a configured ballot verifier", async function () {
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
      zeroAddress,
    ]);

    const identityNullifier = keccak256(stringToHex("unverified-ballot-identity"));
    await registry.write.register(
      [identityNullifier, voter.account.address],
      { account: owner.account },
    );

    await assert.rejects(
      voting.write.submitBallotWithProof(
        [
          identityNullifier,
          canonicalProofNullifier("unverified-ballot-nullifier"),
          keccak256(stringToHex("unverified-ballot-package")),
          keccak256(stringToHex("unverified-ballot-public-inputs")),
          "0x1234",
        ],
        { account: voter.account },
      ),
    );
  });

  it("registers through an eligibility verifier seam", async function () {
    const verifier = await viem.deployContract("MockEligibilityVerifier");
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      verifier.address,
    ]);

    const identityNullifier = keccak256(
      stringToHex("proof-identity-nullifier"),
    );
    const publicInputsHash = await registry.read.registrationPublicInputsHash([
      identityNullifier,
      voter.account.address,
    ]);
    const offChainPublicInputsHash = computeRegistrationPublicInputsHash({
      electionId,
      identityNullifier,
      votingKey: voter.account.address,
    });

    assert.equal(publicInputsHash, offChainPublicInputsHash);

    await verifier.write.setAccepted([publicInputsHash, true], {
      account: owner.account,
    });
    await registry.write.registerWithProof(
      [identityNullifier, voter.account.address, "0x1234"],
      { account: outsider.account },
    );

    const registeredVotingKey = await registry.read.votingKeyOf([
      identityNullifier,
    ]) as string;
    assert.equal(registeredVotingKey.toLowerCase(), voter.account.address.toLowerCase());
  });

  it("binds an Anon Aadhaar proof to the election nullifier and voting key", async function () {
    const anonAadhaar = await viem.deployContract("MockAnonAadhaar");
    const adapter = await viem.deployContract("AnonAadhaarEligibilityVerifier", [
      anonAadhaar.address,
      electionId,
      3_600n,
    ]);
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      adapter.address,
    ]);
    const identityNullifier = `0x${123n.toString(16).padStart(64, "0")}` as const;
    const signal = await adapter.read.registrationSignal([
      identityNullifier,
      voter.account.address,
    ]) as bigint;
    const publicClient = await viem.getPublicClient();
    const block = await publicClient.getBlock();
    const nullifierSeed = bytes32ToSnarkField(electionId);
    const proof = encodeAbiParameters(
      parseAbiParameters(
        "uint256 nullifierSeed, uint256 nullifier, uint256 timestamp, uint256 signal, uint256[4] revealArray, uint256[8] groth16Proof",
      ),
      [
        nullifierSeed,
        123n,
        block.timestamp,
        signal,
        [0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
      ],
    );
    await anonAadhaar.write.setAccepted([true]);
    await registry.write.registerWithProof(
      [identityNullifier, voter.account.address, proof],
      { account: outsider.account },
    );
    assert.equal(
      (await registry.read.votingKeyOf([identityNullifier]) as Address).toLowerCase(),
      voter.account.address.toLowerCase(),
    );

    const changedIdentity = `0x${124n.toString(16).padStart(64, "0")}` as const;
    await assert.rejects(
      registry.write.registerWithProof(
        [changedIdentity, outsider.account.address, proof],
        { account: outsider.account },
      ),
    );
  });

  it("rejects proof registration without an accepted eligibility proof", async function () {
    const verifier = await viem.deployContract("MockEligibilityVerifier");
    const registry = await viem.deployContract("VoterRegistry", [
      electionId,
      owner.account.address,
      verifier.address,
    ]);

    await assert.rejects(
      registry.write.registerWithProof(
        [
          keccak256(stringToHex("unaccepted-identity")),
          voter.account.address,
          "0x1234",
        ],
        { account: outsider.account },
      ),
    );
  });

  it("enforces batcher authorization and nullifier-root continuity", async function () {
    const batcher = await viem.deployContract("BatchCommitment", [
      electionId,
      owner.account.address,
      owner.account.address,
      zeroAddress,
    ]);

    const firstRoot = keccak256(stringToHex("batch-root-1"));
    const firstNullifierRoot = keccak256(
      stringToHex("nullifier-root-1"),
    );
    const manifestDigest = keccak256(stringToHex("manifest-1"));

    await batcher.write.submitBatch(
      [firstRoot, zeroHash, firstNullifierRoot, manifestDigest, 10n],
      { account: owner.account },
    );

    assert.equal(await batcher.read.batchCount(), 1n);
    assert.equal(await batcher.read.latestNullifierRoot(), firstNullifierRoot);

    await assert.rejects(
      batcher.write.submitBatch(
        [
          keccak256(stringToHex("batch-root-2")),
          zeroHash,
          keccak256(stringToHex("nullifier-root-2")),
          keccak256(stringToHex("manifest-2")),
          5n,
        ],
        { account: owner.account },
      ),
    );
  });

  it("accepts proof-gated batches through the batch verifier seam", async function () {
    const verifier = await viem.deployContract("MockBatchProofVerifier");
    const batcher = await viem.deployContract("BatchCommitment", [
      electionId,
      owner.account.address,
      owner.account.address,
      verifier.address,
    ]);

    const cidMerkleRoot = keccak256(stringToHex("proof-batch-root"));
    const nullifierRoot = keccak256(stringToHex("proof-nullifier-root"));
    const manifestDigest = keccak256(stringToHex("proof-manifest"));
    const batchPublicInputsHash = keccak256(stringToHex("proof-batch-public-inputs"));

    await assert.rejects(
      batcher.write.submitBatchWithProof(
        [
          cidMerkleRoot,
          zeroHash,
          nullifierRoot,
          manifestDigest,
          batchPublicInputsHash,
          3n,
          "0x1234",
        ],
        { account: outsider.account },
      ),
    );

    await verifier.write.setAccepted([batchPublicInputsHash, true], {
      account: owner.account,
    });
    await batcher.write.submitBatchWithProof(
      [
        cidMerkleRoot,
        zeroHash,
        nullifierRoot,
        manifestDigest,
        batchPublicInputsHash,
        3n,
        "0x1234",
      ],
      { account: outsider.account },
    );

    const batch = await batcher.read.getBatch([0n]) as {
      cidMerkleRoot: string;
      batchPublicInputsHash: string;
      batcher: string;
    };
    assert.equal(batch.cidMerkleRoot, cidMerkleRoot);
    assert.equal(batch.batchPublicInputsHash, batchPublicInputsHash);
    assert.equal(batch.batcher.toLowerCase(), outsider.account.address.toLowerCase());
    assert.equal(await batcher.read.latestNullifierRoot(), nullifierRoot);
  });

  it("rejects proof-gated batches without a configured batch verifier", async function () {
    const batcher = await viem.deployContract("BatchCommitment", [
      electionId,
      owner.account.address,
      owner.account.address,
      zeroAddress,
    ]);

    await assert.rejects(
      batcher.write.submitBatchWithProof(
        [
          keccak256(stringToHex("unverified-batch-root")),
          zeroHash,
          keccak256(stringToHex("unverified-nullifier-root")),
          keccak256(stringToHex("unverified-manifest")),
          keccak256(stringToHex("unverified-public-inputs")),
          1n,
          "0x1234",
        ],
        { account: outsider.account },
      ),
    );
  });

  it("cannot publish a tally without a configured proof verifier", async function () {
    const tally = await viem.deployContract("TallyVerifier", [
      electionId,
      owner.account.address,
      "0x0000000000000000000000000000000000000000",
    ]);

    await assert.rejects(
      tally.write.publishTally(
        [
          keccak256(stringToHex("result")),
          keccak256(stringToHex("public-inputs")),
          "0x1234",
        ],
        { account: owner.account },
      ),
    );
    assert.equal(await tally.read.resultPublished(), false);
  });

  it("publishes a tally only after the configured verifier accepts the public inputs", async function () {
    const verifier = await viem.deployContract("MockTallyProofVerifier");
    const tally = await viem.deployContract("TallyVerifier", [
      electionId,
      owner.account.address,
      verifier.address,
    ]);
    const resultHash = keccak256(stringToHex("encrypted-aggregate-and-decrypted-result"));
    const publicInputsHash = keccak256(stringToHex("tally-public-inputs"));

    await assert.rejects(
      tally.write.publishTally(
        [resultHash, publicInputsHash, "0x1234"],
        { account: owner.account },
      ),
    );

    await verifier.write.setAccepted([publicInputsHash, true], {
      account: owner.account,
    });
    await assert.rejects(
      tally.write.publishTally(
        [resultHash, publicInputsHash, "0x1234"],
        { account: outsider.account },
      ),
    );
    await tally.write.publishTally(
      [resultHash, publicInputsHash, "0x1234"],
      { account: owner.account },
    );

    assert.equal(await tally.read.resultPublished(), true);
    assert.equal(await tally.read.resultHash(), resultHash);
    assert.equal(await tally.read.publicInputsHash(), publicInputsHash);
  });
});
