import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import {
  keccak256,
  stringToHex,
  zeroAddress,
  zeroHash,
  type Address,
  type Hex,
} from "viem";

import { hashMerklePair } from "../packages/crypto/src/index.js";

const hash = (value: string) => keccak256(stringToHex(value));
const electionId = hash("receipt-election");
const receiptTypes = {
  IntakeReceipt: [
    { name: "electionId", type: "bytes32" },
    { name: "eligibilityRoot", type: "bytes32" },
    { name: "packageDigest", type: "bytes32" },
    { name: "packageLeafHash", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "includeBy", type: "uint64" },
  ],
} as const;

describe("batcher intake receipts and omission accountability", async function () {
  const { viem, networkHelpers } = await network.create();
  const [owner, batcher, voter, outsider] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();

  async function deploy() {
    const batchCommitment = await viem.deployContract("BatchCommitment", [
      electionId,
      owner.account.address,
      batcher.account.address,
      zeroAddress,
    ]);
    const registry = await viem.deployContract("BatcherReceiptRegistry", [
      electionId,
      owner.account.address,
      batchCommitment.address,
      batcher.account.address,
    ]);
    return { batchCommitment, registry };
  }

  async function signReceipt(
    verifyingContract: Address,
    receipt: {
      electionId: Hex;
      eligibilityRoot: Hex;
      packageDigest: Hex;
      packageLeafHash: Hex;
      issuedAt: bigint;
      includeBy: bigint;
    },
  ) {
    return batcher.signTypedData({
      account: batcher.account,
      domain: {
        name: "ScalableVotingBatcherReceipt",
        version: "1",
        chainId: await publicClient.getChainId(),
        verifyingContract,
      },
      types: receiptTypes,
      primaryType: "IntakeReceipt",
      message: receipt,
    });
  }

  it("opens a signed deadline claim and resolves it with committed inclusion", async function () {
    const { batchCommitment, registry } = await deploy();
    const now = await networkHelpers.time.latest();
    const packageLeafHash = hash("eligible-package-leaf");
    const receipt = {
      electionId,
      eligibilityRoot: hash("active-eligibility-root"),
      packageDigest: hash("eligible-package-digest"),
      packageLeafHash,
      issuedAt: BigInt(now),
      includeBy: BigInt(now + 60),
    };
    const signature = await batcher.signTypedData({
      account: batcher.account,
      domain: {
        name: "ScalableVotingBatcherReceipt",
        version: "1",
        chainId: await publicClient.getChainId(),
        verifyingContract: registry.address,
      },
      types: receiptTypes,
      primaryType: "IntakeReceipt",
      message: receipt,
    });
    assert.equal(
      (await registry.read.verifyReceipt([receipt, signature]) as string).toLowerCase(),
      batcher.account.address.toLowerCase(),
    );
    await assert.rejects(registry.write.openOmissionClaim(
      [receipt, signature], { account: voter.account },
    ));

    await networkHelpers.time.increaseTo(receipt.includeBy + 1n);
    await registry.write.openOmissionClaim(
      [receipt, signature], { account: voter.account },
    );
    const receiptDigest = await registry.read.receiptDigest([receipt]);
    const openedClaim = await registry.read.claims([receiptDigest]) as readonly [
      number, string, string, Hex, Hex, Hex, Hex, bigint, bigint,
    ];
    assert.equal(openedClaim[0], 1);
    assert.equal(openedClaim[2].toLowerCase(), voter.account.address.toLowerCase());

    const sibling = hash("second-package-leaf");
    const committedRoot = hashMerklePair(packageLeafHash, sibling);
    await batchCommitment.write.submitBatch([
      committedRoot,
      zeroHash,
      hash("receipt-nullifier-root"),
      hash("receipt-manifest"),
      2n,
    ], { account: batcher.account });
    await assert.rejects(registry.write.resolveWithInclusion([
      receiptDigest,
      committedRoot,
      [hash("wrong-sibling")],
      [false],
    ], { account: outsider.account }));
    const anotherCommittedRoot = hash("another-committed-batch-root");
    await batchCommitment.write.submitBatch([
      anotherCommittedRoot,
      hash("receipt-nullifier-root"),
      hash("receipt-nullifier-root-2"),
      hash("receipt-manifest-2"),
      1n,
    ], { account: batcher.account });
    await assert.rejects(registry.write.resolveWithInclusion([
      receiptDigest,
      anotherCommittedRoot,
      [sibling],
      [false],
    ], { account: outsider.account }));
    await registry.write.resolveWithInclusion([
      receiptDigest,
      committedRoot,
      [sibling],
      [false],
    ], { account: outsider.account });
    const resolvedClaim = await registry.read.claims([receiptDigest]) as readonly [
      number, string, string, Hex, Hex, Hex, Hex, bigint, bigint,
    ];
    assert.equal(resolvedClaim[0], 2);
    assert.equal(resolvedClaim[6], committedRoot);
    await assert.rejects(registry.write.resolveWithInclusion([
      receiptDigest,
      committedRoot,
      [sibling],
      [false],
    ], { account: outsider.account }));
  });

  it("rejects receipts not signed by an authorized batcher", async function () {
    const { registry } = await deploy();
    const now = await networkHelpers.time.latest();
    const receipt = {
      electionId,
      eligibilityRoot: hash("eligibility-root"),
      packageDigest: hash("package-digest"),
      packageLeafHash: hash("package-leaf"),
      issuedAt: BigInt(now),
      includeBy: BigInt(now + 60),
    };
    const signature = await outsider.signTypedData({
      account: outsider.account,
      domain: {
        name: "ScalableVotingBatcherReceipt",
        version: "1",
        chainId: await publicClient.getChainId(),
        verifyingContract: registry.address,
      },
      types: receiptTypes,
      primaryType: "IntakeReceipt",
      message: receipt,
    });
    await assert.rejects(registry.read.verifyReceipt([receipt, signature]));
  });

  it("rejects an altered package digest after receipt signing", async function () {
    const { registry } = await deploy();
    const now = await networkHelpers.time.latest();
    const receipt = {
      electionId,
      eligibilityRoot: hash("altered-digest-root"),
      packageDigest: hash("original-package-digest"),
      packageLeafHash: hash("altered-digest-leaf"),
      issuedAt: BigInt(now),
      includeBy: BigInt(now + 60),
    };
    const signature = await signReceipt(registry.address, receipt);
    const alteredReceipt = {
      ...receipt,
      packageDigest: hash("altered-package-digest"),
    };

    await assert.rejects(
      registry.read.verifyReceipt([alteredReceipt, signature]),
    );
  });

  it("rejects an altered package leaf after receipt signing", async function () {
    const { registry } = await deploy();
    const now = await networkHelpers.time.latest();
    const receipt = {
      electionId,
      eligibilityRoot: hash("altered-leaf-root"),
      packageDigest: hash("altered-leaf-digest"),
      packageLeafHash: hash("original-package-leaf"),
      issuedAt: BigInt(now),
      includeBy: BigInt(now + 60),
    };
    const signature = await signReceipt(registry.address, receipt);
    const alteredReceipt = {
      ...receipt,
      packageLeafHash: hash("altered-package-leaf"),
    };

    await assert.rejects(
      registry.read.verifyReceipt([alteredReceipt, signature]),
    );
  });

  it("rejects a receipt for another election", async function () {
    const { registry } = await deploy();
    const now = await networkHelpers.time.latest();
    const receipt = {
      electionId: hash("another-election"),
      eligibilityRoot: hash("wrong-election-root"),
      packageDigest: hash("wrong-election-digest"),
      packageLeafHash: hash("wrong-election-leaf"),
      issuedAt: BigInt(now),
      includeBy: BigInt(now + 60),
    };
    const signature = await signReceipt(registry.address, receipt);

    await assert.rejects(registry.read.verifyReceipt([receipt, signature]));
  });

  it("cryptographically binds the eligibility root but trusts the authorized signer to choose it", async function () {
    const { registry } = await deploy();
    const now = await networkHelpers.time.latest();
    const receipt = {
      electionId,
      eligibilityRoot: hash("signer-asserted-eligibility-root"),
      packageDigest: hash("root-bound-digest"),
      packageLeafHash: hash("root-bound-leaf"),
      issuedAt: BigInt(now),
      includeBy: BigInt(now + 60),
    };
    const signature = await signReceipt(registry.address, receipt);
    assert.equal(
      ((await registry.read.verifyReceipt([receipt, signature])) as Address).toLowerCase(),
      batcher.account.address.toLowerCase(),
    );

    const alteredReceipt = {
      ...receipt,
      eligibilityRoot: hash("different-eligibility-root"),
    };
    await assert.rejects(
      registry.read.verifyReceipt([alteredReceipt, signature]),
    );
  });
});
