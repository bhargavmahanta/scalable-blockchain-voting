import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { keccak256, stringToHex } from "viem";

const hash = (value: string) => keccak256(stringToHex(value));
const fieldRoot =
  "0x0000000000000000000000000000000000000000000000000000000000001234";

describe("V4 constituency sharding and national index", async function () {
  const { viem, networkHelpers } = await network.create();
  const [timelock, registrar, outsider] = await viem.getWalletClients();

  async function deployConfig(
    registryAddress: `0x${string}`,
    nationalElectionId: `0x${string}`,
    constituencyId: `0x${string}`,
  ) {
    const now = BigInt(await networkHelpers.time.latest());
    return viem.deployContract("ElectionConfigV4", [
      {
        nationalElectionId,
        constituencyId,
        eligibilityRoot: fieldRoot,
        eligibilityRootVersion: 1n,
        candidateProfile: 4,
        candidateListHash: hash(`candidates-${constituencyId}`),
        trusteeKeysetHash: hash(`keyset-${constituencyId}`),
        dkgTranscriptHash: hash(`dkg-${constituencyId}`),
        eligibilityVerifierVersion: 1,
        batchVerifierVersion: 1,
        tallyVerifierVersion: 1,
        votingStartsAt: now,
        votingEndsAt: now + 100n,
        settlementEndsAt: now + 1_000n,
      },
      registryAddress,
    ]);
  }

  async function deploy() {
    const registry = await viem.deployContract("VerifierRegistryV4", [
      timelock.account.address,
      registrar.account.address,
    ]);
    const nationalElectionId = hash("india-national-v4");
    const firstId = hash("constituency-1");
    const secondId = hash("constituency-2");
    const firstConfig = await deployConfig(
      registry.address,
      nationalElectionId,
      firstId,
    );
    const secondConfig = await deployConfig(
      registry.address,
      nationalElectionId,
      secondId,
    );
    const firstBatches = await viem.deployContract("MockAcceptedBallotsV4", [
      10n,
    ]);
    const secondBatches = await viem.deployContract("MockAcceptedBallotsV4", [
      20n,
    ]);
    const firstTally = await viem.deployContract("MockPublishedTallyV4", [
      firstConfig.address,
      firstBatches.address,
      hash("result-1"),
      hash("artifact-1"),
      hash("inputs-1"),
      true,
    ]);
    const secondTally = await viem.deployContract("MockPublishedTallyV4", [
      secondConfig.address,
      secondBatches.address,
      hash("result-2"),
      hash("artifact-2"),
      hash("inputs-2"),
      true,
    ]);
    const index = await viem.deployContract("NationalElectionIndexV4", [
      nationalElectionId,
      2,
      timelock.account.address,
      registrar.account.address,
    ]);
    return {
      nationalElectionId,
      firstId,
      secondId,
      firstConfig,
      secondConfig,
      firstTally,
      secondTally,
      index,
    };
  }

  it("freezes the constituency roster and builds a deterministic verified index", async function () {
    const {
      firstId,
      secondId,
      firstConfig,
      secondConfig,
      firstTally,
      secondTally,
      index,
    } = await deploy();
    await index.write.registerConstituency(
      [firstConfig.address, firstTally.address],
      { account: registrar.account },
    );
    await assert.rejects(
      index.write.freezeRegistration([], { account: timelock.account }),
    );
    await index.write.registerConstituency(
      [secondConfig.address, secondTally.address],
      { account: registrar.account },
    );
    await index.write.freezeRegistration([], { account: timelock.account });

    await index.write.recordConstituencyTally([secondId], {
      account: outsider.account,
    });
    await assert.rejects(
      index.write.accumulateNextTally([], { account: outsider.account }),
    );
    await index.write.recordConstituencyTally([firstId], {
      account: outsider.account,
    });
    await index.write.accumulateNextTally([], { account: outsider.account });
    const afterFirst = await index.read.nationalTallyAccumulator();
    await index.write.accumulateNextTally([], { account: outsider.account });
    assert.notEqual(await index.read.nationalTallyAccumulator(), afterFirst);
    assert.equal(await index.read.nationalAcceptedBallotCount(), 30n);
    await index.write.finalizeNationalIndex([], { account: outsider.account });
    assert.equal(await index.read.nationalIndexFinalized(), true);
  });

  it("rejects duplicates and registration after the roster is frozen", async function () {
    const {
      firstConfig,
      secondConfig,
      firstTally,
      secondTally,
      index,
    } = await deploy();
    await index.write.registerConstituency(
      [firstConfig.address, firstTally.address],
      { account: registrar.account },
    );
    await assert.rejects(
      index.write.registerConstituency(
        [firstConfig.address, firstTally.address],
        { account: registrar.account },
      ),
    );
    await index.write.registerConstituency(
      [secondConfig.address, secondTally.address],
      { account: registrar.account },
    );
    await index.write.freezeRegistration([], { account: timelock.account });
    await assert.rejects(
      index.write.registerConstituency(
        [secondConfig.address, secondTally.address],
        { account: registrar.account },
      ),
    );
  });
});
