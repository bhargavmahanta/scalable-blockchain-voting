import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("V4 production deployment boundary", function () {
  it("deploys no mock, trusted registration, direct-vote, or trusted-batch path", async function () {
    const source = await readFile(
      "ignition/modules/ProductionV4.ts",
      "utf8",
    );
    for (const forbidden of [
      "Mock",
      "zeroAddress",
      'm.contract("VoterRegistry"',
      'm.contract("VotingContract"',
      'm.contract("EligibleVotingContract"',
      'm.contract("BatchCommitment",',
      'm.contract("TallyVerifier",',
    ]) {
      assert.equal(
        source.includes(forbidden),
        false,
        `production module contains forbidden path: ${forbidden}`,
      );
    }
    for (const required of [
      'm.contract("ElectionConfigV4"',
      'm.contract("BatchCommitmentV4"',
      'm.contract("TallyVerifierV4"',
      '"VerifierRegistryV4"',
    ]) {
      assert.equal(
        source.includes(required),
        true,
        `production module is missing: ${required}`,
      );
    }
  });
});
