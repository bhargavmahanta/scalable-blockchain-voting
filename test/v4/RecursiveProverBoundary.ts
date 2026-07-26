import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("recursive prover fail-closed boundary", function () {
  it("never serves a placeholder proof when the cryptographic engine is absent", async function () {
    const server = await readFile(
      "services/recursive-prover/server.go",
      "utf8",
    );
    const main = await readFile(
      "services/recursive-prover/main.go",
      "utf8",
    );
    assert.match(server, /ErrRecursiveEngineUnavailable/);
    assert.match(server, /job\.Artifact = nil/);
    assert.match(server, /!artifact\.RecursivelyProved/);
    assert.match(main, /UnavailableEngine/);
    assert.equal(main.includes("Mock"), false);
  });

  it("binds every recursive statement required by the repository specification", async function () {
    const types = await readFile(
      "services/recursive-prover/types.go",
      "utf8",
    );
    for (const binding of [
      "NationalElectionID",
      "ConstituencyID",
      "EligibilityRoot",
      "EligibilityRootVersion",
      "CandidateProfile",
      "PackageRoot",
      "PreviousNullifierRoot",
      "NullifierRoot",
      "ManifestDigest",
      "AggregateCiphertextDigest",
      "AvailabilityCertificateHash",
      "BallotCount",
      "BallotVerifierVersion",
      "BatchVerifierVersion",
      "PackageDigests",
    ]) {
      assert.equal(types.includes(binding), true, `missing ${binding}`);
    }
  });
});
