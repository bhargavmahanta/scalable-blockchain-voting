import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

type ManifestArtifact = {
  path: string;
  bytes: number;
  sha256: string;
  normalization?: "lf";
};

type ArtifactManifest = {
  version: number;
  algorithm: "sha256";
  artifacts: readonly ManifestArtifact[];
};

const manifestPath = resolve(
  process.argv[2] ?? "circuits/proving-artifacts.manifest.json",
);
const manifest = JSON.parse(
  await readFile(manifestPath, "utf8"),
) as ArtifactManifest;

assert.equal(manifest.version, 1, "unsupported proving-artifact manifest");
assert.equal(manifest.algorithm, "sha256");
assert.equal(manifest.artifacts.length > 0, true, "artifact manifest is empty");

const verified = [];
for (const artifact of manifest.artifacts) {
  assert.match(artifact.sha256, /^[0-9a-f]{64}$/);
  const artifactPath = resolve(artifact.path);
  const rawContent = await readFile(artifactPath);
  const content = artifact.normalization === "lf"
    ? Buffer.from(rawContent.toString("utf8").replaceAll("\r\n", "\n"), "utf8")
    : rawContent;
  assert.equal(
    content.byteLength,
    artifact.bytes,
    `${artifact.path} byte length does not match the committed manifest`,
  );
  const digest = createHash("sha256")
    .update(content)
    .digest("hex");
  assert.equal(
    digest,
    artifact.sha256,
    `${artifact.path} digest does not match the committed manifest`,
  );
  verified.push({
    path: artifact.path,
    bytes: artifact.bytes,
    sha256: digest,
  });
}

console.log(JSON.stringify({
  manifestVersion: manifest.version,
  algorithm: manifest.algorithm,
  verified,
}, null, 2));
