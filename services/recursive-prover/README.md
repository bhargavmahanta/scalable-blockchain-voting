# Recursive prover service

This service owns the V4 proof-job API:

- `POST /v1/manifests`
- `GET /v1/jobs/{jobId}`
- `GET /v1/artifacts/{jobId}`

It accepts only version-4, constituency-bound manifests containing 32–256
unique package digests. Workers enforce timeouts and never return an artifact
unless an engine marks it `recursivelyProved`.

The checked-in engine is deliberately fail-closed. It proves the job boundary,
validation, concurrency, and API behavior, but does **not** claim to aggregate
SnarkJS proofs. The production engine must:

1. convert the committed Circom/SnarkJS BN254 fixture proof and verification key;
2. verify every leaf proof and package/public-signal equality;
3. prove nullifier uniqueness and the exact state transition;
4. reconstruct the package root and encrypted aggregate;
5. recursively combine 32–256 leaf proofs; and
6. emit a proof accepted by `BatchCommitmentV4.finalizeWithProof`.

Until those checks and an independent audit pass, deployment must use the
bonded fraud-proof path and recursive finalization remains disabled.
