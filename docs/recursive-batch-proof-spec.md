# Recursive batch proof specification

This document defines the proof required to remove the remaining V3 batcher
trust. No artifact in the repository currently claims to satisfy this statement.

The fail-closed Go job API in `services/recursive-prover/` validates the V4
manifest envelope and exposes submit/status/artifact operations. It deliberately
returns no proof until the native recursive engine implements and passes every
constraint below.

## Public statement

A batch proof must bind:

- election ID;
- candidate-list hash;
- active eligibility root and its registry version;
- election encryption public-key hash;
- previous and next nullifier-state roots;
- content/package Merkle root;
- exact aggregate ciphertext digest;
- number of accepted ballots;
- batch manifest digest; and
- the verifier/version identifiers for every recursively checked proof.

## Private witness

The prover supplies the canonical V3 packages, their unified Groth16 proofs,
content identifiers, nullifier-state membership/non-membership paths, and the
intermediate encrypted aggregates.

## Required constraints

For every package, the proof must establish:

1. canonical schema and election/candidate/root/key agreement;
2. validity of the unified eligibility/nullifier/encryption proof;
3. equality between proof public signals and package fields;
4. uniqueness of the election nullifier against the previous state and all
   earlier entries in this batch;
5. a valid transition to the published next nullifier root;
6. equality between canonical package/content leaves and the published Merkle
   root; and
7. equality between homomorphic accumulation of all ciphertexts and the
   published aggregate ciphertext digest.

## Contract acceptance

The generated verifier adapter must reconstruct the public-input hash from
explicit contract arguments. `BatchCommitment.submitBatchWithProof` must accept
only that adapter, reject stale previous roots, and keep verifier version changes
auditable. Mocks remain test-only.

## Security and performance acceptance

- Invalid ballot, stale eligibility root, duplicate nullifier, omitted package,
  changed content ID, changed aggregate, and reordered/unbound public input
  adversarial fixtures must fail.
- At least two independently generated valid batches must verify on-chain.
- Setup provenance, circuit constraints, verifier bytecode, proof size,
  proving time, peak memory, and verification gas must be recorded.
- The implementation requires an independent circuit and contract audit before
  any production claim.
