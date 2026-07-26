# Scalable Blockchain Voting

[![CI](https://github.com/IEEECS-VIT/scalable-blockchain-voting/actions/workflows/ci.yml/badge.svg)](https://github.com/IEEECS-VIT/scalable-blockchain-voting/actions/workflows/ci.yml)

Zero-cost testnet demonstration of a privacy-preserving voting pipeline using
election-scoped identities, encrypted ballot packages, batch commitments, and
verifiable tally publication.

## Current status

This repository includes:

- a Hardhat 3 + TypeScript development environment;
- immutable election configuration;
- a versioned eligibility-root registry that keeps identity records off-chain;
- proof-based registration calldata generation for relayer submission;
- dry-run/live script support for a dedicated registration relayer account;
- a direct ballot-commitment path for local contract testing;
- a real unified BabyJubJub/Groth16 circuit proving private eligibility
  membership, election nullifier derivation, and encrypted one-hot ballot
  validity, with a generated Solidity verifier;
- encrypted ballot package utilities;
- version-3 root-bound vote-package, real-proof-checked batch, receipt, and
  encrypted tally CLI flows (with V2 retained for comparison);
- IPFS upload, batch manifest, and data-availability scripts;
- append-only batch commitments with nullifier-root continuity;
- a proof-verifier seam for future batch-validity submission;
- independently generated BabyJubJub 5-of-9 trustee decryption shares with DLEQ
  correctness proofs, plus an explicitly demo-only dealer ceremony;
- signed batcher intake receipts, public omission claims, and committed Merkle
  inclusion resolution;
- reproducible local gas and synthetic ingestion regression benchmarks;
- tally result/public-input hash binding; and
- a tally-verifier adapter that requires a real verifier contract before a
  result can be marked verified.

The repository also includes an adapter for the official Anon Aadhaar verifier
interface, an Anon Aadhaar registration-artifact builder, an ERC-4337 bundler
submission bridge, a deterministic biometric pass/fail simulation, and a
functional artifact-backed local dashboard. Live Anon Aadhaar proof material,
provider-issued Paymaster data, and Amoy transaction evidence remain external
deployment inputs; they are never replaced with fake evidence.

The V3 canonical demo uses BabyJubJub from the unified proof through encrypted
aggregation and threshold decryption. Recursive batch verification, an on-chain
tally SNARK, audited DKG, and live infrastructure remain explicit research or
deployment gates; they are not misrepresented as completed trustless proofs.

## Important security boundary

The current batch contract records roots; it does not prove that every ballot
inside a batch is valid or available. Until a batch-validity and
nullifier-state proof is implemented, the batcher is trusted and the project
must be presented as a testnet demonstration—not a production election
system.

## Requirements

- Node.js 22.13 or newer
- npm 10 or newer

## Setup

```bash
npm install
cp .env.example .env
npm run compile
npm test
```

Generate a new unified eligibility-and-ballot proof with the committed proving
artifacts:

```bash
npm run circuit:input:eligible-ballot -- ./eligible-input.json 1 1
npm run proof:eligible-ballot -- ./eligible-input.json ./eligible-proof-output
```

Build V3 package, batch, tally, and independent trustee artifacts:

```bash
npm run build:vote-package:v3 -- descriptor.json vote-package-v3.json
npm run build:batch:v3 -- batch-input.json batch-artifact-v3.json
npm run build:tally:v3 -- tally-input.json encrypted-tally-v3.json
npm run ceremony:threshold -- ceremony-config.json ceremony-output
npm run trustee:decrypt-share -- trustee-private.json encrypted-tally-v3.json public-share.json
npm run finalize:tally:v3 -- finalize-input.json tally-result-v3.json
```

Run the complete local cryptographic demo and dashboard:

```bash
npm run demo:serve
```

Then open `http://127.0.0.1:8080`. This regenerates V3 unified-proof packages,
the root-bound batch, receipts, independent public trustee shares, and the 5-of-9
result. Private ceremony files are created outside the served directory and
removed after use.

To regenerate the V3 proving key and verifier, run
`npm run circuit:setup:eligible-ballot`. This performs a fresh local ceremony;
it is not a production multi-party key ceremony. The public proving key and
WASM are committed so normal demo proof generation does not require rerunning
that ceremony.

Local deployment:

```bash
npm run deploy:local
```

Polygon Amoy deployment:

```bash
npm run deploy:amoy
```

Amoy uses chain ID `80002` and POL as its gas token.
For real verifier-address parameters, copy and edit
[ignition/parameters.example.json](ignition/parameters.example.json), then run:

```bash
npx hardhat ignition deploy ignition/modules/VotingSystem.ts --network amoy --parameters ignition/parameters.example.json
```

Final-demo readiness check:

```bash
npm run check:readiness -- path/to/readiness.json
```

See [docs/demo-readiness.md](docs/demo-readiness.md) for the artifact format.

Local deterministic demo fixture:

```bash
npm run demo:fixture -- ./demo-output
```

This fixture is useful for script demos, but its proof bytes are placeholders.

For the steps that require external Amoy, Anon Aadhaar, IPFS, or bundler
credentials, follow [docs/live-amoy-checklist.md](docs/live-amoy-checklist.md).

Runbook and alignment review:

- [docs/demo-runbook.md](docs/demo-runbook.md)
- [docs/research-alignment-review.md](docs/research-alignment-review.md)
- [docs/v3-research-improvement-report.md](docs/v3-research-improvement-report.md)
- [docs/local-benchmarks.md](docs/local-benchmarks.md)
- [docs/recursive-batch-proof-spec.md](docs/recursive-batch-proof-spec.md)
- [docs/v4-production.md](docs/v4-production.md)

## Repository layout

```text
contracts/   Solidity contracts and verifier interfaces
ignition/    Repeatable deployment modules
test/        Contract tests
circuits/    Real ballot and unified eligibility-ballot circuits
packages/    Shared cryptography, proof-input, and Merkle utilities
frontend/    Functional local demo UI and future production frontend
docs/        Architecture, scope, and implementation roadmap
```

See [docs/architecture.md](docs/architecture.md) for trust boundaries and
[docs/implementation-roadmap.md](docs/implementation-roadmap.md) for the next
build milestones.
