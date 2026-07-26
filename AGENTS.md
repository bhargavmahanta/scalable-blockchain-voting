# AGENTS.md — scalable-blockchain-voting

## Repository
`scalable-blockchain-voting` (IEEECS-VIT) — Hardhat 3 + TypeScript project.
Privacy-preserving blockchain voting pipeline demo.

## Key structure

| Path | Purpose |
|------|---------|
| `contracts/` | Solidity contracts, verifier adapters, mocks, generated verifiers |
| `ignition/modules/` | Hardhat Ignition deployment modules |
| `test/` | Contract + crypto tests (Hardhat + node:test) |
| `test/fixtures/` | Proof artifacts for benchmarks |
| `circuits/` | Circom circuits (`ballot_validity`, `eligible_ballot`) |
| `packages/crypto/src/` | Shared TS: proofs, pipelines, Merkle, threshold |
| `scripts/` | CLI flows (build, deploy, ceremony, benchmark, demo) |
| `frontend/` | Local demo UI |
| `docs/` | Architecture, roadmap, benchmarks, runbook |

## Contracts (13 total)

- **ElectionConfig** — Immutable election params (id, candidate hash, pubkey hash, window)
- **VoterRegistry** — Registrar seam + proof-based registration via IEligibilityVerifier
- **VotingContract** — Direct ballot path (1-tx/ballot), Groth16 verifier seam
- **EligibilityRootRegistry** — Versioned Poseidon Merkle root, freeze support
- **EligibleVotingContract** — V3 unified proof path, any-relayer submission
- **BatchCommitment** — Append-only batch roots, trusted + proof-gated submit
- **BatcherReceiptRegistry** — EIP-712 signed intake receipts, omission claims
- **TallyVerifier** — Proof-gated tally publication
- **AnonAadhaarEligibilityVerifier** — Official Anon Aadhaar adapter
- **BallotGroth16VerifierAdapter** / **EligibleBallotGroth16VerifierAdapter** — Snarkjs proof adapters
- **Mock* — Test verifiers for all seam interfaces
- **generated/** — `BallotGroth16Verifier.sol`, `EligibleBallotGroth16Verifier.sol`

## Trust model (documented honestly)

Batch contract records roots but does NOT prove every ballot is valid. Batcher
is trusted. The README, architecture.md, and every relevant contract docstring
states this. **Never weaken this honesty.**

## Testing

- `npm test` — `hardhat test` (all Hardhat tests)
- `npm run test:crypto` — node:test crypto tests
- Test framework: Hardhat (`network.create()` + viem) + node:test (`describe`/`it`)
- Gas benchmark: `test/GasBenchmark.ts` (uses real Groth16 proof fixture)
- Scale benchmark: `npm run benchmark:scale -- <N>`

## CI

- `.github/workflows/ci.yml` runs deterministic installs, dependency and
  proving-artifact checks, type checking, Solidity/circuit compilation,
  Hardhat/crypto tests, Slither, dependency review, and secret scanning.
- `.github/workflows/nightly.yml` runs proof suites and the synthetic scale
  benchmark on a schedule or manual dispatch.
- Branches use the `name/feature` convention, for example
  `bhargav/security-fixes`.

## Circuits

- `ballot_validity.circom` — 4-candidate one-hot EC-ElGamal, 22 public signals
- `eligible_ballot.circom` — Unified membership + nullifier + encryption, 23 public signals, 24-level Merkle tree
- Proving artifacts committed; `npm run circuit:setup:eligible-ballot` for fresh ceremony

## Commands

```
npm run compile         # Hardhat compile
npm test                # Hardhat contract tests
npm run test:crypto     # Crypto/script tests
npm run benchmark:scale -- <N>
npm run demo:serve      # Local demo dashboard
npm run check:readiness -- <path>
npm run deploy:local    # Hardhat Ignition local
npm run deploy:amoy     # Polygon Amoy
```

## Key conventions

- Solidity 0.8.28, TypeScript, ESM (`"type": "module"`)
- OpenZeppelin Ownable, EIP712, ECDSA
- Curves: BabyJubJub for EC-ElGamal; secp256k1 for EIP-712 sigs
- Hardhat 3 (`hardhat.config.ts` uses `defineConfig`)
- Never commit `.env` or secrets
- Prefer additions over modifications — most work is new files
