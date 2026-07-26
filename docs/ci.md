# CI Pipeline

GitHub Actions runs on push and pull request to `main`.

## Workflow: `.github/workflows/ci.yml`

| Step | What it verifies | Notes |
|------|------------------|-------|
| `npm ci` | Lockfile-exact dependency resolution | Cached via `setup-node` |
| `npm audit --audit-level=high` | Known high-severity dependency issues | Reports all high/critical findings without hiding unfixed transitive risks |
| `npm audit --audit-level=critical` | Critical dependency issues | Fails the build on critical findings |
| `npm run verify:artifacts` | Committed WASM, zkey, and verification-key integrity | SHA-256 and exact byte length |
| `npm run typecheck` | TypeScript compilation | Catches type errors before runtime |
| `npm run compile` | Solidity compilation (Hardhat) | Compiles all `.sol` files with solc 0.8.28 |
| `npm run circuit:compile:eligible-ballot` | Circom constraint inspection | Detects unconstrained-signal warnings without overwriting committed proving artifacts |
| `npm test` | Hardhat contract and circuit tests | 147 tests including real proof verification |
| `npm run test:crypto` | Crypto/script tests (node:test) | TypeScript pipeline tests |
| Readiness annotation | Non-blocking demo check | Reports mock status, not a failure |
| Slither | Solidity static analysis | High-severity findings fail CI |
| Dependency review | New vulnerable dependencies | Pull requests; annotation-only on forks where GitHub disables the dependency graph |
| Gitleaks | Accidental secret commits | Full Git history |

## Nightly workflow

`.github/workflows/nightly.yml` reruns the real proof suites, crypto pipeline,
artifact verification, and a 10,000-nullifier synthetic scale benchmark. It is
separate from pull-request CI so cryptographic regression evidence remains
regular without making every small change wait for the longest jobs.

## What CI does NOT do

1. **Full trusted-setup ceremony** — Only needed when circuit changes; committed artifacts suffice.
2. **Live deployment** — Requires RPC keys unavailable in CI.
3. **Real-proof generation** — Snarkjs adds minutes without regression value.
4. **IPFS upload** — Requires local IPFS/gateway.
5. **ERC-4337 bundler submission** — Requires provider-issued Paymaster data.

These match the project's documented trust boundaries.
