# Guardian

**Know what you trust.** A local, explainable npm supply-chain security platform. Guardian reads source and manifests, connects behavioral signals, verifies package integrity, traverses dependency graphs, and presents evidence and practical next steps. It does not certify packages as safe or execute uploaded code.

## What works

- Next.js/React/TypeScript interface with self-hosted Inter, Tailwind CSS, Lucide icons, Framer Motion, responsive layouts and persistent dark-mode preference.
- Independent security assessments: Behavioral findings, Known vulnerabilities (OSV), Package integrity (SRI), and Dependency inspection coverage are kept distinct and never collapsed into a misleading score.
- Advanced static data-flow engine (Intelligence Engine 2.0):
  - Scope-aware lexical binding, variable reassignment and shadowing.
  - Function call argument-to-parameter propagation and return value tracing.
  - Object property field tracking and destructuring assignment.
  - Static ES module (`import`/`export`) and CommonJS (`require`/`module.exports`/`exports`) cross-file data flow.
  - Structured evidence with step-by-step source-to-sink paths (`FlowStep`), file/line/column locations, snippets, bindings, and explicit limitation disclosures.
- Bounded dependency inspection:
  - Modern lockfile (`package-lock.json` v2/v3) traversal resolving direct and transitive dependencies with nearest `node_modules` lookup.
  - Dependency inspection profiles: **Fast** (up to 6 packages / 2 levels) and **Deep** (up to 20 packages / 4 levels), with operator-configurable ceilings (`GUARDIAN_MAX_PACKAGES`, `GUARDIAN_MAX_DEPTH`, etc.).
  - Deduplicated, memory-only tarball downloads from `registry.npmjs.org`.
- Package integrity verification:
  - Strict Subresource Integrity (SRI) validation before archive extraction supporting SHA-512, SHA-384, SHA-256, and SHA-1.
  - Independent verification of lockfile checksums and published npm registry digests.
  - Separate statuses for `verified`, `missing`, `invalid`, `unsupported`, and `mismatch` (extraction refused on mismatch).
- Vulnerability intelligence (OSV):
  - Exact-version batch matching against the OSV API.
  - Bounded advisory enrichment: published CVSS scores/vectors, affected version ranges, fixed-version boundaries, and aliases.
  - Guardian review priority kept distinct from published CVSS severity.
- Safe scan cancellation:
  - Backend job cancellation endpoint (`POST /api/jobs/{id}/cancel`) releasing concurrency semaphore slots.
  - Responsive scan cancellation UI with active progress feedback.
- ZIP uploads, individual or paired npm manifests, and direct npm registry name/version inspection.
- SQLite report history, shareable local report URLs (`?scan=<id>`), and complete JSON export.
- Simple/Advanced modes over identical findings, source evidence, recommendations, coverage gaps, and contextual deterministic explanations.
- Eight synthetic fixtures, including benign HTTP/environment access, sensitive data flow, and installer behaviors. Fixture source is test data: never execute it.

## Setup

Requires Node.js 20.9+ (tested on 26), Python 3.9+ (tested on 3.9.6), and npm. No Docker, database service, account or LLM key required.

```sh
cd /Users/daksh/Desktop/Guardian
npm ci --ignore-scripts
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
```

Start the backend in one terminal:

```sh
.venv/bin/python -m uvicorn backend.guardian.main:app --host 127.0.0.1 --port 8000
```

Start the frontend in another:

```sh
npm run dev
```

Open http://127.0.0.1:3000. Backend OpenAPI: http://127.0.0.1:8000/docs. The frontend proxies `/api/*` to the backend, so browser requests remain same-origin. Keep both processes running.

### Configuration

See `.env.example`. Next.js reads `GUARDIAN_API_URL` from `.env.local` (default `http://127.0.0.1:8000`). Python uses shell environment variables; it does not automatically read dotenv files.

```sh
GUARDIAN_OSV_ENABLED=false .venv/bin/python -m uvicorn backend.guardian.main:app --host 127.0.0.1 --port 8000
```

Operator budget ceilings:
- `GUARDIAN_MAX_PACKAGES` (default: 6 fast, 20 deep, max ceiling: 40)
- `GUARDIAN_MAX_DEPTH` (default: 2 fast, 4 deep, max ceiling: 6)
- `GUARDIAN_DEPENDENCY_SECONDS` (default: 25 fast, 60 deep, max ceiling: 120)
- `GUARDIAN_REGISTRY_REQUESTS` (default: 14 fast, 42 deep, max ceiling: 82)
- `GUARDIAN_DOWNLOAD_MB` (default: 20 fast, 50 deep, max ceiling: 100)
- `GUARDIAN_EXPANDED_MB` (default: 40 fast, 80 deep, max ceiling: 150)
- `GUARDIAN_DB` overrides the SQLite path (default: `backend/guardian.sqlite3`).

Stored evidence snippets may contain sensitive data: the local database and JSON exports should be treated as private.

## Development and verification

```sh
npm run build
npm run typecheck
npm run format
.venv/bin/python -m pytest backend/tests -q
# Production frontend, after build:
npm start
# Regenerate inert source fixtures and uploadable ZIPs:
python3 scripts/create_fixtures.py
```

Webpack mode is selected explicitly because Turbopack's CSS worker could not bind an internal port in this desktop execution environment. This does not change the application architecture.

## Demo walkthrough

1. Click **Everyday package**. The actual fixture is analyzed: environment and public HTTP access are observations, not elevated risk.
2. Click **Sensitive data flow**. Open the sensitive-transmission finding, switch to **Advanced**, and inspect the step-by-step source-to-sink path, intermediate variable bindings, line/column numbers, and analysis limitations.
3. Click **Suspicious installer**. See multiple independent and correlated signals. Ask **What should I do next?** and follow a citation back to its finding.
4. Upload `fixtures/postinstall.zip`, or inspect a real npm package by name/version. Select **Fast** or **Deeper** dependency inspection budget.
5. Review **Dependencies** tab to see direct/transitive dependency trees, lockfile and registry checksum verifications, and findings attributed per dependency.
6. Review **Coverage**, particularly if OSV is unavailable or budget limits were reached.

Example scans are explicitly marked synthetic. No prefilled or fabricated report data is used.

## Screenshots

Verified production screenshot: [Advanced report](docs/screenshots/advanced-report.png).

## Verification on 2026-10-31

- Production `npm run build`: passed (Next.js 16.4.3 / webpack).
- `npm run typecheck`: passed (strict TypeScript 5.9).
- `npm run format`: passed (Prettier).
- `pytest backend/tests -q`: 104 tests passed in ~3.8s.
- Integration tests verified:
  1. Benign synthetic package (observations only).
  2. Sensitive-data source-to-sink flow (step-by-step trace).
  3. Cross-file data-flow scenario (ESM/CJS propagation).
  4. Malicious transitive dependency (attributed finding & dedup).
  5. Valid package integrity (SHA-512, SHA-384, SHA-256, SHA-1).
  6. Missing integrity metadata (distinguished from verified).
  7. Invalid and mismatched integrity (extraction refused, separate integrity finding).
  8. OSV advisory response (batch match, CVSS vectors, fixed boundaries).
  9. Fast and deep inspection profiles (bounded depth/package budgets).
  10. Simple and Advanced report rendering (everyday vs technical evidence).
  11. JSON export (complete report data structure).
  12. Historical report loading (backward compatibility with legacy v1 reports).
  13. Safe scan cancellation (job cancellation, abort before save, semaphore slot release).

`backend/requirements.lock.txt` records the tested Python dependency versions; install it instead of `requirements.txt` to reproduce this environment.

## Limitations

This is a single-user, loopback-only prototype without authentication. Do not expose it publicly. Jobs are in-memory and are interrupted by backend restarts; completed reports persist in SQLite. Source parsing has a 20-second timeout, 256 MB Node heap, and bounded evidence.

Static data flow simulates module initialization and directly invoked call paths; loops, callbacks, dynamic imports (`import()`), dynamic requires (`require(x)`), and runtime framework lifecycles remain unmodeled. Static inference does not establish runtime execution or malicious intent.

Dependencies are inspected via bounded lockfile resolution; packages without exact lockfile versions remain uninspected. Integrity verification confirms byte consistency with the digest, not that the code is benign. OSV checks exact versions only; semver ranges are disclosed as uninspected. There is no runtime sandbox execution, LLM dependency, PyPI support, or multi-tenant scaffolding.

See [architecture](ARCHITECTURE.md), [detection rules](DETECTION_RULES.md), [product requirements](PRD.md), and [roadmap](ROADMAP.md).
