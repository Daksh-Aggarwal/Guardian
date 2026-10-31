# Guardian

**Know what you trust.** A local, explainable npm supply-chain security platform. Guardian reads source and manifests, connects behavioral signals, verifies package integrity, traverses dependency graphs, and presents evidence and practical next steps. It does not certify packages as safe or execute uploaded code.

## What works

- Next.js/React/TypeScript interface with self-hosted Inter, Tailwind CSS, Lucide icons, Framer Motion, responsive layouts and persistent dark-mode preference.
- Independent security assessments & three-dimensional coverage (Intelligence Engine 2.1.1):
  - Behavioral findings & source coverage (files analyzed, parser boundaries, explicit disclaimers on partial code coverage).
  - Known vulnerabilities (OSV) with positional querybatch correspondence and bounded pagination.
  - Package integrity (SRI) for root tarball and inspected dependencies.
  - Dependency inspection coverage with strict reconciliation even at discovery limits.
  - The three dimensions are strictly decoupled: an OSV outage never marks complete source inspection as incomplete, and an archive parsing limit is never concealed by external vulnerability data.
- Advanced static data-flow engine (Intelligence Engine 2.0 / 2.1 / 2.1.1):
  - Scope-aware lexical binding, variable reassignment and shadowing.
  - Function call argument-to-parameter propagation and return value tracing.
  - Object property field tracking and destructuring assignment.
  - Static ES module (`import`/`export`) and CommonJS (`require`/`module.exports`/`exports`) cross-file data flow.
  - Structured evidence with step-by-step source-to-sink paths (`FlowStep`), file/line/column locations, snippets, bindings, and explicit limitation disclosures.
- Bounded and reconciled dependency inspection (Intelligence Engine 2.1 / 2.1.1):
  - Modern lockfile (`package-lock.json` v2/v3) traversal resolving direct and transitive dependencies with nearest `node_modules` lookup.
  - Guaranteed accounting reconciliation even at graph discovery ceilings (`MAX_DISCOVERED = 2000`): packages omitted due to ceilings are accounted for explicitly as `skipped`.
  - Invariants hold under all paths: `inspected + skipped + unavailable + unresolved + integrity_failed + not_attempted == total` and `direct + transitive == total`.
  - Dependency inspection profiles: **Fast** (up to 6 packages / 2 levels) and **Deep** (up to 20 packages / 4 levels), with operator-configurable ceilings (`GUARDIAN_MAX_PACKAGES`, `GUARDIAN_MAX_DEPTH`, etc.).
  - Deduplicated, memory-only tarball downloads from `registry.npmjs.org`.
- Package integrity verification:
  - Strict Subresource Integrity (SRI) validation before archive extraction supporting SHA-512, SHA-384, SHA-256, and SHA-1.
  - Independent verification of lockfile checksums and published npm registry digests.
  - Separate statuses for `verified`, `missing`, `invalid`, `unsupported`, and `mismatch` (extraction refused on mismatch).
- Hardened vulnerability intelligence (OSV 2.1.1):
  - Correct querybatch contract: validates positional query-to-result mapping; allows 0, 1, or multiple vulnerabilities per query; rejects malformed records without crashes.
  - Explicit bounded pagination: follows `next_page_token` up to 5 pages per dependency, enforces 8 MB aggregate batch budget, detects loops, deduplicates advisory IDs, and gracefully preserves partial results if pagination fails.
  - Bounded advisory enrichment: validated CVSS types (`CVSS_V2`, `CVSS_V3`, `CVSS_V4`) and vector strings, affected version ranges, sanitized fixed-version boundaries, and HTTPS-only reference links.
  - Preserved batch matches when detail enrichment is unavailable, marked with distinct evidence quality (`advisory.detail_status = 'unavailable'`).
  - Guardian review priority kept distinct from published CVSS severity.
- Cooperative and thread-safe scan cancellation:
  - Explicit job states: `queued`, `running`, `cancelling`, `cancelled`, `complete`, `failed`.
  - Cancellation requests transition active jobs to `cancelling` without prematurely claiming worker termination.
  - Atomic check-before-save under concurrency lock guarantees workers never persist a report after cancellation is accepted.
  - If persistence has begun under lock, cancellation is safely blocked until completion, ensuring report integrity.
  - Exactly-once semaphore slot release and idempotent cancellation requests.
- Hardened in-memory archive ingestion:
  - Memory-only extraction with streaming decompression tracking against per-file (1 MB) and aggregate (25 MB) limits.
  - Path traversal and path encoding guards: control character rejection, null byte rejection, absolute path rejection, Windows backslash rejection, and duplicate normalized path collision prevention (`seen_paths`).
  - Strict file-type verification: symlinks, hardlinks, FIFOs, and special device entries are rejected in both ZIP and TAR archives.
  - Nested archives are treated as unextracted inert files and skipped, preventing decompression recursion.
  - Manifest JSON object parsing validation with 1 MB size boundaries.
- ZIP uploads, individual or paired npm manifests, and direct npm registry name/version inspection.
- SQLite report history, shareable local report URLs (`?scan=<id>`), and complete JSON export.
- Simple/Advanced modes over identical findings, source evidence, recommendations, coverage gaps, and contextual deterministic explanations.
- Guardian Cognitive Intelligence 1.0 (LLM-Powered Security Advisor):
  - Natural-language reasoning grounded strictly in Guardian's deterministic findings and evidence.
  - Google Gemini API integration using official `google-genai` Python SDK (`from google import genai`) with configurable models (`gemini-3.8-flash` by default).
  - Explicit privacy consent required before any external inference; transparent disclosure of data shared vs retained locally.
  - Automated secret redaction layer stripping API keys, tokens, credentials, private keys, and auth headers before context transmission.
  - Dedicated context minimization and duplicate advisory aggregation (grouping repeated GHSA/CVE advisories across dependencies).
  - Multi-turn report-scoped conversation sessions with bounded recent history and local SQLite persistence.
  - Strict citation validation: every citation must reference an existing report finding; fabricated citations are automatically rejected.
  - Resilient provider fallback: graceful degradation to local deterministic explanations upon missing API key, AI disablement, network failure, or API quota/timeout.
  - Coverage-aware behavioral presentation distinguishing complete source coverage, partial coverage, and unavailable assessments.
- Guardian Autopilot — Remediation Agent 1.0 (Local Project Remediation):
  - Local project connection using modern Browser File System Access API (`window.showDirectoryPicker` in read-only mode).
  - Deterministic project understanding: manifests, lockfiles, framework detection (Next.js, Express, React, Vite, NestJS, Fastify, etc.), runtime engines, language detection (TypeScript/JavaScript), and test configurations.
  - Configurable snapshot boundaries: max 250 files, 1 MB per file, 10 MB aggregate snapshot, with automatic rejection of path traversal, secret-bearing files (`.env`, private keys), and standard exclusions (`.git`, `node_modules`, binaries).
  - Ephemeral in-memory project snapshots with 30-minute inactivity TTL and LRU session eviction; source files are never persisted into SQLite.
  - Dedicated, unchecked-by-default project-code consent modal for external AI remediation planning, completely decoupled from conversational AI consent.
  - Structured remediation plans powered by Gemini (or local deterministic planner fallback) with Pydantic validation: summary, expected outcome, trade-offs, potential regressions, assumptions, manual steps, and verification strategies.
  - Strict text-edit validation: exact verbatim `old_text` -> `new_text` replacements, requiring anchors to appear exactly once, non-overlapping edits, SHA-256 pre-verification, and standard unified diff generation.
  - Interactive unified diff viewer with additions, deletions, line numbers, file-by-file navigation, and downloadable `.patch` bundles.
  - Explicit user approval workflow with Git branch advisory and rollback safeguard warnings.
  - Browser-side file modification requesting `readwrite` permission only upon user approval, verifying SHA-256 before modification, capturing local IndexedDB backup snapshots, applying sequential writes, and providing automatic partial-write rollback.
  - Safe Undo operation verifying post-application file states before restoring originals from IndexedDB.
  - Deterministic outcome verification: rescans modified code, compares pre-remediation vs post-remediation findings, categorizing resolved, persistent, and newly introduced signals.
  - Strict execution boundaries: safe static analysis only; manual package commands (e.g. `npm install`, `npm test`) are presented clearly but never automatically executed.
  - Cross-browser compatibility fallback for non-Chromium browsers with ZIP archive inspection and `.patch` bundle export.
- Nine synthetic fixtures, including benign HTTP/environment access, sensitive data flow, installer behaviors, and full remediation demonstration. Fixture source is test data: never execute it.

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

### Guardian Intelligence (Gemini Advisor) Configuration

Guardian Intelligence is disabled by default and runs entirely deterministically unless explicitly enabled with a configured API key:

- `GUARDIAN_AI_ENABLED`: Set to `true` to enable external LLM reasoning.
- `GUARDIAN_AI_PROVIDER`: Provider name (default: `gemini`).
- `GEMINI_API_KEY`: Google Gemini API key (never transmitted to browser or exposed in reports/logs).
- `GEMINI_MODEL`: Model identifier (default: `gemini-3.8-flash`).
- `GUARDIAN_AI_TIMEOUT_SECONDS`: Request timeout in seconds (default: `30`).
- `GUARDIAN_AI_MAX_TURNS`: Max turns per report conversation (default: `30`).

To run with Gemini enabled:

```sh
GUARDIAN_AI_ENABLED=true GEMINI_API_KEY=your_key .venv/bin/python -m uvicorn backend.guardian.main:app --host 127.0.0.1 --port 8000
```

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
4. Click **Project workspace** in the sidebar (or **Open project folder** on the dashboard).
   - Select `fixtures/remediation-demo` (or upload its ZIP).
   - See detected project metadata (Jest test runner), file counts, and exclusions.
   - Click **Inspect project** to run a real scan.
   - Review findings (e.g. `INSTALL_REMOTE` lifecycle execution risk).
   - Click **Prepare a fix with Guardian**.
   - Review the generated remediation plan, trade-offs, manual steps (`npm install`), and inspect the exact unified diff removing the dangerous hook.
   - Click **Approve and apply** to write the change to disk with automatic IndexedDB rollback backup.
   - Click **Rescan & verify outcome** to verify that the installer finding is resolved!
   - Test **Undo latest changes** to safely restore original files.
5. Upload `fixtures/postinstall.zip`, or inspect a real npm package by name/version. Select **Fast** or **Deeper** dependency inspection budget.
6. Review **Dependencies** tab to see direct/transitive dependency trees, lockfile and registry checksum verifications, and findings attributed per dependency.
7. Review **Coverage**, particularly if OSV is unavailable or budget limits were reached.

Example scans are explicitly marked synthetic. No prefilled or fabricated report data is used.

## Screenshots

Verified production screenshot: [Advanced report](docs/screenshots/advanced-report.png).

## Verification on 2026-10-31

- Production `npm run build`: passed (Next.js 16.4.3 / webpack).
- `npm run typecheck`: passed (strict TypeScript 5.9).
- `npm run format`: passed (Prettier).
- `pytest backend/tests -q`: 180 tests passed in ~4.9s.
- Integration tests verified:
  1. Benign synthetic package (observations only).
  2. Sensitive-data source-to-sink flow (step-by-step trace).
  3. Cross-file data-flow scenario (ESM/CJS propagation).
  4. Malicious transitive dependency (attributed finding & dedup).
  5. Valid package integrity (SHA-512, SHA-384, SHA-256, SHA-1).
  6. Missing integrity metadata (distinguished from verified).
  7. Invalid and mismatched integrity (extraction refused, separate integrity finding).
  8. OSV querybatch validation (0, 1, multiple vulns; query count match; malformed handling).
  9. OSV bounded pagination (next_page_token traversal, 5-page ceiling, loop protection, network failure resilience).
  10. Decoupled coverage dimensions (source coverage vs dependency coverage vs OSV coverage).
  11. Reconciled dependency accounting at discovery ceilings (below cap, at cap, above cap, cycles, nested resolution).
  12. Cooperative scan cancellation & persistence concurrency (atomic persistence lock, idempotency).
  13. Archive hardening (traversal, normalized path collisions, symlinks/hardlinks/FIFOs/devices, decompression limits, unextracted nested archives).
  14. Fast and deep inspection profiles (bounded depth/package budgets).
  15. Simple and Advanced report rendering (everyday vs technical evidence).
  16. JSON export & legacy report compatibility (backward compatibility with legacy v1 reports).
  17. Guardian Cognitive Intelligence 1.0 (Gemini 3.8 Flash, secret redaction, citation validation, deterministic fallback).
  18. Guardian Autopilot Remediation 1.0 (Local project access, bounds, edit validation, unified diffs, approval, browser application, IndexedDB backup rollback, safe undo, and verification).

`backend/requirements.lock.txt` records the tested Python dependency versions; install it instead of `requirements.txt` to reproduce this environment.

## Limitations

This is a single-user, loopback-only prototype without authentication. Do not expose it publicly. Jobs are in-memory and are interrupted by backend restarts; completed reports persist in SQLite. Source parsing has a 20-second timeout, 256 MB Node heap, and bounded evidence.

Static data flow simulates module initialization and directly invoked call paths; loops, callbacks, dynamic imports (`import()`), dynamic requires (`require(x)`), and runtime framework lifecycles remain unmodeled. Static inference does not establish runtime execution or malicious intent.

Dependencies are inspected via bounded lockfile resolution; packages without exact lockfile versions remain uninspected. Integrity verification confirms byte consistency with the digest, not that the code is benign. OSV checks exact versions only; semver ranges are disclosed as uninspected. There is no runtime sandbox execution, LLM dependency, PyPI support, or multi-tenant scaffolding.

See [architecture](ARCHITECTURE.md), [detection rules](DETECTION_RULES.md), [product requirements](PRD.md), and [roadmap](ROADMAP.md).
