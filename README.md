# Guardian

**Know what you trust.** A local, explainable npm and PyPI supply-chain security platform. Guardian reads source and manifests, connects behavioral signals, verifies package integrity, traverses dependency graphs, and presents evidence and practical next steps. It does not certify packages as safe or execute uploaded code.

Guardian 0.2 adds a pre-installation CLI with shared static analysis, exact verified npm/wheel installation, private local reports, and explicit report import into the independent website. npm scripts remain disabled; Python source builds are refused. Optional Supabase GitHub login, CLI device authorization and explicit report sync are available; see the [account setup and Vercel/Render deployment guide](docs/ACCOUNTS-DEPLOYMENT.md). See the [CLI guide, security boundaries and demonstrated scenarios](docs/CLI.md).

The [npm acquisition regression guide](docs/CLI-BUDGETS.md) documents separate upload/package archive limits, unique-artifact versus installation-location budgets, structured diagnostics, and actual Lodash/Express smoke results.

## What works

- **Guardian Handoff 1.0.1 — AI-Agnostic Remediation & Agent Instruction Export (Hardened)**:
  - **Shared Canonical Handoff Architecture**: Single canonical, validated, evidence-backed representation (`CanonicalHandoff`, schema v1.0.0) from which all target export formats are deterministically derived. Avoids prompt drift and guarantees identical ground truth across all coding agents.
  - **Strict Finding Scope & Input Validation**: Zero silent finding substitution; explicit validation rejects empty selections (`400 Bad Request`) and invalid finding IDs (`404 Not Found`); deduplication preserves canonical report order; accurate scope classification (`finding` for exactly one finding, `findings` for multiple, `scan` for entire scan).
  - **Two Meaningfully Differentiated Remediation Modes**:
    - *Focused Fix*: Directs the receiving agent to confirm issue presence in the current checkout, identify root causes, implement minimal safe edits strictly limited to affected files/lines, preserve compatibility, add focused regression tests, and report unresolved areas.
    - *Deep Security Remediation*: Comprehensive security investigation instructions expanding beyond direct findings to analyze direct and transitive dependency trees, inspect shared package paths, evaluate lockfile consistency, search repository-wide for similar insecure call patterns, review package integrity and provenance, and formulate prioritized follow-up security concerns.
  - **Evidence-Grounded Recommendations & Classification**: Distinguishes confirmed scanner observations, advisory evidence, remediation hypotheses, and required verification. Recommends candidate upgrades with unverified compatibility rather than assuming safety; cautions that lifecycle scripts may compile native bindings (e.g. `node-gyp`) and should not be removed blindly; requires workspace tracing for behavioral findings.
  - **Exact Ecosystem-Aware Dependency Matching**: Replaces substring comparisons with exact normalized identity matching (handling scoped npm packages and PEP 503 PyPI normalization), keeping npm and PyPI ecosystems strictly separate.
  - **Reconciled Coverage & Inspection Accounting**: Accurately classifies coverage as `complete` vs `partial` based on authoritative dependency accounting (including unresolved, unavailable, skipped, integrity-failed, and not-attempted states); distinguishes zero dependencies from unresolved dependencies.
  - **Evidence-Based Scan Provenance**: Clearly explains that findings describe the scanned commit SHA rather than remote HEAD without fabricating staleness; differentiates local in-memory snapshots from expired snapshots.
  - **Adversarial Markdown & Prompt Injection Defense**: Context-aware inline escaping, table cell pipe escaping, dynamic backtick scaling for code-fence breakout prevention, credential redaction, and prominent prompt-injection defense directives across all adapters instructing receiving agents to treat scanner evidence as inert untrusted data.
  - **Ecosystem-Aware Validation Guidance**: Tailors validation commands to the project's ecosystem (`npm test`, `npm run typecheck` for npm; `pytest`, `pip check`, `mypy` for PyPI; manifest inspection for unknown).
  - **Five Tailored Agent Target Adapters**:
    1. *Universal Markdown*: Self-contained instruction package suitable for ChatGPT, Gemini, Claude, or any desktop/web coding assistant.
    2. *Claude Code*: Autonomous CLI agent workflow emphasizing file pre-inspection, minimal targeted edits, test execution commands, and concise terminal output.
    3. *Cursor*: Interactive IDE pair-programming workflow emphasizing workspace file references, scoped interactive edits, and immediate linter/typechecker verification.
    4. *OpenAI Codex*: Agentic repository repair workflow emphasizing architecture conventions, deterministic change planning, and command output reporting.
    5. *GitHub Copilot*: GitHub-aligned chat and agent workflow emphasizing repo coding standards, regression tests, and pull request safety.
  - **Machine-Readable JSON Evidence Appendix**: Every export includes an independently parseable `## Guardian Evidence Appendix` fenced JSON block adhering to versioned schema `1.0.0`, preserving finding IDs, advisory references, CVSS ratings, dependency paths, and provenance.
  - **Interactive Handoff Interface**: Modal dialog with dynamic mode switching, agent target selection, scope toggle (Single finding / Selected findings / Entire scan), race-condition-protected asynchronous fetching, real-time summary statistics, readable instruction preview, raw markdown view, JSON appendix view, one-click clipboard copying, and sanitized `.md` file download.

- **Guardian 4.0 — GitHub Integration & Repository-Native Remediation**:
  - **GitHub App Connection & Secure Session Handling**: Server-side GitHub App installation flow with RS256 JWT generation, short-lived in-memory token caching with expiration buffers, single-use cryptographic CSRF state parameters, and active connection management. Zero client-side token exposure and zero plaintext installation tokens in SQLite.
  - **Repository & Branch Discovery**: Live discovery of accessible user and organization repositories with name search, private vs public indicators, default branch detection, and branch resolution to immutable commit SHAs.
  - **Bounded Git Data Ingestion**: Secure source retrieval via GitHub's Git Trees and Blobs API with truncated tree detection, strict file limits (250 files, 1 MB per file, 10 MB aggregate snapshot), and automated exclusion of secret-bearing files (`.env`, `.pem`), `.git`, `node_modules`, and binaries.
  - **Seamless Scanner Integration**: Ingests into Guardian's authoritative static security engine (AST data-flow tracking, lockfile traversal, OSV intelligence, package integrity, and 4D decoupled assessment) preserving immutable commit SHA references and `real` dataset classification.
  - **Repository Identity & Investigation Workspace**: Stable GitHub repository identity (`github:{repo_id}`) uniting all historical scans across branches, branch-aware security timeline, and explicit cross-branch comparison labeling.
  - **Guardian Autopilot Repository-Native Remediation**: Generates reviewed remediation diffs, performs pre-flight verification asserting the target branch has not moved, creates dedicated remediation branches (`guardian/remediation/<short-plan-id>`), commits verified changes atomically via Git Data API, opens descriptive GitHub Pull Requests with human review disclosures, and provides a safe PR closure path without touching default branches or executing code.
- **Guardian 3.1 — Data Integrity, Project Intelligence & Investigation Workspace**:
  - **Explicit Project Classification & Dataset Filtering**: Scan records carry explicit `classification: "real" | "demo"` metadata (`synthetic fixture` -> `demo`, real uploads/registries/local projects -> `real`). Global dataset filter (`All`, `Real Projects`, `Demo Data`) persistently filters dashboard metrics, project lists, recommended actions, and scan history without mutative record loss. Deduplicated project metrics prevent repeated scans of the same project from inflating counts.
  - **Reconciled Data Accounting & Report Semantics**: Actionable security findings are strictly separated from informational observations (e.g. benign lifecycle scripts or credential reads). Dependency counts are reconciled across report headers, dimension cards, and inspection breakdowns: `declaredDirect + transitive === totalResolved`, and `inspected + skipped + unavailable + unresolved + integrity_failed + not_attempted === totalResolved`.
  - **Responsive Layout & Visual Consistency**: Four-dimension assessment cards adaptively render across 4 columns ($\ge 1350$px), 2 columns ($768–1349$px), and 1 column ($< 768$px) with word-break safeguards preventing viewport clipping or horizontal scrollbars.
  - **Project Investigation Workspace**: Dedicated 6-tab workspace for deep project-level security analysis consuming genuine report and lockfile data:
    1. *Overview*: Project identity, demo/real classification badge, package count breakdown, decoupled 4-dimension posture summary, and delta comparisons with preceding scans.
    2. *Dependency Graph*: Interactive hierarchical DAG explorer powered by `@xyflow/react` and `@dagrejs/dagre`, featuring zoom/pan/minimap controls, severity filtering, search, depth limit sliders, focused upstream/downstream subtree isolation, and an interactive package detail drawer.
    3. *Vulnerabilities*: Hierarchical Project $\rightarrow$ Dependency $\rightarrow$ Advisory $\rightarrow$ Evidence explorer displaying published CVSS severity, Guardian review priority, and direct jump-to-graph actions.
    4. *Behavioral Flows*: Visual source-to-sink flow step progression (`Source` $\rightarrow$ `Assignment` $\rightarrow$ `Argument` $\rightarrow$ `Parameter` $\rightarrow$ `Return` $\rightarrow$ `Sink`) with syntax code snippets, variable binding badges, and explicit limitations disclosure.
    5. *Remediation History*: Project-level audit log of Guardian Autopilot remediation plans, user approvals/rejections, file application outcomes, and rescan verification states.
    6. *Security Timeline*: Chronological multi-scan security posture tracking across independent dimensions with side-by-side two-scan delta comparison.
  - **Guardian Autopilot Safety Hardening**: Multi-file rollback journal that removes newly created files on failure, undo operations that safely remove created files, pre-flight collision rejection if a `create` target already exists, and reapplication validation.
  - **Standardized Product Terminology**: Canonical naming enforced across all user interfaces: **Guardian** (platform), **Guardian Intelligence** (AI security advisor), and **Guardian Autopilot** (AI remediation system).
- **Guardian 3.0 Experience Overhaul**:
  - **Security Command Centre Dashboard**: Workspace overview with real historical metrics (projects inspected, scans requiring attention, dependencies inventoried, critical advisory matches), decoupled 4-dimension posture breakdown, prioritized evidence-grounded next steps, and modernized scan launchpad with file dropzone and multi-stage progress tracking.
  - **Major Report Redesign**: Adaptive assessment summary that dynamically leads with primary security concerns (vulnerabilities, behavioral signals, or coverage boundaries), 4 independent assessment dimension cards, tabbed report navigation (Findings, Dependencies, Coverage, Evidence & Data Flows), meaningful advisory titles (replacing repetitive generic titles), package-grouped finding exploration without concealing underlying findings, and practical filters.
  - **Guardian Intelligence Drawer**: Persistent, collapsible right-side drawer sliding in smoothly alongside the report, context-aware of selected findings and reports, dynamic suggested prompts, rich markdown rendering, and clickable citations that highlight and jump to findings in the report.
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

## Architecture Diagrams

### 1. Project Investigation Workspace Architecture

```
+--------------------------------------------------------------------------------------------------+
|                                GUARDIAN PROJECT WORKSPACE                                       |
|                                                                                                  |
|  +--------------------+  +----------------------+  +---------------------+  +-----------------+  |
|  | Project Selector   |  | Classification Badge |  | Historical Scans    |  | Intelligence    |  |
|  | (Deduplicated)     |  | [REAL] / [DEMO]      |  | Scan Switcher / Run |  | Drawer Launcher |  |
|  +--------------------+  +----------------------+  +---------------------+  +-----------------+  |
|                                                                                                  |
|  +---------------+ +------------------+ +-----------------+ +--------------+ +---------------+   |
|  | 1. Overview   | | 2. Dep Graph     | | 3. Vulnerability| | 4. Behav Flow| | 5. Remediation|   |
|  | 4 Dimensions  | | ReactFlow+Dagre  | | Dependency-First| | Source->Sink | | Autopilot Log |   |
|  | Scan Deltas   | | Subtree Tracing  | | Advisories+CVSS | | Syntax Steps | | Rescan Verify |   |
|  +---------------+ +------------------+ +-----------------+ +--------------+ +---------------+   |
|                                   | 6. Security Timeline  |                                      |
|                                   | Cross-Scan Delta View |                                      |
|                                   +-----------------------+                                      |
+--------------------------------------------------------------------------------------------------+
```

### 2. Ingestion, Storage, Filtering & Data Accounting Flow

```
+----------------------------------------------------------------------------------------------------+
|                                    GUARDIAN 3.1 DATA FLOW                                          |
|                                                                                                    |
|  [User Input / Files / ZIP / Local FS / npm Registry]                                              |
|                           │                                                                        |
|                           ▼                                                                        |
|  [Ingestion & Classification Engine] ─── Explicit Metadata: classification = "real" | "demo"       |
|                           │                                                                        |
|                           ▼                                                                        |
|  [Analysis Engine: AST Syntax / OSV Intelligence / SRI Integrity / Lockfile Traversal]             |
|                           │                                                                        |
|                           ▼                                                                        |
|  [Immutable Report Generation] ─── Reconciled Accounting (getDependencyAccounting / Breakdown)    |
|                           │                                                                        |
|                           ▼                                                                        |
|  [SQLite Storage: backend/guardian.sqlite3] ─── Preserves report + classification + plans          |
|                           │                                                                        |
|                           ▼                                                                        |
|  [Frontend API Proxy: /api/scans] ─── Session-level Dataset Filter: "all" | "real" | "demo"        |
|               │                                                 │                                  |
|               ▼                                                 ▼                                  |
|  [Dashboard Command Centre]                       [Project Investigation Workspace]                |
|  - Deduplicated Project Metrics                   - 6 Dedicated Interactive Analysis Tabs          |
|  - 4D Responsive Assessment Cards                 - Hierarchical DAG / Trace / Audit Views         |
+----------------------------------------------------------------------------------------------------+
```

### 3. Guardian Autopilot Remediation Lifecycle & Rollback Journal State Machine

```
+----------------------------------------------------------------------------------------------------+
|                       GUARDIAN AUTOPILOT SAFETY & ROLLBACK STATE MACHINE                           |
|                                                                                                    |
|   [Finding Review]                                                                                 |
|          │                                                                                         |
|          ▼                                                                                         |
|   [Plan Generation] ──── LLM / Deterministic Planner (Exact verbatim anchors, Pydantic validated)  |
|          │                                                                                         |
|          ▼                                                                                         |
|   [Diff Inspection] ─── User reviews unified diff and manual action requirements                   |
|          │                                                                                         |
|          ▼                                                                                         |
|   [Explicit Approval] ── User confirms apply with Git branch safeguard check                       |
|          │                                                                                         |
|          ▼                                                                                         |
|   [Pre-Flight Verification]                                                                        |
|     ├── For updates: verify disk SHA-256 matches expected before_hash                              |
|     └── For creates: verify target file DOES NOT already exist on disk                             |
|          │                                                                                         |
|          ├── If Pre-check Fails ──────> [ABORT: No files touched]                                  |
|          ▼                                                                                         |
|   [Capture Rollback Snapshot] ──────── Store original file bytes in IndexedDB                      |
|          │                                                                                         |
|          ▼                                                                                         |
|   [Apply Operational Journal] ──────── Track modified and created files sequentially               |
|          │                                                                                         |
|          ├── If Any Write Fails ──────> [AUTOMATIC ROLLBACK JOURNAL]                               |
|          │                              ├── Restore modified files from backup                     |
|          │                              └── Delete created files via directoryHandle.removeEntry   |
|          ▼                                                                                         |
|   [Application Complete] ───────────── Plan recorded as applied; ready for rescan                  |
|          │                                                                                         |
|          ├── User Requests [Undo] ────> [UNDO ROLLBACK ENGINE]                                     |
|          │                              ├── Verify file hashes match post-applied state            |
|          │                              ├── Restore original file contents from IndexedDB          |
|          │                              └── Delete files created by this plan                      |
|          ▼                                                                                         |
|   [Rescan & Verification] ──────────── Deterministic outcome comparison (resolved / persistent)     |
+----------------------------------------------------------------------------------------------------+
```

## Setup

Requires Node.js 22+ for the account SDK (tested on 26), Python 3.9+ (tested on 3.9.6), and npm. No Docker, database service, account or LLM key required.

```sh
cd Guardian
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

## Verification on 2026-10-31 (Guardian 3.1)

- Production `npm run build`: passed (Next.js 16.4.3 / webpack).
- `npm run typecheck`: passed (strict TypeScript 5.9 with zero errors).
- `npm run format`: passed (Prettier formatting verified).
- `npm test` (`scripts/test_fs_reapply.mjs`): 10 filesystem safety and rollback tests passed.
- `pytest backend/tests -q`: 187 tests passed in ~5.1s.
- Integration & Integrity tests verified:
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
  16. JSON export & legacy report compatibility (backward compatibility with legacy v1 reports and automatic `demo`/`real` classification migration).
  17. Guardian Cognitive Intelligence (Gemini 3.8 Flash, secret redaction, citation validation, deterministic fallback).
  18. Guardian Autopilot Remediation (Local project access, bounds, edit validation, unified diffs, approval, browser application, IndexedDB backup rollback, safe undo, and verification).
  19. Data Integrity & Exact Accounting: `declaredDirect + transitive === totalResolved` and disjoint status partition `inspected + skipped + unavailable + unresolved + integrity_failed + not_attempted === totalResolved`.
  20. Autopilot Multi-File Safety Hardening: Pre-flight create collision rejection, operational write journal, automatic removal of newly created files upon write failure, and safe undo removal of created files without touching subsequent user modifications.
  21. Project Investigation Workspace: 6 interactive tabs (Overview, Dependency Graph via `@xyflow/react` and `@dagrejs/dagre`, Vulnerabilities, Behavioral Flows, Remediation History, Security Timeline).

`backend/requirements.lock.txt` records the tested Python dependency versions; install it instead of `requirements.txt` to reproduce this environment.

## Limitations

This is a single-user, loopback-only prototype without authentication. Do not expose it publicly. Jobs are in-memory and are interrupted by backend restarts; completed reports persist in SQLite. Source parsing has a 20-second timeout, 256 MB Node heap, and bounded evidence.

Static data flow simulates module initialization and directly invoked call paths; loops, callbacks, dynamic imports (`import()`), dynamic requires (`require(x)`), and runtime framework lifecycles remain unmodeled. Static inference does not establish runtime execution or malicious intent.

Website dependencies are inspected via bounded lockfile resolution; packages without exact lockfile versions remain uninspected. Integrity verification confirms byte consistency with the digest, not that the code is benign. Website OSV checks exact versions only; semver ranges are disclosed as uninspected. The CLI separately resolves supported npm/PyPI graphs before installation, with vulnerability intelligence explicitly not checked. There is no runtime sandbox execution, required LLM service, source-build sandbox or public cloud source-execution service. The optional public account service stores explicitly synchronized reports; source analysis remains local. See [CLI limitations](docs/CLI.md).

See [architecture](ARCHITECTURE.md), [detection rules](DETECTION_RULES.md), [product requirements](PRD.md), and [roadmap](ROADMAP.md).
