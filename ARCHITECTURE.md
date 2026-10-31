# Architecture

## Modules

- `app/`: Next.js App Router page, metadata, typography, theme and responsive styling.
- `components/scan-panel.tsx`: uploads, package lookups, profile selector (`fast`/`deep`), scan progress track, and safe scan cancellation.
- `components/report.tsx`: Simple/Advanced mode toggle, independent behavioral verdict, findings, dependencies, coverage, and JSON export.
- `components/intelligence.tsx`: independent assessment cards, dependency inspection tree, SRI integrity details, source-to-sink data-flow visualization, and advisory details.
- `components/explainer.tsx`: contextual question UI and finding citations.
- `components/ui.tsx`: small shared visual primitives.
- `lib/types.ts`: typed frontend report and job contracts, HTTP error handling, and API client.
- `backend/guardian/models.py`: authoritative Pydantic models for findings, evidence, data flows, integrity results, inspections (`InspectionSummary` with reconciled status counts), advisories, reports, and API requests.
- `backend/guardian/dependencies.py`: modern lockfile graph traversal (`lock_graph`), nearest `node_modules` resolution, bounded `RegistrySession` retrieval, and reconciled dependency accounting across direct/transitive and six mutually exclusive statuses.
- `backend/guardian/integrity.py`: strict Subresource Integrity (SRI) validation against compressed tarball bytes.
- `backend/guardian/config.py`: operator-controlled inspection budgets (`Budget`) and parser ceilings.
- `backend/guardian/ingestion.py`: in-memory archive parsing (ZIP and gzipped tarballs) with streaming decompression limits, path sanitization, and constrained registry downloads.
- `backend/guardian/limits.py`: 11 MB HTTP body boundary before multipart parsing.
- `backend/guardian/engine.py`: manifest inventory, lifecycle rules, typosquatting, AST orchestration, structured findings, and behavioral assessment (with explicit coverage-incomplete rationale).
- `scripts/parse.cjs`: trusted Babel CLI front-end adapter; stdin JSON payload, stdout structured AST observations.
- `scripts/static-flow.cjs`: scope-aware lexical bindings, interprocedural parameter propagation, object fields, destructuring, and static ESM/CJS cross-file data-flow tracking.
- `backend/guardian/intelligence.py`: exact-version OSV batch queries, bounded advisory enrichment (CVSS, ranges, fixes), validation guards, and coverage tracking.
- `backend/guardian/explanations.py`: `EvidenceExplainer` deterministic provider citing existing findings.
- `backend/guardian/advisor.py`: `GeminiAdvisor` provider using `google-genai` SDK, structured output parsing, citation validation, prompt-injection defense fences, and provider factory (`get_advisor`).
- `backend/guardian/projects.py`: ephemeral in-memory project snapshots (30-min inactivity TTL, 20-session LRU ceiling), deterministic project understanding (frameworks, runtime, language, test framework), and safe path normalization.
- `backend/guardian/remediation.py`: structured remediation planning (Gemini and deterministic fallbacks), strict text-edit validation (`old_text` -> `new_text` uniqueness and hash verification), unified diff generation, and pre/post scan verification comparison.
- `backend/guardian/remediation_models.py`: Pydantic contracts for remediation plans, proposed file changes, text edits, project metadata, and verification results.
- `lib/fs-access.ts`: browser File System Access API integration, permission lifecycle (`read` on open, `readwrite` only upon approved apply), SHA-256 pre-check, partial-write rollback, and patch bundle generation.
- `lib/indexeddb-backup.ts`: browser IndexedDB persistence for local recovery snapshots and safe undo operations.
- `components/project-workspace.tsx`: local project directory picker, exclusion inventory drawer, and project scan orchestration.
- `components/remediation-panel.tsx`: remediation approval workflow, project-code AI consent modal, git branch advisory, apply execution, undo, and rescan verification.
- `components/remediation-plan.tsx` and `components/diff-viewer.tsx`: structured plan presentation and interactive unified diff viewer.
- `backend/guardian/context.py`: privacy-first context builder, duplicate advisory aggregation, relevant finding selection, and bounded conversation history.
- `backend/guardian/redact.py`: automated secret redaction layer stripping API keys, tokens, JWTs, private keys, passwords, and auth headers before external transmission.
- `backend/guardian/storage.py`: SQLite report persistence, historical retrieval, and report-scoped multi-turn conversation and message persistence.
- `backend/guardian/main.py`: FastAPI application, bounded two-job concurrency semaphore, thread lifecycle with six explicit job states (`queued`, `running`, `cancelling`, `cancelled`, `complete`, `failed`), atomic check-before-save, idempotent cancellation, conversational intelligence endpoints, and API routes.

## Data flow

Browser → Next.js same-origin `/api` rewrite → FastAPI → bounded input → manifests + Babel static flow analysis → Python rules → bounded lockfile traversal & SRI tarball verification → OSV enrichment → independent assessments → SQLite report → Simple/Advanced UI and grounded explanation provider.

Completed reports are immutable snapshots. Report URLs use `?scan=<id>`; they are local links, not public shares. The browser polls `/api/jobs/<id>` every ~650 ms during execution. Active jobs follow an explicit state machine:
- `queued`: job created, awaiting a worker semaphore slot.
- `running`: worker acquired slot, executing analysis stages.
- `cancelling`: cooperative cancellation requested; worker signalled via `threading.Event`.
- `cancelled`: worker stopped cooperatively before persistence; semaphore slot released.
- `complete`: scan finished successfully; report persisted in SQLite.
- `failed`: scan failed due to error; semaphore slot released.

Workers perform an atomic check under concurrency lock immediately before calling `storage.save(report)`: if the job was marked `cancelling` or `cancelled`, the report is discarded, preventing race conditions. Terminal states (`cancelled`, `complete`, `failed`) are immutable.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Backend health and engine version |
| GET | `/api/ai/status` | AI provider configuration and availability status (no secrets) |
| GET | `/api/scans` | Latest 50 stored reports |
| POST | `/api/scans/upload` | Multipart `files` (ZIP or manifests) + optional `profile` form parameter (`fast` / `deep`); returns job ID |
| POST | `/api/scans/package` | JSON `name`, `version`, optional `profile` (`fast` / `deep`); returns job ID |
| GET | `/api/examples` | Available synthetic fixtures |
| POST | `/api/scans/example/{id}` | Analyze a real local fixture |
| GET | `/api/jobs/{id}` | Job state (`queued`, `running`, `cancelling`, `cancelled`, `complete`, `failed`) and stage |
| POST | `/api/jobs/{id}/cancel` | Cancel an active scan job cooperatively and release worker slot |
| GET | `/api/scans/{id}` | Full immutable report |
| GET | `/api/scans/{id}/conversation` | Report-scoped conversation messages |
| POST | `/api/scans/{id}/conversation/message` | Send contextual question to advisor (Gemini/deterministic) |
| DELETE | `/api/scans/{id}/conversation` | Clear conversation history for report |
| POST | `/api/scans/{id}/conversation/new` | Start a new conversation session for report |
| POST | `/api/scans/{id}/explain` | Contextual grounded explanation query (legacy compatibility) |
| POST | `/api/scans/project` | Ingest local project snapshot and trigger scan |
| GET | `/api/projects/{id}/metadata` | Deterministic project metadata (framework, runtime, language, test framework) |
| DELETE | `/api/projects/{id}` | Discard ephemeral in-memory project snapshot |
| POST | `/api/scans/{id}/remediation/plan` | Generate and validate structured remediation plan (Gemini / deterministic) |
| GET | `/api/remediation/plans/{id}` | Retrieve stored remediation plan |
| POST | `/api/remediation/plans/{id}/approve` | Mark remediation plan as approved by user |
| POST | `/api/remediation/plans/{id}/reject` | Mark remediation plan as rejected by user |
| POST | `/api/remediation/plans/{id}/applied` | Record plan application result from browser |
| POST | `/api/remediation/plans/{id}/verification` | Compare baseline and rescanned reports to verify remediation outcomes |
| GET | `/api/remediation/plans/{id}/verification` | Retrieve stored verification record |

## Analysis and risk

Static analysis executes in a separate Node.js process using Babel AST inspection (`scripts/static-flow.cjs`). Policy and assessment remain in Python.
The static-flow engine tracks:
1. **Lexical scopes & bindings**: Lexical block scoping, function scopes, variable declarations (`const`, `let`, `var`), reassignment, and shadowing.
2. **Interprocedural data flow**: Function calls pass arguments into parameter bindings and propagate return values.
3. **Object properties**: Field-level property writes, reads, and object destructuring (`const { a: { b } } = obj`).
4. **Module exports & imports**: Static ES module imports/exports (`export const`, `export { a as b }`, `import { b }`) and CommonJS patterns (`module.exports = ...`, `exports.foo = ...`, `require('./path')`).
5. **Cross-file tracing**: Multi-file source-to-sink paths connecting private sources to network request sinks across files.

Static data-flow findings (`SENSITIVE_TRANSMISSION`) include structured `data_flows` containing ordered `FlowStep` records (source, assignment, argument, parameter, return, sink), variable bindings, and explicit analysis limitations. Statically inferred paths are explicitly labeled as static inference, not proof of runtime execution.

Assessment areas and coverage dimensions remain strictly independent (Intelligence Engine 2.1.1):
- **Behavioral assessment & source coverage**: Evaluates static code behavior findings (excluding OSV and integrity), producing a risk rating (`No elevated signals`, `Review suggested`, `Review recommended`, `High concern`, `Critical concern`) and evidence-backed rationale. If source inspection is incomplete (e.g. parser timeout, unparsed files, or manifest-only scan), the rationale explicitly notes that source inspection was partial. Source coverage status is decoupled from external OSV or dependency retrieval outages.
- **Known vulnerabilities (OSV)**: Tracks exact-version OSV advisory matches via `/v1/querybatch` with strict 1:1 positional result validation, independent result handling (0, 1, or multiple vulnerabilities), and bounded pagination up to 5 pages per dependency with loop detection. Valid batch matches are preserved when advisory enrichment is unavailable, marked with `detail_status = 'unavailable'`.
- **Package integrity**: Tracks SRI validation results for the root package and all inspected dependencies.
- **Dependency inspection coverage**: Tracks lockfile traversal and retrieval using reconciled status counts (`inspected`, `skipped`, `unavailable`, `unresolved`, `integrity_failed`, `not_attempted`) satisfying strict totals consistency (`direct + transitive == total` and the status sum == `total`), guaranteed even when the discovery ceiling (`MAX_DISCOVERED = 2000`) is reached.

## Security boundaries

- Never execute package code, install dependencies from uploaded manifests, or invoke lifecycle commands.
- Archive members are read in memory, never extracted to the filesystem. Reject absolute/traversal/Windows paths, control characters (ASCII < 32), null bytes, links, FIFOs, sockets, character/block devices, and duplicate normalized path collisions (`seen_paths`). Nested archives are treated as unextracted non-source files and skipped.
- Streaming decompression bomb protection tracks actual bytes read against 1 MB per file and 25 MB aggregate expanded archive limits.
- Strict Subresource Integrity (SRI): validates compressed bytes using `hashlib` and `hmac.compare_digest` against supplied lockfile and registry hashes across SHA-512, SHA-384, SHA-256, and SHA-1. Extraction is refused upon digest mismatch.
- Limits: 10 MB input total, 11 MB entire HTTP request, 25 MB expanded archive, 1 MB per file, 500 archive entries.
- Registry downloads are strictly HTTPS `registry.npmjs.org` only, standard port, no redirects, bounded downloads (20 MB fast / 50 MB deep). No arbitrary URL fetching.
- OSV responses are bounded: 4 MB batch cap, 8 MB aggregate batch pagination cap, 2 MB detail cap, 5-page per-dependency limit, 15-second total timeout, query count validation, npm package/ecosystem check, CVSS type verification, and HTTPS-only reference URLs.
- Trusted parser uses fixed argv, stdin source data, no shell, 20-second timeout, and 256 MB heap. Bounded call depth (default 8) and module limits (default 100) prevent resource exhaustion.
- At most two concurrent analysis jobs via `BoundedSemaphore(2)`. Cooperative scan cancellation releases the semaphore slot exactly once. Atomic persistence lock ensures cancellations accepted before persistence discard the report, while scans already persisting under lock complete safely.
- OSV sends names and versions only; source snippets stay local.
- Local-only server binding (127.0.0.1) and no authentication. Do not expose this prototype to untrusted network clients.
