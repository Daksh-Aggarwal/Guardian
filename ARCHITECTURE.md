# Architecture

## Modules

- `app/`: Next.js App Router page, metadata, typography, theme and responsive styling.
- `components/scan-panel.tsx`: uploads, package lookups, profile selector (`fast`/`deep`), scan progress track, and safe scan cancellation.
- `components/report.tsx`: Simple/Advanced mode toggle, independent behavioral verdict, findings, dependencies, coverage, and JSON export.
- `components/intelligence.tsx`: independent assessment cards, dependency inspection tree, SRI integrity details, source-to-sink data-flow visualization, and advisory details.
- `components/explainer.tsx`: contextual question UI and finding citations.
- `components/ui.tsx`: small shared visual primitives.
- `lib/types.ts`: typed frontend report and job contracts, HTTP error handling, and API client.
- `backend/guardian/models.py`: authoritative Pydantic models for findings, evidence, data flows, integrity results, inspections, advisories, reports, and API requests.
- `backend/guardian/dependencies.py`: modern lockfile graph traversal (`lock_graph`), nearest `node_modules` resolution, and bounded `RegistrySession` retrieval.
- `backend/guardian/integrity.py`: strict Subresource Integrity (SRI) validation against compressed tarball bytes.
- `backend/guardian/config.py`: operator-controlled inspection budgets (`Budget`) and parser ceilings.
- `backend/guardian/ingestion.py`: in-memory archive parsing (ZIP and gzipped tarballs) and constrained registry downloads.
- `backend/guardian/limits.py`: 11 MB HTTP body boundary before multipart parsing.
- `backend/guardian/engine.py`: manifest inventory, lifecycle rules, typosquatting, AST orchestration, structured findings, and behavioral assessment.
- `scripts/parse.cjs`: trusted Babel CLI front-end adapter; stdin JSON payload, stdout structured AST observations.
- `scripts/static-flow.cjs`: scope-aware lexical bindings, interprocedural parameter propagation, object fields, destructuring, and static ESM/CJS cross-file data-flow tracking.
- `backend/guardian/intelligence.py`: exact-version OSV batch queries, bounded advisory enrichment (CVSS, ranges, fixes), and coverage tracking.
- `backend/guardian/explanations.py`: `EvidenceExplainer` deterministic provider citing existing findings.
- `backend/guardian/storage.py`: SQLite report persistence and historical retrieval.
- `backend/guardian/main.py`: FastAPI application, bounded two-job concurrency semaphore, thread lifecycle, job stages, cancellation, and API routes.

## Data flow

Browser → Next.js same-origin `/api` rewrite → FastAPI → bounded input → manifests + Babel static flow analysis → Python rules → bounded lockfile traversal & SRI tarball verification → OSV enrichment → independent assessments → SQLite report → Simple/Advanced UI and grounded explanation provider.

Completed reports are immutable snapshots. Report URLs use `?scan=<id>`; they are local links, not public shares. The browser polls `/api/jobs/<id>` every ~650 ms during execution. Stages are emitted by the actual worker. Safe cancellation signals the worker thread and aborts before persistence.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Backend health and engine version |
| GET | `/api/scans` | Latest 50 stored reports |
| POST | `/api/scans/upload` | Multipart `files` (ZIP or manifests) + optional `profile` form parameter (`fast` / `deep`); returns job ID |
| POST | `/api/scans/package` | JSON `name`, `version`, optional `profile` (`fast` / `deep`); returns job ID |
| GET | `/api/examples` | Available synthetic fixtures |
| POST | `/api/scans/example/{id}` | Analyze a real local fixture |
| GET | `/api/jobs/{id}` | Running / complete / failed / cancelled state and stage |
| POST | `/api/jobs/{id}/cancel` | Cancel an active scan job and release worker slot |
| GET | `/api/scans/{id}` | Full immutable report |
| POST | `/api/scans/{id}/explain` | Contextual grounded explanation query |

## Analysis and risk

Static analysis executes in a separate Node.js process using Babel AST inspection (`scripts/static-flow.cjs`). Policy and assessment remain in Python.
The static-flow engine tracks:
1. **Lexical scopes & bindings**: Lexical block scoping, function scopes, variable declarations (`const`, `let`, `var`), reassignment, and shadowing.
2. **Interprocedural data flow**: Function calls pass arguments into parameter bindings and propagate return values.
3. **Object properties**: Field-level property writes, reads, and object destructuring (`const { a: { b } } = obj`).
4. **Module exports & imports**: Static ES module imports/exports (`export const`, `export { a as b }`, `import { b }`) and CommonJS patterns (`module.exports = ...`, `exports.foo = ...`, `require('./path')`).
5. **Cross-file tracing**: Multi-file source-to-sink paths connecting private sources to network request sinks across files.

Static data-flow findings (`SENSITIVE_TRANSMISSION`) include structured `data_flows` containing ordered `FlowStep` records (source, assignment, argument, parameter, return, sink), variable bindings, and explicit analysis limitations. Statically inferred paths are explicitly labeled as static inference, not proof of runtime execution.

Assessment areas remain strictly independent:
- **Behavioral assessment**: Evaluates static code behavior findings (excluding OSV and integrity), producing a risk rating (`No elevated signals`, `Review suggested`, `Review recommended`, `High concern`, `Critical concern`) and evidence-backed rationale.
- **Known vulnerabilities**: Tracks exact-version OSV advisory matches, published CVSS vectors, and fixed boundaries.
- **Package integrity**: Tracks SRI validation results for the root package and all inspected dependencies.
- **Source inspection**: Tracks coverage (inspected, skipped, unresolved, unavailable) under the selected budget profile.

## Security boundaries

- Never execute package code, install dependencies from uploaded manifests, or invoke lifecycle commands.
- Archive members are read in memory, never extracted to the filesystem. Reject absolute/traversal/Windows paths, links, tar special files and duplicate paths.
- Strict Subresource Integrity (SRI): validates compressed bytes using `hashlib` and `hmac.compare_digest` against supplied lockfile and registry hashes across SHA-512, SHA-384, SHA-256, and SHA-1. Extraction is refused upon digest mismatch.
- Limits: 10 MB input total, 11 MB entire HTTP request, 25 MB expanded archive, 1 MB per file, 500 archive entries.
- Registry downloads are strictly HTTPS `registry.npmjs.org` only, standard port, no redirects, bounded downloads (20 MB fast / 50 MB deep). No arbitrary URL fetching.
- Trusted parser uses fixed argv, stdin source data, no shell, 20-second timeout, and 256 MB heap. Bounded call depth (default 8) and module limits (default 100) prevent resource exhaustion.
- At most two concurrent analysis jobs via `BoundedSemaphore(2)`. Scan cancellation releases the semaphore slot safely.
- OSV sends names and versions only; source snippets stay local.
- Local-only server binding (127.0.0.1) and no authentication. Do not expose this prototype to untrusted network clients.
