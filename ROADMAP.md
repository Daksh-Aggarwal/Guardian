# Roadmap

## Implemented

- [x] Local Next.js + FastAPI + SQLite architecture.
- [x] Responsive dashboard, theme switch, scan history, and JSON export.
- [x] Safe in-memory ZIP/manifests/tarball ingestion and resource limits.
- [x] Scope-aware lexical binding, block and function scoping, variable reassignment and shadowing.
- [x] Interprocedural argument-to-parameter propagation and return value tracking.
- [x] Object property tracking and destructuring assignment.
- [x] Static ES module (`import`/`export`) and CommonJS (`require`/`exports`) cross-file data-flow analysis.
- [x] Source-to-sink data-flow trace visualization with step markers, locations, snippets, bindings, and limitations.
- [x] Modern lockfile (`package-lock.json` v2/v3) dependency graph traversal with nearest `node_modules` lookup.
- [x] Fast and Deep dependency inspection profiles with operator-configurable ceilings.
- [x] Strict Subresource Integrity (SRI) verification for tarballs across SHA-512, SHA-384, SHA-256, and SHA-1.
- [x] OSV vulnerability intelligence batch queries and advisory detail enrichment (CVSS vectors, affected ranges, fixed versions).
- [x] Independent assessment areas: Behavioral signals, Known vulnerabilities, Package integrity, and Dependency coverage.
- [x] Safe scan cancellation endpoint (`POST /api/jobs/{id}/cancel`) and interactive UI control.
- [x] Simple and Advanced report modes over identical finding models.
- [x] Deterministic contextual explanation provider citing stored findings.
- [x] Synthetic demonstration fixtures and comprehensive test suite (151 automated tests).
- [x] Cooperative thread-safe scan cancellation with explicit job lifecycle states (`queued`, `running`, `cancelling`, `cancelled`, `complete`, `failed`) and atomic pre-persistence checks.
- [x] Reconciled disjoint dependency inspection accounting across direct/transitive packages and six mutually exclusive statuses, guaranteed even at discovery ceilings.
- [x] Correct OSV querybatch contract validation (0, 1, or multiple vulnerabilities per query; strict positional correspondence; graceful malformed-record handling).
- [x] OSV bounded pagination (`next_page_token` traversal up to 5 pages per dependency, loop detection, aggregate byte budgets, resilient partial results).
- [x] Decoupled three-dimensional coverage semantics throughout models and UI (source/behavioral, dependency resolution, vulnerability intelligence).
- [x] Archive ingestion hardening with normalized path collision rejection, control character detection, symlink/hardlink/special entry rejection, aggregate decompression bomb protection, and unextracted nested archive handling.

## Next priorities

1. Interactive dependency graph visualizer showing dependency edges and risk propagation.
2. Evidence snippet secret redaction prior to export or display.
3. Configurable report retention and historical report deletion policies.
4. Expanded lockfile support for pnpm and Yarn Berry v2+ formats.
5. Automated CI/CD action/CLI command (`guardian scan`) for pull request checks.
6. Accessible keyboard navigation and screen-reader audit.

## Later

- Isolated microVM execution sandbox for dynamic package detonation.
- PyPI and crates.io package registry adapters.
- Sigstore / npm provenance signature verification.
- Provider-backed LLM explanation integration with strict citation verification.
- Team workspaces and role-based access control.
