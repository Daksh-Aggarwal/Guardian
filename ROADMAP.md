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
- [x] Guardian Cognitive Intelligence 1.0: Google Gemini (`gemini-3.8-flash`) provider integration via `google-genai` SDK, structured advisor output, prompt-injection defense fences, citation validation against report findings, and deterministic fallback.
- [x] Privacy-first context management: explicit user consent controls, automated secret redaction layer, and compact context minimization.
- [x] Multi-turn report-scoped conversation sessions stored in SQLite with strict report isolation and bounded turn limits.
- [x] Coverage-aware behavioral assessment presentation and duplicate advisory aggregation.
- [x] Guardian Autopilot — Remediation Agent 1.0: Local project connection via Browser File System Access API (`window.showDirectoryPicker` in read-only initial mode).
- [x] Ephemeral in-memory project snapshot retention (30-min inactivity TTL, 20-session LRU ceiling) with deterministic project understanding (frameworks, runtime, language, test runners).
- [x] Decoupled project-code AI consent boundary with automated secret redaction.
- [x] Structured remediation planning with Pydantic schemas, prompt-injection defense fences, and resilient deterministic fallback.
- [x] Strict text-edit validation: exact verbatim `old_text` -> `new_text` replacements, requiring anchors to appear exactly once, non-overlapping edit checks, SHA-256 pre-verification, and unified diff generation.
- [x] Polished interactive unified diff viewer with additions, deletions, line numbers, file tabs, and downloadable `.patch` bundles.
- [x] Explicit user approval workflow with Git branch advisories.
- [x] Browser-side `readwrite` file application with SHA-256 pre-flight checks, automatic IndexedDB rollback backups, partial-write recovery, and safe undo verification.
- [x] Deterministic rescan & outcome verification comparing pre-remediation and post-remediation security findings.
- [x] Guardian 3.0 Security Command Centre: Meaningful metrics derived from historical report data, 4D decoupled security posture breakdown, evidence-grounded recommended actions, and modernized security launchpad.
- [x] Redesigned Report Experience: Adaptive contextual summaries, 4 independent dimension cards, tabbed report navigation (Findings, Dependencies, Coverage, Evidence & Data Flows), meaningful advisory titles, package-grouped finding presentation, and practical multi-dimensional filters.
- [x] Guardian 3.1 Data Integrity & Project Investigation Workspace:
  - [x] Explicit project classification (`real` vs `demo`) with safe legacy migration validator and persistent global dataset filter (`All`, `Real Projects`, `Demo Data`).
  - [x] Deduplicated dashboard metrics by unique project name, distinguishing scans, unique projects, and unique dependency names.
  - [x] Reconciled dependency accounting and report semantics (`declaredDirect + transitive === totalResolved`, disjoint status sum == `totalResolved`).
  - [x] Responsive 4/2/1 dimension grid breakpoints preventing clipping or horizontal scrolling across all viewports.
  - [x] Project Investigation Workspace integrating 6 dedicated tabs:
    - [x] Overview: Project identity, metadata, 4 independent dimensions, and previous scan delta.
    - [x] Interactive Dependency Graph: Hierarchical DAG visualizer (`@xyflow/react` + `@dagrejs/dagre`), zoom/pan/minimap, severity filtering, depth limits, focused subtree tracing, and package detail inspector panel.
    - [x] Vulnerabilities Explorer: Dependency-first OSV advisory explorer with CVSS vectors, Guardian review priority, and jump-to-graph actions.
    - [x] Behavioral Flow Explorer: Step-by-step source-to-sink flow trace (`Source` -> `Assignment` -> `Argument` -> `Parameter` -> `Return` -> `Sink`) with syntax code snippets.
    - [x] Remediation History: Project-level audit log of Guardian Autopilot plans, status badges, and rescan verification outcomes.
    - [x] Security Timeline: Chronological security posture timeline and side-by-side 2-scan delta comparator.
  - [x] Guardian Autopilot Multi-File Safety Hardening: Pre-flight create collision rejection, operational write journal, automatic removal of newly created files upon write failure, and safe undo removal of created files without touching user edits.
  - [x] Product Terminology Standardization: Guardian, Guardian Intelligence, Guardian Autopilot.
- [x] Guardian Handoff 1.0 & 1.0.1 — AI-Agnostic Remediation & Agent Instruction Export Hardening:
  - [x] Shared canonical handoff model (`CanonicalHandoff`, schema v1.0.0) grounding all target formats in identical scan truth.
  - [x] Strict scope enforcement: zero silent fallback, empty selection rejection, duplicate normalization, and exact scope classification.
  - [x] Substantive remediation mode divergence: Focused Fix (minimal safe edits, unit tests) vs Deep Security Remediation (transitive dependencies, shared package paths, pattern search, blast radius).
  - [x] Evidence-grounded recommendations: explicit classification, candidate upgrade compatibility disclosures, lifecycle script native binding cautions, and workspace dataflow tracing requirements.
  - [x] Exact ecosystem-aware package normalization: PEP 503 PyPI normalization, scoped npm package support, elimination of substring matching false positives.
  - [x] Reconciled coverage accounting across inspected, skipped, unavailable, unresolved, integrity-failed, and not-attempted states.
  - [x] Evidence-based provenance: accurate scanned commit SHA disclosures, no fabricated staleness.
  - [x] Adversarial security hardening: context-aware escaping, dynamic code-fence backtick scaling, table cell escaping, and prompt-injection defense directives.
  - [x] Ecosystem-aware validation guidance (npm, PyPI, and unknown).
  - [x] API session/installation access boundary enforcement.
  - [x] Five tailored coding agent targets: Universal Markdown, Claude Code, Cursor, OpenAI Codex, and GitHub Copilot.
  - [x] Machine-readable JSON evidence appendix with versioned schema `1.0.0` preserving findings, advisories, CVSS, paths, and provenance.
  - [x] Automatic secret and credential redaction, markdown injection sanitization, and adversarial prompt injection defense.
  - [x] Support for single-finding, multiple selected findings, and entire-scan scopes.
  - [x] Preserved GitHub and local project provenance without fabricated metadata.
  - [x] Interactive UI modal with mode switching, agent selection, readable preview, raw markdown, JSON appendix, copy-to-clipboard, and sanitized `.md` download.
- [x] Guardian 4.0 — GitHub Integration & Repository-Native Remediation:
  - [x] Server-side GitHub App installation flow with RS256 JWT signing, short-lived in-memory token caching, and cryptographic single-use CSRF state tokens.
  - [x] Repository and branch discovery with real-time name search, visibility status (private vs public), and default branch identification.
  - [x] Bounded Git Data API repository retrieval (trees and blobs) with truncated tree detection, strict file boundaries (250 files, 1 MB file, 10 MB aggregate), and secret file exclusions.
  - [x] Full integration with Guardian's authoritative 4D security analysis engine, persisting immutable source commit SHA and branch metadata.
  - [x] Project Investigation Workspace support for GitHub-backed repositories with stable repository identity (`github:{repo_id}`) and branch-aware security timeline comparisons.
  - [x] Guardian Autopilot GitHub-native remediation: pre-flight source commit verification (rejecting stale branches), atomic Git tree and commit creation, automated descriptive Pull Request opening with human-review disclosures, and safe PR closure audit path.

## Next priorities

1. Configurable report retention and historical report deletion policies.
2. Expanded lockfile support for pnpm and Yarn Berry v2+ formats.
3. Automated CI/CD action/CLI command (`guardian scan`) for pull request checks.
4. Accessible keyboard navigation and screen-reader audit.

## Later

- Isolated microVM execution sandbox for dynamic package detonation.
- PyPI and crates.io package registry adapters.
- Sigstore / npm provenance signature verification.
- Team workspaces and role-based access control.
