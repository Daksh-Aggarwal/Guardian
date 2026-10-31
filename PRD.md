# Guardian product requirements

## Vision

Make software trust decisions understandable and evidence-based. Guardian is an inspection and decision-assistance platform, not a malware oracle or a chatbot wrapped around a vulnerability list.

## Users

- Nontechnical builders deciding whether to install a package.
- Developers reviewing dependency changes, transitive relationships, or unfamiliar install behavior.
- Security reviewers who need inspectable evidence, data-flow provenance, and explicit uncertainty.

## Implemented journeys

1. Upload a project ZIP or package manifests with a chosen dependency inspection profile (`fast` or `deep`); receive actual analysis-stage updates and a persistent report.
2. Enter an npm name and version/dist-tag; inspect published registry tarballs and verify Subresource Integrity (SRI) without installing or running code.
3. Inspect structured source-to-sink data-flow traces in Simple mode (everyday language) or Advanced mode (line/column numbers, code snippets, variable bindings, and limitations).
4. Review modern lockfile dependency trees, distinguishing direct and transitive dependencies with lockfile and registry checksum statuses.
5. Inspect published vulnerability advisories with CVSS vectors, affected ranges, and fixed-version boundaries alongside Guardian's separate review priority.
6. Cancel active scan jobs cleanly without losing previous report history or causing worker lockups.
7. Open reports from history, filter findings, review coverage limitations, and export reports as complete JSON documents.
8. Ask contextual questions and receive evidence-grounded answers citing specific findings, using the integrated Guardian Intelligence advisor (Gemini 3.8 Flash or local deterministic engine) with multi-turn continuity and secret redaction.
9. Run labeled synthetic examples demonstrating benign patterns, sensitive exfiltration, and installer risks.
10. Connect an existing local project folder via the browser File System Access API, analyze project context (frameworks, runtime, manifests, test runners), generate structured remediation plans with trade-offs and potential risks, inspect interactive unified diffs, approve and apply modifications with automatic IndexedDB rollback backups, safely undo changes, and rescan to deterministically verify finding resolution.
11. Review the Security Command Centre dashboard to monitor workspace-wide security posture across 4 decoupled dimensions, inspect real historical metrics, and act on evidence-grounded next steps with 1-click report navigation.
12. Explore redesigned reports with adaptive summaries, package-grouped finding hierarchies, meaningful advisory titles, fixed-version callouts, and dedicated Evidence & Data Flows tabs.
13. Interact with the collapsible Guardian Intelligence drawer, asking contextual questions about specific selected findings, with responses citing verified findings that deep-link to report evidence.
14. Investigate projects in the Project Investigation Workspace: explore interactive hierarchical dependency graphs powered by ReactFlow and Dagre, isolate vulnerable subtrees, inspect step-by-step behavioral data flows, review Autopilot remediation history with verification states, and track security posture changes across historical scans.

## Core report contract

Every finding separates observed behavior, severity, detection confidence, inferred consequences, recommendations, source evidence, and explicit limitations. Independent security assessments (Behavior, Known vulnerabilities, Package integrity, and Dependency coverage) are strictly separated and never collapsed into a single numerical score. A clean scan is never a safety certificate.

**Simple mode** uses everyday explanations and readable evidence locations. **Advanced mode** reveals the same finding's observed behavior, rule ID, line/column, AST code snippet, and intermediate variable bindings. Switching modes preserves report state, finding IDs, assessment, and active selection.

## Delivered capabilities (Intelligence Engine 2.1.1 + Guardian Cognitive Intelligence 1.0 + Guardian Autopilot Remediation 1.0 + Guardian 3.1 Investigation Workspace + Guardian 4.0 GitHub Integration & Remediation)

Local npm-focused Next.js/FastAPI application; GitHub App integration featuring server-side installation flow, RS256 JWT generation, short-lived token caching with expiration buffers, single-use cryptographic CSRF state parameters, accessible repository discovery, and branch-to-commit resolution; bounded GitHub source retrieval via Git Trees and Blobs API with truncated tree detection, strict file and byte limits (250 files, 1 MB per file, 10 MB aggregate), and secret-bearing file exclusion; repository-native Autopilot remediation with pre-flight branch commit verification, atomic multi-file Git tree and commit creation, automated pull request opening with human-review disclosures, and safe PR closure; safe bounded ingestion with normalized path collision rejection, streaming decompression bomb limits, special entry guards, and unextracted nested archive handling; explicit demo vs real project classification and session-persisted dataset filtering; deduplicated workspace metrics; scope-aware lexical AST data-flow analysis with parameter, object-field, and cross-file propagation; modern lockfile traversal with reconciled disjoint dependency accounting (`inspected`, `skipped`, `unavailable`, `unresolved`, `integrity_failed`, `not_attempted`) guaranteed even at discovery ceilings; SRI tarball verification; adversarially validated OSV vulnerability enrichment with correct querybatch contract, bounded 5-page pagination, loop detection, and distinguished evidence quality; decoupled three-dimensional coverage semantics (source/behavioral, dependency resolution, vulnerability intelligence); fast/deep inspection profiles; cooperative thread-safe scan cancellation with explicit lifecycle states (`queued`, `running`, `cancelling`, `cancelled`, `complete`, `failed`) and atomic persistence lock synchronization; SQLite persistence for immutable reports, report-scoped multi-turn conversation sessions, remediation plans, and verification records; Guardian Cognitive Intelligence featuring Google Gemini (`gemini-3.8-flash`) integration via `google-genai` SDK, automated secret redaction, explicit privacy consent, duplicate advisory aggregation, strict citation validation against stored findings, and graceful deterministic fallback; Guardian Autopilot Remediation featuring browser File System Access API integration, ephemeral in-memory snapshot retention with 30-min TTL, deterministic project understanding (frameworks, runtime, manifests, test runners), decoupled project-code AI consent, Pydantic-validated structured remediation plans, verbatim text-edit validation requiring unique anchors, non-overlapping edit checks, interactive unified diff viewer, user approval workflow with Git branch advisories, browser-side `readwrite` file application with SHA-256 pre-flight checks, automatic IndexedDB rollback backups, operational write journal, multi-file write failure rollback with created file removal, safe undo verification, and rescan verification; Project Investigation Workspace across six interactive tabs (Overview, `@xyflow/react` and `@dagrejs/dagre` interactive Dependency Graph with subtree tracing and package inspector, Vulnerabilities explorer, Behavioral Flows explorer, Remediation History audit log, and Security Timeline); responsive light/dark interface with 4/2/1 dimension grid breakpoints; comprehensive automated verification suite (208 backend pytest tests and 10 filesystem safety tests).

## Product boundaries

No account, cloud deployment, automated package blocking, guaranteed malware classification, package execution or independent AI-generated claims. Missing coverage, skipped dependencies, and unavailable intelligence remain clearly visible.

## Future direction

Dynamic execution sandboxing in isolated microVMs, PyPI / crates.io ecosystem support, CI/CD pipeline integration, evidence-preserving LLM explanation providers, and team collaboration workflows. None of these is presented as implemented.
