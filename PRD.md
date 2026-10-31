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

## Core report contract

Every finding separates observed behavior, severity, detection confidence, inferred consequences, recommendations, source evidence, and explicit limitations. Independent security assessments (Behavior, Known vulnerabilities, Package integrity, and Dependency coverage) are strictly separated and never collapsed into a single numerical score. A clean scan is never a safety certificate.

**Simple mode** uses everyday explanations and readable evidence locations. **Advanced mode** reveals the same finding's observed behavior, rule ID, line/column, AST code snippet, and intermediate variable bindings. Switching modes preserves report state, finding IDs, assessment, and active selection.

## Delivered capabilities (Intelligence Engine 2.1.1 + Guardian Cognitive Intelligence 1.0)

Local npm-focused Next.js/FastAPI application; safe bounded ingestion with normalized path collision rejection, streaming decompression bomb limits, special entry guards, and unextracted nested archive handling; scope-aware lexical AST data-flow analysis with parameter, object-field, and cross-file propagation; modern lockfile traversal with reconciled disjoint dependency accounting (`inspected`, `skipped`, `unavailable`, `unresolved`, `integrity_failed`, `not_attempted`) guaranteed even at discovery ceilings; SRI tarball verification; adversarially validated OSV vulnerability enrichment with correct querybatch contract, bounded 5-page pagination, loop detection, and distinguished evidence quality; decoupled three-dimensional coverage semantics (source/behavioral, dependency resolution, vulnerability intelligence); fast/deep inspection profiles; cooperative thread-safe scan cancellation with explicit lifecycle states (`queued`, `running`, `cancelling`, `cancelled`, `complete`, `failed`) and atomic persistence lock synchronization; SQLite persistence for immutable reports and report-scoped multi-turn conversation sessions; Guardian Cognitive Intelligence 1.0 featuring Google Gemini (`gemini-3.8-flash`) integration via `google-genai` SDK, automated secret redaction, explicit privacy consent, duplicate advisory aggregation, strict citation validation against stored findings, and graceful deterministic fallback; responsive light/dark interface; comprehensive 170-test automated verification suite.

## Product boundaries

No account, cloud deployment, automated package blocking, guaranteed malware classification, package execution or independent AI-generated claims. Missing coverage, skipped dependencies, and unavailable intelligence remain clearly visible.

## Future direction

Dynamic execution sandboxing in isolated microVMs, PyPI / crates.io ecosystem support, interactive dependency graph visualizations, CI/CD pipeline integration, evidence-preserving LLM explanation providers, and team collaboration workflows. None of these is presented as implemented.
