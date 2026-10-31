# Working on Guardian

## Structure

`app/` owns Next.js routes/theme; `components/` owns scan/report/explanation/remediation UI; `lib/types.ts` mirrors Pydantic report and remediation contracts; `lib/fs-access.ts` and `lib/indexeddb-backup.ts` manage local browser filesystem handles and recovery snapshots. Python application modules live in `backend/guardian/` (including `remediation.py`, `projects.py`, and `remediation_models.py`); `scripts/parse.cjs` is the trusted Babel AST adapter. `fixtures/` contains inert synthetic npm sources, ZIPs, and remediation demonstration fixtures. `backend/tests/` covers policy, ingestion, intelligence, project access, and remediation behavior.

## Commands

- `npm ci --ignore-scripts`
- `python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt`
- `.venv/bin/python -m uvicorn backend.guardian.main:app --host 127.0.0.1 --port 8000`
- `npm run dev` (frontend on 127.0.0.1:3000)
- `npm run build`; `npm run typecheck`
- `.venv/bin/python -m pytest backend/tests -q`
- `python3 scripts/create_fixtures.py` regenerates fixture data, never executes it.

## Conventions and constraints

Keep TypeScript strict, report contracts explicit and components focused. Keep detection policy in Python and syntax observation in the Babel adapter. Add explanatory fields and source evidence to any new rule. Simple/Advanced are presentations of the same finding IDs and assessment. The explanation provider must cite existing findings; it cannot change scanner verdicts. The LLM acts as an explanatory security advisor; the deterministic analysis engine remains authoritative. Keep documentation synchronized with behavior. Preserve explicit job lifecycle states (queued, running, cancelling, cancelled, complete, failed), decoupled three-dimensional coverage semantics (source, dependency resolution, vulnerability intelligence), and reconciled dependency accounting. Preserve privacy-first context boundaries: redact all secrets before external AI calls; require explicit opt-in user consent (with dedicated, independent consent for project code remediation); never upload source archives or execute uploaded code. Project handles remain in browser memory; file-system modifications occur strictly in the browser upon explicit user approval with pre-flight SHA-256 verification and automatic IndexedDB rollback backups. Prefer minimal dependencies and local services; no Docker/auth/cloud scaffolding without an actual requirement.

## Frontend UI and Copilot conventions

- **Contextual Copilot Panel**: `components/intelligence-panel.tsx` provides a persistent, collapsible right-side drawer that operates alongside the report. When a finding is selected or focused, pass `finding_id` in API requests so advisor explanations are scoped to the active finding.
- **Findings Hierarchy & Grouping**: When grouping findings by package, never conceal or drop individual findings. Display meaningful advisory summaries (`f.advisory?.summary`) instead of generic rule or package labels. Preserve original CVSS and review priorities separately.
- **Decoupled Assessment Domains**: Behavioral assessment, known vulnerabilities, package integrity, and inspection coverage remain strictly separate cards and metrics. Never combine them into an artificial single score.
- **Design Tokens & Themes**: All visual tokens in `app/globals.css` must support both light mode and deliberately designed dark mode (rich navy/slate surfaces, high contrast borders, and restrained accents). Never rely on simplistic CSS filter inversions.

## Security requirements

Never run fixture or uploaded code, package lifecycle scripts, user-supplied shell commands, or `npm install` inside an uploaded package. The parser may parse source only. Do not write extracted files to disk. Preserve download hostname allowlists, redirect rejection, request/file/archive/count limits, parser timeout and job concurrency boundaries. No arbitrary URL fetching. Fail visibly on unavailable intelligence and incomplete analysis. Credentials may appear in snippets; do not upload reports/source to third-party tools. Exclude secret-bearing files (`.env`, private keys) and `.git` from project snapshots, and forbid modification of lockfiles by LLM. Keep services on loopback. Recommended manual commands are displayed clearly but never executed automatically.

## Testing expectations

Tests should demonstrate behavior distinctions, including benign counterexamples, evidence locations, risk priorities, parser failure, network unavailability and malicious archives. Test the actual API path and production frontend build. External intelligence tests must mock responses; no real malware or dependency install hooks. Treat all fixture JS as inert data.

<!-- BEGIN:nextjs-agent-rules -->

## This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
