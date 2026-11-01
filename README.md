# Guardian

> **Know what you trust.** A local-first, explainable supply-chain security and remediation platform for npm and PyPI.

Guardian reads package manifests, extracts deep dependency trees, verifies cryptographic package integrity, performs deterministic static AST data-flow analysis, and surfaces actionable security intelligence. It explains findings with evidence-grounded AI, assists with safe in-browser automated remediations, and exports hardened instructions to external coding agents—all without executing untrusted code or sending source files to the cloud.

---

## Executive Overview

Software supply-chain attacks are surging: malicious lifecycle scripts, typosquatted package names, credential exfiltration, and deeply nested transitive vulnerabilities routinely evade traditional scanners. Conventional software composition analysis (SCA) tools either produce opaque lists of CVEs or collapse complex risk profiles into misleading single scores.

Guardian takes a radically different approach:

* **Deterministic Evidence First**: Rather than guessing intent, Guardian tracks concrete AST data flows from sensitive sources (environment variables, files, credentials) to network or process sinks.
* **Decoupled 4-Dimension Posture**: Risk is evaluated across four strictly independent domains—Behavioral Signals, Known Vulnerabilities (OSV), Package Integrity (SRI), and Inspection Coverage. A clean scan is never mislabeled as a "safety guarantee".
* **Safe In-Browser Autopilot**: Remediation plans are validated down to exact verbatim text replacements and applied directly in the browser via the File System Access API—backed by SHA-256 pre-flight checks, automatic IndexedDB snapshots, write journals, and one-click undo.
* **AI-Agnostic Coding Agent Handoff**: Seamlessly hand off evidence-backed remediation tasks to tools like Claude Code, Cursor, OpenAI Codex, or GitHub Copilot with built-in prompt-injection defense and machine-readable JSON evidence.
* **Zero Arbitrary Code Execution**: Guardian never runs package lifecycle scripts (`preinstall`, `postinstall`), never executes uploaded archives, and never runs untrusted code in an unmonitored sandbox.

---

## Core Capabilities

### 1. Deterministic Static Data-Flow Engine
Powered by a trusted Babel AST front-end and a Python static analysis core, Guardian models execution semantics without running code:
* **Scope-Aware Lexical Analysis**: Tracks variable declarations, reassignments, lexical scopes, and shadowing.
* **Interprocedural Propagation**: Traces values through function arguments, parameter bindings, and return values.
* **Object Field & Destructuring Tracking**: Follows data across object property writes, reads, and destructuring patterns.
* **Cross-File Data Flow**: Follows static ES Module (`import`/`export`) and CommonJS (`require`/`module.exports`) propagation paths.
* **Concrete Source-to-Sink Evidence**: Pinpoints the exact line, column, code snippet, and intermediate variable bindings for sensitive operations (e.g. `process.env.AWS_SECRET_ACCESS_KEY` $\rightarrow$ `https.request()`).

### 2. Decoupled 4-Dimension Security Assessment
Guardian refuses to conceal critical risk factors behind an arbitrary single score. Every scan report provides four independent assessments:

| Dimension | Scope & Methodology | Key Indicators |
|---|---|---|
| **1. Behavioral Assessment** | Static AST data-flow analysis & manifest inspection | Lifecycle execution scripts, dynamic code evaluation, network calls, filesystem access, typosquatting |
| **2. Known Vulnerabilities** | Querybatch integration with Open Source Vulnerabilities (OSV) database | CVE/GHSA advisories, CVSS vectors, affected version ranges, sanitized fixed versions |
| **3. Package Integrity** | Subresource Integrity (SRI) validation against published registries and lockfiles | SHA-512 / SHA-384 / SHA-256 / SHA-1 checksum match, digest tampering detection |
| **4. Inspection Coverage** | Reconciled dependency accounting across direct and transitive graphs | Exact counts for inspected, skipped, unavailable, unresolved, and integrity-failed packages |

### 3. Project Investigation Workspace
A dedicated, multi-faceted workspace for deep project-level security audits across 6 interactive views:
* **Overview**: Project identity, detected frameworks (Next.js, Express, React, Vite, Fastify, Jest, etc.), 4D posture summary, and scan-over-scan deltas.
* **Interactive Dependency Graph**: Hierarchical directed acyclic graph (DAG) powered by `@xyflow/react` and `@dagrejs/dagre` with zoom, pan, minimap, depth controls, severity filtering, focused upstream/downstream subtree isolation, and package detail drawer.
* **Vulnerabilities Explorer**: Dependency-first breakdown mapping packages to OSV advisories with published CVSS severity, Guardian review priority, and 1-click jump-to-graph actions.
* **Behavioral Flows Explorer**: Visual step-by-step trace (`Source` $\rightarrow$ `Assignment` $\rightarrow$ `Argument` $\rightarrow$ `Parameter` $\rightarrow$ `Return` $\rightarrow$ `Sink`) with syntax code snippets, variable binding badges, and explicit limitation disclosures.
* **Remediation History**: Audit log of Guardian Autopilot remediation plans, user approvals/rejections, applied files, and post-remediation rescan verification states.
* **Security Timeline**: Chronological tracking of security posture changes across commits with side-by-side delta comparisons between any two historical scans.

### 4. Guardian Autopilot — Safe Local Remediation
Remediate security findings directly in your local repository with ironclad safety boundaries:
* **Browser File System Access API**: Connects local directories (`window.showDirectoryPicker`) in read-only mode until explicit user approval. Source files never leave your machine.
* **Structured Remediation Planning**: Generates targeted remediation plans powered by Google Gemini (or local deterministic planner) with Pydantic validation, trade-off analysis, potential regressions, and manual validation steps.
* **Verbatim Text-Edit Validation**: Enforces exact verbatim `old_text` $\rightarrow$ `new_text` replacements with single-anchor verification and non-overlapping edit checks.
* **Interactive Unified Diff Viewer**: Review file-by-file changes with additions, deletions, line numbers, and downloadable `.patch` bundles.
* **Multi-Layer Safety Engine**:
  * *Pre-flight verification*: Asserts target files have not drifted by comparing on-disk SHA-256 hashes against expected baselines.
  * *Pre-flight collision rejection*: Refuses to create new files if a file already exists at the target path.
  * *Automatic IndexedDB Backup*: Captures an instant snapshot of original file contents in local browser storage before applying any write.
  * *Operational Write Journal*: Writes files sequentially; if any write fails, an automatic rollback restores modified files and deletes newly created files.
  * *Safe One-Click Undo*: Verifies file integrity before cleanly restoring the pre-remediation state from IndexedDB.
  * *Deterministic Rescan Verification*: Re-analyzes modified code to mathematically verify whether targeted findings are resolved, persistent, or if new signals were introduced.

### 5. Guardian Handoff — AI-Agnostic Agent Instructions Export
When you prefer delegating security fixes to an external coding assistant or autonomous agent, Guardian Handoff exports evidence-grounded, prompt-injection-defended instruction packages:
* **Canonical Schema (`v1.0.0`)**: Every export is derived from a single validated representation (`CanonicalHandoff`), preventing prompt drift across tools.
* **5 Tailored Agent Adapters**:
  1. *Universal Markdown*: Self-contained prompt for ChatGPT, Claude web, Gemini, or any LLM interface.
  2. *Claude Code*: Terminal-optimized instructions with file pre-inspection, minimal diffs, and verification commands.
  3. *Cursor*: IDE pair-programming workflow emphasizing scoped edits, workspace symbols, and linter checks.
  4. *OpenAI Codex*: Deterministic repository repair workflow focusing on architecture conventions and test execution.
  5. *GitHub Copilot*: GitHub-aligned chat and agent workflow emphasizing repo coding standards and pull requests.
* **Two Remediation Modes**:
  * *Focused Fix*: Minimal, conservative patch strictly addressing the immediate finding.
  * *Deep Security Remediation*: Expanded security review checking transitive trees, lockfile consistency, whole-repo insecure pattern searches, and follow-up concerns.
* **Hardened Security Defenses**: Context-aware escaping, pipe character escaping, dynamic backtick scaling (preventing code fence breakout), credential redaction, and prompt-injection defense directives instructing agents to treat scanner evidence as inert data.
* **Machine-Readable JSON Evidence Appendix**: Appends an independently parseable JSON block preserving exact finding IDs, CVSS scores, dependency paths, and provenance.

### 6. Guardian Intelligence — Contextual AI Security Advisor
* **Collapsible Persistent Drawer**: Slides in alongside reports, maintaining context with whichever finding or project tab you are currently viewing.
* **Grounded Reasoning**: Powered by Google Gemini (`gemini-3.8-flash`) via the official `google-genai` SDK, with automatic graceful fallback to the local deterministic engine when offline.
* **Privacy-First Guardrails**: Automated secret redaction layer strips API keys, tokens, credentials, and private keys before inference; requires explicit opt-in user consent.
* **Strict Citation Verification**: Every claim or citation made by the AI advisor must reference a verified finding ID from the active report—hallucinated citations are rejected. Clickable citations in the chat immediately highlight and scroll to the exact finding in the report.

### 7. Repository Integration & Pre-Installation CLI
* **GitHub App Integration**: Connect GitHub repositories with RS256 JWT authentication, explore branches and commit SHAs, ingest source via Git Trees/Blobs APIs under strict limits, and open automated Guardian Autopilot remediation Pull Requests.
* **Pre-Installation CLI (`guardian`)**: Command-line tool for npm and PyPI developers. Resolves dependency graphs and installs packages directly into isolated project environments without executing arbitrary lifecycle scripts (`npm ci --ignore-scripts` equivalent with offline hash verification).

---

## Architecture

```
+---------------------------------------------------------------------------------------------------------+
|                                           GUARDIAN ARCHITECTURE                                         |
|                                                                                                         |
|   +-----------------------+     +------------------------+     +------------------------------------+   |
|   |   Project ZIP / Code  |     |   npm / PyPI Registry  |     |   Local Folder (FS Access API)     |   |
|   +-----------+-----------+     +-----------+------------+     +-----------------+------------------+   |
|               │                             │                                    │                      |
|               └──────────────────────┬──────┴────────────────────────────────────┘                      |
|                                      ▼                                                                  |
|                        +───────────────────────────+                                                    |
|                        |   Bounded Ingestion Core  | (Decompression limits, path traversal guards,      |
|                        +─────────────┬─────────────+  secret file exclusion, normalized path checks)    |
|                                      ▼                                                                  |
|                        +───────────────────────────+                                                    |
|                        |   Static Analysis Engine  |                                                    |
|                        |   - Babel AST Static Flow | (Lexical scope, parameter propagation,             |
|                        |   - Python Security Rules |  CommonJS / ESM cross-file data flows)             |
|                        +─────────────┬─────────────+                                                    |
|                                      │                                                                  |
|            ┌─────────────────────────┼─────────────────────────┐                                        |
|            ▼                         ▼                         ▼                                        |
|   +────────────────-+       +────────────────-+       +────────────────-+                               |
|   |  OSV Database   |       |   SRI Digest    |       | Lockfile Graph  |                               |
|   |  (Batch Query)  |       |  Verification   |       | (Reconciliation)|                               |
|   +────────┬────────+       +────────┬────────+       +────────┬────────+                               |
|            └─────────────────────────┼─────────────────────────┘                                        |
|                                      ▼                                                                  |
|                        +───────────────────────────+                                                    |
|                        | Immutable Security Report | (4 Decoupled Dimensions, Reconciled Accounting)   |
|                        +─────────────┬─────────────+                                                    |
|                                      ▼                                                                  |
|      ┌───────────────────────────────┴───────────────────────────────┐                                  |
|      ▼                                                               ▼                                  |
|  +─────────────────────────────────────────────+       +─────────────────────────────────────────────+  |
|  |             Next.js Web Interface           |       |              Local Guardian CLI             |  |
|  | - Security Command Centre & Report View     |       | - guardian check                            |  |
|  | - 6-Tab Project Investigation Workspace    |       | - guardian install (script-free, verified)  |  |
|  | - Interactive Dependency DAG (ReactFlow)    |       | - Private local SQLite report persistence   |  |
|  | - Guardian Intelligence Advisor (Gemini)    |       +─────────────────────────────────────────────+  |
|  | - Guardian Autopilot In-Browser Remediation |                                                        |
|  | - Guardian Handoff to External AI Agents   |                                                        |
|  +─────────────────────────────────────────────+                                                        |
+---------------------------------------------------------------------------------------------------------+
```

### Safety & In-Browser Rollback Architecture

```
[Finding Identified] ──> [Generate Remediation Plan] ──> [Review Unified Diff]
                                                                  │
                                                                  ▼
                                                      [Explicit User Approval]
                                                                  │
                                                                  ▼
                                                    [Pre-Flight Verification]
                                                    - Target file SHA-256 match
                                                    - New file does not exist
                                                                  │
                     ┌─────────────────── Fail ───────────────────┤ Success
                     ▼                                            ▼
               [Abort Apply]                         [Capture IndexedDB Backup]
             (No disk changes)                                    │
                                                                  ▼
                                                    [Apply Changes via Journal]
                                                    - Sequential atomic writes
                                                                  │
                     ┌─────────────────── Fail ───────────────────┤ Success
                     ▼                                            ▼
           [Automatic Rollback]                         [Plan Marked Applied]
         - Restore modified files                                 │
         - Delete created files                     ┌─────────────┴─────────────┐
                                                    ▼                           ▼
                                            [Rescan & Verify]           [One-Click Undo]
                                         (Prove finding resolved)   (Restore from IndexedDB)
```

---

## Live Demo Presentation Walkthrough

Follow this step-by-step walkthrough to present Guardian's core capabilities in a live demo:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              LIVE DEMO FLOW (10-15 MIN)                                │
│                                                                                        │
│  1. Baseline Inspection ──> 2. AST Data Flow ──> 3. AI Intelligence ──>                │
│     (Benign fixture)          (Exfiltration)        (Grounded Advisor)                 │
│                                                                                        │
│  4. Graph Investigation ──> 5. In-Browser Autopilot ──> 6. Multi-Agent Handoff         │
│     (Interactive DAG)          (Safe Fix & Rescan)         (Claude Code / Cursor)      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Step 1: The Everyday Baseline (Observations vs False Positives)
1. In the **Security Command Centre**, click the synthetic fixture: **Everyday package**.
2. Notice that public HTTP access and reading environment variables are cataloged as **Observations**, not elevated risks.
3. Show how Guardian avoids alert fatigue: normal library behavior is recognized without triggering alarm bells.

### Step 2: Uncovering AST Data-Flow Leaks
1. Click **Sensitive data flow** on the launchpad.
2. In the report, select the sensitive data transmission finding and toggle to **Advanced mode**.
3. Point out the exact step-by-step AST propagation trace:
   * **Source**: `process.env.NPM_TOKEN` (reading authentication secret).
   * **Assignment**: Bound to local variable `token`.
   * **Parameter**: Passed as header payload into `requestOptions`.
   * **Sink**: Transmitted across the network via `https.request()`.
4. Highlight that Guardian provides line numbers, column numbers, syntax snippets, and explicit static analysis limitations.

### Step 3: Correlated Behavioral Risks & Guardian Intelligence
1. Click **Suspicious installer**.
2. Notice multiple correlated risks: `INSTALL_REMOTE` (downloading code in a postinstall script) combined with `EXEC_DYNAMIC` (spawning child processes).
3. Open the **Guardian Intelligence** drawer on the right.
4. Click the suggested question: *"What should I do next?"*
5. Demonstrate that the AI advisor cites verified findings with clickable links that scroll and highlight the evidence directly in the report.

### Step 4: Exploring the Project Investigation Workspace
1. Navigate to **Project workspace** in the sidebar.
2. Open the **Dependency Graph** tab to reveal the interactive DAG:
   * Zoom, pan, and search for specific packages.
   * Filter nodes by severity (Critical / High / Medium / Low).
   * Click an infected dependency to isolate its upstream and downstream subtrees.
   * Open the package inspector drawer to view exact lockfile resolution versions and SRI checksum verifications.
3. Check the **Behavioral Flows** tab to see source-to-sink data paths visualized as discrete flow step cards.

### Step 5: Guardian Autopilot In-Browser Remediation
1. In the Project Workspace, select `fixtures/remediation-demo` (or connect a local folder with the directory picker).
2. Click **Inspect project** to analyze the codebase.
3. Review the identified `INSTALL_REMOTE` lifecycle finding.
4. Click **Prepare a fix with Guardian**.
5. Inspect the generated plan:
   * View the structured analysis: summary, trade-offs, potential regressions, and manual steps.
   * Open the **Interactive Diff Viewer** showing the exact unified diff removing the dangerous install hook.
6. Click **Approve and apply**:
   * The browser requests write permission only upon user confirmation.
   * Guardian captures an IndexedDB backup snapshot and writes the changes to disk.
7. Click **Rescan & verify outcome**:
   * Guardian automatically rescans the updated project.
   * The verification panel confirms: `INSTALL_REMOTE` **Resolved**!
8. Click **Undo latest changes** to demonstrate instant, risk-free rollback restoring the original files.

### Step 6: Multi-Agent Handoff
1. Open any report and click **Export Handoff Instructions**.
2. In the modal, select your target coding assistant (e.g., **Claude Code**, **Cursor**, or **Universal Markdown**).
3. Toggle between **Focused Fix** and **Deep Security Remediation** to show how instructions adapt based on task depth.
4. Point out the built-in defenses:
   * Escaped markdown delimiters preventing prompt injection.
   * Directives instructing the external agent to treat findings as untrusted data.
   * The **JSON Evidence Appendix** adhering to Canonical Handoff Schema `1.0.0`.
5. Click **Copy to Clipboard** or **Download (.md)** to hand off the task.

---

## Quickstart

### Prerequisites
* **Node.js**: 20.9+ (tested on Node 22 and 26)
* **Python**: 3.9+ (tested on Python 3.9.6, 3.11, 3.12)
* **npm**: standard package manager

### 1. Installation
Clone the repository and install dependencies:

```sh
cd Guardian
npm ci --ignore-scripts
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
```

### 2. Launch Services
Start the Python FastAPI backend:
```sh
.venv/bin/python -m uvicorn backend.guardian.main:app --host 127.0.0.1 --port 8000
```

In a second terminal, start the Next.js frontend:
```sh
npm run dev
```

Open **http://127.0.0.1:3000** in your browser.  
Backend OpenAPI documentation is available at **http://127.0.0.1:8000/docs**.

> The Next.js frontend automatically proxies `/api/*` requests to `http://127.0.0.1:8000`, so all browser requests remain strictly same-origin.

---

## Configuration

Configuration is managed via environment variables. See `.env.example` for reference.

### Backend Environment Variables
Set shell variables before launching the Uvicorn server:

```sh
# Enable Google Gemini AI Security Advisor (Optional)
GUARDIAN_AI_ENABLED=true
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-3.8-flash

# OSV Vulnerability Intelligence (Defaults to true)
GUARDIAN_OSV_ENABLED=true

# Database Path (Defaults to backend/guardian.sqlite3)
GUARDIAN_DB=backend/guardian.sqlite3

# Operator Inspection Ceilings
GUARDIAN_MAX_PACKAGES=20       # Max packages per deep scan (default: 6 fast, 20 deep)
GUARDIAN_MAX_DEPTH=4          # Max dependency tree depth (default: 2 fast, 4 deep)
GUARDIAN_DOWNLOAD_MB=50        # Max aggregate download size in MB
GUARDIAN_EXPANDED_MB=80        # Max aggregate decompressed size in MB
```

> **Privacy Guarantee**: Guardian works completely offline and deterministically without an LLM key. When `GUARDIAN_AI_ENABLED` is omitted or `false`, the platform automatically falls back to its deterministic explanation engine. API keys and source code are never uploaded or exposed in logs.

---

## Guardian CLI

Guardian includes a pre-installation CLI tool that allows developers to safely check and install packages from their terminal:

```sh
# Install CLI in editable mode inside your virtual environment
.venv/bin/python -m pip install -e .

# Inspect an npm or PyPI package without running scripts
guardian check --ecosystem npm lodash@4.17.21
guardian check --ecosystem pypi requests

# Verify integrity and install with lifecycle scripts disabled
guardian install express                      # npm project
guardian install requests                     # PyPI project
guardian install                              # All declared dependencies in manifest
```

See [docs/CLI.md](docs/CLI.md) for full CLI commands, security boundaries, and local cache mechanics.

---

## Verification & Testing

Guardian maintains an exhaustive test suite covering static analysis, archive security, rollback journals, and OSV integration:

```sh
# Run full backend test suite (200+ tests)
.venv/bin/python -m pytest backend/tests -q

# Run frontend typecheck and tests
npm run typecheck
npm test

# Build production bundle
npm run build
```

---

## Security Principles & System Guardrails

* **Zero Arbitrary Execution**: Guardian never executes package lifecycle scripts (`preinstall`, `postinstall`, `prepare`), never executes uploaded archives, and never executes untrusted code in an unmonitored sandbox.
* **Privacy & Local-First Boundaries**: Project files remain in browser memory handles; file writes occur strictly upon explicit user approval; all secrets, tokens, and keys are automatically redacted prior to any external AI advisor call.
* **Reconciled Accounting Invariants**: Every dependency and finding is accounted for arithmetically:
  $$\text{declaredDirect} + \text{transitive} = \text{totalResolved}$$
  $$\text{inspected} + \text{skipped} + \text{unavailable} + \text{unresolved} + \text{integrity\_failed} + \text{not\_attempted} = \text{totalResolved}$$
* **No Single Artificial Metric**: Behavioral risk, known vulnerabilities, cryptographic integrity, and inspection coverage are strictly separated. An OSV API outage never conceals static behavioral findings, and static clean scans never guarantee the absence of unknown vulnerabilities.
* **Operator Ceilings**: Hard limits on memory (256 MB Node heap), decompression size (25 MB aggregate), package depth, and execution time (20s parser timeout) protect the host system from zip-bomb and resource exhaustion attacks.

---

## Project Structure

```
Guardian/
├── app/                        # Next.js App Router (Layouts, themes, navigation)
├── components/                 # React UI Components
│   ├── scan-panel.tsx          # Scan launchpad, file dropzone & package lookup
│   ├── report.tsx              # 4D report view, finding breakdown & filters
│   ├── project-workspace.tsx   # 6-tab Project Investigation Workspace
│   ├── dependency-graph.tsx    # Interactive DAG explorer (@xyflow/react + dagre)
│   ├── vulnerabilities-explorer.tsx # Hierarchical OSV vulnerability explorer
│   ├── behavioral-flow-explorer.tsx # Visual source-to-sink data flow steps
│   ├── remediation-panel.tsx   # Guardian Autopilot approval, apply & undo
│   ├── remediation-plan.tsx    # Structured remediation plan & trade-offs
│   ├── diff-viewer.tsx         # Interactive unified diff viewer
│   ├── handoff-modal.tsx       # Guardian Handoff export dialog (5 AI targets)
│   ├── intelligence-panel.tsx  # Persistent Guardian Intelligence drawer
│   └── github-connect-panel.tsx# GitHub App repository connection panel
├── backend/guardian/           # Python Security Core & FastAPI Application
│   ├── main.py                 # API routes, job state machine & concurrency lock
│   ├── engine.py               # Manifest inventory, static flow orchestration
│   ├── dependencies.py         # Lockfile graph traversal & dependency accounting
│   ├── integrity.py            # Subresource Integrity (SRI) validation
│   ├── intelligence.py         # OSV batch query, CVSS & advisory enrichment
│   ├── advisor.py              # Gemini AI security advisor & secret redaction
│   ├── projects.py             # In-memory project snapshots & framework detection
│   ├── remediation.py          # Autopilot remediation planning & diff validation
│   ├── handoff.py              # Canonical handoff builder & target adapters
│   └── storage.py              # SQLite report & conversation persistence
├── scripts/                    # AST Parsers & Verification Scripts
│   ├── parse.cjs               # Trusted Babel AST adapter
│   └── static-flow.cjs         # Scope-aware static data-flow tracker
├── fixtures/                   # Synthetic test fixtures (inert, never executed)
│   ├── benign/                 # Benign baseline patterns
│   ├── exfiltration/           # Sensitive data exfiltration AST traces
│   ├── postinstall/            # Correlated postinstall execution risks
│   └── remediation-demo/       # Complete Autopilot repair demonstration
└── docs/                       # Technical documentation & guides
    ├── CLI.md                  # Pre-installation CLI guide
    ├── CLI-BUDGETS.md          # Acquisition budgets & diagnostics
    └── ACCOUNTS-DEPLOYMENT.md  # Account sync & deployment guide
```

---

## Documentation

* [Architecture Deep Dive](ARCHITECTURE.md) — System modules, data flow, concurrency, and API contracts
* [Detection Rules Specification](DETECTION_RULES.md) — Rule IDs, severity classifications, and AST matchers
* [Product Requirements (PRD)](PRD.md) — Personas, delivered capabilities, and design contracts
* [Roadmap](ROADMAP.md) — Ecosystem expansion, sandboxing evolution, and future milestones
* [CLI Security & Resolution](docs/CLI.md) — Command reference, offline verified installs, and security limits
