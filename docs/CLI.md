# Guardian CLI 0.2

Guardian has a local npm and PyPI pre-installation workflow. The website remains an independent scanner. Both call `core.analyze_sources`, delegating to the existing Python rules, Python AST visitor, and Babel static-flow engine. The CLI never contacts a Guardian server, AI provider, or OSV, and never uploads source, artifacts, or reports automatically.

This release implements a conservative subset of package-manager behavior. Unsupported graphs fail closed. Passing static inspection does not prove that importing or running a package is safe.

## Install and run

From this trusted checkout, with Node.js 20.9+, npm, and Python 3.9+ (3.11+ recommended):

```sh
npm ci --ignore-scripts
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
# A current pip/setuptools is needed for the editable entry point:
.venv/bin/python -m pip install --upgrade pip setuptools
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/guardian --help
.venv/bin/guardian --version
```

Distribution name: `guardian-local-security`; executable: `guardian`. Editable installation is the supported distribution workflow: the trusted parser, Babel and npm semver dependencies reside in this repository. Keep the checkout and its `node_modules`. A standalone Python wheel does not bundle Node.js or JavaScript dependencies; copying only Python files is insufficient for npm resolution and JavaScript analysis. A missing parser yields incomplete coverage, never a clean allow. No published release or prebuilt standalone binary is supplied.

Without installing the entry point, run from the checkout:

```sh
.venv/bin/python -m backend.guardian --help
.venv/bin/python -m backend.guardian check --ecosystem npm lodash@4.17.21
```

The implementation uses pathlib, fixed subprocess argv and secure temporary directories. Automated installation tests ran on macOS with actual npm and pip. Linux and Windows are not verified in this change; Windows requires working Node/npm commands and a Python virtual environment. Python 3.9 remains compatible but is past upstream support.

Run the independent website in two terminals:

```sh
.venv/bin/python -m uvicorn backend.guardian.main:app --host 127.0.0.1 --port 8000
npm run dev
```

Open [the local website](http://127.0.0.1:3000). Uploads, project inspection and registry scans do not require the CLI or an account.

## Commands

Run the executable from the target project. One supported ecosystem manifest selects automatically. With both ecosystems or neither present, use `--ecosystem`; Guardian never infers ecosystem from a package name. `npm:` and `pypi:` prefixes also select explicitly.

```sh
guardian install express                      # npm project
guardian install lodash@4.17.21
guardian install requests                     # Python project, active target venv
guardian install                              # supported declared dependencies
guardian install --ecosystem npm express
guardian install --ecosystem pypi requests
guardian check npm:express                    # no installation
guardian check pypi:requests
guardian audit                               # source + declared dependency artifacts
guardian report
guardian report --json
guardian report --output guardian-report.json
guardian status
guardian login                               # explicit unavailable-feature error
guardian logout                              # confirms local mode/no stored credentials
guardian sync                                # explicit unavailable-feature error
```

`check` and `audit` never change installation state. Online audit acquires declared dependency artifacts; it does not attest bytes already in `node_modules` or `site-packages`. npm includes existing declared dependencies when adding a package; PyPI preserves existing supported project constraints. Neither executes project scripts.

| Flag (after subcommand) | Behavior |
| --- | --- |
| `--ecosystem npm\|pypi` | Explicit selection; conflicts and mixed prefixes rejected. |
| `--json` | JSON report/error on stdout, with stable exit code. |
| `--output PATH` | Atomic private JSON export; parent must exist. |
| `--offline` | Local acquired archives or project source audit, no registry resolution. |
| `--no-sync` | Local only, also the unconditional default. |
| `--yes` | Acknowledge WARN; insufficient for BLOCK or REVIEW. |
| `--force --yes` | Explicit locally recorded findings override. Cannot override unverified bytes, incomplete graphs/source coverage, source builds, or required missing intelligence. |
| `--verbose` | Include informational observations and coverage limitations. |
| `--policy PATH` | Explicit JSON policy; project policy files are not automatically trusted. |

Offline examples:

```sh
guardian check ./previously-acquired.tgz --ecosystem npm --offline
guardian check ./distribution-1.0.0-py3-none-any.whl --ecosystem pypi --offline
guardian check ./distribution-1.0.0.tar.gz --ecosystem pypi --offline
guardian audit --ecosystem npm --offline
```

Local artifacts retain SHA-256 identity but cannot establish trusted registry provenance or complete dependencies: expect REVIEW or BLOCK, not installation approval. Offline source audit explicitly omits dependencies. There is no persistent artifact cache for offline registry resolution; arbitrary local archive installation is refused. npm accepts local `.tgz`/`.tar.gz`; PyPI accepts compatible `.whl`, `.tar.gz` and `.zip` sdists.

## npm security and supported workflows

1. Read supported declarations and package-lock v2/v3 without running package code. Resolve tags/ranges with trusted semver. Traverse direct, transitive and optional dependencies, pinning every version; cycles may reference resolved ancestors.
2. Acquire only through bounded HTTPS npm allowlists, rejecting redirects and URL/git/file dependencies. Verify registry integrity and existing lock integrity before parsing. Verify tarball identity/declarations match registry metadata.
3. Validate every archive header and expanded-size bounds. Reject traversal, absolute/Windows paths, duplicate normalized paths, noncanonical npm roots, links and special files. Read source in memory; unsupported assets remain coverage gaps.
4. Shared analysis and central policy evaluate every acquired dependency. Failed integrity/resolution never reaches installation.
5. Recheck approved hashes. Populate a fresh isolated npm cache from approved tarballs, then run trusted `npm ci --offline --ignore-scripts --no-audit --no-fund` against the exact generated lock. Clean HOME/config excludes inherited npm settings and Node preload flags. Cache integrity binds installed bytes to inspected bytes; npm cannot choose an online substitute.
6. Stage before touching existing `node_modules`. Recheck manifest/lock content, swap the staged tree and write the manifest/lock. Restore previous files if handoff fails. The CLI serializes installs via `.guardian-install.lock`; after a crash, remove a stale lock only after confirming no process still holds it.

Locked versions/digests are retained unless an explicit root replacement is requested. The generated v3 lock and installation layout use a conservative nested tree, so lock locations can change without version changes. npm validates this exact graph before project mutation. Installing independent tarballs is not used as a substitute for a graph. Requested root versions are written exactly to the manifest.

Peers, workspaces, overrides, bundled dependencies, aliases, shrinkwrap, lock v1, git/file/direct URLs and unsupported lock locations fail closed. Optional dependencies are inspected even if npm later omits them for the platform. Deep acquisition budgets/operator ceilings apply: defaults include 20 graph locations, 42 requests, 60 seconds; hard ceiling 40 locations. Large graphs may remain unsupported.

All lifecycle scripts, including root project hooks and benign hooks, remain disabled after installation. Guardian has no automatic script approval runner. Packages needing a native build may remain nonfunctional. Review scripts/referenced source before separately deciding to run a package manager command yourself; that leaves Guardian's script-free boundary.

## PyPI security and supported workflows

Bounded resolution uses registry JSON and wheel METADATA: PEP 440 pins/ranges, compatible platform/interpreter tags, `Requires-Python`, `Requires-Dist`, markers, extras and bounded backtracking. Direct URL/VCS requirements are rejected before acquisition. Downloads use trusted HTTPS hosts, no redirects, resource limits and registry SHA-256. Wheel filename, embedded identity and selected release must agree.

Projects support plain named `requirements.txt` lines or static PEP 621 `project.dependencies`. Requirement includes/directives/constraints/editables/input hash options/continuations, dynamic dependencies, Poetry/uv/Pipenv locks and other unsupported lock formats fail closed. Exporting a supported named requirements file is a manual user decision. Python manifests are not rewritten, and unsupported locks are never claimed honored. Manifest snapshots are verified again before installation; symlinked manifests are refused.

Compatible wheels are preferred. Archives are validated before static analysis; metadata/bookkeeping are inspected separately, and opaque native assets require REVIEW. Activate the target venv explicitly:

```sh
source /path/to/target-venv/bin/activate
/path/to/Guardian/.venv/bin/guardian install --ecosystem pypi requests
```

`VIRTUAL_ENV` selects the target; global installs are refused. Resolution uses Guardian's interpreter/platform. Before pip starts, the target interpreter's version/implementation/platform/ABI/architecture are checked with isolated Python and site loading disabled; mismatches are refused. Approved hashes are checked again, then approved wheel archives are written to a private temporary directory. Trusted target pip runs with `--isolated --no-index --no-deps --only-binary=:all: --require-hashes --no-cache-dir --no-compile --force-reinstall`. Same-version installed packages are replaced from approved bytes. Wheels are never imported for analysis/validation.

pip may partially modify the environment before failure; Guardian records failure without claiming rollback. Use a dedicated project venv. The target interpreter, pip and preexisting startup configuration are part of the trusted host boundary.

Sdists are acquired, hash-checked and inspected when no compatible wheel exists. Dynamic dependencies/build metadata make the plan incomplete. Guardian never runs setup.py, PEP 517 metadata hooks, build backends or build dependency installation. No host build or claimed sandbox exists. Sdist installation cannot be forced. A future secured build workflow must inspect the final wheel separately.

## Policy and reports

| Decision | Meaning |
| --- | --- |
| ALLOW | Verified bytes, completed supported graph/source inspection and no warning/blocking findings under policy. Not a safety certification. |
| WARN | Findings below blocking thresholds; installation needs `--yes`. |
| BLOCK | Findings meet blocking thresholds; a permitted explicit findings override must be acknowledged to install. |
| REVIEW | Insufficient provenance, coverage or execution support. Installation refused. |

Default block threshold: high severity with medium/high confidence. Critical low-confidence findings receive WARN. Informational observations remain in reports. Coverage defects can coexist with BLOCK and make it non-overridable. Integrity acquisition failures use a separate exit code and never reach installers.

Explicit policy example:

```json
{"block_severity":"high","block_confidence":"medium","require_intelligence":true}
```

CLI vulnerability intelligence is `not checked`, disclosed independently of behavior, integrity and inspection. `require_intelligence: true` requires REVIEW and cannot be overridden. The default evaluates local static behavior/provenance without requiring advisory availability. Website OSV behavior remains unchanged.

Reports retain existing finding IDs, severity/confidence, evidence and flow traces. Package findings carry ecosystem and artifact SHA-256. Typed, versioned `cli.schema_version: "1.0"` adds roots, exact identities/hashes, dependency edges, package/aggregate decisions, reasons, overrides and actual installation outcome. Existing report fields and independent assessment domains remain website/Handoff compatible.

Storage: `$XDG_STATE_HOME/guardian` or `~/.local/state/guardian` on Unix, `%LOCALAPPDATA%/Guardian` on Windows; `GUARDIAN_HOME` overrides. JSON files use private creation permissions and atomic replacement; source archives are not retained. Snippets may contain secrets: keep reports/exports private. Security decisions and install failures are saved. Acquisition errors emit a structured error rather than fabricating a completed analysis.

Exit codes: `0` successful command/permitted acknowledged installation; `2` block; `3` review/unacknowledged warning; `4` acquisition/configuration/unavailable feature; `5` integrity; `6` internal error; `7` install failure. Displaying an earlier BLOCK with `report` returns `0`; its stored decision remains BLOCK.

## Website import and connected-mode boundary

Export JSON, open **Open a Guardian CLI report** on the website overview, choose the file, check explicit local-storage consent and click Import. Existing report UI shows decision/reasons/status. The imported report gets a new ID, redacted credentials, stripped GitHub identity and prominent unverified-origin label. It cannot overwrite trusted scans or turn supplied claims into independently verified scans. Existing Handoff uses its stored evidence.

`POST /api/cli/reports` accepts `{report, consent:true}`, validates CLI metadata and enforces an 8 MB import limit. `GET /api/cli/capabilities` advertises actual capabilities.

**No Guardian account identity, device approval, revocable account-token service, cloud storage or cross-device sharing exists.** GitHub installation sessions are not CLI account credentials. `login`/`sync` explicitly fail; `status`/`logout` honestly describe local mode without storing tokens. Authenticated connected scenario F is not demonstrated. A future backend needs browser device approval, identity-scoped report ownership, expiry/revocation, OS credential storage and explicit sync consent. There are no fake tokens or plaintext project credentials.

The GitHub audit removed HTTP global-installation fallbacks and sole-installation auto-authorization. Valid sessions must authorize the exact report installation for report/job/snapshot/remediation/conversation/history/Handoff access. Another app installation is insufficient. Legacy GitHub reports lacking installation identity require a rescan. Concurrent session-storage work in this checkout persists sessions in SQLite; integration guards validate expiry before reading authorization. This is a single-user loopback service; the existing GitHub installation handshake is not a general public account service.

## Development and demonstrated scenarios

```sh
.venv/bin/python -m pytest backend/tests -q
npm test
npm run typecheck
npm run build
git diff --check
```

Synthetic registries in `test_cli_npm.py`/`test_cli_pypi.py` serve inert in-memory archives, independent of live registries. Real trusted npm/pip perform approved benign installs into temporary projects/venvs. Fixture modules, scripts and build backends never run. `test_cli.py` covers actual parsing/acquisition/core/policy/reporting/install prevention; `test_cli_bridge.py` covers HTTP consent, import validation and isolation.

| Scenario | Actual demonstration |
| --- | --- |
| A npm prevention | CLI + mock registry blocks malicious transitive source before installer; lifecycle sentinel absent. |
| B PyPI prevention | CLI + mock registry blocks malicious wheel; sdist checked without running backend. |
| C benign npm install | CLI + real offline npm installs inspected bytes with exact lock and disabled hooks. |
| D benign PyPI install | CLI + real pip installs inspected wheel into temporary venv; adapter test repairs same-version substituted bytes. |
| E independent website | Existing upload/project/package API tests and production frontend build, no CLI/account. |
| F authenticated sync | Not implemented: no suitable account/device backend. Explicit local import is separately tested/labeled. |
| G offline local | CLI scans acquired archives and project source, saves/exports reports without Guardian services. |

These are reproducible local tests, not live public-registry production claims. Static analysis is bounded: callbacks, dynamic imports, computed behavior, uncalled functions and native code may be uninspected. Actual parser/flow omissions require REVIEW. Even supported complete static coverage cannot prove runtime reachability, benign intent, author identity, registry trustworthiness or host safety.

## Verification record — November 1, 2026

- Full backend suite: **390 passed**. Existing dependency/deprecation warnings remain.
- Frontend tests: **35 passed** (29 filesystem/project/version tests, 6 Handoff tests).
- Production Next.js build and strict TypeScript check: passed.
- Python compilation and CLI help/version/status smoke checks: passed.
- Prettier checks for the new import component, updated TypeScript contracts and npm manifests: passed. Existing formatting issues remain elsewhere in `app/page.tsx` and `components/report.tsx`; no unrelated formatting rewrite was applied. No separate lint script is configured.
- Changed-file whitespace checks passed for this implementation. Full-tree `git diff --check` still flags trailing whitespace and an extra final blank line in concurrently modified `backend/guardian/storage.py`, which was preserved.

Changed components: `core.py`, `supply_models.py`, `policy.py`, `npm_adapter.py`, `pypi_adapter.py`, `cli.py`, `__main__.py`, `local_reports.py`, `cli_bridge.py`; report models, engine parser environment and Python AST source-to-sink integration; API/GitHub isolation and Handoff artifact identity; `components/cli-report-import.tsx`, existing report/overview UI and `lib/types.ts`; four CLI/bridge test modules plus session regression fixtures; root `pyproject.toml`, Python requirements, npm manifests, README and architecture docs. Concurrent session persistence changes in `storage.py`/GitHub/API were retained and integrated without discarding them.
