# CLI acquisition budgets and diagnostics

## Root causes

The original Lodash failure occurred inside `RegistrySession.retrieve()`: its first archive read used the global 500-entry project-upload reader. The npm adapter repeated that same restriction in its second archive pass. The adapter then replaced the archive exception with a generic acquisition error, concealing the cause. Lodash's release contains well over 500 files and is not an oversized download.

The Express failure was separate: the resolver used `len(records)` (nested installation locations) against the website deep-profile package limit of 20, with a hard maximum of 40. Repeated copies of an identical dependency consumed that same budget, were appended as duplicate artifacts, and were analysed repeatedly.

The fixes keep the existing detection engine, policy, integrity verification, registry allowlist, exact lockfile workflow and script-free installer. No online `npm install` resolution or package execution is used.

## Archive profiles

Every archive has independent entry, compressed-byte, expanded-byte, per-file, supported-text-file and elapsed-time limits. Environment values are clamped, never allowed to remove hard ceilings. Sizes are MiB (1,048,576 bytes); all numbers below are **default / hard ceiling**.

| Budget | Project upload | npm tarball | PyPI wheel | PyPI sdist |
| --- | --- | --- | --- | --- |
| Entries | 500 / 500 | 10,000 / 20,000 | 10,000 / 20,000 | 10,000 / 20,000 |
| Compressed MiB | 10 / 10 | 20 / 50 | 30 / 100 | 20 / 50 |
| Expanded MiB | 25 / 25 | 80 / 200 | 100 / 300 | 80 / 200 |
| Single file MiB | 1 / 1 | 1 / 4 | 5 / 20 | 2 / 8 |
| Supported text/source files | 500 / 500 | 5,000 / 10,000 | 5,000 / 10,000 | 5,000 / 10,000 |
| Archive inspection seconds | 15 / 30 | 20 / 60 | 20 / 60 | 20 / 60 |
| CLI analysis seconds per artifact | — | 30 / 60 | 30 / 60 | 30 / 60 |

Archive environment names follow `GUARDIAN_<PROFILE>_ARCHIVE_<FIELD>`, where profile is `UPLOAD`, `NPM`, `WHEEL` or `SDIST`, and field is `ENTRIES`, `COMPRESSED_MB`, `EXPANDED_MB`, `FILE_MB`, `SOURCES`, `SECONDS` or `ANALYSIS_SECONDS`. The CLI applies the corresponding per-artifact analysis-time setting to online and local npm/wheel/sdist plans. Complete PyPI plan analysis defaults to 180 seconds, with a 600-second hard ceiling configured by `GUARDIAN_PYPI_ANALYSIS_SECONDS`. Upload settings cannot raise the existing upload hard limits.

Example:

```sh
GUARDIAN_NPM_ARCHIVE_ENTRIES=15000 guardian check --ecosystem npm example
```

`RegistrySession.retrieve()` supplies the npm profile on its actual first archive read. The adapter reuses those verified extracted contents rather than parsing the archive again. Local npm checks use that same reader/profile. Both the PyPI CLI adapter and the website PyPI session choose wheel/sdist profiles instead of inheriting upload limits.

All opaque member bytes count against expanded/per-file limits even when excluded from analysis. Skipped files remain coverage gaps. Member reads validate damage/CRC and run under a deadline. Traversal, absolute/Windows paths, duplicate normalized paths, symlinks, hardlinks and special files remain refused. npm requires the canonical `package/` root, including opaque entries. Inspection reads members in memory; it never writes extracted source onto disk. Only approved installation invokes trusted package managers to install the approved archives.

## npm graph and session budgets

CLI budgets are independent of website fast/deep scan profiles.

| Budget | Default | Hard ceiling | Environment variable |
| --- | ---: | ---: | --- |
| Unique artifacts | 256 | 1,024 | `GUARDIAN_NPM_UNIQUE_ARTIFACTS` |
| Installation locations | 2,048 | 10,000 | `GUARDIAN_NPM_LOCATIONS` |
| Dependency depth, root = 1 | 32 | 64 | `GUARDIAN_NPM_DEPTH` |
| HTTP requests | 512 | 2,048 | `GUARDIAN_NPM_REQUESTS` |
| Downloaded MiB, metadata + artifacts | 128 | 512 | `GUARDIAN_NPM_DOWNLOAD_MB` |
| Expanded MiB across artifacts | 256 | 1,024 | `GUARDIAN_NPM_EXPANDED_MB` |
| Resolution + acquisition seconds | 180 | 600 | `GUARDIAN_NPM_SECONDS` |
| Complete plan analysis seconds | 180 | 600 | `GUARDIAN_NPM_ANALYSIS_SECONDS` |

A unique artifact means one exact `(npm, name, version)` identity. Its registry metadata, verified compressed bytes, source contents and static findings are reused. Two versions remain separate artifacts. Each installation location still validates its own lockfile digest against those same bytes; a different or mismatching expectation cannot be hidden by the cache.

Every location remains in the generated lockfile and in `cli.installation_locations`, with its exact identity/hash and location-specific dependency edges. Reused artifacts can have different child versions in different lockfile contexts: the report retains both exact child artifacts and each location's edge. Cycles reference compatible ancestors and terminate. Root/direct status is retained if a shared artifact is also directly requested.

Existing locked versions remain pinned; supported graphs use the existing conservative nested installation layout rather than assuming independently installed tarballs are equivalent to a graph. Peers, workspaces, overrides, bundled dependencies and other unsupported manager features still fail closed. There is no new general npm hoisting/peer solver.

The installer rechecks artifact hashes, names, versions and SRI. A digest binds the approved manifest, generated lockfile and location/hash map, so modifying the approved graph fails before npm. Only unique tarballs populate an isolated cache; exact installation remains offline `npm ci --ignore-scripts`, with project preflight checks and staged handoff/rollback.

Reports distinguish `unique_artifacts`, `location_count`, `installation_locations`, acquisition counters and configured budgets. Existing inspection summaries describe unique acquired artifacts; location count is shown separately. Repetition cannot create duplicate findings merely because one exact artifact appears in multiple locations.

PyPI's CLI resolver additionally caps aggregate expanded content at 128 MiB, configurable through `GUARDIAN_PYPI_EXPANDED_MB` with a 512 MiB hard ceiling. Website PyPI retrieval keeps its operator-controlled session ceiling. Increasing wheel entry limits therefore does not create an unbounded aggregate expansion path.

## Static-analysis boundaries

Archive acceptance and dependency resolution do not establish complete behavioral inspection. Existing Babel limits still apply: default 100 modules, 100,000 AST nodes and 100,000 evaluation steps; existing operator ceilings are 300 modules, 300,000 nodes and 400,000 steps. These are independent of accepted archive/source-file counts. The Node heap remains bounded at 256 MiB. Python AST and source omissions retain their existing handling.

Actual parser failures, module/step/call/trace omissions, opaque content and exhausted analysis time require REVIEW and cannot be forced through policy. Findings already obtained are retained. A plan whose time budget expires leaves remaining artifacts explicitly uninspected. This work does not expand the detection engine into complete runtime, callback, native-code or arbitrary dynamic-module analysis.

## Safe diagnostics

Acquisition errors now expose stable `diagnostic.category`, `operation`, optional package, budget, configured limit, encountered count and safe detail. Examples include:

- `registry_unavailable`, `registry_timeout`, `registry_http_error`, `registry_response_limit`
- `tarball_timeout`, `tarball_download_limit`, `download_budget_limit`, `registry_request_limit`
- `invalid_package_metadata`, `invalid_registry_location`, `dependency_resolution_failure`, `unsupported_dependency_feature`, `dependency_graph_limit`, `acquisition_time_limit`
- `archive_entry_limit`, `archive_source_limit`, `archive_file_limit`, `archive_expanded_limit`, `archive_compressed_limit`, `archive_timeout`, `unsupported_archive_entry`, `unsafe_archive_path`, `unsafe_archive_root`, `duplicate_archive_path`, `invalid_archive`
- `integrity_mismatch`, `integrity_unverified`, `integrity_invalid`

Normal terminal output identifies the category and measured limit when applicable. `--verbose` adds operation/package/budget fields before any report exists. `--json` returns structured diagnostics without contaminating stdout with progress output. Integrity failure remains exit 5; other acquisition failures remain exit 4; incomplete analysis produces a REVIEW report/exit 3. Internal programming errors remain internal errors rather than fabricated network outages. Original exception causes are preserved internally; raw causes, credentials, response bodies and sensitive host paths are not printed.

Request accounting counts actual HTTP calls. Full packuments are reused for exact release metadata; duplicate artifacts do not trigger repeated tarball downloads or decompression. Successful and partially failed transfers consume download budget, and failed archive reads consume actual expanded-byte work already performed.

## Regression and real registry evidence

`backend/tests/test_npm_acquisition_budgets.py` adds deterministic coverage for:

- A valid npm package with 1,200 additional source files and opaque assets through the actual RegistrySession path; exactly one archive read.
- Configurable entry caps and the actual 20,001st-entry hard-ceiling rejection; independent source/file/expanded/time/byte limits and unchanged upload cap.
- A graph with 41 locations but 13 artifacts, two versions of one package, shared children and ancestor cycles; exactly 25 HTTP calls and one analysis per artifact.
- Per-location integrity expectations and context-specific child versions for a shared artifact.
- Exact real npm installation of a deduplicated graph without executing its lifecycle hook, and refusal of modified approved graphs.
- Normal/verbose/JSON timeout, HTTP, invalid metadata, oversize download, archive, graph and integrity diagnostics; private causes are not exposed.
- Partial download accounting, internal-error distinction and unoverrideable static-analysis budget exhaustion.
- Wheels/sdists with more than 500 files; opaque and aggregate Python expansion limits.

Existing npm/PyPI, API, engine, upload and session-isolation tests remain in the regression suite. Tests use mock registries, never real malware or live registry dependencies.

Live smoke commands were actually run on November 1, 2026 in an isolated temporary project, without `--force`, custom allow policies, package imports or lifecycle execution:

| Command | Actual outcome |
| --- | --- |
| `guardian check --ecosystem npm lodash@4.17.21` | Acquisition completed: 1 artifact, 1 location, 2 HTTP requests; REVIEW / exit 3 due to existing module/coverage limits. |
| `guardian check --ecosystem npm express` | Acquisition completed: 68 artifacts, 503 locations, 136 HTTP requests; REVIEW / exit 3 due to existing unsupported/static coverage. |
| `guardian install --ecosystem npm lodash@4.17.21` | REVIEW / exit 3; installation blocked before npm because coverage was incomplete. No claim of a successful Lodash installation. |
| `npm ls --depth=0` | Exit 0 with an empty project tree; Lodash was not installed. |
| `guardian audit --ecosystem npm` | A local report was generated; REVIEW / exit 3, including unverified local project provenance and partial dependency source coverage. |
| `guardian report` | Report displayed successfully / exit 0. |

The smoke runner used `--json` to record results. The resolver downloaded 566,639 bytes and expanded 1,412,415 member bytes for Lodash; Express downloaded 5,228,849 bytes and expanded 2,301,912 member bytes. Live Express resolution took approximately 38 seconds in that run. Registry state/timing can change; these figures are observations, not fixed expected values.

Repeat the commands in a clean project with an installed Guardian CLI and explicit ecosystem. Do not interpret REVIEW as acquisition failure, successful installation, or proof of malicious behavior. The archive/location failures are fixed; full static coverage and successful installation of these particular large/dynamic packages remain unproven under the existing engine's limits.

Final verification: **442 backend tests passed**, including **43 new acquisition/budget regression cases**; **35 frontend tests passed**; strict TypeScript checking, Python compilation and an isolated production Next.js build passed. Whitespace checks passed for changed implementation files. Whole-file Prettier still flags the pre-existing `initSession` signature in `lib/types.ts`; it was left unchanged to preserve unrelated session work. No separate Python lint/format command is configured in this repository. No live-registry command is part of the standard automated suite.
