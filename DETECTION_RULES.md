# Implemented detection rules

## Interpretation

Severity is potential review priority. Confidence measures strength of observed evidence, never probability that the author is malicious. Ordinary capabilities remain informational. The overall behavioral verdict follows the maximum severity of behavioral findings and names its supporting rules. Independent domains (behavior, vulnerabilities, integrity) are never collapsed into a single score. Critical is reserved in the contract; current rules emit up to high.

When source inspection is incomplete (e.g. parser timeout, unparsed files, or manifest-only scan), the behavioral assessment rationale explicitly notes that source inspection was partial and that an absence of signals in uninspected files does not certify package safety. Source coverage is decoupled from external OSV intelligence availability and dependency graph budgets.

| Rule | Evidence and rationale | Priority / confidence | Domain |
|---|---|---|---|
| CREDENTIAL_ACCESS | AST environment access (`process.env`), common AWS/GitHub/npm credential literals, or sensitive-file string (`.ssh/`, `id_rsa`, `.npmrc`, `.aws/credentials`) | info / high | behavior |
| NETWORK | AST fetch, axios, http(s) request/get; ordinary capability | info / high | behavior |
| SENSITIVE_TRANSMISSION | Static data-flow path connecting a sensitive source to a network sink via lexical bindings, function calls, object fields, or module imports. Contextual authentication (Authorization headers) is separated into medium priority. | high (outbound payload) or medium (auth context) / medium (low if unmodeled transformation occurs) | behavior |
| DYNAMIC_EXECUTION | AST eval call or Function constructor/call | low / high | behavior |
| ENCODED_CONTENT | atob or Buffer.from with base64/hex encoding argument | info / high | behavior |
| OBFUSCATED_EXECUTION | Statically connected decoded data reaching dynamic code execution | medium / medium | behavior |
| INSTALL_SCRIPT | Manifest preinstall/install/postinstall/prepare command | info / high | behavior |
| INSTALL_REMOTE | Lifecycle command curl/wget with HTTP(S) URL; elevated if piped to sh/bash or eval/node -e also occurs | medium or high / high | behavior |
| PROCESS_EXECUTION | child_process exec/spawn/execFile and synchronous variants | low / high | behavior |
| REMOTE_PAYLOAD | Literal child-process command downloads through curl/wget | medium / high | behavior |
| FILESYSTEM | Common fs read/write/readdir calls, including promises | info / high | behavior |
| TYPO | Edit distance one or selected character substitution compared with 25 curated popular npm names | medium / low | behavior |
| PACKAGE_INTEGRITY | Published tarball failed Subresource Integrity (SRI) validation against lockfile or npm registry digest | high / high | integrity |
| OSV | Exact npm version matched by OSV vulnerability database with published advisory details (CVSS, affected ranges, fixed boundaries). When enrichment is unavailable, the batch match is preserved with `detail_status = 'unavailable'` and explicit limitation notes. | advisory priority (medium default) / high match confidence | vulnerability |

## Structured evidence

Each finding stores ID, rule, title, category, severity, confidence, observed behavior, everyday explanation, possible consequence, action, and an evidence array.
- Source evidence includes file, one-based line and column, a bounded snippet, and detection detail.
- Data-flow findings (`SENSITIVE_TRANSMISSION`) store ordered `data_flows` with `FlowStep` records (source, assignment, argument, parameter, return, sink), variable binding names, and analysis limitation notes.
- Advisory findings (`OSV`) store structured `advisory` details (CVE/GHSA ID, summary, severity, CVSS scores/vectors, affected ranges, fixed versions, and aliases).
- Findings retain up to 12 evidence items per kind per file; parser observations are capped at 250 per file and truncation is disclosed.

## False-positive controls and known gaps

- **Scope-aware lexical analysis**: The static-flow engine (`scripts/static-flow.cjs`) maintains lexical scope trees, distinguishes block and function scopes, handles variable shadowing and reassignment, and tracks object properties and destructuring.
- **Interprocedural propagation**: Function arguments are mapped to formal parameter bindings and return values are tracked back to call sites.
- **Cross-file tracing**: Static ES module (`import`/`export`) and CommonJS (`require`/`module.exports`) imports and exports are linked across project source files.
- **Intentional authentication separation**: Sensitive values reaching HTTP `Authorization` headers or auth options are classified under `authentication` context with medium review priority and distinct explanations.
- **Coverage-incomplete disclosures**: If packages or files are skipped due to budget limits, retrieval outages, or extraction failures, behavioral verdicts refuse to assert safety and explicitly disclose partial coverage.
- **Explicit static inference**: All data-flow paths are labeled as static inference, not runtime proof. When an unknown transformation occurs on a path, confidence is downgraded to `low` and limitation notes are attached.
- **Remaining gaps**:
  - Loops (`for`, `while`) and iteration constructs are not unrolled; variable mutations inside loops are approximated.
  - Dynamic imports (`import(x)`) and dynamic requires (`require(variable)`) cannot be statically resolved and are disclosed in scan coverage.
  - Asynchronous event listeners, promises, and uncalled callbacks are not simulated beyond direct invocations.
  - Shell lifecycle detection is pattern-based; complex scripts and external scripts require manual inspection.
  - OSV queries exact versions; dependencies without exact lockfile versions remain uninspected.
  - Tarball integrity proves byte consistency with the digest, not that the package author is trusted.

## Verification sources

Parser options and AST nodes follow [Babel parser documentation](https://babeljs.io/docs/babel-parser). Subresource Integrity validation follows W3C SRI specifications and RFC 6920. OSV request ordering, batch queries, and advisory details follow [OSV API documentation](https://google.github.io/osv.dev/). The UI does not invent vulnerability summaries or CVSS scores absent from upstream responses.
