/* Bounded abstract data-flow evaluator, not a JavaScript runtime.
 * Values contain origins, paths, object fields, static API references or AST closures.
 * No host function is callable, no user module is imported, no source is evaluated.
 */
const { parse } = require("@babel/parser");
const posix = require("node:path").posix;
const CREDENTIAL =
  /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|pypi-[A-Za-z0-9_-]{32,}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b|-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/;
const PRIVATE_FILE =
  /(\.ssh\/|id_rsa|id_ed25519|\.npmrc|\.pypirc|\.aws\/credentials|\.kube\/config|kubeconfig|\.docker\/config\.json|\.git-credentials|\.netrc|(?:^|[\/\\])\.env(?:\.[a-z0-9_]+)?$|\.bash_history|\.zsh_history|\.config\/gcloud|\.azure\/accessTokens\.json|\.vault-token|discord[\/\\]Local Storage[\/\\]leveldb|Login Data|Local State|key4\.db|logins\.json|\/etc\/shadow)/i;
const PERSISTENCE_PATH =
  /(\/etc\/cron|\/var\/spool\/cron|crontab|\/etc\/systemd\/system|\.config\/systemd\/user|LaunchAgents|LaunchDaemons|\.bashrc|\.bash_profile|\.zshrc|\.profile|\.git\/hooks\/(?:pre-commit|post-checkout|post-merge|pre-push)|CurrentVersion\\Run|schtasks)/i;
const CLOUD_METADATA =
  /(?:https?:\/\/)?(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)(?:\/|$)/i;
const MINING_INDICATOR =
  /\b(?:stratum\+tcp:\/\/|stratum\+ssl:\/\/|xmrig|cryptonight|randomx|coinhive|minergate|nanopool|supportxmr|hashvault)\b/i;
const SELF_PROPAGATION_CMD =
  /\b(?:npm\s+publish|twine\s+upload|gh\s+repo\s+create|git\s+push\b.*--force)\b/i;
const DEFENSE_IMPAIR_CMD =
  /\b(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|Set-MpPreference\s+-DisableRealtimeMonitoring|ufw\s+disable|iptables\s+-F|setenforce\s+0)\b/i;
const SENSITIVE_NAME =
  /(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL|ACCESS_KEY)/i;
const empty = () => ({ paths: [], props: new Map() });
let sequence = 0;
class Scope {
  constructor(parent = null, fn = false) {
    this.parent = parent;
    this.fn = fn;
    this.bindings = new Map();
  }
  cell(name) {
    return this.bindings.get(name) || this.parent?.cell(name);
  }
  declare(name, value = empty(), kind = "let") {
    let target = this;
    if (kind === "var")
      while (target.parent && !target.fn) target = target.parent;
    if (!target.bindings.has(name))
      target.bindings.set(name, { id: `b${++sequence}:${name}`, value });
    return target.bindings.get(name);
  }
}
function analyzeProject(files, overrides = {}) {
  const limits = {
    maxNodes: 100000,
    maxSteps: 100000,
    maxCalls: 300,
    maxDepth: 8,
    maxModules: 100,
    maxPaths: 12,
    maxTrace: 24,
    ...overrides,
  };
  const modules = new Map(),
    warnings = new Set(),
    projectStagedFiles = new Set();
  let nodes = 0,
    steps = 0,
    calls = 0,
    depth = 0;
  const active = new Set();
  function warn(m, text) {
    if (warnings.size < 200) {
      const msg = `${m?.file || "project"}: ${text}`;
      warnings.add(msg);
      m?.warnings.add(msg);
    }
  }
  function tick(m) {
    if (++steps > limits.maxSteps)
      throw new Error("Static evaluation step budget exceeded");
  }
  function loc(m, n, kind, detail, binding) {
    return {
      file: m.file,
      line: n?.loc?.start.line || 1,
      column: (n?.loc?.start.column || 0) + 1,
      snippet: m.code.slice(n?.start || 0, n?.end || 0).slice(0, 500),
      detail,
      kind,
      ...(binding ? { binding } : {}),
    };
  }
  function unique(paths, m) {
    const seen = new Set(),
      out = [];
    for (const p of paths) {
      const k = JSON.stringify(p);
      if (!seen.has(k)) {
        seen.add(k);
        out.push(p);
      }
    }
    if (out.length > limits.maxPaths)
      warn(m, "Origin-path limit reached; additional paths omitted.");
    return out.slice(0, limits.maxPaths);
  }
  function allPaths(v, m, seen = new Set()) {
    if (!v || seen.has(v)) return [];
    seen.add(v);
    return unique(
      [
        ...(v.paths || []),
        ...[...(v.props || new Map()).values()].flatMap((p) =>
          allPaths(p, m, seen),
        ),
      ],
      m,
    );
  }
  function allHostPaths(v, m, seen = new Set()) {
    if (!v || seen.has(v)) return [];
    seen.add(v);
    return unique(
      [
        ...(v.hostPaths || []),
        ...[...(v.props || new Map()).values()].flatMap((p) =>
          allHostPaths(p, m, seen),
        ),
      ],
      m,
    );
  }
  function merge(values, m, level = 0) {
    values = values.filter(Boolean);
    if (values.length === 1) return values[0];
    if (level > 6) {
      warn(m, "Object merge depth limit; origins conservatively flattened.");
      return {
        ...empty(),
        paths: unique(
          values.flatMap((v) => allPaths(v, m)),
          m,
        ),
        hostPaths: unique(
          values.flatMap((v) => allHostPaths(v, m)),
          m,
        ),
        unknown: true,
      };
    }
    const props = new Map();
    for (const key of new Set(
      values.flatMap((v) => [...(v.props?.keys() || [])]),
    ))
      props.set(
        key,
        merge(
          values.map((v) => v.props?.get(key) || empty()),
          m,
          level + 1,
        ),
      );
    const same = (key) =>
      values.length && values.every((v) => v[key] === values[0][key])
        ? values[0][key]
        : undefined;
    return {
      paths: unique(
        values.flatMap((v) => v.paths || []),
        m,
      ),
      hostPaths: unique(
        values.flatMap((v) => v.hostPaths || []),
        m,
      ),
      props,
      unknown: values.some((v) => v.unknown),
      ref: same("ref"),
      fn: same("fn"),
      ns: same("ns"),
      literal: same("literal"),
      encoded: values.some((v) => v.encoded),
      hostInfo: values.some((v) => v.hostInfo),
      remoteData: values.some((v) => v.remoteData),
      fileRead: values.some((v) => v.fileRead),
      persistenceTarget: values.some((v) => v.persistenceTarget),
      socketRef: values.some((v) => v.socketRef),
      shellProcess: values.some((v) => v.shellProcess),
      envGate: values.some((v) => v.envGate),
      stagedArtifact: values.some((v) => v.stagedArtifact),
    };
  }
  function trail(v, m, n, kind, detail, binding) {
    const step = loc(m, n, kind, detail, binding);
    return {
      ...v,
      paths: (v.paths || []).map((p) => {
        if (p.length >= limits.maxTrace) {
          warn(m, "Trace length limit reached; middle steps omitted.");
          return [...p.slice(0, limits.maxTrace - 2), step];
        }
        return [...p, step];
      }),
      hostPaths: (v.hostPaths || []).map((p) => {
        if (p.length >= limits.maxTrace) return [...p.slice(0, limits.maxTrace - 2), step];
        return [...p, step];
      }),
    };
  }
  function emit(m, kind, n, detail, extras = {}) {
    const key = `${kind}:${n.start}:${extras.context || ""}`;
    if (m.seen.has(key)) return;
    m.seen.add(key);
    if (m.events.length >= 250) {
      warn(m, "Observation limit reached.");
      return;
    }
    m.events.push({ ...loc(m, n, "observation", detail), kind, ...extras });
  }
  function source(m, n, detail, context = "secret") {
    emit(m, "credential", n, detail);
    return { ...empty(), paths: [[loc(m, n, "source", detail)]], context };
  }
  function hostSource(m, n, detail) {
    return { ...empty(), hostPaths: [[loc(m, n, "source", detail)]], hostInfo: true };
  }
  function property(v, key, m, n) {
    if (v.ns) {
      const mod = modules.get(v.ns);
      if (mod?.exports.has(key)) return mod.exports.get(key)();
      return mod?.cjs?.props?.get(key) || { ...empty(), unknown: true };
    }
    if (v.props?.has(key)) return v.props.get(key);
    if (v.ref === "process" && key === "env")
      return { ...empty(), ref: "process.env" };
    if (v.ref === "process" && ["platform", "arch", "version", "versions", "argv", "execPath", "pid", "ppid"].includes(key))
      return { ...hostSource(m, n, `Process attribute process.${key}`), ref: `process.${key}`, envGate: true };
    if (v.ref === "process.env")
      return {
        ...source(
          m,
          n,
          `Environment value ${key}`,
          SENSITIVE_NAME.test(key) ? "secret" : "configuration",
        ),
        ref: `env-value:${key}`,
        envGate: /^(CI|GITHUB_ACTIONS|NODE_ENV|USER|USERNAME|LOGNAME|HOSTNAME|COMPUTERNAME|GITLAB_CI|JENKINS_URL)$/i.test(key),
      };
    if (v.ref) return { ...empty(), ref: v.ref + "." + key, paths: v.paths || [], hostPaths: v.hostPaths || [], hostInfo: v.hostInfo, socketRef: v.socketRef, shellProcess: v.shellProcess, remoteData: v.remoteData, encoded: v.encoded, fileRead: v.fileRead, stagedArtifact: v.stagedArtifact };
    return v.paths?.length || v.hostPaths?.length
      ? { ...empty(), paths: v.paths || [], hostPaths: v.hostPaths || [], hostInfo: v.hostInfo, remoteData: v.remoteData, encoded: v.encoded, stagedArtifact: v.stagedArtifact }
      : empty();
  }
  function names(pattern) {
    if (!pattern) return [];
    if (pattern.type === "Identifier") return [pattern.name];
    if (pattern.type === "RestElement") return names(pattern.argument);
    if (pattern.type === "AssignmentPattern") return names(pattern.left);
    if (pattern.type === "ObjectPattern")
      return pattern.properties.flatMap((p) => names(p.value || p.argument));
    if (pattern.type === "ArrayPattern") return pattern.elements.flatMap(names);
    return [];
  }
  function keyOf(n) {
    return n?.type === "Identifier"
      ? n.name
      : ["StringLiteral", "NumericLiteral"].includes(n?.type)
        ? String(n.value)
        : null;
  }
  function bind(
    pattern,
    value,
    scope,
    m,
    kind = "assignment",
    declaration = false,
    varKind = "let",
  ) {
    if (!pattern) return;
    if (pattern.type === "Identifier") {
      let cell = declaration
        ? scope.declare(pattern.name, empty(), varKind)
        : scope.cell(pattern.name);
      if (!cell) {
        warn(
          m,
          `Unbound assignment to ${pattern.name}; treated as a local unknown binding.`,
        );
        cell = scope.declare(pattern.name);
      }
      cell.value = trail(
        value,
        m,
        pattern,
        kind,
        `${kind}: ${pattern.name}`,
        cell.id,
      );
      return;
    }
    if (pattern.type === "AssignmentPattern") {
      bind(
        pattern.left,
        value?.unknown
          ? merge([value, evaluate(pattern.right, scope, m)], m)
          : value,
        scope,
        m,
        kind,
        declaration,
        varKind,
      );
      return;
    }
    if (pattern.type === "ObjectPattern") {
      for (const p of pattern.properties) {
        if (p.type === "RestElement") {
          warn(m, "Object rest destructuring is conservatively propagated.");
          bind(
            p.argument,
            merge([value], m),
            scope,
            m,
            kind,
            declaration,
            varKind,
          );
        } else {
          const key =
            p.computed && p.key.type !== "StringLiteral" ? null : keyOf(p.key);
          if (key === null) {
            warn(m, "Dynamic destructuring key is unsupported.");
            continue;
          }
          bind(
            p.value,
            property(value, key, m, p),
            scope,
            m,
            kind,
            declaration,
            varKind,
          );
        }
      }
      return;
    }
    if (pattern.type === "ArrayPattern") {
      pattern.elements.forEach((p, i) =>
        bind(
          p,
          property(value, String(i), m, p),
          scope,
          m,
          kind,
          declaration,
          varKind,
        ),
      );
      return;
    }
    if (pattern.type === "RestElement") {
      bind(pattern.argument, value, scope, m, kind, declaration, varKind);
      return;
    }
    if (
      ["MemberExpression", "OptionalMemberExpression"].includes(pattern.type)
    ) {
      const object = evaluate(pattern.object, scope, m),
        key = pattern.computed
          ? keyOf(pattern.property)
          : pattern.property.name;
      if (key === null) {
        warn(m, "Dynamic object-property write is unsupported.");
        return;
      }
      // Object references share one abstract heap cell, preserving ordinary aliases.
      if (
        (object.ref === "process.env" && key === "NODE_TLS_REJECT_UNAUTHORIZED" && String(value.literal) === "0") ||
        (key === "rejectUnauthorized" && value.literal === false)
      ) {
        emit(m, "defense-impairment", pattern, "TLS certificate verification disabled");
      }
      object.props.set(
        key,
        trail(value, m, pattern, "property", `Property ${key}`),
      );
      if (object.ref === "module" && key === "exports") m.cjs = value;
      if (object.ref === "exports") m.cjs.props.set(key, value);
      return;
    }
    warn(m, `Unsupported binding pattern ${pattern.type}.`);
  }
  function resolve(spec, m) {
    m.imports.add(spec);
    if (!spec.startsWith(".")) {
      if (
        [
          "stratum-client",
          "coinhive",
          "node-cryptonight",
          "cryptonight-hashing",
        ].includes(spec)
      ) {
        return { ref: `mining:${spec}` };
      }
      if (
        [
          "axios",
          "node-fetch",
          "undici",
          "http",
          "https",
          "node:http",
          "node:https",
          "fs",
          "node:fs",
          "fs/promises",
          "node:fs/promises",
          "child_process",
          "node:child_process",
          "os",
          "node:os",
          "dns",
          "node:dns",
          "dns/promises",
          "node:dns/promises",
          "net",
          "node:net",
          "tls",
          "node:tls",
          "dgram",
          "node:dgram",
          "crypto",
          "node:crypto",
          "zlib",
          "node:zlib",
          "vm",
          "node:vm",
          "path",
          "node:path",
          "querystring",
          "node:querystring",
          "url",
          "node:url",
          "util",
          "node:util",
          "stream",
          "node:stream",
          "worker_threads",
          "node:worker_threads",
          "node-os-utils",
          "request",
          "got",
        ].includes(spec)
      )
        return {
          ref: spec
            .replace(/^node:/, "")
            .replace("fs/promises", "fs.promises")
            .replace("dns/promises", "dns")
            .replace("node-fetch", "fetch")
            .replace(/^(request|got)$/, "axios"),
        };
      warn(
        m,
        `Unresolved external import ${spec}; dependency modules are analyzed separately.`,
      );
      return { ref: `unknown:${spec}`, unknown: true };
    }
    const base = posix.normalize(posix.join(posix.dirname(m.file), spec));
    const candidates = [
      base,
      ...[".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"].map((e) => base + e),
      ...["index.js", "index.ts", "index.mjs", "index.cjs"].map(
        (e) => base + "/" + e,
      ),
    ];
    if (/\.js$/.test(base))
      candidates.push(base.slice(0, -3) + ".ts", base.slice(0, -3) + ".tsx");
    const file = candidates.find((p) => modules.has(p));
    if (!file) {
      warn(
        m,
        `Unresolved relative import ${spec}; custom aliases/package exports are not resolved.`,
      );
      return { ...empty(), unknown: true };
    }
    initialize(modules.get(file));
    return { ...empty(), ns: file };
  }
  function fn(node, scope, m) {
    return { ...empty(), fn: { node, scope, module: m } };
  }
  function predeclare(body, scope, m) {
    const stack = [...body];
    while (stack.length) {
      const n = stack.pop();
      if (!n || typeof n !== "object") continue;
      if (
        [
          "FunctionDeclaration",
          "FunctionExpression",
          "ArrowFunctionExpression",
          "ObjectMethod",
        ].includes(n.type)
      )
        continue;
      if (n.type === "VariableDeclaration" && n.kind === "var")
        for (const d of n.declarations)
          for (const id of names(d.id)) scope.declare(id, empty(), "var");
      for (const [k, v] of Object.entries(n)) {
        if (["loc", "comments"].includes(k)) continue;
        if (Array.isArray(v))
          stack.push(...v.filter((x) => x && typeof x === "object"));
        else if (v && typeof v === "object") stack.push(v);
      }
    }

    for (let stmt of body) {
      if (
        stmt.type === "ExportNamedDeclaration" ||
        stmt.type === "ExportDefaultDeclaration"
      )
        stmt = stmt.declaration || stmt;
      if (stmt.type === "VariableDeclaration")
        for (const d of stmt.declarations)
          for (const name of names(d.id))
            scope.declare(name, empty(), stmt.kind);
      if (stmt.type === "FunctionDeclaration" && stmt.id) {
        scope.declare(stmt.id.name).value = fn(stmt, scope, m);
      }
    }
  }
  function invoke(value, args, n, caller) {
    const f = value.fn;
    if (!f) return merge(args, caller);
    if (
      depth >= limits.maxDepth ||
      ++calls > limits.maxCalls ||
      active.has(f.node)
    ) {
      warn(
        caller,
        "Function recursion/call budget reached; returned data is conservatively propagated.",
      );
      return { ...merge(args, caller), unknown: true };
    }
    depth++;
    active.add(f.node);
    const scope = new Scope(f.scope, true);
    let ret = empty();
    try {
      f.node.params.forEach((p, i) => {
        for (const name of names(p)) scope.declare(name);
        bind(
          p,
          trail(
            args[i] || empty(),
            caller,
            n,
            "argument",
            `Argument ${i + 1} to ${f.node.id?.name || "function"}`,
          ),
          scope,
          f.module,
          "parameter",
        );
      });
      if (f.node.type === "FunctionExpression" && f.node.id)
        scope.declare(f.node.id.name, value);
      if (f.node.body.type === "BlockStatement") {
        predeclare(f.node.body.body, scope, f.module);
        ret = statements(f.node.body.body, scope, f.module).value || empty();
      } else
        ret = trail(
          evaluate(f.node.body, scope, f.module),
          f.module,
          f.node.body,
          "return",
          "Function return",
        );
    } finally {
      depth--;
      active.delete(f.node);
    }
    return ret;
  }
  function evaluate(n, scope, m) {
    if (!n) return empty();
    tick(m);
    switch (n.type) {
      case "Identifier": {
        const cell = scope.cell(n.name);
        if (cell) return cell.get ? cell.get() : cell.value;
        if (
          [
            "process",
            "fetch",
            "Buffer",
            "JSON",
            "eval",
            "Function",
            "atob",
            "require",
            "module",
            "exports",
            "console",
          ].includes(n.name)
        )
          return { ...empty(), ref: n.name };
        return empty();
      }
      case "StringLiteral": {
        if (MINING_INDICATOR.test(n.value))
          emit(m, "cryptomining", n, "Cryptomining pool or miner indicator");
        if (CLOUD_METADATA.test(n.value))
          emit(m, "cloud-metadata", n, "Cloud instance metadata endpoint reference");
        if (CREDENTIAL.test(n.value) || PRIVATE_FILE.test(n.value))
          return {
            ...source(
              m,
              n,
              PRIVATE_FILE.test(n.value)
                ? "Sensitive credential-file reference"
                : "Credential-shaped string; validity unknown",
            ),
            literal: n.value,
            persistenceTarget: PERSISTENCE_PATH.test(n.value),
          };
        return {
          ...empty(),
          literal: n.value,
          persistenceTarget: PERSISTENCE_PATH.test(n.value),
        };
      }
      case "BooleanLiteral":
      case "NumericLiteral":
      case "NullLiteral":
        return { ...empty(), literal: n.value };
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        return fn(n, scope, m);
      case "ObjectExpression": {
        const value = empty();
        for (const p of n.properties) {
          if (p.type === "SpreadElement") {
            const other = evaluate(p.argument, scope, m);
            for (const [k, v] of other.props) value.props.set(k, v);
            value.paths.push(...other.paths);
          } else {
            const key = p.computed ? keyOf(p.key) : keyOf(p.key);
            if (key !== null)
              value.props.set(
                key,
                p.type === "ObjectMethod"
                  ? fn(p, scope, m)
                  : evaluate(p.value, scope, m),
              );
            else if (p.value) {
              const val = evaluate(p.value, scope, m);
              if (
                typeof val.literal === "string" &&
                PERSISTENCE_PATH.test(val.literal)
              )
                val.persistenceTarget = true;
              warn(m, "Dynamic object keys are unsupported.");
            }
          }
        }
        if (value.props.get("rejectUnauthorized")?.literal === false) {
          emit(m, "defense-impairment", n, "TLS certificate verification disabled");
        }
        return value;
      }
      case "ArrayExpression":
        return {
          ...empty(),
          props: new Map(
            n.elements.map((e, i) => [String(i), evaluate(e, scope, m)]),
          ),
        };
      case "MemberExpression":
      case "OptionalMemberExpression": {
        const object = evaluate(n.object, scope, m),
          key = n.computed ? keyOf(n.property) : n.property.name;
        if (key === null) {
          warn(m, "Dynamic property access is conservatively propagated.");
          return merge([object], m);
        }
        const value = property(object, key, m, n);
        if (value.ref === "process.env")
          emit(m, "credential", n, "Environment-variable access");
        return value;
      }
      case "AssignmentExpression": {
        const right = evaluate(n.right, scope, m);
        const v =
          n.operator === "="
            ? right
            : merge([evaluate(n.left, scope, m), right], m);
        bind(n.left, v, scope, m);
        return v;
      }
      case "BinaryExpression":
      case "LogicalExpression": {
        const left = evaluate(n.left, scope, m),
          right = evaluate(n.right, scope, m),
          merged = merge([left, right], m);
        if (
          n.operator === "+" &&
          typeof left.literal === "string" &&
          typeof right.literal === "string"
        ) {
          const combined = left.literal + right.literal;
          merged.literal = combined;
          if (PRIVATE_FILE.test(combined) && !merged.paths?.length) {
            const s = source(m, n, "Sensitive credential-file reference");
            merged.paths = s.paths;
          }
          if (PERSISTENCE_PATH.test(combined)) merged.persistenceTarget = true;
          if (CLOUD_METADATA.test(combined))
            emit(m, "cloud-metadata", n, "Cloud instance metadata endpoint reference");
        }
        if (
          ["===", "!==", "==", "!=", "<", ">", "<=", ">="].includes(n.operator) &&
          (left.envGate || right.envGate || left.hostInfo || right.hostInfo)
        ) {
          merged.envGate = true;
        }
        return merged;
      }
      case "TemplateLiteral": {
        const exprs = n.expressions.map((e) => evaluate(e, scope, m));
        const merged = merge(exprs, m);
        const raw = (n.quasis || []).map((q) => q.value?.cooked || q.value?.raw || "").join("/");
        if (PRIVATE_FILE.test(raw) && !merged.paths?.length) {
          const s = source(m, n, "Sensitive credential-file reference");
          merged.paths = s.paths;
        }
        if (PERSISTENCE_PATH.test(raw)) merged.persistenceTarget = true;
        if (CLOUD_METADATA.test(raw))
          emit(m, "cloud-metadata", n, "Cloud instance metadata endpoint reference");
        if (MINING_INDICATOR.test(raw))
          emit(m, "cryptomining", n, "Cryptomining pool or miner indicator");
        return merged;
      }
      case "ConditionalExpression":
        warn(
          m,
          "Conditional expression paths are merged; runtime reachability is unknown.",
        );
        evaluate(n.test, scope, m);
        return merge(
          [evaluate(n.consequent, scope, m), evaluate(n.alternate, scope, m)],
          m,
        );
      case "AwaitExpression":
      case "TSAsExpression":
      case "TSTypeAssertion":
      case "TSNonNullExpression":
      case "ParenthesizedExpression":
      case "SpreadElement":
        return evaluate(n.argument || n.expression, scope, m);
      case "SequenceExpression": {
        let v = empty();
        for (const e of n.expressions) v = evaluate(e, scope, m);
        return v;
      }
      case "UnaryExpression":
      case "UpdateExpression":
        evaluate(n.argument, scope, m);
        return empty();
      case "ImportExpression":
        warn(m, "Dynamic import is unsupported.");
        return empty();
      case "CallExpression":
      case "OptionalCallExpression":
      case "NewExpression":
        return call(n, scope, m);
      default:
        warn(
          m,
          `Unsupported expression ${n.type}; its effects are not fully modeled.`,
        );
        return empty();
    }
  }
  function runCallbacks(n, args, scope, m, syntheticArgs = []) {
    let hasCb = false;
    for (let i = 0; i < n.arguments.length; i++) {
      const astArg = n.arguments[i];
      if (
        ["ArrowFunctionExpression", "FunctionExpression"].includes(
          astArg?.type,
        ) &&
        args[i]?.fn
      ) {
        hasCb = true;
        const before = snapshot(scope);
        invoke(args[i], syntheticArgs, n, m);
        for (const [c, v] of before) c.value = merge([v, c.value], m);
      }
    }
    if (hasCb) {
      warn(
        m,
        "Callback scheduling is unsupported; callback bodies may be uninspected.",
      );
    }
  }
  function call(n, scope, m) {
    if (n.callee.type === "Import") {
      warn(m, "Dynamic import is unsupported.");
      return empty();
    }
    const callee = evaluate(n.callee, scope, m),
      args = n.arguments.map((a) => evaluate(a, scope, m)),
      ref = callee.ref || "";
    if (ref === "require") {
      if (n.arguments[0]?.type !== "StringLiteral") {
        warn(m, "Dynamic require is unsupported.");
        return empty();
      }
      const imported = resolve(n.arguments[0].value, m);
      if (imported.ref?.startsWith("mining:")) {
        emit(m, "cryptomining", n, `Cryptomining library import: ${n.arguments[0].value}`);
      }
      if (imported.ns) {
        const mod = modules.get(imported.ns);
        return mod.cjsAssigned ? mod.cjs : imported;
      }
      return { ...empty(), ...imported };
    }
    if (callee.fn) return invoke(callee, args, n, m);
    if (ref.startsWith("mining:")) {
      emit(m, "cryptomining", n, `Cryptomining client invocation via ${ref}`);
      runCallbacks(n, args, scope, m);
      return { ...empty(), ref: "mining-instance" };
    }
    if (
      /^(os\.(homedir|hostname|userInfo|networkInterfaces|platform|arch|release|cpus|type|endianness)|dns\.getServers|process\.cwd)$/.test(
        ref,
      )
    ) {
      return {
        ...hostSource(m, n, `Host environment fingerprint via ${ref}()`),
        ref: `host:${ref}`,
        envGate: /^(os\.(platform|arch|hostname|userInfo)|process\.cwd)$/.test(ref),
      };
    }
    if (/^path\.(join|resolve)$/.test(ref)) {
      const merged = merge(args, m);
      const lits = args
        .map((a) => (typeof a.literal === "string" ? a.literal : ""))
        .filter(Boolean)
        .join("/");
      if (lits) {
        merged.literal = lits;
        if (PRIVATE_FILE.test(lits) && !merged.paths?.length) {
          const s = source(m, n, "Sensitive credential-file reference");
          merged.paths = s.paths;
        }
        if (PERSISTENCE_PATH.test(lits)) merged.persistenceTarget = true;
      }
      return merged;
    }
    if (/^querystring\.(stringify|escape)$/.test(ref)) {
      return merge(args, m);
    }
    const network =
      /^(fetch|axios(?:\.(get|post|put|patch|delete|head|options|request))?|https?\.(request|get)|undici\.(fetch|request))$/.test(
        ref,
      );
    if (network) {
      emit(m, "network", n, `Outbound request via ${ref}`);
      m.hasNetworkDownload = true;
      if (
        args.some(
          (a) =>
            (typeof a.literal === "string" && CLOUD_METADATA.test(a.literal)) ||
            a.props?.get("hostname")?.literal === "169.254.169.254" ||
            a.props?.get("host")?.literal === "169.254.169.254" ||
            a.props?.get("hostname")?.literal === "metadata.google.internal",
        )
      ) {
        emit(m, "cloud-metadata", n, `Cloud metadata service request via ${ref}`);
      }
      const flowArgs = args.map((v) =>
        v.ref === "process.env"
          ? source(m, n, "Entire environment object passed to request")
          : v,
      );
      const mergedFlow = merge(flowArgs, m);
      const paths = allPaths(mergedFlow, m);
      const hPaths = allHostPaths(mergedFlow, m);
      if (paths.length) {
        const options =
          ref === "axios.post" || ref === "axios.put" || ref === "axios.patch"
            ? args[2]
            : args[1] || args[0];
        const auth = allPaths(options?.props?.get("headers"), m);
        const authKeys = [
          ...(options?.props?.get("headers")?.props?.keys() || []),
        ];
        const authOnly =
          auth.length > 0 &&
          authKeys.some((k) => /^(authorization|x-api-key)$/i.test(k)) &&
          paths.every((p) =>
            auth.some((a) => JSON.stringify(a) === JSON.stringify(p)),
          );
        const context = authOnly ? "authentication" : "payload";
        const flows = paths.map((p) => ({
          status: "statically inferred",
          context,
          steps: [...p, loc(m, n, "sink", `Network sink: ${ref}`)],
          limitations: [
            "Static path does not prove runtime execution, destination trust, or malicious intent.",
          ],
        }));
        // Multiple calls to one helper retain distinct source paths rather than deduplicating by sink alone.
        let prior = m.events.find(
          (e) =>
            e.kind === "exfiltration" &&
            e.line === (n.loc?.start.line || 1) &&
            e.column === (n.loc?.start.column || 0) + 1 &&
            e.context === context,
        );
        if (prior) {
          prior.flows = unique(
            [...prior.flows.map((f) => f.steps), ...flows.map((f) => f.steps)],
            m,
          ).map((s) => ({ ...flows[0], steps: s }));
        } else
          emit(
            m,
            "exfiltration",
            n,
            "Sensitive source reaches network arguments through a statically inferred path",
            { context, flows },
          );
      } else if (hPaths.length) {
        emit(
          m,
          "info-exfiltration",
          n,
          "Host fingerprint data reaches outbound network request",
        );
      }
      const synRes = {
        ...empty(),
        ref: "http-response",
        remoteData: true,
        paths: [[loc(m, n, "source", `Remote HTTP response from ${ref}`)]],
      };
      runCallbacks(n, args, scope, m, [synRes, synRes, synRes]);
      if (/^https?\.request$/.test(ref))
        return { ...empty(), ref: "request-stream", remoteData: true };
      return synRes;
    }
    if (/^request-stream\.(write|end)$/.test(ref)) {
      const mergedArgs = merge(args, m);
      const paths = allPaths(mergedArgs, m);
      const hPaths = allHostPaths(mergedArgs, m);
      emit(m, "network", n, "Request body stream");
      if (paths.length)
        emit(
          m,
          "exfiltration",
          n,
          "Sensitive source reaches HTTP request body",
          {
            context: "payload",
            flows: paths.map((p) => ({
              status: "statically inferred",
              context: "payload",
              steps: [...p, loc(m, n, "sink", "HTTP request stream")],
              limitations: [
                "Static flow only; execution and intent are unknown.",
              ],
            })),
          },
        );
      else if (hPaths.length)
        emit(
          m,
          "info-exfiltration",
          n,
          "Host fingerprint data reaches HTTP request body stream",
        );
      return empty();
    }
    if (/^http-response\.(on|once|addListener|then|json|text)$/.test(ref)) {
      const chunkVal = {
        ...empty(),
        ref: "http-response-chunk",
        remoteData: true,
        paths: [[loc(m, n, "source", "Remote HTTP response body")]],
      };
      runCallbacks(n, args, scope, m, [chunkVal]);
      return { ...chunkVal, ref: "http-response" };
    }
    if (/^http-response\.pipe$/.test(ref)) {
      const dest = args.find((a) => a.ref === "fs-write-stream");
      if (dest) {
        m.hasFileWrite = true;
        m.hasStagedDownload = true;
        if (dest.filePath) {
          m.stagedFiles.add(dest.filePath);
          projectStagedFiles.add(dest.filePath);
        }
        return { ...dest, stagedArtifact: true };
      }
      return args[0] || empty();
    }
    if (
      ref === "eval" ||
      ref === "Function" ||
      /^vm\.(runInNewContext|runInThisContext|runInContext|compileFunction)$/.test(
        ref,
      )
    ) {
      emit(m, "dynamic", n, "Dynamic code execution via " + ref);
      m.hasDynamicOrExec = true;
      if (args.some((v) => v.remoteData))
        emit(
          m,
          "c2-execution",
          n,
          "Remote network response reaches dynamic code execution",
        );
      if (args.some((v) => v.encoded))
        emit(
          m,
          "encoded-execution",
          n,
          "Decoded value reaches dynamic execution",
        );
      return empty();
    }
    if (
      ref === "atob" ||
      (ref === "Buffer.from" && ["base64", "hex"].includes(args[1]?.literal)) ||
      /^zlib\.(inflateSync|inflate|gunzipSync|gunzip|unzipSync|unzip|brotliDecompressSync)$/.test(
        ref,
      )
    ) {
      emit(m, "encoding", n, "Encoded content is decoded");
      return { ...merge(args, m), encoded: true, ref: "decoded-value" };
    }
    if (/^crypto\.(createDecipheriv|createDecipher)$/.test(ref)) {
      emit(m, "encoding", n, "Cryptographic decipher created");
      return { ...merge(args, m), encoded: true, ref: "crypto-decipher" };
    }
    if (/^crypto-decipher\.(update|final)$/.test(ref)) {
      emit(m, "encoding", n, "Encrypted payload decrypted");
      return { ...merge(args, m), encoded: true, ref: "decoded-value" };
    }
    if (/^dns\.(resolve|resolve4|resolve6|resolveTxt|resolveAny|lookup)$/.test(ref)) {
      emit(m, "network", n, `DNS query via ${ref}`);
      const mergedArgs = merge(args, m);
      const paths = allPaths(mergedArgs, m);
      const hPaths = allHostPaths(mergedArgs, m);
      if (paths.length || hPaths.length || mergedArgs.encoded) {
        emit(
          m,
          "dns-tunneling",
          n,
          `Host or credential data passed to DNS query (${ref})`,
        );
      }
      const dnsRes = {
        ...empty(),
        remoteData: true,
        ref: "dns-response",
      };
      runCallbacks(n, args, scope, m, [empty(), dnsRes]);
      return dnsRes;
    }
    if (/^(net|tls)\.(Socket|connect|createConnection)$/.test(ref)) {
      emit(m, "network", n, `Raw socket connection via ${ref}`);
      m.hasSocketConnect = true;
      const sock = { ...empty(), ref: "net-socket", socketRef: true };
      runCallbacks(n, args, scope, m, [sock]);
      return sock;
    }
    if (/^net-socket\.(connect|on|once|write)$/.test(ref)) {
      emit(m, "network", n, `Socket operation via ${ref}`);
      m.hasSocketConnect = true;
      runCallbacks(n, args, scope, m, [{ ...empty(), remoteData: true }]);
      return { ...empty(), ref: "net-socket", socketRef: true };
    }
    if (/^(net-socket|shell-process|shell-stream)\.pipe$/.test(ref)) {
      const isSocketCaller = /^net-socket/.test(ref);
      const isShellCaller = /^(shell-process|shell-stream)/.test(ref);
      const hasSocketArg = args.some(
        (a) => a.socketRef || a.ref === "net-socket",
      );
      const hasShellArg = args.some(
        (a) =>
          a.shellProcess ||
          a.ref === "shell-process" ||
          a.ref === "shell-stream",
      );
      if ((isSocketCaller && hasShellArg) || (isShellCaller && hasSocketArg)) {
        emit(
          m,
          "reverse-shell",
          n,
          "Process stream piped directly to or from network socket",
        );
      }
      return args[0] || empty();
    }
    if (/^(https?|net|tls)\.createServer$/.test(ref)) {
      runCallbacks(n, args, scope, m, [
        { ...empty(), remoteData: true },
        { ...empty(), ref: "request-stream" },
      ]);
      return { ...empty(), ref: "http-server" };
    }
    if (/^http-server\.listen$/.test(ref)) {
      emit(
        m,
        "persistence",
        n,
        "Persistent network server listener started via listen()",
      );
      runCallbacks(n, args, scope, m);
      return empty();
    }
    if (
      /^child_process\.(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)$/.test(
        ref,
      )
    ) {
      emit(m, "execution", n, "Operating-system process creation");
      m.hasDynamicOrExec = true;
      const cmdLit = typeof args[0]?.literal === "string" ? args[0].literal : "";
      if (/^(?:\/bin\/(?:ba|z|da)?sh|(?:ba|z)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i.test(cmdLit)) {
        m.hasShellSpawn = true;
      }
      const allArgsText = args
        .map((a) => (typeof a.literal === "string" ? a.literal : ""))
        .join(" ");
      const combinedCmd = (cmdLit + " " + allArgsText).trim();
      const hasRevShellCmd =
        /\/dev\/tcp\/|\bnc\s+.*-e\b|\bncat\b.*-e|\bbash\s+-i\b|\bsocat\b.*exec:/i.test(
          combinedCmd,
        );
      const hasSocketStdio = args.some(
        (a) =>
          a.socketRef ||
          (a.props?.get("stdio") &&
            (a.props.get("stdio")?.socketRef ||
              [...(a.props.get("stdio")?.props?.values() || [])].some(
                (p) => p?.socketRef,
              ))),
      );
      if (hasRevShellCmd) {
        emit(
          m,
          "reverse-shell",
          n,
          "Shell command establishes a reverse shell connection",
        );
      } else if (hasSocketStdio) {
        emit(
          m,
          "reverse-shell",
          n,
          "Interactive shell spawned with standard streams attached to network socket",
        );
      }
      if (args.some((v) => v.remoteData)) {
        emit(
          m,
          "c2-execution",
          n,
          "Remote network response executed via child_process",
        );
      }
      const isStagedTarget =
        args.some((v) => v.stagedArtifact) ||
        (m.hasStagedDownload && args.some((v) => v.remoteData)) ||
        (projectStagedFiles.size > 0 &&
          args.some((v) => {
            if (typeof v.literal !== "string") return false;
            return [...projectStagedFiles].some(
              (f) => f && (v.literal === f || v.literal.includes(f)),
            );
          }));
      if (isStagedTarget) {
        emit(
          m,
          "staged-dropper",
          n,
          "Downloaded file written to disk and executed via child_process",
        );
      }
      if (
        args.some(
          (v) =>
            typeof v.literal === "string" &&
            /\b(curl|wget)\b.*https?:\/\//.test(v.literal),
        )
      )
        emit(m, "remote", n, "Shell downloads a remote payload");
      if (
        args.some(
          (v) =>
            typeof v.literal === "string" && MINING_INDICATOR.test(v.literal),
        )
      )
        emit(m, "cryptomining", n, "Process command launches cryptominer");
      if (
        args.some(
          (v) =>
            v.persistenceTarget ||
            (typeof v.literal === "string" && PERSISTENCE_PATH.test(v.literal)),
        )
      )
        emit(
          m,
          "persistence",
          n,
          "Process command modifies system persistence configuration",
        );
      if (
        args.some(
          (v) =>
            typeof v.literal === "string" &&
            SELF_PROPAGATION_CMD.test(v.literal),
        )
      )
        emit(
          m,
          "self-propagation",
          n,
          "Process command publishes package or pushes repository changes",
        );
      if (
        args.some(
          (v) =>
            typeof v.literal === "string" && DEFENSE_IMPAIR_CMD.test(v.literal),
        )
      )
        emit(
          m,
          "defense-impairment",
          n,
          "Process command impairs host security controls or TLS verification",
        );
      if (
        args.some(
          (v) =>
            typeof v.literal === "string" &&
            /\brm\s+-(?:rf|fr)\s+(?:\/|~|\$HOME|\.\.)/i.test(v.literal),
        )
      )
        emit(
          m,
          "destructive-fs",
          n,
          "Process command performs destructive recursive deletion",
        );
      runCallbacks(n, args, scope, m);
      const streamObj = {
        ...empty(),
        ref: "shell-stream",
        shellProcess: true,
      };
      return {
        ...empty(),
        ref: "shell-process",
        shellProcess: true,
        props: new Map([
          ["stdin", streamObj],
          ["stdout", streamObj],
          ["stderr", streamObj],
        ]),
      };
    }
    if (
      /^fs(?:\.promises)?\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|readdir|readdirSync|createWriteStream|rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync|chmod|chmodSync)$/.test(
        ref,
      )
    ) {
      emit(m, "filesystem", n, "File-system access");
      const targetArg = args[0] || empty();
      const targetLit = typeof targetArg.literal === "string" ? targetArg.literal : "";
      if (/writeFile|appendFile|createWriteStream/.test(ref)) {
        m.hasFileWrite = true;
        const hasRemoteArg = args.some((a) => a.remoteData);
        if (hasRemoteArg) {
          m.hasStagedDownload = true;
          if (targetLit) {
            m.stagedFiles.add(targetLit);
            projectStagedFiles.add(targetLit);
          }
        }
        if (targetArg.persistenceTarget || PERSISTENCE_PATH.test(targetLit)) {
          emit(
            m,
            "persistence",
            n,
            `File write targets persistence location (${targetLit || "persistence path"})`,
          );
        }
        if (/\.github[\/\\]workflows[\/\\]/i.test(targetLit)) {
          emit(
            m,
            "self-propagation",
            n,
            "File write injects or modifies GitHub Actions workflow",
          );
        }
      }
      if (/rm|rmdir|unlink/.test(ref)) {
        if (/^(?:\/|~|\.\.\/|[A-Za-z]:\\$)/.test(targetLit)) {
          emit(
            m,
            "destructive-fs",
            n,
            `File deletion targets sensitive or parent path (${targetLit})`,
          );
        }
      }
      if (/createWriteStream/.test(ref)) {
        return {
          ...empty(),
          ref: "fs-write-stream",
          filePath: targetLit,
        };
      }
      if (/readFile|readdir/.test(ref)) {
        const readVal = {
          ...merge(args, m),
          fileRead: true,
        };
        if (PRIVATE_FILE.test(targetLit) && !readVal.paths?.length) {
          const s = source(m, n, "Sensitive credential-file reference");
          readVal.paths = s.paths;
        }
        runCallbacks(n, args, scope, m, [empty(), readVal]);
        return readVal;
      }
      runCallbacks(n, args, scope, m);
      return merge(args, m);
    }
    if (
      ref === "JSON.stringify" ||
      ref === "Buffer.from" ||
      ref === "decoded-value.toString" ||
      ref.endsWith(".toString")
    ) {
      const obj = n.callee.object ? evaluate(n.callee.object, scope, m) : empty();
      return {
        ...merge([obj, ...args], m),
        ref: ref === "Buffer.from" ? "buffer" : undefined,
        encoded:
          ref === "decoded-value.toString" ||
          obj.encoded ||
          ["base64", "hex"].includes(args[0]?.literal),
      };
    }
    // Unknown transformations preserve origins but disclose the unknown edge.
    const value = merge(args, m);
    if (value.paths.length) {
      warn(
        m,
        `Unknown call ${ref || "target"}: return conservatively carries argument origins.`,
      );
      return trail(
        { ...value, unknown: true },
        m,
        n,
        "unknown-call",
        "Unmodeled transformation; propagation is uncertain",
      );
    }
    runCallbacks(n, args, scope, m);
    return value;
  }
  function snapshot(scope) {
    const saved = new Map();
    for (let s = scope; s; s = s.parent)
      for (const cell of s.bindings.values()) saved.set(cell, cell.value);
    return saved;
  }
  function statements(body, scope, m) {
    let returned = [];
    for (const s of body) {
      const result = statement(s, scope, m);
      if (result?.value) returned.push(result.value);
      if (result?.stop) return { value: merge(returned, m), stop: true };
    }
    return { value: returned.length ? merge(returned, m) : null };
  }
  function statement(n, scope, m) {
    if (!n) return;
    tick(m);
    switch (n.type) {
      case "ExpressionStatement":
        evaluate(n.expression, scope, m);
        if (
          n.expression.type === "AssignmentExpression" &&
          n.expression.left.type === "MemberExpression" &&
          n.expression.left.object.name === "module" &&
          keyOf(n.expression.left.property) === "exports"
        )
          m.cjsAssigned = true;
        break;
      case "VariableDeclaration":
        for (const d of n.declarations)
          if (d.init)
            bind(
              d.id,
              evaluate(d.init, scope, m),
              scope,
              m,
              "assignment",
              true,
              n.kind,
            );
        break;
      case "FunctionDeclaration":
        break;
      case "BlockStatement": {
        const child = new Scope(scope);
        predeclare(n.body, child, m);
        return statements(n.body, child, m);
      }
      case "ReturnStatement":
        return {
          value: trail(
            evaluate(n.argument, scope, m),
            m,
            n,
            "return",
            "Function return",
          ),
          stop: true,
        };
      case "IfStatement": {
        const cond = evaluate(n.test, scope, m);
        warn(m, "Conditional branches are merged; reachability is not proven.");
        const evCountBefore = m.events.length;
        const before = snapshot(scope);
        const a = statement(n.consequent, scope, m),
          after = snapshot(scope);
        for (const [c, v] of before) c.value = v;
        const b = statement(n.alternate, scope, m);
        for (const [c, v] of after) c.value = merge([v, c.value], m);
        if (cond.envGate) {
          const newEvents = m.events.slice(evCountBefore);
          if (
            newEvents.some((e) =>
              [
                "execution",
                "exfiltration",
                "info-exfiltration",
                "dynamic",
                "encoded-execution",
                "c2-execution",
                "reverse-shell",
                "staged-dropper",
              ].includes(e.kind),
            )
          ) {
            emit(
              m,
              "conditional-evasion",
              n.test,
              "Environment or host-attribute check gates sensitive execution or network behavior",
            );
          }
        }
        return {
          value: merge([a?.value || empty(), b?.value || empty()], m),
          stop: !!a?.stop && !!b?.stop,
        };
      }
      case "ImportDeclaration": {
        const imported = resolve(n.source.value, m);
        for (const s of n.specifiers) {
          const cell = scope.declare(s.local.name);
          const key =
            s.type === "ImportDefaultSpecifier" ? "default" : keyOf(s.imported);
          cell.get = () =>
            s.type === "ImportNamespaceSpecifier"
              ? { ...empty(), ...imported }
              : imported.ns
                ? property(imported, key, m, s)
                : {
                    ...empty(),
                    ref:
                      imported.ref +
                      (key && key !== "default" ? "." + key : ""),
                  };
        }
        break;
      }
      case "ExportNamedDeclaration": {
        if (n.declaration) {
          statement(n.declaration, scope, m);
          const ids =
            n.declaration.type === "VariableDeclaration"
              ? n.declaration.declarations.flatMap((d) => names(d.id))
              : names(n.declaration.id);
          for (const id of ids)
            m.exports.set(id, () => scope.cell(id)?.value || empty());
        }
        const imported = n.source ? resolve(n.source.value, m) : null;
        for (const s of n.specifiers) {
          const key = keyOf(s.exported);
          m.exports.set(key, () =>
            imported
              ? property(imported, keyOf(s.local), m, s)
              : scope.cell(s.local.name)?.get?.() ||
                scope.cell(s.local.name)?.value ||
                empty(),
          );
        }
        break;
      }
      case "ExportDefaultDeclaration": {
        const d = n.declaration;
        let value;
        if (d.type === "FunctionDeclaration") {
          value = fn(d, scope, m);
          if (d.id) scope.declare(d.id.name, value);
        } else value = evaluate(d, scope, m);
        m.exports.set("default", () => value);
        break;
      }
      case "ExportAllDeclaration": {
        const imported = resolve(n.source.value, m);
        if (imported.ns)
          for (const key of modules.get(imported.ns).exports.keys())
            if (key !== "default")
              m.exports.set(key, () => property(imported, key, m, n));
        break;
      }
      case "ForStatement":
      case "ForOfStatement":
      case "ForInStatement":
      case "WhileStatement":
      case "DoWhileStatement":
        warn(
          m,
          "Loop effects are not modeled; source in this loop is uninspected.",
        );
        break;
      case "TryStatement":
        warn(m, "Exception-dependent paths are conservatively analyzed.");
        statement(n.block, scope, m);
        if (n.handler) {
          const s = new Scope(scope);
          for (const name of names(n.handler.param)) s.declare(name);
          statement(n.handler.body, s, m);
        }
        return statement(n.finalizer, scope, m);
      case "EmptyStatement":
      case "TSInterfaceDeclaration":
      case "TSTypeAliasDeclaration":
        break;
      default:
        warn(m, `Unsupported statement ${n.type}; effects are uninspected.`);
    }
  }
  function initialize(m) {
    if (m.state === "done" || m.error) return;
    if (m.state === "loading") {
      warn(
        m,
        "Circular module relationship encountered; partially initialized exports may be unresolved.",
      );
      return;
    }
    m.state = "loading";
    const scope = new Scope(null, true);
    m.scope = scope;
    m.cjs = empty();
    scope.declare("exports", { ...m.cjs, ref: "exports" });
    scope.declare("module", {
      ...empty(),
      ref: "module",
      props: new Map([["exports", m.cjs]]),
    });
    predeclare(m.ast.program.body, scope, m);
    // ESM imports are hoisted even when textually below a call.
    for (const s of m.ast.program.body)
      if (s.type === "ImportDeclaration") statement(s, scope, m);
    try {
      statements(
        m.ast.program.body.filter((s) => s.type !== "ImportDeclaration"),
        scope,
        m,
      );
    } catch (e) {
      warn(m, e.message);
    }
    m.state = "done";
  }
  for (const [file, code] of Object.entries(files)) {
    if (modules.size >= limits.maxModules) {
      warnings.add(
        "project: Module count limit reached; remaining source files uninspected.",
      );
      break;
    }
    const m = {
      file,
      code,
      events: [],
      seen: new Set(),
      warnings: new Set(),
      exports: new Map(),
      imports: new Set(),
      stagedFiles: new Set(),
      hasNetworkDownload: false,
      hasFileWrite: false,
      hasStagedDownload: false,
      hasSocketConnect: false,
      hasShellSpawn: false,
      hasDynamicOrExec: false,
      error: null,
      state: "new",
    };
    modules.set(file, m);
    try {
      m.ast = parse(code, {
        sourceType: "unambiguous",
        plugins: ["typescript", "jsx"],
      });
      const stack = [m.ast];
      while (stack.length) {
        const n = stack.pop();
        if (n?.type && ++nodes > limits.maxNodes)
          throw new Error("AST node budget exceeded");
        for (const [key, v] of Object.entries(n || {})) {
          if (["loc", "comments", "tokens"].includes(key)) continue;
          if (Array.isArray(v))
            for (const x of v)
              if (x && typeof x === "object") stack.push(x);
              else {
              }
          else if (v && typeof v === "object") stack.push(v);
        }
      }
    } catch (e) {
      m.error = String(e.message).slice(0, 200);
    }
  }
  for (const m of modules.values()) initialize(m);
  const output = [...modules.values()].map((m) => ({
    file: m.file,
    events: m.events,
    error: m.error,
    coverage: [...m.warnings],
  }));
  if (output.length)
    output[0].coverage.push(
      ...[...warnings].filter((w) => w.startsWith("project:")),
    );
  return output;
}
module.exports = { analyzeProject };
