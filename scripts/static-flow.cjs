/* Bounded abstract data-flow evaluator, not a JavaScript runtime.
 * Values contain origins, paths, object fields, static API references or AST closures.
 * No host function is callable, no user module is imported, no source is evaluated.
 */
const { parse } = require("@babel/parser");
const posix = require("node:path").posix;
const CREDENTIAL =
  /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,})\b/;
const PRIVATE_FILE = /(\.ssh\/|id_rsa|\.npmrc|\.aws\/credentials)/i;
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
    warnings = new Set();
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
      props,
      unknown: values.some((v) => v.unknown),
      ref: same("ref"),
      fn: same("fn"),
      ns: same("ns"),
      literal: same("literal"),
      encoded: values.some((v) => v.encoded),
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
  function property(v, key, m, n) {
    if (v.ns) {
      const mod = modules.get(v.ns);
      if (mod?.exports.has(key)) return mod.exports.get(key)();
      return mod?.cjs?.props?.get(key) || { ...empty(), unknown: true };
    }
    if (v.props?.has(key)) return v.props.get(key);
    if (v.ref === "process" && key === "env")
      return { ...empty(), ref: "process.env" };
    if (v.ref === "process.env")
      return {
        ...source(
          m,
          n,
          `Environment value ${key}`,
          SENSITIVE_NAME.test(key) ? "secret" : "configuration",
        ),
        ref: `env-value:${key}`,
      };
    if (v.ref) return { ...empty(), ref: v.ref + "." + key };
    return v.paths?.length ? { ...empty(), paths: v.paths } : empty();
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
    if (!spec.startsWith(".")) {
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
        ].includes(spec)
      )
        return {
          ref: spec
            .replace(/^node:/, "")
            .replace("fs/promises", "fs.promises")
            .replace("node-fetch", "fetch"),
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
      case "StringLiteral":
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
          };
        return { ...empty(), literal: n.value };
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
            else warn(m, "Dynamic object keys are unsupported.");
          }
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
      case "LogicalExpression":
        return merge(
          [evaluate(n.left, scope, m), evaluate(n.right, scope, m)],
          m,
        );
      case "TemplateLiteral":
        return merge(
          n.expressions.map((e) => evaluate(e, scope, m)),
          m,
        );
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
      if (imported.ns) {
        const mod = modules.get(imported.ns);
        return mod.cjsAssigned ? mod.cjs : imported;
      }
      return { ...empty(), ...imported };
    }
    if (callee.fn) return invoke(callee, args, n, m);
    const network =
      /^(fetch|axios(?:\.(get|post|put|patch|delete|head|options|request))?|https?\.(request|get)|undici\.(fetch|request))$/.test(
        ref,
      );
    if (network) {
      emit(m, "network", n, `Outbound request via ${ref}`);
      const flowArgs = args.map((v) =>
        v.ref === "process.env"
          ? source(m, n, "Entire environment object passed to request")
          : v,
      );
      const paths = allPaths(merge(flowArgs, m), m);
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
      }
      if (/^https?\.request$/.test(ref))
        return { ...empty(), ref: "request-stream" };
      return empty();
    }
    if (/^request-stream\.(write|end)$/.test(ref)) {
      const paths = allPaths(merge(args, m), m);
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
      return empty();
    }
    if (ref === "eval" || ref === "Function") {
      emit(m, "dynamic", n, "Dynamic code execution via " + ref);
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
      (ref === "Buffer.from" && ["base64", "hex"].includes(args[1]?.literal))
    ) {
      emit(m, "encoding", n, "Encoded content is decoded");
      return { ...merge(args, m), encoded: true, ref: "decoded-value" };
    }
    if (
      /^child_process\.(exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(
        ref,
      )
    ) {
      emit(m, "execution", n, "Operating-system process creation");
      if (
        args.some(
          (v) =>
            typeof v.literal === "string" &&
            /\b(curl|wget)\b.*https?:\/\//.test(v.literal),
        )
      )
        emit(m, "remote", n, "Shell downloads a remote payload");
      return empty();
    }
    if (
      /^fs(?:\.promises)?\.(readFile|readFileSync|writeFile|writeFileSync|readdir|readdirSync)$/.test(
        ref,
      )
    )
      emit(m, "filesystem", n, "File-system access");
    if (
      ref === "JSON.stringify" ||
      ref === "Buffer.from" ||
      ref === "decoded-value.toString"
    )
      return {
        ...merge(args.length ? args : [evaluate(n.callee.object, scope, m)], m),
        encoded: ref === "decoded-value.toString",
      };
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
    if (
      n.arguments.some((a) =>
        ["ArrowFunctionExpression", "FunctionExpression"].includes(a.type),
      )
    )
      warn(
        m,
        "Callback scheduling is unsupported; callback bodies may be uninspected.",
      );
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
        evaluate(n.test, scope, m);
        warn(m, "Conditional branches are merged; reachability is not proven.");
        const before = snapshot(scope);
        const a = statement(n.consequent, scope, m),
          after = snapshot(scope);
        for (const [c, v] of before) c.value = v;
        const b = statement(n.alternate, scope, m);
        for (const [c, v] of after) c.value = merge([v, c.value], m);
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
