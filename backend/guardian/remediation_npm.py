"""In-memory npm lockfile construction. Never runs npm or project code.

Only Guardian's installed semver library evaluates ranges. Registry callbacks are
injected so construction and validation share the same metadata contract.
"""
import base64
import copy
import json
import os
import re
import subprocess
from urllib.parse import urlsplit

from .npm_adapter import _semver, _requirement, ROOT
from .dependencies import MAX_DISCOVERED

GROUPS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
GRAPH_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta")
NODE_FIELDS = GRAPH_FIELDS + ("engines", "bin", "os", "cpu", "license", "deprecated")


class NpmPlanError(ValueError):
    def __init__(self, message, status="REJECTED"):
        super().__init__(message)
        self.status = status


def object_json(content, path):
    try:
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("expected an object")
        return data
    except (ValueError, TypeError) as error:
        raise NpmPlanError(f"{path} is not a valid JSON object: {error}") from error


def serialize_like(original, data):
    # Keep common indentation/newline conventions; anchors remain original bytes.
    match = re.search(r"\n([ \t]+)\"", original)
    indent = match.group(1) if match else None
    text = json.dumps(data, indent=indent, ensure_ascii=False)
    if "\r\n" in original:
        text = text.replace("\n", "\r\n")
    return text + ("\r\n" if original.endswith("\r\n") else "\n" if original.endswith("\n") else "")


def lock_graph(lock):
    if lock.get("lockfileVersion") not in (2, 3):
        raise NpmPlanError(f"package-lock.json lockfileVersion={lock.get('lockfileVersion')!r} is unsupported; npm v2/v3 is required.")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise NpmPlanError("package-lock.json requires a packages graph and root packages[''] entry.")
    return packages


def dist_fields(meta, name, version):
    dist = meta.get("dist", {})
    if not isinstance(dist, dict):
        dist = {}
    tarball, integrity = dist.get("tarball"), dist.get("integrity")
    if not integrity and isinstance(dist.get("shasum"), str) and re.fullmatch(r"[0-9a-fA-F]{40}", dist["shasum"]):
        integrity = "sha1-" + base64.b64encode(bytes.fromhex(dist["shasum"])).decode()
    if not isinstance(tarball, str) or not isinstance(integrity, str) or not integrity:
        raise NpmPlanError(f"Registry metadata for {name}@{version} lacks a published tarball or integrity/shasum; UNVERIFIED.", "UNVERIFIED")
    url = urlsplit(tarball)
    if url.scheme != "https" or url.hostname != "registry.npmjs.org" or url.username or url.password or url.port not in (None, 443):
        raise NpmPlanError(f"Registry tarball for {name}@{version} is outside the npm HTTPS allowlist.")
    return {"resolved": tarball, "integrity": integrity}


def published_metadata(query, name, version):
    _requirement(name, version)
    meta, status, detail = query(name, version)
    if status in ("unavailable", "invalid"):
        raise NpmPlanError(f"npm registry verification is unavailable for {name}@{version}: {detail}; UNVERIFIED.", "UNVERIFIED")
    if status != "ok" or not isinstance(meta, dict):
        raise NpmPlanError(f"Invalid/nonexistent package version: {name}@{version} does not exist in npm registry.")
    if meta.get("name") != name or meta.get("version") != version:
        raise NpmPlanError(f"Registry identity mismatch: requested {name}@{version}, received {meta.get('name')}@{meta.get('version')}; UNVERIFIED.", "UNVERIFIED")
    dist_fields(meta, name, version)
    return meta


def package_name(path):
    return path.rsplit("node_modules/", 1)[-1]


def parent_path(path):
    return path.rsplit("/node_modules/", 1)[0] if "/node_modules/" in path else ""


def resolve(packages, owner, name, peer=False):
    current = parent_path(owner) if peer and owner else owner
    while True:
        candidate = f"{current}/node_modules/{name}" if current else f"node_modules/{name}"
        if candidate in packages:
            return candidate
        if not current:
            return None
        current = parent_path(current)


def declarations(meta, root=False):
    result = {}
    for group in (("dependencies", "devDependencies", "optionalDependencies") if root else ("dependencies", "optionalDependencies")):
        values = meta.get(group, {})
        if not isinstance(values, dict):
            raise NpmPlanError(f"Invalid {group} declaration in npm metadata.")
        result.update(values)
    return result


def graph_errors(packages):
    """Check actual nearest-node resolution, including peers and optional nodes present."""
    errors = []
    checks = []
    for path, node in packages.items():
        if not isinstance(node, dict):
            errors.append(f"package-lock.json packages[{path!r}] is not an object.")
            continue
        requirements = [(name, spec, False) for name, spec in declarations(node, root=not path).items()]
        peers = node.get("peerDependencies", {})
        if not isinstance(peers, dict):
            raise NpmPlanError(f"Invalid peerDependencies at {path!r}.")
        requirements += [(name, spec, True) for name, spec in peers.items()]
        for name, spec, peer in requirements:
            _requirement(name, spec)
            target = resolve(packages, path, name, peer)
            optional = name in node.get("optionalDependencies", {}) or (peer and node.get("peerDependenciesMeta", {}).get(name, {}).get("optional"))
            if target is None and optional:
                continue
            version = packages.get(target, {}).get("version")
            checks.append((version, spec, f"package-lock.json graph: {path or '<root>'} requires {name}@{spec}, resolves {target or '<missing>'}@{version or '<missing>'}."))
    if len(checks) > 20000:
        raise NpmPlanError("Lockfile graph exceeds 20,000 dependency edges.")
    if checks:
        # Evaluate the entire graph in one bounded trusted process, rather than
        # launching Node once per edge in a real-world lockfile.
        code = "const s=require(process.argv[1]);const p=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(p.map(([v,r])=>typeof v==='string'&&s.valid(v)!==null&&s.satisfies(v,r))));"
        result = subprocess.run(['node', '--max-old-space-size=128', '-e', code, str(ROOT / 'node_modules/semver')],
                                input=json.dumps([(v, spec) for v, spec, _ in checks]), capture_output=True, text=True, timeout=10,
                                env={k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'WINDIR') if k in os.environ})
        if result.returncode:
            raise NpmPlanError("Guardian's npm semver graph validation is unavailable.", "UNVERIFIED")
        valid = json.loads(result.stdout)
        errors.extend(message for (_, _, message), ok in zip(checks, valid) if not ok)
    return errors


def legacy_entry(lock, path):
    current = lock.get("dependencies", {})
    for part in path.split("/node_modules/"):
        name = part[len("node_modules/"):] if part.startswith("node_modules/") else part
        if not isinstance(current, dict) or name not in current:
            return None
        entry = current[name]
        current = entry.get("dependencies", {}) if isinstance(entry, dict) else {}
    return entry


def published_node_errors(lock, path, meta):
    node = lock["packages"][path]
    name, version = package_name(path), node.get("version")
    errors = []
    for field, expected in dist_fields(meta, name, version).items():
        if node.get(field) != expected:
            errors.append(f"Lockfile {field} metadata for {name}@{version} at {path} does not match registry: {node.get(field)!r} vs {expected!r}.")
    for field in GRAPH_FIELDS:
        if node.get(field, {}) != meta.get(field, {}):
            errors.append(f"Lockfile {path}.{field} does not match published {name}@{version} dependency metadata.")
    if lock["lockfileVersion"] == 2:
        legacy = legacy_entry(lock, path)
        if not isinstance(legacy, dict):
            errors.append(f"Lockfile v2 legacy dependencies entry is missing for {path}.")
        else:
            for field in ("version", "resolved", "integrity"):
                if legacy.get(field) != node.get(field):
                    errors.append(f"Lockfile v2 legacy {path}.{field} does not match packages graph.")
            if legacy.get("requires", {}) != declarations(node):
                errors.append(f"Lockfile v2 legacy {path}.requires does not match packages graph.")
    return errors


def sync_legacy(lock, changed_paths):
    if lock["lockfileVersion"] != 2:
        return
    for path in sorted(changed_paths, key=len):
        node = lock["packages"][path]
        current = lock.setdefault("dependencies", {})
        parts = path.split("/node_modules/")
        for i, part in enumerate(parts):
            name = part[len("node_modules/"):] if part.startswith("node_modules/") else part
            entry = current.setdefault(name, {})
            if i != len(parts) - 1:
                current = entry.setdefault("dependencies", {})
        for key in ("version", "resolved", "integrity", "dev", "optional", "hasInstallScript"):
            entry.pop(key, None)
            if key in node:
                entry[key] = node[key]
        requires = declarations(node)
        if requires:
            entry["requires"] = requires
        else:
            entry.pop("requires", None)


def update_node(node, name, version, meta):
    result = dict(node)
    # Old release dependency declarations cannot be carried into the new release.
    for field in NODE_FIELDS + ("hasInstallScript",):
        result.pop(field, None)
    result.update(version=version, **dist_fields(meta, name, version))
    for field in NODE_FIELDS:
        if field in meta:
            result[field] = copy.deepcopy(meta[field])
    scripts = meta.get("scripts", {})
    if any(stage in scripts for stage in ("preinstall", "install", "postinstall")):
        result["hasInstallScript"] = True
    return result


def reachable(packages):
    seen, queue = set(), [""]
    while queue:
        owner = queue.pop()
        if owner in seen:
            continue
        seen.add(owner)
        node = packages[owner]
        for name in declarations(node, root=not owner):
            target = resolve(packages, owner, name)
            if target is not None:
                queue.append(target)
        for name in node.get("peerDependencies", {}):
            target = resolve(packages, owner, name, peer=True)
            if target is not None:
                queue.append(target)
    return seen


def construct_lock(lock, manifest, targets, query):
    """Resolve changed releases and their dependency closures without executing code.

    Existing satisfying nodes are reused. New conflicts are nested under their
    owner. Unsupported workspace/alias/override semantics fail visibly.
    """
    lock = copy.deepcopy(lock)
    packages = lock_graph(lock)
    originally_reachable = reachable(packages)
    if manifest.get("workspaces") or manifest.get("overrides"):
        raise NpmPlanError("npm workspaces/overrides require manual package-manager resolution.")
    for group in GROUPS:
        packages[""].pop(group, None)
        if group in manifest:
            packages[""][group] = copy.deepcopy(manifest[group])
    changed = set()
    queue = []

    def put(path, name, version, optional=False):
        if len(changed) >= MAX_DISCOVERED:
            raise NpmPlanError("Dependency remediation exceeds the configured package resolution budget; UNVERIFIED.", "UNVERIFIED")
        meta = published_metadata(query, name, version)
        if meta.get("bundleDependencies") or meta.get("bundledDependencies"):
            raise NpmPlanError(f"Bundled dependencies in {name}@{version} require manual resolution.")
        previous = packages.get(path, {})
        if previous.get("link") or previous.get("inBundle"):
            raise NpmPlanError(f"Linked/bundled resolution at {path} requires manual resolution.")
        node = update_node(previous, name, version, meta)
        if not previous:
            parent = packages.get(parent_path(path), {})
            for flag in ("dev", "optional", "devOptional"):
                if parent.get(flag):
                    node[flag] = True
            if optional:
                node["optional"] = True
        packages[path] = node
        changed.add(path)
        queue.append(path)

    for name, version in targets.items():
        put(f"node_modules/{name}", name, version)

    processed = set()
    while queue:
        owner = queue.pop(0)
        identity = (owner, packages[owner]["version"])
        if identity in processed:
            continue
        processed.add(identity)
        node = packages[owner]
        for name, spec in declarations(node).items():
            _requirement(name, spec)
            target = resolve(packages, owner, name)
            if target and _semver([packages[target].get("version", "")], spec):
                continue
            data, status, detail = query(name)
            if status != "ok" or not isinstance(data, dict) or not isinstance(data.get("versions"), dict):
                raise NpmPlanError(f"Registry unavailable while resolving {owner} -> {name}@{spec}: {detail}; UNVERIFIED.", "UNVERIFIED")
            version = _semver(list(data["versions"]), spec)
            if not version:
                raise NpmPlanError(f"No published version satisfies {owner} -> {name}@{spec}.")
            put(f"{owner}/node_modules/{name}", name, version, optional=name in node.get("optionalDependencies", {}))

    obsolete = originally_reachable - reachable(packages)
    for path in sorted(obsolete, key=len, reverse=True):
        packages.pop(path, None)
        if lock["lockfileVersion"] == 2:
            parent = parent_path(path)
            container = legacy_entry(lock, parent).get("dependencies", {}) if parent and legacy_entry(lock, parent) else lock.get("dependencies", {})
            container.pop(package_name(path), None)
    errors = graph_errors(packages)
    if errors:
        raise NpmPlanError("; ".join(errors))
    sync_legacy(lock, changed)
    return lock
