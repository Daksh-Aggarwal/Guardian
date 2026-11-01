"""Bounded lockfile graph traversal and per-scan npm retrieval cache."""
import base64
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from urllib.parse import quote
import yaml
import httpx
from . import ingestion
from .config import Budget, ArchiveLimits
from .supply_models import AcquisitionError
from .integrity import verify
from .models import IntegrityResult, PackageInspection, InspectionSummary, Evidence

EXACT = re.compile(r'^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')
MAX_DISCOVERED = 2000

class BudgetExceeded(AcquisitionError):
    pass

@dataclass
class Retrieved:
    files: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    integrity: IntegrityResult = field(default_factory=IntegrityResult)
    registry_integrity: IntegrityResult = field(default_factory=IntegrityResult)
    metadata: dict = field(default_factory=dict)
    raw: bytes = b''

class RegistrySession:
    """Bounded registry traffic and verified, in-memory artifact caches."""
    def __init__(self, budget=None, archive_limits=None):
        self.budget = budget or Budget.from_env()
        self.archive_limits = archive_limits or ArchiveLimits.from_env('npm')
        self.started = time.monotonic()
        self.requests = self.bytes = self.expanded = 0
        self.metadata, self.tarballs, self.errors, self.contents = {}, {}, {}, {}
        self.archive_stats = {}

    def remaining(self):
        return self.budget.seconds - (time.monotonic() - self.started)

    def check_time(self):
        if self.remaining() <= 0:
            raise BudgetExceeded('npm resolution/acquisition elapsed-time budget reached.',
                                 category='acquisition_time_limit', operation='dependency acquisition',
                                 budget='elapsed_seconds', limit=self.budget.seconds,
                                 encountered=round(time.monotonic() - self.started, 3))

    def fetch(self, url, operation='registry metadata', package=None):
        self.check_time()
        if self.requests >= self.budget.requests:
            raise BudgetExceeded('Registry request budget reached.', category='registry_request_limit',
                                 operation=operation, package=package, budget='registry_requests',
                                 limit=self.budget.requests, encountered=self.requests + 1)
        remaining = self.budget.bytes - self.bytes
        if remaining <= 0:
            raise BudgetExceeded('Aggregate download-byte budget reached.', category='download_budget_limit',
                                 operation=operation, package=package, budget='downloaded_bytes',
                                 limit=self.budget.bytes, encountered=self.bytes)
        limit = min(self.archive_limits.compressed if operation == 'tarball download' else ingestion.MAX_UPLOAD, remaining)
        self.requests += 1
        try:
            data = ingestion.download(url, limit, timeout=min(15, max(.1, self.remaining())))
        except AcquisitionError as error:
            self.bytes += error.bytes_received
            error.operation, error.package = operation, package
            if operation == 'tarball download':
                if error.category == 'registry_response_limit':
                    error.category = 'tarball_download_limit'
                elif error.category == 'registry_timeout':
                    error.category = 'tarball_timeout'
            raise
        except httpx.TimeoutException as error:
            raise AcquisitionError('Registry request timed out.', category='tarball_timeout' if operation == 'tarball download' else 'registry_timeout', operation=operation, package=package) from error
        except httpx.HTTPStatusError as error:
            raise AcquisitionError('Registry returned an HTTP error.', category='registry_http_error', operation=operation, package=package, detail=f'HTTP status {error.response.status_code}.') from error
        except httpx.RequestError as error:
            raise AcquisitionError('Registry metadata or artifact is unavailable.', category='registry_unavailable', operation=operation, package=package) from error
        self.bytes += len(data)
        # Enforce the boundary even with alternate/test download transports.
        if len(data) > limit:
            raise AcquisitionError('Registry response exceeds the download limit.', category='tarball_download_limit' if operation == 'tarball download' else 'registry_response_limit', operation=operation, package=package, budget='download_bytes', limit=limit, encountered=len(data))
        self.check_time()
        return data

    def retrieve(self, name, version, expected=None, strict=True):
        ingestion.validate_package(name, version)
        key = (name, version)
        identity = name + '@' + version
        if key in self.errors:
            raise self.errors[key]
        self.check_time()
        try:
            if key not in self.metadata:
                url = 'https://registry.npmjs.org/' + quote(name, safe='') + '/' + quote(version, safe='')
                try:
                    metadata = json.loads(self.fetch(url, package=identity))
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    raise AcquisitionError('Registry metadata must be valid JSON.', category='invalid_package_metadata', operation='registry metadata', package=identity) from error
                self.metadata[key] = metadata
            metadata = self.metadata[key]
            if not isinstance(metadata, dict) or (strict and (metadata.get('name') != name or (EXACT.fullmatch(version) and metadata.get('version') != version))):
                raise AcquisitionError('Registry package identity does not match the requested name/version.', category='invalid_package_metadata', operation='registry metadata', package=identity)
            dist = metadata.get('dist', {})
            if not isinstance(dist, dict) or not isinstance(dist.get('tarball'), str):
                raise AcquisitionError('No valid registry tarball is available.', category='invalid_package_metadata', operation='registry metadata', package=identity)
            if key not in self.tarballs:
                self.tarballs[key] = self.fetch(dist['tarball'], 'tarball download', identity)
            data = self.tarballs[key]
            registry_expected = dist.get('integrity')
            if not registry_expected and isinstance(dist.get('shasum'), str):
                registry_expected = 'sha1-' + base64.b64encode(bytes.fromhex(dist['shasum'])).decode() if re.fullmatch(r'[0-9a-fA-F]{40}', dist['shasum']) else 'invalid-shasum'
            result = Retrieved(metadata=metadata, raw=data, integrity=verify(data, expected, 'lockfile'), registry_integrity=verify(data, registry_expected, 'registry'))
            if any(c.status not in {'missing', 'verified'} for c in (result.integrity, result.registry_integrity)):
                result.warnings.append('Integrity verification failed or is unsupported. Tarball was not extracted or analyzed.')
                return result
            self.check_time()
            if key not in self.contents:
                remaining = self.budget.expanded - self.expanded
                if remaining <= 0:
                    raise BudgetExceeded('Aggregate expanded-byte budget reached.', category='expanded_budget_limit', operation='archive inspection', package=identity, budget='expanded_bytes', limit=self.budget.expanded, encountered=self.expanded)
                stats = {}
                limits = replace(self.archive_limits, expanded=min(self.archive_limits.expanded, remaining))
                try:
                    self.contents[key] = ingestion.archive(data, 'tar', limits=limits, stats=stats, root='package')
                finally:
                    # Failed inspections also consumed decompression work.
                    self.expanded += stats.get('expanded', 0)
                self.archive_stats[key] = stats
            result.files, cached_warnings = self.contents[key]
            result.warnings = list(cached_warnings)
            self.check_time()
            if result.integrity.status == 'missing':
                result.warnings.append('Lockfile integrity is missing; no lockfile digest was verified.')
            if result.registry_integrity.status == 'missing':
                result.warnings.append('Registry integrity is missing; published bytes could not be verified.')
            return result
        except AcquisitionError as error:
            error.package = error.package or identity
            self.errors[key] = error
            raise


def declarations(value):
    out={}
    if not isinstance(value, dict):
        return out
    for key in ('dependencies','devDependencies','optionalDependencies'):
        if isinstance(value.get(key),dict):out.update(value[key])
    return out


def _npm_lock_graph(files, paths):
    warnings = []
    path = paths[0]
    lock = json.loads(files[path])
    packages = lock.get('packages')
    if not isinstance(packages, dict):
        return [], {}, ['Lockfile v1 has no modern packages graph; recursive inspection is unavailable.']
    if len(paths) > 1:
        warnings.append('Only the shallowest package-lock.json graph is inspected; other project lockfiles are uninspected.')

    root = packages.get('', {})
    if not root:
        manifest_path = str(PurePosixPath(path).parent / 'package.json')
        root = json.loads(files[manifest_path]) if manifest_path in files else {}
    root_decls = declarations(root)

    all_pkg_records = [(loc, p) for loc, p in packages.items() if loc and isinstance(p, dict)]
    if len(all_pkg_records) > MAX_DISCOVERED:
        warnings.append(f'Dependency graph inventory capped at {MAX_DISCOVERED} locations.')

    traversable_records = {loc: p for loc, p in all_pkg_records[:MAX_DISCOVERED]}
    omitted_records = {loc: p for loc, p in all_pkg_records[MAX_DISCOVERED:]}

    def resolve(parent, name):
        current = parent
        while True:
            candidate = (current + '/' if current else '') + 'node_modules/' + name
            if candidate in traversable_records:
                return candidate
            if not current:
                break
            current = current.rsplit('/node_modules/', 1)[0] if '/node_modules/' in current else ''
        return None

    nodes = {}
    for loc, p in traversable_records.items():
        name = p.get('name') or loc.split('node_modules/')[-1]
        nodes[loc] = PackageInspection(
            name=name,
            version=str(p.get('version', 'unresolved')),
            location=loc,
            direct=False,
            status='unresolved',
            reason='Not reachable from the root dependency declarations.'
        )

    for loc, p in omitted_records.items():
        name = p.get('name') or loc.split('node_modules/')[-1]
        is_direct = (loc == 'node_modules/' + name and name in root_decls)
        nodes[loc] = PackageInspection(
            name=name,
            version=str(p.get('version', 'unresolved')),
            location=loc,
            direct=is_direct,
            status='skipped',
            reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.'
        )

    queue = deque()
    seen = set()
    expected = {}

    for name, spec in root_decls.items():
        loc = resolve('', name)
        if loc:
            nodes[loc].direct = True
            queue.append((loc, 1))
        else:
            loc = 'unresolved:' + name
            if len(nodes) < MAX_DISCOVERED or loc in nodes:
                nodes[loc] = PackageInspection(name=name, version=str(spec), location=loc, direct=True, status='unresolved', reason='Root dependency has no matching lockfile entry.')
            else:
                nodes[loc] = PackageInspection(name=name, version=str(spec), location=loc, direct=True, status='skipped', reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.')

    while queue:
        loc, depth = queue.popleft()
        if loc in seen:
            continue
        seen.add(loc)
        node = nodes[loc]
        node.depth = depth
        entry = traversable_records[loc]
        expected[loc] = entry.get('integrity')
        node.integrity = IntegrityResult(expected=entry.get('integrity') if isinstance(entry.get('integrity'), str) else None, source='lockfile')
        if entry.get('link') or not EXACT.fullmatch(node.version):
            node.status = 'unresolved'
            node.reason = 'Workspace/link or non-exact version is not registry-resolvable.'
        else:
            node.status = 'uninspected'
            node.reason = 'Awaiting bounded source inspection.'
        for name, spec in declarations(entry).items():
            target = resolve(loc, name)
            if target:
                node.dependencies.append(target)
                if target in seen:
                    warnings.append(f'Reused/cyclic dependency edge: {loc} → {target}; visited once.')
                else:
                    queue.append((target, depth + 1))
            else:
                missing = loc + '/unresolved:' + name
                if len(nodes) < MAX_DISCOVERED or missing in nodes:
                    nodes[missing] = PackageInspection(name=name, version=str(spec), location=missing, direct=False, depth=depth + 1, status='unresolved', reason='Transitive dependency has no matching lockfile entry.')
                else:
                    nodes[missing] = PackageInspection(name=name, version=str(spec), location=missing, direct=False, depth=depth + 1, status='skipped', reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.')
                node.dependencies.append(missing)

    return list(nodes.values()), expected, warnings


def _parse_pnpm_key(k, p):
    if isinstance(p, dict) and p.get('name') and p.get('version'):
        return str(p['name']), str(p['version'])
    cleaned = k.lstrip('/')
    if '(' in cleaned and cleaned.endswith(')'):
        cleaned = cleaned[:cleaned.index('(')]
    if '_' in cleaned and '@' in cleaned:
        first_part = cleaned.split('_')[0]
        if '@' in first_part:
            cleaned = first_part
    if cleaned.startswith('@'):
        parts = cleaned.split('@')
        if len(parts) >= 3:
            name = '@' + parts[1]
            version = parts[2]
            return name, version
    elif '@' in cleaned:
        name, version = cleaned.split('@', 1)
        return name, version
    return cleaned, 'unresolved'


def _pnpm_lock_graph(files, paths):
    warnings = []
    path = paths[0]
    try:
        lock = yaml.safe_load(files[path])
    except Exception as e:
        return [], {}, [f'Could not parse pnpm-lock.yaml: {e}']
    if not isinstance(lock, dict):
        return [], {}, ['pnpm-lock.yaml must contain a YAML mapping.']
    if len(paths) > 1:
        warnings.append('Only the shallowest pnpm-lock.yaml graph is inspected; other project lockfiles are uninspected.')

    root_decls = {}
    if isinstance(lock.get('importers'), dict) and isinstance(lock['importers'].get('.'), dict):
        importer_root = lock['importers']['.']
        for key in ('dependencies', 'devDependencies', 'optionalDependencies'):
            group = importer_root.get(key)
            if isinstance(group, dict):
                for dep_name, dep_val in group.items():
                    if isinstance(dep_val, dict):
                        ver = dep_val.get('version') or dep_val.get('specifier') or ''
                    else:
                        ver = str(dep_val)
                    root_decls[dep_name] = ver
    for key in ('dependencies', 'devDependencies', 'optionalDependencies'):
        group = lock.get(key)
        if isinstance(group, dict):
            for dep_name, dep_val in group.items():
                if dep_name not in root_decls:
                    if isinstance(dep_val, dict):
                        ver = dep_val.get('version') or dep_val.get('specifier') or ''
                    else:
                        ver = str(dep_val)
                    root_decls[dep_name] = ver

    manifest_path = str(PurePosixPath(path).parent / 'package.json')
    if manifest_path in files:
        try:
            pkg_json = json.loads(files[manifest_path])
            if isinstance(pkg_json, dict):
                for k, v in declarations(pkg_json).items():
                    if k not in root_decls:
                        root_decls[k] = str(v)
        except Exception:
            pass

    raw_packages = lock.get('packages', {})
    snapshots = lock.get('snapshots', {})
    if not isinstance(raw_packages, dict): raw_packages = {}
    if not isinstance(snapshots, dict): snapshots = {}

    all_keys = list(dict.fromkeys(list(raw_packages.keys()) + list(snapshots.keys())))
    if len(all_keys) > MAX_DISCOVERED:
        warnings.append(f'Dependency graph inventory capped at {MAX_DISCOVERED} locations.')

    traversable_keys = all_keys[:MAX_DISCOVERED]
    omitted_keys = all_keys[MAX_DISCOVERED:]

    records = {}
    for k in traversable_keys:
        pkg_data = dict(raw_packages.get(k) or {})
        if k in snapshots and isinstance(snapshots[k], dict):
            snap_deps = snapshots[k].get('dependencies')
            if snap_deps and 'dependencies' not in pkg_data:
                pkg_data['dependencies'] = snap_deps
            snap_opt = snapshots[k].get('optionalDependencies')
            if snap_opt and 'optionalDependencies' not in pkg_data:
                pkg_data['optionalDependencies'] = snap_opt
        records[k] = pkg_data

    name_to_keys = {}
    nodes = {}
    expected = {}

    for k in traversable_keys:
        p = records[k]
        name, version = _parse_pnpm_key(k, p)
        loc = f"pnpm:{k.lstrip('/')}"
        name_to_keys.setdefault(name, []).append((version, loc, k))
        nodes[loc] = PackageInspection(
            name=name,
            version=version,
            location=loc,
            direct=False,
            status='unresolved',
            reason='Not reachable from the root dependency declarations.'
        )
        res = p.get('resolution') if isinstance(p, dict) else None
        if isinstance(res, dict) and res.get('integrity'):
            expected[loc] = str(res['integrity'])
        elif isinstance(p, dict) and p.get('integrity'):
            expected[loc] = str(p['integrity'])

    for k in omitted_keys:
        p = raw_packages.get(k) or snapshots.get(k) or {}
        name, version = _parse_pnpm_key(k, p)
        loc = f"pnpm:{k.lstrip('/')}"
        is_direct = (name in root_decls)
        nodes[loc] = PackageInspection(
            name=name,
            version=version,
            location=loc,
            direct=is_direct,
            status='skipped',
            reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.'
        )

    def resolve_pnpm(name, spec=None):
        candidates = name_to_keys.get(name, [])
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0][1], candidates[0][2]
        if spec:
            for ver, loc, k in candidates:
                if ver == str(spec) or (EXACT.fullmatch(ver) and str(spec).endswith(ver)):
                    return loc, k
        return candidates[0][1], candidates[0][2]

    queue = deque()
    seen = set()

    for name, spec in root_decls.items():
        resolved = resolve_pnpm(name, spec)
        if resolved:
            loc, k = resolved
            nodes[loc].direct = True
            queue.append((loc, k, 1))
        else:
            loc = 'unresolved:' + name
            if len(nodes) < MAX_DISCOVERED or loc in nodes:
                nodes[loc] = PackageInspection(name=name, version=str(spec), location=loc, direct=True, status='unresolved', reason='Root dependency has no matching lockfile entry.')
            else:
                nodes[loc] = PackageInspection(name=name, version=str(spec), location=loc, direct=True, status='skipped', reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.')

    while queue:
        loc, k, depth = queue.popleft()
        if loc in seen:
            continue
        seen.add(loc)
        node = nodes[loc]
        node.depth = depth
        integ = expected.get(loc)
        node.integrity = IntegrityResult(expected=integ, source='pnpm-lock.yaml')
        if not EXACT.fullmatch(node.version):
            node.status = 'unresolved'
            node.reason = 'Workspace/link or non-exact version is not registry-resolvable.'
        else:
            node.status = 'uninspected'
            node.reason = 'Awaiting bounded source inspection.'

        entry = records.get(k, {})
        for dep_name, dep_spec in declarations(entry).items():
            target = resolve_pnpm(dep_name, str(dep_spec))
            if target:
                target_loc, target_k = target
                node.dependencies.append(target_loc)
                if target_loc in seen:
                    warnings.append(f'Reused/cyclic dependency edge: {loc} → {target_loc}; visited once.')
                else:
                    queue.append((target_loc, target_k, depth + 1))
            else:
                missing = loc + '/unresolved:' + dep_name
                if len(nodes) < MAX_DISCOVERED or missing in nodes:
                    nodes[missing] = PackageInspection(name=dep_name, version=str(dep_spec), location=missing, direct=False, depth=depth + 1, status='unresolved', reason='Transitive dependency has no matching lockfile entry.')
                else:
                    nodes[missing] = PackageInspection(name=dep_name, version=str(dep_spec), location=missing, direct=False, depth=depth + 1, status='skipped', reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.')
                node.dependencies.append(missing)

    return list(nodes.values()), expected, warnings


def _parse_yarn_descriptor(desc):
    d = desc.strip().strip('"\'')
    if d.startswith('@'):
        parts = d.split('@')
        name = '@' + parts[1]
        spec = parts[2] if len(parts) > 2 else ''
    elif '@' in d:
        name, spec = d.split('@', 1)
    else:
        name, spec = d, ''
    if spec.startswith('npm:'):
        spec = spec[4:]
    elif spec.startswith('workspace:'):
        spec = spec[10:]
    return name, spec


def _yarn_lock_graph(files, paths):
    warnings = []
    path = paths[0]
    try:
        lock = yaml.safe_load(files[path])
    except Exception as e:
        return [], {}, [f'Could not parse yarn.lock: {e}']
    if not isinstance(lock, dict):
        return [], {}, ['yarn.lock must contain a YAML mapping.']

    if '__metadata' not in lock:
        return [], {}, ['Yarn v1 lockfile format is not supported; modern Yarn Berry (v2+) or npm/pnpm lockfile required.']

    if len(paths) > 1:
        warnings.append('Only the shallowest yarn.lock graph is inspected; other project lockfiles are uninspected.')

    manifest_path = str(PurePosixPath(path).parent / 'package.json')
    root_decls = {}
    if manifest_path in files:
        try:
            pkg_json = json.loads(files[manifest_path])
            if isinstance(pkg_json, dict):
                root_decls.update(declarations(pkg_json))
        except Exception:
            pass

    pkg_entries = [(k, v) for k, v in lock.items() if k != '__metadata' and isinstance(v, dict)]
    if len(pkg_entries) > MAX_DISCOVERED:
        warnings.append(f'Dependency graph inventory capped at {MAX_DISCOVERED} locations.')

    traversable_entries = pkg_entries[:MAX_DISCOVERED]
    omitted_entries = pkg_entries[MAX_DISCOVERED:]

    records = {}
    name_to_records = {}
    nodes = {}
    expected = {}

    for k, v in traversable_entries:
        descriptors = [_parse_yarn_descriptor(desc) for desc in k.split(',')]
        primary_name, _ = descriptors[0]
        version = str(v.get('version', 'unresolved'))
        loc = f"yarn:{primary_name}@{version}"
        records[loc] = (v, descriptors)

        nodes[loc] = PackageInspection(
            name=primary_name,
            version=version,
            location=loc,
            direct=False,
            status='unresolved',
            reason='Not reachable from the root dependency declarations.'
        )

        for name, spec in descriptors:
            name_to_records.setdefault(name, []).append((spec, version, loc, v))

        checksum = v.get('checksum')
        if isinstance(checksum, str) and checksum.startswith(('sha512-', 'sha384-', 'sha256-', 'sha1-')):
            expected[loc] = checksum

    for k, v in omitted_entries:
        descriptors = [_parse_yarn_descriptor(desc) for desc in k.split(',')]
        primary_name, _ = descriptors[0]
        version = str(v.get('version', 'unresolved'))
        loc = f"yarn:{primary_name}@{version}"
        is_direct = (primary_name in root_decls)
        nodes[loc] = PackageInspection(
            name=primary_name,
            version=version,
            location=loc,
            direct=is_direct,
            status='skipped',
            reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.'
        )

    def resolve_yarn(name, spec=None):
        candidates = name_to_records.get(name, [])
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0][2], candidates[0][3]
        if spec:
            for s, ver, loc, entry in candidates:
                if s == str(spec) or ver == str(spec):
                    return loc, entry
        return candidates[0][2], candidates[0][3]

    queue = deque()
    seen = set()

    for name, spec in root_decls.items():
        resolved = resolve_yarn(name, str(spec))
        if resolved:
            loc, entry = resolved
            nodes[loc].direct = True
            queue.append((loc, entry, 1))
        else:
            loc = 'unresolved:' + name
            if len(nodes) < MAX_DISCOVERED or loc in nodes:
                nodes[loc] = PackageInspection(name=name, version=str(spec), location=loc, direct=True, status='unresolved', reason='Root dependency has no matching lockfile entry.')
            else:
                nodes[loc] = PackageInspection(name=name, version=str(spec), location=loc, direct=True, status='skipped', reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.')

    while queue:
        loc, entry, depth = queue.popleft()
        if loc in seen:
            continue
        seen.add(loc)
        node = nodes[loc]
        node.depth = depth
        integ = expected.get(loc)
        node.integrity = IntegrityResult(expected=integ, source='yarn.lock')
        if not EXACT.fullmatch(node.version):
            node.status = 'unresolved'
            node.reason = 'Workspace or non-exact version is not registry-resolvable.'
        else:
            node.status = 'uninspected'
            node.reason = 'Awaiting bounded source inspection.'

        for dep_name, dep_spec in declarations(entry).items():
            target = resolve_yarn(dep_name, str(dep_spec))
            if target:
                target_loc, target_entry = target
                node.dependencies.append(target_loc)
                if target_loc in seen:
                    warnings.append(f'Reused/cyclic dependency edge: {loc} → {target_loc}; visited once.')
                else:
                    queue.append((target_loc, target_entry, depth + 1))
            else:
                missing = loc + '/unresolved:' + dep_name
                if len(nodes) < MAX_DISCOVERED or missing in nodes:
                    nodes[missing] = PackageInspection(name=dep_name, version=str(dep_spec), location=missing, direct=False, depth=depth + 1, status='unresolved', reason='Transitive dependency has no matching lockfile entry.')
                else:
                    nodes[missing] = PackageInspection(name=dep_name, version=str(dep_spec), location=missing, direct=False, depth=depth + 1, status='skipped', reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.')
                node.dependencies.append(missing)

    return list(nodes.values()), expected, warnings


def lock_graph(files):
    """Resolve lockfile locations across npm (package-lock.json), pnpm (pnpm-lock.yaml), or Yarn Berry (yarn.lock)."""
    npm_paths = sorted((p for p in files if PurePosixPath(p).name == 'package-lock.json'), key=lambda p: (len(PurePosixPath(p).parts), p))
    if npm_paths:
        return _npm_lock_graph(files, npm_paths)

    pnpm_paths = sorted((p for p in files if PurePosixPath(p).name == 'pnpm-lock.yaml'), key=lambda p: (len(PurePosixPath(p).parts), p))
    if pnpm_paths:
        return _pnpm_lock_graph(files, pnpm_paths)

    yarn_paths = sorted((p for p in files if PurePosixPath(p).name == 'yarn.lock'), key=lambda p: (len(PurePosixPath(p).parts), p))
    if yarn_paths:
        return _yarn_lock_graph(files, yarn_paths)

    manifests = sorted((p for p in files if PurePosixPath(p).name == 'package.json'), key=lambda p: (len(PurePosixPath(p).parts), p))
    root = json.loads(files[manifests[0]]) if manifests else {}
    root_decls = declarations(root)
    nodes = []
    for index, (n, v) in enumerate(root_decls.items()):
        if index < MAX_DISCOVERED:
            nodes.append(PackageInspection(name=n, version=str(v), location='manifest:' + n, direct=True, status='unresolved', reason='No lockfile exact resolution available.'))
        else:
            nodes.append(PackageInspection(name=n, version=str(v), location='manifest:' + n, direct=True, status='skipped', reason=f'Omitted: dependency graph inventory ceiling ({MAX_DISCOVERED}) reached.'))
    warnings = []
    if len(root_decls) > MAX_DISCOVERED:
        warnings.append(f'Dependency graph inventory capped at {MAX_DISCOVERED} locations.')
    return nodes, {}, ['No modern lockfile: declared dependency source is uninspected.'] if nodes else []


def inspect_dependencies(files, analyzer, profile='fast', session=None, cancel=None):
    session = session or RegistrySession(Budget.from_env(profile))
    started = time.monotonic()
    nodes, expected, warnings = lock_graph(files)
    findings = []
    file_count = 0
    analyzed = {}
    attempts = set()
    from .engine import finding
    for node in sorted(nodes, key=lambda n: n.depth if n.depth is not None else 9999):
        if node.status != 'uninspected':
            continue
        if cancel and cancel.is_set():
            node.status = 'not_attempted'
            node.reason = 'Scan cancelled.'
            continue
        key = (node.name, node.version)
        if node.depth > session.budget.depth or (key not in attempts and len(attempts) >= session.budget.packages) or session.remaining() <= 0:
            node.status = 'skipped'
            node.reason = 'Dependency depth, package count, or time budget reached.'
            continue
        attempts.add(key)
        try:
            result = session.retrieve(*key, expected.get(node.location))
            node.integrity = result.integrity
            node.registry_integrity = result.registry_integrity
            failures = [x for x in [result.integrity, result.registry_integrity] if x.status not in {'verified', 'missing'}]
            if failures:
                node.status = 'integrity_failed'
                node.reason = 'Tarball was not extracted because integrity verification failed.'
                f = finding('PACKAGE_INTEGRITY', f'{node.name}: integrity could not be verified', 'Package integrity', 'high', 'high', node.reason, 'The downloaded file did not pass its supplied integrity check. Guardian did not inspect its contents.', 'The bytes may be different, damaged, or described by unsupported metadata. This does not establish malicious behavior.', 'Do not use these bytes; verify the lockfile, registry metadata, and package publisher.', [Evidence(file=node.location, snippet=x.expected or '', detail=x.detail) for x in failures])
                f.domain = 'integrity'
                f.package = f'{node.name}@{node.version}'
                findings.append(f)
                node.finding_ids = [f.id]
                continue
            if key not in analyzed:
                if session.remaining() <= 0:
                    raise BudgetExceeded('Time budget reached before source analysis.')
                prefix = f'dependencies/{node.name}@{node.version}/'
                namespaced = {prefix + p: c for p, c in result.files.items()}
                analyzed[key] = analyzer(namespaced, timeout=max(0.1, min(20, session.remaining())))
                _, _, package_findings, _, package_coverage, count = analyzed[key]
                for f in package_findings:
                    f.package = f'{node.name}@{node.version}'
                findings.extend(package_findings)
                file_count += count
                warnings.extend(f'{node.name}@{node.version}: {w}' for w in package_coverage if not w.startswith('Static analysis only'))
            package_findings = analyzed[key][2]
            node.finding_ids = [f.id for f in package_findings]
            node.status = 'inspected'
            node.reason = 'Bounded static inspection completed; check source coverage limitations.'
            warnings.extend(f'{node.name}@{node.version}: {w}' for w in result.warnings)
        except BudgetExceeded as error:
            node.status = 'skipped'
            node.reason = str(error)
        except Exception:
            node.status = 'unavailable'
            node.reason = 'Registry metadata, tarball, or source inspection unavailable; package is uninspected.'
    for node in nodes:
        if node.status == 'uninspected':
            node.status = 'not_attempted'
            node.reason = 'Inspection not attempted.'
    inspected_count = sum(n.status == 'inspected' for n in nodes)
    skipped_count = sum(n.status == 'skipped' for n in nodes)
    unavailable_count = sum(n.status == 'unavailable' for n in nodes)
    unresolved_count = sum(n.status == 'unresolved' for n in nodes)
    integrity_failed_count = sum(n.status == 'integrity_failed' for n in nodes)
    not_attempted_count = sum(n.status == 'not_attempted' for n in nodes)
    total_count = len(nodes)
    direct_count = sum(bool(n.direct) for n in nodes)
    transitive_count = sum(not n.direct for n in nodes)
    summary = InspectionSummary(
        total=total_count,
        direct=direct_count,
        transitive=transitive_count,
        inspected=inspected_count,
        skipped=skipped_count,
        unavailable=unavailable_count,
        unresolved=unresolved_count,
        integrity_failed=integrity_failed_count,
        not_attempted=not_attempted_count,
        packages_with_findings=sum(bool(n.finding_ids) for n in nodes),
        profile=profile,
        registry_requests=session.requests,
        downloaded_bytes=session.bytes,
        elapsed_ms=int((time.monotonic() - started) * 1000)
    )
    if summary.inspected < summary.total:
        parts = []
        if summary.skipped: parts.append(f'{summary.skipped} skipped by budget')
        if summary.unavailable: parts.append(f'{summary.unavailable} unavailable')
        if summary.unresolved: parts.append(f'{summary.unresolved} unresolved')
        if summary.integrity_failed: parts.append(f'{summary.integrity_failed} integrity failed')
        if summary.not_attempted: parts.append(f'{summary.not_attempted} not attempted')
        reasons = f" ({', '.join(parts)})" if parts else ""
        warnings.append(f'Dependency inspection incomplete: {summary.inspected}/{summary.total} locations inspected{reasons}. Uninspected packages are not evidence of safety.')
    return nodes, summary, findings, warnings, file_count
