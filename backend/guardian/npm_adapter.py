"""Pre-install npm acquisition and exact, offline, script-free installation.

Resolution uses npm's semver implementation, not npm install: metadata and artifacts
only pass through Guardian's HTTPS allowlist. Unsupported npm features fail closed.
Archives stay in memory until an approved installation invokes trusted npm.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from . import ingestion
from .dependencies import RegistrySession, EXACT
from .config import ArchiveLimits, NpmBudget, parser_limits
from .integrity import verify
from .supply_models import Artifact, Plan, AcquisitionError, IntegrityError, InstallError

ROOT = Path(__file__).resolve().parents[2]
NAME = re.compile(r'(?:@[a-z0-9_.-]+/)?[a-z0-9][a-z0-9_.-]*\Z')


def _env(home):
    # Do not inherit npm configuration, Node preload flags, credentials, or proxies.
    env = {k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TMPDIR', 'TEMP', 'TMP') if k in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), NPM_CONFIG_USERCONFIG=str(home / 'empty.npmrc'), NPM_CONFIG_GLOBALCONFIG=str(home / 'global.npmrc'))
    return env


def _run(args, cwd, home, timeout=120):
    try:
        result = subprocess.run(args, cwd=cwd, env=_env(home), capture_output=True, text=True, timeout=timeout, shell=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InstallError('Trusted package manager unavailable or timed out; installation did not complete.') from error
    if result.returncode:
        raise InstallError('npm refused the exact offline graph; installation did not complete. No lifecycle scripts were enabled.')
    return result.stdout


def _semver(versions, spec):
    """Use the trusted installed JS tooling, never code acquired from a package."""
    code = "const s=require(process.argv[1]);const p=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(s.maxSatisfying(p.versions,p.spec)));"
    try:
        result = subprocess.run(['node', '--max-old-space-size=128', '-e', code, str(ROOT / 'node_modules/semver')], input=json.dumps({'versions': versions, 'spec': spec}), capture_output=True, text=True, timeout=10, env={k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'WINDIR') if k in os.environ})
        if result.returncode:
            raise ValueError('semver unavailable')
        return json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise AcquisitionError('npm resolution requires Node.js and Guardian\'s installed semver dependency.', category='dependency_resolution_failure', operation='version selection') from error


def _requirement(name, spec):
    if not isinstance(name, str) or not NAME.fullmatch(name) or len(name) > 214 or not isinstance(spec, str) or len(spec) > 200 or not spec or any(ord(c) < 32 for c in spec):
        raise AcquisitionError('Invalid npm dependency declaration.')
    # Registry tags and semver only. In particular, never hand git/URL/file inputs to npm.
    if any(x in spec for x in (':', '/', '\\', '@', '#')) or spec.startswith('-'):
        raise AcquisitionError('Only registry npm versions, tags, and semver ranges are supported; URL, git, file, workspace, and alias dependencies are refused.')


def _declarations(manifest, root=False):
    if not isinstance(manifest, dict):
        raise AcquisitionError('npm manifest must be an object.', category='invalid_package_metadata', operation='manifest inspection')
    if any(manifest.get(k) for k in ('workspaces', 'overrides', 'bundledDependencies', 'bundleDependencies')):
        raise AcquisitionError('npm workspaces, overrides, and bundled dependencies require separate review and are unsupported.', category='unsupported_dependency_feature', operation='dependency resolution')
    if manifest.get('peerDependencies'):
        raise AcquisitionError('npm peer dependency resolution is not supported by this conservative resolver; installation requires review.', category='unsupported_dependency_feature', operation='dependency resolution')
    groups = ('dependencies', 'optionalDependencies', 'devDependencies') if root else ('dependencies', 'optionalDependencies')
    out = {}
    for group in groups:
        values = manifest.get(group, {})
        if not isinstance(values, dict):
            raise AcquisitionError('npm dependency groups must be objects.', category='invalid_package_metadata', operation='manifest inspection')
        for name, spec in values.items():
            _requirement(name, spec)
            out[name] = spec
    return out


def _snapshot(path):
    if path.is_symlink():
        raise AcquisitionError('Symlinked npm manifests and lockfiles are refused.')
    if not path.exists():
        return None
    if not path.is_file() or path.stat().st_size > ingestion.MAX_FILE:
        raise AcquisitionError('npm manifest or lockfile exceeds the supported size.')
    return path.read_text(encoding='utf-8')


def _graph_digest(manifest, lock, locations):
    return hashlib.sha256(json.dumps([manifest, lock, locations], sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _parse_specs(specs):
    out = {}
    for value in specs:
        # @scope/name@version and unscoped name@version.
        pos = value.rfind('@')
        name, spec = (value[:pos], value[pos + 1:]) if pos > 0 else (value, 'latest')
        _requirement(name, spec)
        out[name] = spec
    return out


def _manifest_files(raw, *, files=None, warnings=None, limits=None):
    if files is None:
        files, warnings = ingestion.archive(raw, 'tar', limits=limits or ArchiveLimits.from_env('npm'), root='package')
    files = {p[len('package/'):]: c for p, c in files.items()}
    try:
        manifest = json.loads(files['package.json'])
    except (KeyError, ValueError) as error:
        raise AcquisitionError('npm artifact has no valid package.json.', category='invalid_package_metadata', operation='manifest inspection') from error
    _declarations(manifest)
    return manifest, files, list(warnings or [])


def acquire_local(path):
    path = Path(path)
    if not path.name.endswith(('.tgz', '.tar.gz')) or path.stat().st_size > ArchiveLimits.from_env('npm').compressed:
        raise AcquisitionError('Local npm input must be a bounded .tgz or .tar.gz artifact.')
    raw = path.read_bytes()
    manifest, files, warnings = _manifest_files(raw)
    name, version = manifest.get('name'), manifest.get('version')
    if not isinstance(name, str) or not NAME.fullmatch(name) or not isinstance(version, str) or not EXACT.fullmatch(version):
        raise AcquisitionError('Local npm package identity must contain a valid name and exact version.')
    return Artifact('npm', name, version, path.name, raw, files, hashlib.sha256(raw).hexdigest(), False, warnings=warnings, kind='tgz')


def resolve(specs, project, offline=False):
    project = Path(project).resolve()
    original = _snapshot(project / 'package.json')
    original_lock = _snapshot(project / 'package-lock.json')
    if (project / 'npm-shrinkwrap.json').exists():
        raise AcquisitionError('npm-shrinkwrap.json is unsupported; refusing to ignore the authoritative lock.')
    try:
        manifest = json.loads(original) if original is not None else {'name': 'guardian-local-project', 'version': '1.0.0', 'private': True}
        locked = json.loads(original_lock) if original_lock is not None else None
    except ValueError as error:
        raise AcquisitionError('Invalid npm project JSON.') from error
    declarations = _declarations(manifest, root=True)
    requested = _parse_specs(specs)
    declarations.update(requested)
    if not declarations:
        raise AcquisitionError('No npm dependencies were specified or declared.')
    old = {}
    if locked is not None:
        if not isinstance(locked, dict) or locked.get('lockfileVersion') not in (2, 3) or not isinstance(locked.get('packages'), dict):
            raise AcquisitionError('Only npm package-lock v2/v3 is supported.')
        old = locked['packages']
        for location, entry in old.items():
            if location and (not isinstance(entry, dict) or entry.get('link') or not re.fullmatch(r'(?:node_modules/(?:@[a-z0-9_.-]+/)?[a-z0-9][a-z0-9_.-]*/?)+', location)):
                raise AcquisitionError('Unsupported or unsafe npm lockfile location.')
            if location:
                _declarations(entry)
    if offline:
        raise AcquisitionError('Offline registry resolution is unavailable. Use guardian check --offline on an already acquired local .tgz artifact.')
    budget = NpmBudget.from_env()
    archive_limits = ArchiveLimits.from_env('npm')
    session = RegistrySession(budget, archive_limits)
    packuments, artifacts, records, locations, roots = {}, [], {}, {}, []
    unique, selections, edges = {}, {}, {}

    def choose(name, spec, fixed=None):
        session.check_time()
        cache_key = (name, spec, fixed)
        if cache_key in selections:
            return selections[cache_key]
        if name not in packuments:
            try:
                data = json.loads(session.fetch('https://registry.npmjs.org/' + quote(name, safe=''), package=name))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise AcquisitionError('npm registry metadata must be valid JSON.', category='invalid_package_metadata', operation='registry metadata', package=name) from error
            if not isinstance(data, dict) or data.get('name') != name or not isinstance(data.get('versions'), dict) or not isinstance(data.get('dist-tags', {}), dict):
                raise AcquisitionError('npm registry identity or release metadata is invalid.', category='invalid_package_metadata', operation='registry metadata', package=name)
            packuments[name] = data
        data = packuments[name]
        versions = data['versions']
        if fixed:
            if spec not in data.get('dist-tags', {}) and _semver([fixed], spec) != fixed:
                raise AcquisitionError('Existing npm lock conflicts with a dependency requirement; refusing an implicit version change.', category='dependency_resolution_failure', operation='version selection', package=name)
            selected = fixed
        else:
            selected = data.get('dist-tags', {}).get(spec)
            if selected is None:
                selected = _semver(list(versions), spec)
        if not isinstance(selected, str) or not EXACT.fullmatch(selected) or selected not in versions:
            raise AcquisitionError('No exact npm version satisfies the requested specification.', category='dependency_resolution_failure', operation='version selection', package=name)
        meta = versions[selected]
        if not isinstance(meta, dict) or meta.get('name') != name or meta.get('version') != selected:
            raise AcquisitionError('npm release metadata identity mismatch.', category='invalid_package_metadata', operation='version selection', package=name)
        _declarations(meta)
        session.metadata[(name, selected)] = meta
        selections[cache_key] = (selected, meta)
        return selected, meta

    def prior(parent, name):
        while True:
            location = (parent + '/' if parent else '') + 'node_modules/' + name
            if location in old:
                return old[location], location
            if not parent:
                return None, None
            parent = parent.rsplit('/node_modules/', 1)[0] if '/node_modules/' in parent else ''

    def graph_limit(message, counter, value, limit, name):
        raise AcquisitionError(message, category='dependency_graph_limit', operation='dependency resolution',
                               package=name, budget=counter, limit=limit, encountered=value)

    def add(name, spec, parent='', ancestors=None, direct=False, old_parent=''):
        session.check_time()
        ancestors = ancestors or []
        for anc_name, anc_version, anc_loc in reversed(ancestors):
            if anc_name == name and _semver([anc_version], spec) == anc_version:
                return anc_loc
        depth = len(ancestors) + 1
        if depth > budget.depth:
            graph_limit('npm dependency graph exceeds the depth budget.', 'dependency_depth', depth, budget.depth, name)
        if len(records) >= budget.locations:
            graph_limit('npm dependency graph exceeds the configured location budget.', 'installation_locations', len(records) + 1, budget.locations, name)
        location = (parent + '/' if parent else '') + 'node_modules/' + name
        entry, old_location = prior(old_parent, name)
        fixed = entry.get('version') if entry and not (direct and name in requested) else None
        version, meta = choose(name, spec, fixed)
        key = (name, version)
        if key not in unique and len(unique) >= budget.artifacts:
            graph_limit('npm dependency graph exceeds the unique artifact budget.', 'unique_artifacts', len(unique) + 1, budget.artifacts, name)
        expected = entry.get('integrity') if entry and entry.get('version') == version else None
        # Even reused bytes must satisfy every location's lock integrity expectation.
        result = session.retrieve(name, version, expected)
        if result.registry_integrity.status != 'verified' or result.integrity.status not in ('missing', 'verified'):
            states = {result.registry_integrity.status, result.integrity.status}
            category = 'integrity_mismatch' if 'mismatch' in states else (
                'integrity_unverified' if result.registry_integrity.status == 'missing' else 'integrity_invalid')
            message = {'integrity_mismatch': 'npm artifact bytes do not match the expected integrity digest.',
                       'integrity_unverified': 'npm artifact lacks trusted registry integrity metadata.',
                       'integrity_invalid': 'npm artifact integrity metadata is invalid or unsupported.'}[category]
            raise IntegrityError(message, category=category,
                                 operation='integrity verification', package=name + '@' + version,
                                 detail='Registry and any supplied lockfile digest must match before inspection.')
        if key not in unique:
            actual, files, warnings = _manifest_files(result.raw, files=result.files, warnings=result.warnings)
            if actual.get('name') != name or actual.get('version') != version or _declarations(actual) != _declarations(meta):
                raise IntegrityError('npm tarball identity or dependency metadata differs from the registry release.', operation='manifest verification', package=name + '@' + version)
            artifact = Artifact('npm', name, version, name.rsplit('/', 1)[-1] + '-' + version + '.tgz', result.raw, files, hashlib.sha256(result.raw).hexdigest(), True, warnings=warnings, direct=direct, kind='tgz',
                                integrity=result.integrity, registry_integrity=result.registry_integrity)
            unique[key] = (artifact, actual)
            artifacts.append(artifact)
        artifact, actual = unique[key]
        artifact.direct = artifact.direct or direct
        record = {'version': version, 'resolved': meta['dist']['tarball'], 'integrity': result.registry_integrity.expected}
        for field in ('dependencies', 'optionalDependencies', 'engines', 'os', 'cpu'):
            if field in meta:
                record[field] = meta[field]
        records[location] = record
        locations[location] = artifact.sha256
        edges[location] = []
        if direct and artifact.identity not in roots:
            roots.append(artifact.identity)
        next_ancestors = ancestors + [(name, version, location)]
        for child, requirement in _declarations(actual).items():
            child_location = add(child, requirement, location, next_ancestors, old_parent=old_location or location)
            edges[location].append(child_location)
            child_id = next(a.identity for a in artifacts if a.sha256 == locations[child_location])
            if child_id not in artifact.dependencies:
                artifact.dependencies.append(child_id)
        return location

    for name, spec in declarations.items():
        add(name, spec, direct=True)
    # Pin explicitly requested roots; other declarations and locked versions persist.
    for name in requested:
        group = next((k for k in ('dependencies', 'devDependencies', 'optionalDependencies') if name in manifest.get(k, {})), 'dependencies')
        manifest.setdefault(group, {})[name] = records['node_modules/' + name]['version']
    root_record = {k: manifest[k] for k in ('name', 'version', 'dependencies', 'devDependencies', 'optionalDependencies') if k in manifest}
    lock = {'name': manifest.get('name', 'guardian-local-project'), 'version': manifest.get('version', '1.0.0'), 'lockfileVersion': 3, 'requires': True, 'packages': {'': root_record, **records}}
    session.check_time()
    analysis = parser_limits()
    graph = [{'location': loc, 'identity': next(a.identity for a in artifacts if a.sha256 == digest),
              'sha256': digest, 'direct': loc.count('node_modules/') == 1, 'dependencies': edges[loc]}
             for loc, digest in locations.items()]
    return Plan('npm', artifacts, roots,
                installer_data={'manifest': manifest, 'lock': lock, 'locations': locations,
                                'approved_graph_sha256': _graph_digest(manifest, lock, locations),
                                'original_manifest': original, 'original_lock': original_lock},
                locations=graph,
                budgets={'unique_artifacts': budget.artifacts, 'installation_locations': budget.locations,
                         'dependency_depth': budget.depth, 'registry_requests': budget.requests,
                         'downloaded_bytes': budget.bytes, 'expanded_bytes': budget.expanded,
                         'acquisition_seconds': budget.seconds, 'analysis_seconds': budget.analysis_seconds,
                         'artifact_analysis_seconds': archive_limits.analysis_seconds,
                         'analysis_modules': analysis['maxModules'], 'analysis_nodes': analysis['maxNodes'],
                         'analysis_steps': analysis['maxSteps']},
                acquisition={'registry_requests': session.requests, 'downloaded_bytes': session.bytes,
                             'expanded_bytes': session.expanded, 'elapsed_ms': int((time.monotonic() - session.started)*1000)})


def install(plan, project):
    project = Path(project).resolve()
    data = plan.installer_data
    if not plan.complete or not plan.artifacts or plan.ecosystem != 'npm':
        raise InstallError('Only a complete approved npm graph can be installed.')
    if _graph_digest(data['manifest'], data['lock'], data['locations']) != data.get('approved_graph_sha256'):
        raise IntegrityError('Approved npm lock graph changed after analysis; installation refused.')
    for artifact in plan.artifacts:
        if not artifact.verified or hashlib.sha256(artifact.raw).hexdigest() != artifact.sha256:
            raise IntegrityError('Approved npm artifact bytes changed or are unverified.')
    if _snapshot(project / 'package.json') != data['original_manifest'] or _snapshot(project / 'package-lock.json') != data['original_lock']:
        raise InstallError('Project manifest or lock changed after analysis; scan again.')
    modules = project / 'node_modules'
    if modules.is_symlink() or (modules.exists() and not modules.is_dir()):
        raise InstallError('Unsafe existing node_modules destination.')
    by_hash = {a.sha256: a for a in plan.artifacts}
    for location, record in data['lock']['packages'].items():
        if not location:
            continue
        artifact = by_hash.get(data['locations'].get(location))
        if not artifact or artifact.name != location.split('node_modules/')[-1] or artifact.version != record.get('version') or verify(artifact.raw, record.get('integrity')).status != 'verified':
            raise IntegrityError('Exact npm lock graph no longer matches approved artifacts.')
    npm = shutil.which('npm')
    if not npm:
        raise InstallError('npm is required for approved npm installation.')
    # Stage on the same filesystem so the final directory handoff is a rename.
    with tempfile.TemporaryDirectory(prefix='.guardian-install-', dir=str(project)) as temp:
        work = Path(temp)
        cache = work / 'cache'
        home = work / 'home'
        home.mkdir()
        (home / 'empty.npmrc').touch()
        (home / 'global.npmrc').touch()
        stage = work / 'project'
        stage.mkdir()
        manifest_text = json.dumps(data['manifest'], indent=2) + '\n'
        lock_text = json.dumps(data['lock'], indent=2) + '\n'
        (stage / 'package.json').write_text(manifest_text)
        (stage / 'package-lock.json').write_text(lock_text)
        flags = ['--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--cache', str(cache), '--registry', 'https://registry.npmjs.org', '--fetch-retries=0']
        for index, artifact in enumerate(plan.artifacts):
            artifact_path = work / (str(index) + '.tgz')
            artifact_path.write_bytes(artifact.raw)
            _run([npm, 'cache', 'add', str(artifact_path), *flags], stage, home)
        _run([npm, 'ci', *flags], stage, home)
        if (stage / 'package-lock.json').read_text() != lock_text:
            raise InstallError('npm changed the approved lockfile; refusing installation.')
        if _snapshot(project / 'package.json') != data['original_manifest'] or _snapshot(project / 'package-lock.json') != data['original_lock']:
            raise InstallError('Project changed during installation staging; scan again.')
        backup = work / 'previous-node-modules'
        moved_old, moved_new = False, False
        try:
            if modules.exists():
                modules.rename(backup)
                moved_old = True
            if (stage / 'node_modules').exists():
                (stage / 'node_modules').rename(modules)
                moved_new = True
            (project / 'package.json').write_text(manifest_text)
            (project / 'package-lock.json').write_text(lock_text)
        except Exception as error:
            if moved_new:
                shutil.rmtree(modules)
            if moved_old:
                backup.rename(modules)
            for filename, original in (('package.json', data['original_manifest']), ('package-lock.json', data['original_lock'])):
                target = project / filename
                if original is None:
                    target.unlink(missing_ok=True)
                else:
                    target.write_text(original)
            raise InstallError('npm installation handoff failed; previous files were restored.') from error
