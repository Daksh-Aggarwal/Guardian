"""Pre-install npm acquisition and exact, offline, script-free installation.

Resolution uses npm's semver implementation, not npm install: metadata and artifacts
only pass through Guardian's HTTPS allowlist. Unsupported npm features fail closed.
Archives stay in memory until an approved installation invokes trusted npm.
"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import tarfile
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from . import ingestion
from .dependencies import RegistrySession, EXACT
from .config import Budget
from .integrity import verify
from .supply_models import Artifact, Plan, AcquisitionError, IntegrityError, InstallError

ROOT = Path(__file__).resolve().parents[2]
MAX_PACKAGES = 40
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
        raise AcquisitionError('npm resolution requires Node.js and Guardian\'s installed semver dependency.') from error


def _requirement(name, spec):
    if not isinstance(name, str) or not NAME.fullmatch(name) or len(name) > 214 or not isinstance(spec, str) or len(spec) > 200 or not spec or any(ord(c) < 32 for c in spec):
        raise AcquisitionError('Invalid npm dependency declaration.')
    # Registry tags and semver only. In particular, never hand git/URL/file inputs to npm.
    if any(x in spec for x in (':', '/', '\\', '@', '#')) or spec.startswith('-'):
        raise AcquisitionError('Only registry npm versions, tags, and semver ranges are supported; URL, git, file, workspace, and alias dependencies are refused.')


def _declarations(manifest, root=False):
    if not isinstance(manifest, dict):
        raise AcquisitionError('npm manifest must be an object.')
    if any(manifest.get(k) for k in ('workspaces', 'overrides', 'bundledDependencies', 'bundleDependencies')):
        raise AcquisitionError('npm workspaces, overrides, and bundled dependencies require separate review and are unsupported.')
    if manifest.get('peerDependencies'):
        raise AcquisitionError('npm peer dependency resolution is not supported by this conservative resolver; installation requires review.')
    groups = ('dependencies', 'optionalDependencies', 'devDependencies') if root else ('dependencies', 'optionalDependencies')
    out = {}
    for group in groups:
        values = manifest.get(group, {})
        if not isinstance(values, dict):
            raise AcquisitionError('npm dependency groups must be objects.')
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


def _parse_specs(specs):
    out = {}
    for value in specs:
        # @scope/name@version and unscoped name@version.
        pos = value.rfind('@')
        name, spec = (value[:pos], value[pos + 1:]) if pos > 0 else (value, 'latest')
        _requirement(name, spec)
        out[name] = spec
    return out


def _manifest_files(raw):
    # Bound every member, including formats the static reader intentionally skips.
    # This also prevents opaque files outside package/ entering approved installs.
    expanded = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            for index, item in enumerate(archive):
                name = ingestion.safe_name(item.name)
                if index >= ingestion.MAX_FILES or item.size > ingestion.MAX_FILE:
                    raise AcquisitionError('npm archive exceeds entry or per-file limits.')
                if not (item.isfile() or item.isdir()):
                    raise AcquisitionError('npm archive links and special files are refused.')
                if not name.startswith('package/') and not (name == 'package' and item.isdir()):
                    raise AcquisitionError('npm archives must use the canonical package/ root.')
                if item.isfile():
                    expanded += item.size
                    if expanded > ingestion.MAX_EXPANDED:
                        raise AcquisitionError('npm archive exceeds the expanded-byte limit.')
    except (tarfile.TarError, OSError) as error:
        raise AcquisitionError('Invalid npm tarball.') from error
    files, warnings = ingestion.archive(raw, 'tar')
    if any(not p.startswith('package/') for p in files):
        raise AcquisitionError('npm archives must use the canonical package/ root.')
    files = {p[len('package/'):]: c for p, c in files.items()}
    try:
        manifest = json.loads(files['package.json'])
    except (KeyError, ValueError) as error:
        raise AcquisitionError('npm artifact has no valid package.json.') from error
    _declarations(manifest)
    return manifest, files, warnings


def acquire_local(path):
    path = Path(path)
    if not path.name.endswith(('.tgz', '.tar.gz')) or path.stat().st_size > ingestion.MAX_UPLOAD:
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
    session = RegistrySession(Budget.from_env('deep'))
    # CLI graph limits are hard ceilings, independent of the web scan profile.
    package_limit = min(MAX_PACKAGES, session.budget.packages)
    packuments, artifacts, records, locations, roots = {}, [], {}, {}, []

    def choose(name, spec, fixed=None):
        if name not in packuments:
            try:
                data = json.loads(session.fetch('https://registry.npmjs.org/' + quote(name, safe='')))
            except Exception as error:
                raise AcquisitionError('npm registry metadata unavailable, malformed, or over budget.') from error
            if not isinstance(data, dict) or data.get('name') != name or not isinstance(data.get('versions'), dict):
                raise AcquisitionError('npm registry identity or release metadata is invalid.')
            packuments[name] = data
        data = packuments[name]
        versions = data['versions']
        if fixed:
            if spec not in data.get('dist-tags', {}) and _semver([fixed], spec) != fixed:
                raise AcquisitionError('Existing npm lock conflicts with a dependency requirement; refusing an implicit version change.')
            selected = fixed
        else:
            selected = data.get('dist-tags', {}).get(spec)
            if selected is None:
                selected = _semver(list(versions), spec)
        if not isinstance(selected, str) or not EXACT.fullmatch(selected) or selected not in versions:
            raise AcquisitionError('No exact npm version satisfies the requested specification.')
        meta = versions[selected]
        if not isinstance(meta, dict) or meta.get('name') != name or meta.get('version') != selected:
            raise AcquisitionError('npm release metadata identity mismatch.')
        _declarations(meta)
        session.metadata[(name, selected)] = meta
        return selected, meta

    def prior(parent, name):
        while True:
            location = (parent + '/' if parent else '') + 'node_modules/' + name
            if location in old:
                return old[location], location
            if not parent:
                return None, None
            parent = parent.rsplit('/node_modules/', 1)[0] if '/node_modules/' in parent else ''

    def add(name, spec, parent='', ancestors=None, direct=False, old_parent=''):
        ancestors = ancestors or []
        for anc_name, anc_version, anc_loc in reversed(ancestors):
            if anc_name == name and _semver([anc_version], spec) == anc_version:
                return anc_loc
        if len(records) >= package_limit:
            raise AcquisitionError(f'npm dependency graph exceeds the {package_limit}-location inspection limit; no installation is permitted.')
        location = (parent + '/' if parent else '') + 'node_modules/' + name
        entry, old_location = prior(old_parent, name)
        fixed = entry.get('version') if entry and not (direct and name in requested) else None
        version, meta = choose(name, spec, fixed)
        expected = entry.get('integrity') if entry and entry.get('version') == version else None
        try:
            result = session.retrieve(name, version, expected)
        except Exception as error:
            raise AcquisitionError('npm package acquisition failed or exceeded its resource budget.') from error
        if result.registry_integrity.status != 'verified' or result.integrity.status not in ('missing', 'verified'):
            raise IntegrityError('npm artifact integrity failed or could not be verified against registry metadata.')
        raw = result.raw
        actual, files, warnings = _manifest_files(raw)
        if actual.get('name') != name or actual.get('version') != version or _declarations(actual) != _declarations(meta):
            raise IntegrityError('npm tarball identity or dependency metadata differs from the registry release.')
        dist = meta.get('dist', {})
        record = {'version': version, 'resolved': dist['tarball'], 'integrity': result.registry_integrity.expected}
        for key in ('dependencies', 'optionalDependencies', 'engines', 'os', 'cpu'):
            if key in meta:
                record[key] = meta[key]
        records[location] = record
        artifact = Artifact('npm', name, version, name.rsplit('/', 1)[-1] + '-' + version + '.tgz', raw, files, hashlib.sha256(raw).hexdigest(), True, warnings=warnings, direct=direct, kind='tgz')
        artifacts.append(artifact)
        locations[location] = artifact.sha256
        if direct:
            roots.append(artifact.identity)
        next_ancestors = ancestors + [(name, version, location)]
        for child, requirement in _declarations(actual).items():
            child_location = add(child, requirement, location, next_ancestors, old_parent=old_location or location)
            artifact.dependencies.append('npm:' + records[child_location].get('name', child) + '@' + records[child_location]['version'])
        return location

    for name, spec in declarations.items():
        add(name, spec, direct=True)
    # Pin explicitly requested roots; other declarations and locked versions persist.
    for name in requested:
        group = next((k for k in ('dependencies', 'devDependencies', 'optionalDependencies') if name in manifest.get(k, {})), 'dependencies')
        manifest.setdefault(group, {})[name] = records['node_modules/' + name]['version']
    root_record = {k: manifest[k] for k in ('name', 'version', 'dependencies', 'devDependencies', 'optionalDependencies') if k in manifest}
    lock = {'name': manifest.get('name', 'guardian-local-project'), 'version': manifest.get('version', '1.0.0'), 'lockfileVersion': 3, 'requires': True, 'packages': {'': root_record, **records}}
    return Plan('npm', artifacts, roots, installer_data={'manifest': manifest, 'lock': lock, 'locations': locations, 'original_manifest': original, 'original_lock': original_lock})


def install(plan, project):
    project = Path(project).resolve()
    data = plan.installer_data
    if not plan.complete or not plan.artifacts or plan.ecosystem != 'npm':
        raise InstallError('Only a complete approved npm graph can be installed.')
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
        if not artifact or artifact.version != record.get('version') or verify(artifact.raw, record.get('integrity')).status != 'verified':
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
