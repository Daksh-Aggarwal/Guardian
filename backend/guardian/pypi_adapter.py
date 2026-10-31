"""Bounded, non-executing PyPI acquisition and exact wheel installation.

Resolution uses wheel METADATA, not imports or source-build metadata hooks. Source
archives can be inspected, but never become installable approvals.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import platform
import re
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
import time
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlparse

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from . import ingestion
from .pypi import download_pypi_url
from .supply_models import Artifact, Plan, AcquisitionError, IntegrityError, InstallError

MAX_PACKAGES = 40
MAX_REQUESTS = 100
MAX_BYTES = 50 * 1024 * 1024
MAX_SECONDS = 90
MAX_STEPS = 200
MANIFESTS = ('requirements.txt', 'pyproject.toml', 'poetry.lock', 'Pipfile', 'Pipfile.lock',
             'uv.lock', 'pylock.toml', 'setup.cfg', 'setup.py', 'requirements.in')


def _manifest_snapshot(project):
    """Capture both absence and bytes; reject links and bound every manifest read."""
    result = {}
    for name in MANIFESTS:
        path = Path(project) / name
        if path.is_symlink():
            raise AcquisitionError('Python dependency manifests must not be symbolic links: ' + name)
        try:
            descriptor = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        except FileNotFoundError:
            result[name] = None
            continue
        except OSError as error:
            raise AcquisitionError('Cannot safely read Python dependency manifest: ' + name) from error
        with os.fdopen(descriptor, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > ingestion.MAX_FILE:
                raise AcquisitionError('Python dependency manifest must be a regular file no larger than 1 MB: ' + name)
            content = stream.read(ingestion.MAX_FILE + 1)
            if len(content) > ingestion.MAX_FILE:
                raise AcquisitionError('Python dependency manifest exceeds the 1 MB limit: ' + name)
            result[name] = content
    return result


def _manifest_hashes(snapshot):
    return {name: hashlib.sha256(content).hexdigest() if content is not None else None
            for name, content in snapshot.items()}


def _runtime_fingerprint():
    return [list(sys.version_info[:3]), sys.implementation.name, sysconfig.get_platform(),
            sysconfig.get_config_var('SOABI'), platform.machine(), struct.calcsize('P')]


def _installation_context(project, snapshot=None):
    return {'project': str(Path(project).resolve()),
            'project_manifests': _manifest_hashes(_manifest_snapshot(project) if snapshot is None else snapshot),
            'python_runtime': _runtime_fingerprint()}


def _requirement(text):
    if not isinstance(text, str) or len(text) > 2000 or text.startswith('-'):
        raise AcquisitionError('Only named PyPI requirements are supported; options and URLs are forbidden.')
    try:
        req = Requirement(text)
    except InvalidRequirement as error:
        raise AcquisitionError('Invalid PyPI requirement: ' + text[:100]) from error
    if req.url:
        raise AcquisitionError('Direct URL, editable, and VCS requirements are not supported.')
    return req


def _active(req, extras=()):
    if not req.marker:
        return True
    return any(req.marker.evaluate(dict(default_environment(), extra=extra)) for extra in set(extras) | {''})


def _manifest_specs(project, snapshot=None):
    """Read a conservative subset; never pass requirement-file options to pip."""
    snapshot = _manifest_snapshot(project) if snapshot is None else snapshot
    if any(snapshot[p] is not None for p in ('poetry.lock', 'Pipfile.lock', 'uv.lock', 'pylock.toml')):
        raise AcquisitionError('This Python lockfile is unsupported; export pinned requirements.txt before resolving.')
    if snapshot['requirements.txt'] is not None:
        result = []
        for line in snapshot['requirements.txt'].decode('utf-8').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Hash-pinned input needs artifact selection across multiple releases;
            # do not silently discard existing constraints or hashes.
            if '\\' in line or '--hash' in line or line.startswith('-'):
                raise AcquisitionError('Requirement directives, continuations, and hash options are unsupported; use named requirements only.')
            result.append(line.split(' #', 1)[0].strip())
        return result
    if snapshot['pyproject.toml'] is not None:
        try:
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib
            data = tomllib.loads(snapshot['pyproject.toml'].decode('utf-8'))
            project_data = data.get('project', {})
            if 'dependencies' in project_data.get('dynamic', []):
                raise AcquisitionError('Dynamic Python dependencies require executing build code and are unsupported.')
            if not isinstance(project_data.get('dependencies'), list):
                raise AcquisitionError('Only static PEP 621 project.dependencies are supported; export requirements.txt for Poetry projects.')
            return project_data['dependencies']
        except (ValueError, TypeError) as error:
            raise AcquisitionError('Invalid static Python dependency manifest.') from error
    raise AcquisitionError('No requirements.txt or static PEP 621 pyproject.toml dependencies found.')


def _inspect(raw, filename, verified=False):
    """Read members in memory and bind package identity to the actual artifact."""
    ingestion.safe_name(filename)
    if '/' in filename:
        raise AcquisitionError('Distribution filename must be a single path component.')
    if len(raw) > ingestion.MAX_UPLOAD:
        raise AcquisitionError('Distribution exceeds the 10 MB artifact limit.')
    wheel = filename.endswith('.whl')
    if not wheel and not filename.endswith(('.tar.gz', '.zip')):
        raise AcquisitionError('Only wheels, .tar.gz sdists, and .zip sdists are supported.')
    try:
        files, warnings = ingestion.archive(raw, 'zip' if wheel or filename.endswith('.zip') else 'tar')
        if wheel:
            expected_name, expected_version, _, tags = parse_wheel_filename(filename)
            if not tags.intersection(set(sys_tags())):
                raise AcquisitionError('Wheel is incompatible with the current Python interpreter/platform.')
            # ingestion validates every archive entry, including ones omitted from
            # source analysis. Read standard wheel metadata only after validation.
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                metadata_paths = [i.filename for i in archive.infolist() if i.filename.endswith('.dist-info/METADATA')]
                if len(metadata_paths) != 1 or '/' in metadata_paths[0].split('.dist-info/')[0]:
                    raise AcquisitionError('Wheel must contain one top-level dist-info/METADATA file.')
                metadata_path = metadata_paths[0]
                metadata = archive.read(metadata_path).decode('utf-8')
                info = Parser().parsestr(metadata)
                name, version = info.get('Name', ''), info.get('Version', '')
                if canonicalize_name(name) != canonicalize_name(expected_name) or Version(version) != expected_version:
                    raise IntegrityError('Wheel filename and embedded metadata identity do not match.')
                files[metadata_path] = metadata
                dependencies = info.get_all('Requires-Dist', [])
                if len(dependencies) > 256:
                    raise AcquisitionError('Wheel exceeds the 256 dependency declaration limit.')
                for dependency in dependencies:
                    _requirement(dependency)
                # Metadata and bookkeeping are inspected separately, not a source
                # coverage gap. Other unknown assets remain visible to policy.
                metadata_prefix = metadata_path.rsplit('/', 1)[0] + '/'
                warnings = [w for w in warnings if not any(w == 'Skipped unsupported or excluded file: ' + metadata_prefix + part for part in ('METADATA', 'WHEEL', 'RECORD', 'LICENSE', 'COPYING', 'INSTALLER', 'REQUESTED', 'top_level.txt'))]
                for part in ('WHEEL', 'entry_points.txt'):
                    path = metadata_prefix + part
                    if path in archive.namelist():
                        files[path] = archive.read(path).decode('utf-8')
                provided = set(info.get_all('Provides-Extra', []))
                py_requires = info.get('Requires-Python')
                if py_requires and Version('.'.join(map(str, sys.version_info[:3]))) not in SpecifierSet(py_requires):
                    raise AcquisitionError('Wheel Requires-Python excludes the current interpreter.')
                if any(p.endswith(('.so', '.pyd', '.dll', '.dylib', '.exe')) for p in archive.namelist()):
                    warnings.append('Skipped native executable content: cannot be analyzed by the static source engine.')
        else:
            expected_name, expected_version = parse_sdist_filename(filename) if filename.endswith('.tar.gz') else parse_sdist_filename(filename[:-4] + '.tar.gz')
            name, version, dependencies, provided = str(expected_name), str(expected_version), [], set()
            warnings.append('Source distribution inspected statically only; dependency/build metadata may be dynamic. Building and installation are disabled.')
        artifact = Artifact(ecosystem='pypi', name=str(canonicalize_name(name)), version=str(version), filename=filename, raw=raw, files=files, sha256=hashlib.sha256(raw).hexdigest(), verified=verified, warnings=warnings, dependencies=[], direct=True, kind='wheel' if wheel else 'sdist')
        return artifact, dependencies, provided
    except (ValueError, KeyError, UnicodeError, zipfile.BadZipFile, InvalidVersion, InvalidSpecifier) as error:
        if isinstance(error, (AcquisitionError, IntegrityError)):
            raise
        raise AcquisitionError('Malformed or unsafe Python distribution: ' + str(error)[:160]) from error


def acquire_local(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > ingestion.MAX_UPLOAD:
        raise AcquisitionError('Local artifact must be a regular file no larger than 10 MB.')
    artifact, _, _ = _inspect(path.read_bytes(), path.name, verified=False)
    artifact.warnings.append('Local artifact SHA-256 identifies bytes; no trusted registry digest was verified.')
    return artifact


class _Resolver:
    def __init__(self):
        self.started = time.monotonic()
        self.requests = self.bytes = self.steps = 0
        self.metadata = {}
        self.releases = {}
        self.artifacts = {}

    def fetch(self, url):
        if self.requests >= MAX_REQUESTS or self.bytes >= MAX_BYTES or time.monotonic() - self.started > MAX_SECONDS:
            raise AcquisitionError('PyPI resolution exceeded its request, byte, or time budget.')
        self.requests += 1
        try:
            raw = download_pypi_url(url, limit=min(ingestion.MAX_UPLOAD, MAX_BYTES - self.bytes), timeout=min(15, max(.1, MAX_SECONDS - (time.monotonic() - self.started))))
        except Exception as error:
            raise AcquisitionError('PyPI metadata or artifact is unavailable; resolution stopped.') from error
        self.bytes += len(raw)
        return raw

    def candidates(self, name, requirements):
        if name not in self.metadata:
            try:
                metadata = json.loads(self.fetch('https://pypi.org/pypi/' + quote(name, safe='') + '/json'))
                if not isinstance(metadata.get('releases'), dict):
                    raise ValueError('releases is not a mapping')
                self.metadata[name] = metadata
            except (ValueError, TypeError, AttributeError) as error:
                raise AcquisitionError('Invalid PyPI metadata response.') from error
        versions = []
        for version, entries in self.metadata[name]['releases'].items():
            if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
                raise AcquisitionError('PyPI release entries must be distribution metadata mappings.')
            try:
                parsed = Version(version)
            except InvalidVersion:
                continue
            if all(parsed in req.specifier for req in requirements) and entries and any(not entry.get('yanked') for entry in entries):
                versions.append((parsed, version))
        return [version for _, version in sorted(versions, reverse=True)][:40]

    def artifact(self, name, version):
        key = name, version
        if key in self.artifacts:
            return self.artifacts[key]
        entries = self.metadata[name]['releases'][version]
        compatible = []
        supported_tags = list(sys_tags())
        tag_rank = {tag: index for index, tag in enumerate(supported_tags)}
        for entry in entries:
            if not isinstance(entry, dict) or entry.get('yanked'):
                continue
            filename = entry.get('filename', '')
            requires_python = entry.get('requires_python')
            try:
                if requires_python and Version('.'.join(map(str, sys.version_info[:3]))) not in SpecifierSet(requires_python):
                    continue
                if entry.get('packagetype') == 'bdist_wheel' and filename.endswith('.whl'):
                    _, _, _, tags = parse_wheel_filename(filename)
                    ranks = [tag_rank[tag] for tag in tags if tag in tag_rank]
                    if ranks:
                        compatible.append((min(ranks), entry))
                elif entry.get('packagetype') == 'sdist' and filename.endswith(('.tar.gz', '.zip')):
                    compatible.append((100000, entry))
            except (ValueError, InvalidSpecifier):
                continue
        if not compatible:
            raise AcquisitionError('No supported compatible wheel or static sdist available for ' + name + '==' + version)
        entry = min(compatible, key=lambda item: item[0])[1]
        filename, url = entry['filename'], entry.get('url', '')
        parsed = urlparse(url)
        if parsed.scheme != 'https' or parsed.hostname != 'files.pythonhosted.org' or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise AcquisitionError('PyPI returned an unsupported artifact URL.')
        digest = entry.get('digests', {}).get('sha256', '')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-fA-F]{64}', digest):
            raise IntegrityError('PyPI artifact does not have a trusted SHA-256 digest.')
        raw = self.fetch(url)
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest.lower()):
            raise IntegrityError('PyPI artifact SHA-256 does not match registry metadata.')
        result = _inspect(raw, filename, verified=True)
        if canonicalize_name(result[0].name) != name or Version(result[0].version) != Version(version):
            raise IntegrityError('PyPI registry identity does not match the artifact identity.')
        self.artifacts[key] = result
        return result

    def solve(self, roots):
        """Bounded backtracking over exact wheel metadata, including extra markers."""
        def search(selected):
            self.steps += 1
            if self.steps > MAX_STEPS or time.monotonic() - self.started > MAX_SECONDS:
                raise AcquisitionError('PyPI dependency backtracking budget exceeded.')
            constraints = {}
            extras = {}
            queue = list(roots)
            processed = set()
            edges = {}
            while queue:
                if time.monotonic() - self.started > MAX_SECONDS:
                    raise AcquisitionError('PyPI resolution time budget exceeded.')
                req, parent, parent_extras = queue.pop(0)
                if not _active(req, parent_extras):
                    continue
                name = str(canonicalize_name(req.name))
                constraints.setdefault(name, []).append(req)
                extras.setdefault(name, set()).update(req.extras)
                if parent:
                    edges.setdefault(parent, set()).add(name)
                if len(constraints) > MAX_PACKAGES:
                    raise AcquisitionError('PyPI dependency graph exceeds the 40-package limit.')
                if name in selected:
                    artifact, dependencies, provided = self.artifact(name, selected[name])
                    if req.extras - provided:
                        raise AcquisitionError('Requested extra is absent from wheel metadata: ' + name)
                    if any(Version(artifact.version) not in r.specifier for r in constraints[name]):
                        return None
                    key = name, tuple(sorted(extras[name]))
                    if key not in processed:
                        processed.add(key)
                        for dependency in dependencies:
                            queue.append((_requirement(dependency), name, extras[name]))
            unresolved = next((name for name in constraints if name not in selected), None)
            if unresolved is None:
                return selected, constraints, edges
            for version in self.candidates(unresolved, constraints[unresolved]):
                # Never hide integrity/acquisition failures as ordinary conflicts.
                self.artifact(unresolved, version)
                result = search(dict(selected, **{unresolved: version}))
                if result:
                    return result
            return None
        result = search({})
        if result is None:
            raise AcquisitionError('No consistent PyPI dependency graph satisfies all constraints.')
        return result


def resolve(specs, project, offline=False):
    if offline:
        raise AcquisitionError('Offline registry resolution is unavailable; use guardian check on an acquired local wheel or sdist.')
    project = Path(project).resolve()
    snapshot = _manifest_snapshot(project)
    if any(snapshot[name] is not None for name in ('poetry.lock', 'Pipfile', 'Pipfile.lock', 'uv.lock', 'pylock.toml')):
        raise AcquisitionError('Unsupported Python lockfile or Pipfile present; Guardian cannot preserve its dependency constraints.')
    context = _installation_context(project, snapshot)
    raw_specs = list(specs) if specs else _manifest_specs(project, snapshot)
    # Adding a requirement must preserve declared project constraints.
    if specs and any(snapshot[name] is not None for name in ('requirements.txt', 'pyproject.toml')):
        raw_specs = _manifest_specs(project, snapshot) + raw_specs
    if len(raw_specs) > 256:
        raise AcquisitionError('Project exceeds the 256 root requirement limit.')
    roots = [(_requirement(spec), None, set()) for spec in raw_specs]
    roots = [(req, parent, extras) for req, parent, extras in roots if _active(req)]
    if not roots:
        return Plan(ecosystem='pypi', artifacts=[], roots=[], complete=True, limitations=[], installer_data=context)
    resolver = _Resolver()
    selected, constraints, edges = resolver.solve(roots)
    root_names = {str(canonicalize_name(req.name)) for req, _, _ in roots}
    artifacts = []
    limitations = []
    for name in constraints:
        artifact, _, _ = resolver.artifact(name, selected[name])
        artifact.direct = name in root_names
        artifact.dependencies = ['pypi:' + child + '@' + selected[child] for child in sorted(edges.get(name, set()))]
        if artifact.kind != 'wheel':
            limitations.append(name + ': source build is required; build execution and dynamic dependency resolution are unsupported.')
        artifacts.append(artifact)
    return Plan(ecosystem='pypi', artifacts=artifacts, roots=['pypi:' + name + '@' + selected[name] for name in sorted(root_names)], complete=not limitations, limitations=limitations, installer_data=context)


def install(plan, project):
    """Install the in-memory approved bytes, without resolution, builds, or network."""
    if not plan.complete or any(not a.verified or a.kind != 'wheel' for a in plan.artifacts):
        raise InstallError('Installation requires a complete graph of verified wheels; source builds are disabled.')
    context = plan.installer_data
    if context.get('project') != str(Path(project).resolve()) or not isinstance(context.get('project_manifests'), dict):
        raise InstallError('Installation plan has no matching project manifest snapshot; resolve and scan again.')
    try:
        current = _manifest_hashes(_manifest_snapshot(project))
    except AcquisitionError as error:
        raise InstallError('Project dependency manifest preflight failed: ' + str(error)) from error
    if current != context['project_manifests']:
        raise InstallError('Project dependency manifests changed after resolution; resolve and scan again before installation.')
    target = os.environ.get('VIRTUAL_ENV')
    if not target:
        raise InstallError('Activate the target Python virtual environment before guardian install (VIRTUAL_ENV is required).')
    target = Path(target).absolute()
    if not (target / 'pyvenv.cfg').is_file():
        raise InstallError('The active Python environment is not a virtual environment.')
    python = target / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not python.is_file():
        raise InstallError('Active virtual environment has no Python interpreter.')
    if not plan.artifacts:
        return
    with tempfile.TemporaryDirectory(prefix='guardian-wheels-') as temp:
        directory = Path(temp)
        lines = []
        names = set()
        for artifact in plan.artifacts:
            if artifact.ecosystem != 'pypi' or artifact.filename in names:
                raise InstallError('Duplicate artifact filename or invalid ecosystem in installation plan.')
            ingestion.safe_name(artifact.filename)
            if '/' in artifact.filename or not artifact.filename.endswith('.whl'):
                raise InstallError('Invalid approved wheel filename.')
            names.add(artifact.filename)
            if not hmac.compare_digest(hashlib.sha256(artifact.raw).hexdigest(), artifact.sha256):
                raise IntegrityError('Approved wheel changed after scanning; installation refused.')
            path = directory / artifact.filename
            path.write_bytes(artifact.raw)
            lines.append(path.as_uri() + ' --hash=sha256:' + artifact.sha256)
        requirements = directory / 'approved.txt'
        requirements.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('PIP_', 'PYTHON'))}
        env['PIP_CONFIG_FILE'] = os.devnull
        fingerprint_code = ("import json,sys,sysconfig,platform,struct;print(json.dumps([list(sys.version_info[:3]),"
                            "sys.implementation.name,sysconfig.get_platform(),sysconfig.get_config_var('SOABI'),"
                            "platform.machine(),struct.calcsize('P')]))")
        try:
            # -S skips site initialization and existing .pth hooks for this
            # metadata-only check. No target package or pip module is imported.
            compatibility = subprocess.run([str(python), '-I', '-S', '-c', fingerprint_code], cwd=temp,
                                           env=env, capture_output=True, text=True, timeout=10)
            if compatibility.returncode or json.loads(compatibility.stdout) != context.get('python_runtime'):
                raise InstallError('Target virtual environment Python/platform differs from the resolving interpreter; run Guardian with the target interpreter.')
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            if isinstance(error, InstallError):
                raise
            raise InstallError('Could not verify target interpreter compatibility; installation stopped before pip.') from error
        # Recheck immediately before mutation after compatibility inspection.
        try:
            if _manifest_hashes(_manifest_snapshot(project)) != context['project_manifests']:
                raise InstallError('Project dependency manifests changed before pip installation; resolve and scan again.')
        except AcquisitionError as error:
            raise InstallError('Project dependency manifest preflight failed: ' + str(error)) from error
        try:
            process = subprocess.run([str(python), '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install', '--no-input', '--no-index', '--no-deps', '--only-binary=:all:', '--require-hashes', '--no-cache-dir', '--no-compile', '--force-reinstall', '-r', str(requirements)], cwd=temp, env=env, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise InstallError('Wheel installation failed or timed out; the environment may be partially changed.') from error
        if process.returncode:
            raise InstallError('pip could not install approved wheels; the environment may be partially changed. ' + process.stderr[-1000:])
