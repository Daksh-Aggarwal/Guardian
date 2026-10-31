"""Bounded in-memory ingestion. No archive member is written to disk."""
import io
import json
import re
import stat
import time
import tarfile
import zipfile
import zlib
from pathlib import PurePosixPath
from urllib.parse import quote, urlparse
import httpx
import yaml
from .config import ArchiveLimits
from .supply_models import AcquisitionError

MAX_UPLOAD = 10 * 1024 * 1024
MAX_EXPANDED = 25 * 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_FILES = 500
EXTENSIONS = {'.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml', '.lock', '.py', '.pyw', '.pth', '.start', '.toml', '.cfg', '.md', '.txt'}
SUPPORTED_MANIFESTS = {'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'}

def safe_name(name):
    if not name or not isinstance(name, str):
        raise ValueError('Archive contains an empty or invalid path.')
    if any(ord(c) < 32 for c in name) or '\x00' in name or '\\' in name or ':' in name:
        raise ValueError('Archive contains an unsafe path.')
    if name.startswith('/') or name.startswith('~'):
        raise ValueError('Archive contains an unsafe path.')
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts:
        raise ValueError('Archive contains an unsafe path.')
    norm = str(p)
    if norm in ('.', ''):
        raise ValueError('Archive contains an empty or invalid path.')
    return norm

def archive(data, kind='zip', *, limits=None, stats=None, root=None):
    """Inspect bounded members in memory; count opaque bytes without executing them."""
    limits = limits or ArchiveLimits.from_env('upload')
    stats = stats if stats is not None else {}
    stats.update(entries=0, expanded=0, sources=0)
    started = time.monotonic()

    def fail(message, category, budget=None, limit=None, encountered=None):
        raise AcquisitionError(message, category=category, operation='archive inspection',
                               budget=budget, limit=limit, encountered=encountered)

    def deadline():
        if time.monotonic() - started > limits.seconds:
            fail('Package archive inspection time limit reached.', 'archive_timeout',
                 'archive_seconds', limits.seconds, round(time.monotonic() - started, 3))

    if len(data) > limits.compressed:
        fail('Archive exceeds the compressed-byte limit.', 'archive_compressed_limit',
             'compressed_bytes', limits.compressed, len(data))
    files, warnings, seen_paths = {}, [], set()
    declared_total = 0
    stream = io.BytesIO(data)
    try:
        handle = zipfile.ZipFile(stream) if kind == 'zip' else tarfile.open(fileobj=stream, mode='r:gz')
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, zlib.error) as error:
        raise AcquisitionError('Invalid or unsupported archive format.', category='invalid_archive', operation='archive inspection') from error
    try:
        with handle:
            members = handle.infolist() if kind == 'zip' else handle
            for index, item in enumerate(members):
                deadline()
                stats['entries'] = index + 1
                if index >= limits.entries:
                    fail(f'Archive exceeds the {limits.entries}-entry limit.', 'archive_entry_limit',
                         'archive_entries', limits.entries, index + 1)
                raw_name = item.filename if kind == 'zip' else item.name
                try:
                    name = safe_name(raw_name)
                except ValueError as error:
                    raise AcquisitionError('Archive contains an unsafe path.', category='unsafe_archive_path', operation='archive inspection') from error
                if name in seen_paths:
                    fail('Archive contains duplicate file names.', 'duplicate_archive_path')
                seen_paths.add(name)
                if kind == 'zip':
                    mode = item.external_attr >> 16
                    if stat.S_ISLNK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
                        fail('Archive links and special files are not supported.', 'unsupported_archive_entry')
                    directory, declared_size = item.is_dir(), item.file_size
                else:
                    if not (item.isfile() or item.isdir()):
                        fail('Archive links and special files are not supported.', 'unsupported_archive_entry')
                    directory, declared_size = item.isdir(), item.size
                if root and not (name.startswith(root + '/') or (name == root and directory)):
                    fail(f'Archive must use the canonical {root}/ root.', 'unsafe_archive_root')
                if directory:
                    continue
                if declared_size > limits.file:
                    fail('Archive exceeds the per-file size limit.', 'archive_file_limit', 'file_bytes', limits.file, declared_size)
                declared_total += declared_size
                if declared_total > limits.expanded:
                    fail('Archive exceeds the expanded-byte / expanded limit.', 'archive_expanded_limit',
                         'expanded_bytes', limits.expanded, declared_total)
                supported = PurePosixPath(name).suffix in EXTENSIONS and not any(p in {'.git', 'node_modules'} for p in PurePosixPath(name).parts)
                if supported and stats['sources'] >= limits.sources:
                    fail('Archive exceeds the supported source-file count limit.', 'archive_source_limit',
                         'source_files', limits.sources, stats['sources'] + 1)
                reader = handle.open(item) if kind == 'zip' else handle.extractfile(item)
                if reader is None:
                    fail('Archive member could not be read.', 'invalid_archive')
                content, file_bytes = bytearray(), 0
                with reader:
                    while True:
                        deadline()
                        block = reader.read(min(65536, limits.file + 1 - file_bytes))
                        if not block:
                            break
                        file_bytes += len(block)
                        stats['expanded'] += len(block)
                        if file_bytes > limits.file:
                            fail('Expanded file exceeds the per-file size limit.', 'archive_file_limit', 'file_bytes', limits.file, file_bytes)
                        if stats['expanded'] > limits.expanded:
                            fail('Archive exceeds the expanded-byte / expanded limit.', 'archive_expanded_limit', 'expanded_bytes', limits.expanded, stats['expanded'])
                        if supported:
                            content.extend(block)
                if not supported:
                    warnings.append('Skipped unsupported or excluded file: ' + name)
                    continue
                stats['sources'] += 1
                try:
                    files[name] = content.decode('utf-8')
                except UnicodeDecodeError:
                    warnings.append('Skipped non-UTF-8 file: ' + name)
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, RuntimeError, zlib.error) as error:
        raise AcquisitionError('Archive extraction failed or member is damaged.', category='invalid_archive', operation='archive inspection') from error
    if not files:
        raise AcquisitionError('No supported source files or manifests found.', category='no_supported_source', operation='archive inspection')
    return files, warnings

def uploaded(name, data):
    if len(data) > MAX_UPLOAD:
        raise ValueError('Upload exceeds the 10 MB limit.')
    if name.lower().endswith('.zip'):
        return archive(data)
    if name not in SUPPORTED_MANIFESTS:
        raise ValueError('Upload a project ZIP, package.json, package-lock.json, pnpm-lock.yaml, or yarn.lock.')
    if len(data) > MAX_FILE:
        raise ValueError('Manifest exceeds the 1 MB limit.')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('Manifest must be valid UTF-8.')

    if name.endswith('.json'):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            raise ValueError('Manifest must be valid UTF-8 JSON.')
        if not isinstance(parsed, dict):
            raise ValueError('Manifest must be a JSON object.')
    elif name in {'pnpm-lock.yaml', 'yarn.lock'}:
        try:
            parsed = yaml.safe_load(text)
        except Exception:
            raise ValueError(f'Manifest {name} must be valid YAML.')
        if not isinstance(parsed, dict):
            raise ValueError(f'Manifest {name} must be a YAML mapping.')
    return {name: text}, []

def download(url, limit=MAX_UPLOAD, timeout=15):
    # Strict destination allowlist, no redirects, no user-provided URLs.
    try:
        parsed = urlparse(url)
        allowed = parsed.scheme == 'https' and parsed.hostname == 'registry.npmjs.org' and parsed.port in (None, 443) and not parsed.username and not parsed.password
    except ValueError as error:
        raise AcquisitionError('Registry returned an unsupported download location.', category='invalid_registry_location', operation='download') from error
    if not allowed:
        raise AcquisitionError('Registry returned an unsupported download location.', category='invalid_registry_location', operation='download')
    result = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with httpx.Client(timeout=max(.1, timeout), follow_redirects=False) as client:
            with client.stream('GET', url) as response:
                response.raise_for_status()
                for block in response.iter_bytes(chunk_size=65536):
                    if time.monotonic() > deadline:
                        raise AcquisitionError('Registry download time limit reached.', category='registry_timeout', operation='download', bytes_received=len(result))
                    result.extend(block)
                    if len(result) > limit:
                        raise AcquisitionError('Registry response exceeds the download limit.', category='registry_response_limit', operation='download', budget='download_bytes', limit=limit, encountered=len(result), bytes_received=len(result))
    except httpx.TimeoutException as error:
        raise AcquisitionError('Registry request timed out.', category='registry_timeout', operation='download', bytes_received=len(result)) from error
    except httpx.HTTPStatusError as error:
        raise AcquisitionError('Registry returned an HTTP error.', category='registry_http_error', operation='download', detail=f'HTTP status {error.response.status_code}.', bytes_received=len(result)) from error
    except httpx.RequestError as error:
        raise AcquisitionError('Registry is unavailable.', category='registry_unavailable', operation='download', bytes_received=len(result)) from error
    return bytes(result)

def validate_package(name, version):
    if not re.fullmatch(r'(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+', name) or not re.fullmatch(r'[a-zA-Z0-9_.+-]+', version):
        raise ValueError('Use a valid npm name and an exact version or dist-tag.')

def registry_package(name, version):
    # Compatibility helper. The API uses RegistrySession to retain integrity metadata.
    validate_package(name, version)
    metadata = json.loads(download('https://registry.npmjs.org/' + quote(name, safe='') + '/' + quote(version, safe='')))
    tarball = metadata.get('dist', {}).get('tarball')
    if not tarball:
        raise ValueError('No package tarball is available.')
    from .integrity import verify
    data = download(tarball)
    integrity = verify(data, metadata.get('dist', {}).get('integrity'), 'registry')
    if integrity.status not in {'verified', 'missing'}:
        raise ValueError(integrity.detail)
    files, warnings = archive(data, 'tar')
    if integrity.status == 'missing':
        warnings.append('Registry integrity missing; downloaded bytes were not verified.')
    return files, warnings
