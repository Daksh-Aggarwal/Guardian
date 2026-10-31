"""Bounded in-memory ingestion. No archive member is written to disk."""
import io
import json
import re
import stat
import time
import tarfile
import zipfile
from pathlib import PurePosixPath
from urllib.parse import quote, urlparse
import httpx
import yaml

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

def archive(data, kind='zip'):
    files, warnings = {}, []
    actual_total = 0
    seen_paths = set()
    stream = io.BytesIO(data)
    try:
        handle = zipfile.ZipFile(stream) if kind == 'zip' else tarfile.open(fileobj=stream, mode='r:gz')
    except Exception as error:
        raise ValueError('Invalid or unsupported archive format.') from error
    with handle:
        members = handle.infolist() if kind == 'zip' else handle
        for index, item in enumerate(members):
            if index >= MAX_FILES:
                raise ValueError('Archive exceeds the 500-entry limit.')
            raw_name = item.filename if kind == 'zip' else item.name
            name = safe_name(raw_name)
            if name in seen_paths:
                raise ValueError('Archive contains duplicate file names.')
            seen_paths.add(name)
            if kind == 'zip':
                mode = item.external_attr >> 16
                if stat.S_ISLNK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
                    raise ValueError('Archive links and special files are not supported.')
                directory, declared_size = item.is_dir(), item.file_size
            else:
                if not (item.isfile() or item.isdir()):
                    raise ValueError('Archive links and special files are not supported.')
                directory, declared_size = item.isdir(), item.size
            if directory:
                continue
            if declared_size > MAX_FILE:
                raise ValueError('Archive exceeds the 1 MB per-file or 25 MB expanded limit.')
            if PurePosixPath(name).suffix not in EXTENSIONS or any(p in {'.git', 'node_modules'} for p in PurePosixPath(name).parts):
                warnings.append('Skipped unsupported or excluded file: ' + name)
                continue
            try:
                reader = handle.open(item) if kind == 'zip' else handle.extractfile(item)
                if reader is None:
                    continue
                with reader:
                    content = reader.read(MAX_FILE + 1)
            except Exception as error:
                raise ValueError('Archive extraction failed or member is damaged.') from error
            if len(content) > MAX_FILE:
                raise ValueError('Expanded file is too large.')
            actual_total += len(content)
            if actual_total > MAX_EXPANDED:
                raise ValueError('Archive exceeds the 1 MB per-file or 25 MB expanded limit.')
            try:
                files[name] = content.decode('utf-8')
            except UnicodeDecodeError:
                warnings.append('Skipped non-UTF-8 file: ' + name)
    if not files:
        raise ValueError('No supported source files or manifests found.')
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
    parsed = urlparse(url)
    if parsed.scheme != 'https' or parsed.hostname != 'registry.npmjs.org' or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise ValueError('Registry returned an unsupported download location.')
    result = bytearray()
    deadline = time.monotonic() + timeout
    with httpx.Client(timeout=max(.1, timeout), follow_redirects=False) as client:
        with client.stream('GET', url) as response:
            response.raise_for_status()
            for block in response.iter_bytes(chunk_size=65536):
                if time.monotonic() > deadline:
                    raise ValueError("Registry download time limit reached.")
                result.extend(block)
                if len(result) > limit:
                    raise ValueError('Registry response exceeds the download limit.')
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
