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

MAX_UPLOAD = 10 * 1024 * 1024
MAX_EXPANDED = 25 * 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_FILES = 500
EXTENSIONS = {'.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.json'}

def safe_name(name):
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or '\x00' in name:
        raise ValueError('Archive contains an unsafe path.')
    return str(p)

def archive(data, kind='zip'):
    files, warnings = {}, []
    total = 0
    stream = io.BytesIO(data)
    handle = zipfile.ZipFile(stream) if kind == 'zip' else tarfile.open(fileobj=stream, mode='r:gz')
    with handle:
        members = handle.infolist() if kind == 'zip' else handle
        for index, item in enumerate(members):
            if index >= MAX_FILES:
                raise ValueError('Archive exceeds the 500-entry limit.')
            name = safe_name(item.filename if kind == 'zip' else item.name)
            if kind == 'zip':
                if stat.S_ISLNK(item.external_attr >> 16):
                    raise ValueError('Archive links are not supported.')
                directory, size = item.is_dir(), item.file_size
            else:
                if not (item.isfile() or item.isdir()):
                    raise ValueError('Archive links and special files are not supported.')
                directory, size = item.isdir(), item.size
            if directory:
                continue
            total += size
            if size > MAX_FILE or total > MAX_EXPANDED:
                raise ValueError('Archive exceeds the 1 MB per-file or 25 MB expanded limit.')
            if name in files:
                raise ValueError('Archive contains duplicate file names.')
            if PurePosixPath(name).suffix not in EXTENSIONS or any(p in {'.git', 'node_modules'} for p in PurePosixPath(name).parts):
                warnings.append('Skipped unsupported or excluded file: ' + name)
                continue
            reader = handle.open(item) if kind == 'zip' else handle.extractfile(item)
            with reader:
                content = reader.read(MAX_FILE + 1)
            if len(content) > MAX_FILE:
                raise ValueError('Expanded file is too large.')
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
    if name not in {'package.json', 'package-lock.json'}:
        raise ValueError('Upload a project ZIP, package.json, or package-lock.json.')
    if len(data) > MAX_FILE:
        raise ValueError('Manifest exceeds the 1 MB limit.')
    text = data.decode('utf-8')
    if not isinstance(json.loads(text), dict):
        raise ValueError('Manifest must be a JSON object.')
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
