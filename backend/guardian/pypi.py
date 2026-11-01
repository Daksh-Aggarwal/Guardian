"""Bounded PyPI package retrieval, SHA-256 integrity verification, and archive extraction."""
import base64
import json
import re
import time
from dataclasses import replace
from urllib.parse import quote, urlparse
import httpx

from .config import Budget, ArchiveLimits
from .integrity import verify
from .models import IntegrityResult
from .dependencies import Retrieved, BudgetExceeded
from . import ingestion

EXACT = re.compile(r'^\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.+-]+)?$')
PYPI_NAME_REGEX = re.compile(r'^[A-Za-z0-9_.-]+$')
MAX_UPLOAD = 10 * 1024 * 1024
ALLOWED_HOSTS = {'pypi.org', 'files.pythonhosted.org'}

def validate_pypi_package(name, version=None):
    if not name or not isinstance(name, str) or not PYPI_NAME_REGEX.fullmatch(name):
        raise ValueError('Use a valid PyPI package name.')
    if version and version != 'latest' and not re.fullmatch(r'[a-zA-Z0-9_.+-]+', version):
        raise ValueError('Use a valid PyPI version specification.')

def download_pypi_url(url, limit=MAX_UPLOAD, timeout=15):
    parsed = urlparse(url)
    if parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise ValueError('PyPI returned an unsupported download location.')
    result = bytearray()
    deadline = time.monotonic() + timeout
    with httpx.Client(timeout=max(0.1, timeout), follow_redirects=False) as client:
        with client.stream('GET', url) as response:
            response.raise_for_status()
            for block in response.iter_bytes(chunk_size=65536):
                if time.monotonic() > deadline:
                    raise ValueError('PyPI download time limit reached.')
                result.extend(block)
                if len(result) > limit:
                    raise ValueError('PyPI response exceeds the download limit.')
    return bytes(result)

class PyPISession:
    """Bounded retrieval session for PyPI packages."""
    def __init__(self, budget=None):
        self.budget = budget or Budget.from_env()
        self.started = time.monotonic()
        self.requests = 0
        self.bytes = 0
        self.expanded = 0
        self.metadata = {}
        self.packages = {}
        self.errors = {}
        self.contents = {}

    def remaining(self):
        return self.budget.seconds - (time.monotonic() - self.started)

    def fetch(self, url, limit=MAX_UPLOAD):
        if self.remaining() <= 0 or self.requests >= self.budget.requests or self.bytes >= self.budget.bytes:
            raise BudgetExceeded('PyPI time, request, or aggregate download budget reached.')
        self.requests += 1
        data = download_pypi_url(
            url,
            min(limit, self.budget.bytes - self.bytes),
            timeout=min(8.0, max(0.1, self.remaining()))
        )
        self.bytes += len(data)
        return data

    def retrieve(self, name, version='latest', expected=None, strict=True):
        validate_pypi_package(name, version)
        key = (name.lower(), version)
        if key in self.errors:
            raise ValueError(self.errors[key])
        try:
            if key not in self.metadata:
                if version and version != 'latest':
                    url = f'https://pypi.org/pypi/{quote(name, safe="")}/{quote(version, safe="")}/json'
                else:
                    url = f'https://pypi.org/pypi/{quote(name, safe="")}/json'
                raw_meta = self.fetch(url)
                try:
                    meta_dict = json.loads(raw_meta)
                except Exception as e:
                    raise ValueError('PyPI metadata must be valid JSON.') from e
                if not isinstance(meta_dict, dict) or 'info' not in meta_dict:
                    raise ValueError('Invalid PyPI package metadata response.')
                self.metadata[key] = meta_dict

            meta = self.metadata[key]
            info = meta.get('info', {})
            actual_name = info.get('name', name)
            actual_version = info.get('version', version)

            # Available release distribution files
            urls = meta.get('urls', [])
            if not urls and 'releases' in meta and actual_version in meta['releases']:
                urls = meta['releases'][actual_version]

            if not urls:
                raise ValueError(f'No release files available for PyPI package {name} {actual_version}.')

            # Select wheel distribution if available, otherwise source distribution
            chosen = None
            for candidate in urls:
                if candidate.get('packagetype') == 'bdist_wheel' and candidate.get('url'):
                    chosen = candidate
                    break
            if not chosen:
                for candidate in urls:
                    if candidate.get('packagetype') == 'sdist' and candidate.get('url'):
                        chosen = candidate
                        break
            if not chosen:
                chosen = urls[0]

            pkg_url = chosen.get('url')
            if not pkg_url:
                raise ValueError('No downloadable distribution URL found.')

            if key not in self.packages:
                self.packages[key] = (chosen, self.fetch(pkg_url, ArchiveLimits.from_env('wheel' if chosen.get('filename', '').endswith('.whl') else 'sdist').compressed))
            target_entry, data = self.packages[key]

            # Verify integrity
            digests = target_entry.get('digests', {})
            sha256_hex = digests.get('sha256')
            registry_expected = None
            if sha256_hex and re.fullmatch(r'[0-9a-fA-F]{64}', sha256_hex):
                registry_expected = 'sha256-' + base64.b64encode(bytes.fromhex(sha256_hex)).decode()

            result = Retrieved(
                metadata={'name': actual_name, 'version': actual_version, 'ecosystem': 'pypi', 'requires_dist': info.get('requires_dist', [])},
                raw=data,
                integrity=verify(data, expected, 'lockfile'),
                registry_integrity=verify(data, registry_expected, 'registry')
            )

            checks = [result.integrity, result.registry_integrity]
            if any(c.status not in {'missing', 'verified'} for c in checks):
                result.warnings.append('Integrity verification failed or is unsupported. Package archive was not extracted or analyzed.')
                return result

            if self.remaining() <= 0:
                raise BudgetExceeded('Dependency time budget reached before extraction.')

            # Determine archive format
            filename = target_entry.get('filename', '')
            kind = 'zip' if filename.endswith('.whl') or filename.endswith('.zip') else 'tar'

            if key not in self.contents:
                stats = {}
                limits = ArchiveLimits.from_env('wheel' if filename.endswith('.whl') else 'sdist')
                remaining = self.budget.expanded - self.expanded
                if remaining <= 0:
                    raise BudgetExceeded('Aggregate expanded-byte budget reached.')
                try:
                    self.contents[key] = ingestion.archive(data, kind, limits=replace(limits, expanded=min(limits.expanded, remaining)), stats=stats)
                finally:
                    self.expanded += stats.get('expanded', 0)

            result.files, cached_warnings = self.contents[key]
            result.warnings = list(cached_warnings)

            # If requirements.txt is absent but requires_dist exists, synthesize a requirements.txt
            # for dependency resolution and OSV queries
            if 'requirements.txt' not in result.files and info.get('requires_dist'):
                valid_dist = []
                for dist in info['requires_dist']:
                    # Remove environment markers like '; python_version < "3.8"'
                    clean = dist.split(';')[0].strip()
                    if clean:
                        valid_dist.append(clean)
                if valid_dist:
                    result.files['requirements.txt'] = '\n'.join(valid_dist)

            if self.expanded > self.budget.expanded:
                raise BudgetExceeded('Aggregate extracted source budget reached.')
            if result.integrity.status == 'missing':
                result.warnings.append('Lockfile integrity is missing; no lockfile digest was verified.')
            if result.registry_integrity.status == 'missing':
                result.warnings.append('Registry integrity is missing; published bytes could not be verified.')
            return result
        except BudgetExceeded:
            raise
        except Exception as error:
            self.errors[key] = str(error) if isinstance(error, ValueError) else 'PyPI download unavailable or timed out.'
            raise ValueError(self.errors[key]) from error
