"""Ephemeral in-memory local project snapshots and deterministic project understanding."""
import hashlib
import json
import logging
import posixpath
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from .remediation_models import ProjectMetadata

logger = logging.getLogger("guardian.projects")

# Configurable resource limits
MAX_PROJECT_FILES = 250
MAX_FILE_SIZE = 1_048_576          # 1 MB per file
MAX_AGGREGATE_SIZE = 10_485_760    # 10 MB aggregate project snapshot
MAX_RETAINED_SESSIONS = 20
SESSION_TTL_SECONDS = 1800         # 30 minutes of inactivity

EXCLUDED_DIR_NAMES = {
    '.git', 'node_modules', '.venv', 'venv', '.next', 'dist', 'build',
    'coverage', '.cache', '.turbo', '.vscode', '.idea', 'vendor'
}

SECRET_FILE_PATTERNS = [
    re.compile(r'^\.env(\..+)?$', re.IGNORECASE),
    re.compile(r'.*\.(pem|key|pfx|p12|pkcs12|crt|cert)$', re.IGNORECASE),
    re.compile(r'^(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\..+)?$', re.IGNORECASE),
    re.compile(r'^(credentials|secrets|service-account|serviceAccountKey)\.json$', re.IGNORECASE),
]

def compute_sha256(content: str) -> str:
    """Computes SHA-256 hash of UTF-8 encoded text content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def parse_package_specifier(raw: Optional[str]) -> Tuple[str, Optional[str]]:
    """
    Parses npm package specifier into (name, version).
    Correctly supports scoped packages like '@babel/core@7.26.0' -> ('@babel/core', '7.26.0').
    """
    if not raw or not isinstance(raw, str):
        return ("", None)
    trimmed = raw.strip()
    if not trimmed:
        return ("", None)
    if trimmed.startswith("@"):
        slash_idx = trimmed.find("/")
        if slash_idx != -1:
            at_idx = trimmed.find("@", slash_idx + 1)
            if at_idx != -1:
                return (trimmed[:at_idx], trimmed[at_idx + 1:] or None)
            return (trimmed, None)
    at_idx = trimmed.find("@")
    if at_idx > 0:
        return (trimmed[:at_idx], trimmed[at_idx + 1:] or None)
    return (trimmed, None)

def is_secret_file(filename: str) -> bool:
    """Detects secret-bearing or private credential filenames."""
    basename = posixpath.basename(filename)
    return any(p.match(basename) for p in SECRET_FILE_PATTERNS)

def validate_and_normalize_path(path: str) -> str:
    """
    Validates that a file path is a safe relative project path.
    Rejects path traversal, absolute paths, backslashes, null bytes, and control characters.
    """
    if not path or not isinstance(path, str):
        raise ValueError("Invalid file path: path must be a non-empty string.")

    # Control chars and null bytes
    if any(ord(c) < 32 for c in path) or '\0' in path:
        raise ValueError(f"Path contains control characters or null bytes: {repr(path)}")

    # Reject backslashes
    if '\\' in path:
        raise ValueError(f"Windows backslashes are not permitted in project paths: {path}")

    # Reject absolute paths
    if path.startswith('/'):
        raise ValueError(f"Absolute paths are not permitted in project snapshots: {path}")

    normalized = posixpath.normpath(path)
    if normalized == '.' or normalized.startswith('../') or normalized == '..':
        raise ValueError(f"Path traversal detected in project path: {path}")

    parts = normalized.split('/')
    for part in parts:
        if part in EXCLUDED_DIR_NAMES:
            raise ValueError(f"Path references excluded directory '{part}': {path}")

    if is_secret_file(normalized):
        raise ValueError(f"Secret-bearing files cannot be included in project snapshots: {normalized}")

    return normalized

def detect_project_metadata(files: Dict[str, str], scan_id: str, name: str, project_id: Optional[str] = None) -> ProjectMetadata:
    """Deterministically identifies framework, runtime, language, and test runner from manifests."""
    framework: Optional[str] = None
    runtime: Optional[str] = None
    language: Optional[str] = None
    test_framework: Optional[str] = None
    manifest_paths = [p for p in files if posixpath.basename(p) in {'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'}]

    # Inspect root package.json if present
    pkg_json_content = files.get('package.json')
    pkg_data = {}
    if pkg_json_content:
        try:
            pkg_data = json.loads(pkg_json_content)
        except Exception:
            pass

    all_deps = {}
    if isinstance(pkg_data, dict):
        for dep_key in ['dependencies', 'devDependencies', 'peerDependencies']:
            d = pkg_data.get(dep_key)
            if isinstance(d, dict):
                all_deps.update(d)

        # Detect runtime engines
        engines = pkg_data.get('engines')
        if isinstance(engines, dict) and 'node' in engines:
            runtime = f"Node.js ({engines['node']})"

        # Detect framework
        if 'next' in all_deps:
            framework = "Next.js"
        elif '@remix-run/react' in all_deps:
            framework = "Remix"
        elif 'nuxt' in all_deps:
            framework = "Nuxt"
        elif 'vue' in all_deps:
            framework = "Vue"
        elif 'svelte' in all_deps or '@sveltejs/kit' in all_deps:
            framework = "Svelte"
        elif 'react' in all_deps:
            framework = "React"
        elif 'express' in all_deps:
            framework = "Express"
        elif 'fastify' in all_deps:
            framework = "Fastify"
        elif '@nestjs/core' in all_deps:
            framework = "NestJS"
        elif 'electron' in all_deps:
            framework = "Electron"
        elif 'vite' in all_deps:
            framework = "Vite"

        # Detect test framework
        scripts = pkg_data.get('scripts', {})
        test_script = scripts.get('test', '') if isinstance(scripts, dict) else ''
        if 'vitest' in all_deps or 'vitest' in test_script:
            test_framework = "Vitest"
        elif 'jest' in all_deps or 'jest' in test_script:
            test_framework = "Jest"
        elif 'mocha' in all_deps or 'mocha' in test_script:
            test_framework = "Mocha"
        elif '@playwright/test' in all_deps:
            test_framework = "Playwright"
        elif 'cypress' in all_deps:
            test_framework = "Cypress"
        elif test_script:
            test_framework = "npm test"

    # Detect language
    has_ts_files = any(p.endswith(('.ts', '.tsx', '.mts', '.cts')) for p in files)
    has_ts_dep = 'typescript' in all_deps or 'tsconfig.json' in files
    if has_ts_files or has_ts_dep:
        language = "TypeScript"
    else:
        language = "JavaScript"

    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=SESSION_TTL_SECONDS)

    total_bytes = sum(len(c.encode('utf-8')) for c in files.values())

    return ProjectMetadata(
        scan_id=scan_id,
        name=name,
        project_id=project_id,
        framework=framework,
        runtime=runtime,
        language=language,
        test_framework=test_framework,
        total_files=len(files),
        total_bytes=total_bytes,
        manifest_paths=sorted(manifest_paths),
        created_at=now.isoformat(),
        expires_at=expires.isoformat()
    )

@dataclass
class ProjectSnapshot:
    scan_id: str
    name: str
    files: Dict[str, str]                          # normalized path -> text content
    file_hashes: Dict[str, str]                    # normalized path -> sha256
    metadata: ProjectMetadata
    project_id: Optional[str] = None
    created_at_time: float = field(default_factory=time.monotonic)
    last_accessed_at: float = field(default_factory=time.monotonic)

    def is_expired(self) -> bool:
        return (time.monotonic() - self.last_accessed_at) > SESSION_TTL_SECONDS

    def touch(self):
        self.last_accessed_at = time.monotonic()

class ProjectSnapshotManager:
    """Thread-safe in-memory project snapshot manager with bounded memory and automatic TTL eviction."""
    def __init__(self):
        self._lock = threading.Lock()
        self._snapshots: Dict[str, ProjectSnapshot] = {}

    def save_snapshot(self, scan_id: str, name: str, raw_files: Dict[str, str], project_id: Optional[str] = None) -> ProjectSnapshot:
        with self._lock:
            self._cleanup_expired_locked()

            # Evict oldest if ceiling reached
            if len(self._snapshots) >= MAX_RETAINED_SESSIONS:
                oldest_id = min(self._snapshots.keys(), key=lambda k: self._snapshots[k].last_accessed_at)
                del self._snapshots[oldest_id]

            # Validate file count limit
            if len(raw_files) > MAX_PROJECT_FILES:
                raise ValueError(f"Project contains {len(raw_files)} files, which exceeds maximum limit of {MAX_PROJECT_FILES} files.")

            normalized_files: Dict[str, str] = {}
            file_hashes: Dict[str, str] = {}
            total_bytes = 0

            for raw_path, content in raw_files.items():
                norm_path = validate_and_normalize_path(raw_path)
                if norm_path in normalized_files:
                    raise ValueError(f"Duplicate normalized file path: '{norm_path}'")

                if not isinstance(content, str):
                    raise ValueError(f"File content must be UTF-8 string: '{norm_path}'")

                encoded_bytes = content.encode('utf-8')
                file_size = len(encoded_bytes)

                if file_size > MAX_FILE_SIZE:
                    raise ValueError(f"File '{norm_path}' ({file_size} bytes) exceeds 1 MB limit.")

                total_bytes += file_size
                if total_bytes > MAX_AGGREGATE_SIZE:
                    raise ValueError(f"Aggregate project snapshot exceeds 10 MB limit ({total_bytes} bytes).")

                normalized_files[norm_path] = content
                file_hashes[norm_path] = compute_sha256(content)

            stable_project_id = project_id or f"proj_{uuid4().hex[:12]}"
            meta = detect_project_metadata(normalized_files, scan_id, name, project_id=stable_project_id)
            snapshot = ProjectSnapshot(
                scan_id=scan_id,
                name=name,
                files=normalized_files,
                file_hashes=file_hashes,
                metadata=meta,
                project_id=stable_project_id,
                created_at_time=time.monotonic(),
                last_accessed_at=time.monotonic()
            )
            self._snapshots[scan_id] = snapshot
            return snapshot

    def get_snapshot(self, scan_id: str) -> Optional[ProjectSnapshot]:
        with self._lock:
            snap = self._snapshots.get(scan_id)
            if not snap:
                return None
            if snap.is_expired():
                del self._snapshots[scan_id]
                return None
            snap.touch()
            return snap

    def discard_snapshot(self, scan_id: str) -> bool:
        with self._lock:
            if scan_id in self._snapshots:
                del self._snapshots[scan_id]
                return True
            return False

    def _cleanup_expired_locked(self):
        expired_keys = [k for k, v in self._snapshots.items() if v.is_expired()]
        for k in expired_keys:
            del self._snapshots[k]

# Global singleton project snapshot manager
project_manager = ProjectSnapshotManager()
