"""GitHub App authentication, bounded repository ingestion, and repository-native remediation."""
import base64
import json
import logging
import os
import posixpath
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .models import GitHubMetadata
from .projects import (
    compute_sha256,
    is_secret_file,
    validate_and_normalize_path,
    MAX_PROJECT_FILES,
    MAX_FILE_SIZE,
    MAX_AGGREGATE_SIZE,
    EXCLUDED_DIR_NAMES
)
from .remediation_models import RemediationPlan
from . import storage

logger = logging.getLogger("guardian.github")

# Supported file extensions for repository code scanning
SUPPORTED_EXTENSIONS = {
    '.js', '.mjs', '.cjs', '.jsx',
    '.ts', '.mts', '.cts', '.tsx',
    '.json', '.yaml', '.yml'
}

# Supported filenames without standard extensions
SUPPORTED_FILENAMES = {
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'tsconfig.json', 'jsconfig.json', '.npmrc'
}

STATE_TTL_SECONDS = 600  # 10 minutes
TOKEN_EXPIRY_BUFFER = 60  # Refresh token 60s before expiration

class GitHubConfig:
    """Server-side GitHub App configuration."""
    @classmethod
    def app_id(cls) -> Optional[str]:
        val = os.getenv("GITHUB_APP_ID")
        return str(val).strip() if val else None

    @classmethod
    def client_id(cls) -> Optional[str]:
        val = os.getenv("GITHUB_APP_CLIENT_ID")
        return val.strip() if val else None

    @classmethod
    def client_secret(cls) -> Optional[str]:
        val = os.getenv("GITHUB_APP_CLIENT_SECRET")
        return val.strip() if val else None

    @classmethod
    def private_key_pem(cls) -> Optional[bytes]:
        raw = os.getenv("GITHUB_APP_PRIVATE_KEY")
        if not raw:
            # Check key file path if configured
            key_path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH")
            if key_path and os.path.exists(key_path):
                try:
                    return Path(key_path).read_bytes()
                except Exception as err:
                    logger.error(f"Failed to read GitHub App private key from path: {err}")
            return None
        
        # Check if base64 encoded
        cleaned = raw.strip()
        if cleaned.startswith("-----BEGIN"):
            return cleaned.encode('utf-8')
        try:
            decoded = base64.b64decode(cleaned)
            if b"-----BEGIN" in decoded:
                return decoded
        except Exception:
            pass
        return cleaned.encode('utf-8')

    @classmethod
    def install_url(cls) -> Optional[str]:
        return os.getenv("GITHUB_APP_INSTALL_URL")

    @classmethod
    def api_base(cls) -> str:
        return os.getenv("GITHUB_API_BASE", "https://api.github.com").rstrip('/')

    @classmethod
    def is_configured(cls) -> bool:
        return bool(cls.app_id() and cls.private_key_pem())

# Thread-safe in-memory state store and token cache
_state_lock = threading.Lock()
_state_store: Dict[str, float] = {}  # state -> timestamp

_token_lock = threading.Lock()
_token_cache: Dict[int, Tuple[str, float]] = {}  # installation_id -> (token, expires_at_timestamp)

def _generate_app_jwt() -> str:
    """Generates RS256 JWT for GitHub App authentication."""
    app_id = GitHubConfig.app_id()
    pem_bytes = GitHubConfig.private_key_pem()
    if not app_id or not pem_bytes:
        raise ValueError("GitHub App ID or private key is not configured.")

    try:
        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception as err:
        raise ValueError(f"Failed to parse GitHub App private key: {err}")

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": str(app_id),
        "iat": now - 60,
        "exp": now + 600  # Max 10 min
    }

    def b64url(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b'=')

    header_b64 = b64url(json.dumps(header).encode('utf-8'))
    payload_b64 = b64url(json.dumps(payload).encode('utf-8'))
    signing_input = header_b64 + b'.' + payload_b64

    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b'.' + b64url(sig)).decode('utf-8')

def _call_app_api(endpoint: str, method: str = "GET", json_data: Any = None) -> Any:
    """Calls GitHub API authenticated with App JWT."""
    jwt_token = _generate_app_jwt()
    url = f"{GitHubConfig.api_base()}{endpoint}"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Guardian-Security-Engine"
    }

    try:
        resp = requests.request(method, url, headers=headers, json=json_data, timeout=15)
    except Exception as err:
        logger.error(f"GitHub App API connection failure ({endpoint}): {type(err).__name__}")
        raise RuntimeError(f"Failed to reach GitHub API: {type(err).__name__}")

    if resp.status_code >= 400:
        logger.warning(f"GitHub App API error {resp.status_code} on {endpoint}")
        try:
            err_msg = resp.json().get("message", resp.text)
        except Exception:
            err_msg = resp.text
        raise RuntimeError(f"GitHub API error ({resp.status_code}): {err_msg}")

    return resp.json() if resp.content else {}

def get_installation_access_token(installation_id: int) -> str:
    """Retrieves short-lived installation access token with in-memory caching."""
    now = time.time()
    with _token_lock:
        if installation_id in _token_cache:
            token, expires_at = _token_cache[installation_id]
            if expires_at > now + TOKEN_EXPIRY_BUFFER:
                return token

    # Generate new token
    res = _call_app_api(f"/app/installations/{installation_id}/access_tokens", method="POST")
    token = res.get("token")
    expires_str = res.get("expires_at")
    if not token:
        raise RuntimeError("GitHub did not return an installation access token.")

    # Parse ISO 8601 expiration time
    try:
        dt = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        expires_at = dt.timestamp()
    except Exception:
        expires_at = now + 3600

    # Validate minimal permissions
    permissions = res.get("permissions", {})
    if permissions.get("contents") not in ("read", "write"):
        logger.warning(f"Installation {installation_id} has insufficient 'contents' permission: {permissions.get('contents')}")

    with _token_lock:
        _token_cache[installation_id] = (token, expires_at)

    return token

def _call_installation_api(installation_id: int, endpoint: str, method: str = "GET", json_data: Any = None) -> Any:
    """Calls GitHub API authenticated with Installation token."""
    token = get_installation_access_token(installation_id)
    url = f"{GitHubConfig.api_base()}{endpoint}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Guardian-Security-Engine"
    }

    try:
        resp = requests.request(method, url, headers=headers, json=json_data, timeout=20)
    except Exception as err:
        logger.error(f"GitHub Installation API connection failure ({endpoint}): {type(err).__name__}")
        raise RuntimeError(f"Failed to communicate with GitHub API: {type(err).__name__}")

    if resp.status_code >= 400:
        logger.warning(f"GitHub Installation API returned {resp.status_code} for {endpoint}")
        try:
            err_msg = resp.json().get("message", resp.text)
        except Exception:
            err_msg = resp.text
        raise RuntimeError(f"GitHub API error ({resp.status_code}): {err_msg}")

    return resp.json() if resp.content else {}

# State Management for CSRF & Replay Prevention
def create_install_state() -> str:
    """Creates a cryptographically secure, single-use state token."""
    state = secrets.token_urlsafe(32)
    with _state_lock:
        now = time.time()
        # Clean expired states
        expired = [k for k, v in _state_store.items() if now - v > STATE_TTL_SECONDS]
        for k in expired:
            del _state_store[k]
        _state_store[state] = now
    return state

def verify_and_consume_state(state: str) -> bool:
    """Validates state existence and unexpired status, immediately consuming it."""
    if not state:
        return False
    with _state_lock:
        if state not in _state_store:
            return False
        created_at = _state_store.pop(state)
        return (time.time() - created_at) <= STATE_TTL_SECONDS

# Authentication & Connection Flow
def get_connection_status() -> Dict[str, Any]:
    """Returns current GitHub App configuration and connection status."""
    configured = GitHubConfig.is_configured()
    if not configured:
        return {
            "configured": False,
            "connected": False,
            "installation": None,
            "reason": "GitHub App ID or private key is not configured in server environment."
        }

    active = storage.get_active_github_installation()
    if not active:
        return {
            "configured": True,
            "connected": False,
            "installation": None,
            "reason": "No GitHub App installation connected."
        }

    # Verify installation is still valid with GitHub
    try:
        inst = _call_app_api(f"/app/installations/{active['id']}")
        account = inst.get("account", {})
        active_info = {
            "id": inst.get("id"),
            "account_id": account.get("id"),
            "account_login": account.get("login"),
            "account_type": account.get("type", "User"),
            "avatar_url": account.get("avatar_url"),
            "repository_selection": inst.get("repository_selection", "all"),
            "installed_at": inst.get("created_at")
        }
        return {
            "configured": True,
            "connected": True,
            "installation": active_info,
            "reason": None
        }
    except Exception as err:
        logger.warning(f"Connected installation {active['id']} failed verification: {err}")
        return {
            "configured": True,
            "connected": False,
            "installation": None,
            "reason": f"GitHub installation is no longer accessible ({err})."
        }

def create_connect_flow() -> Dict[str, str]:
    """Generates an installation URL with single-use CSRF state."""
    if not GitHubConfig.is_configured():
        raise ValueError("GitHub App configuration is missing on server.")

    state = create_install_state()
    base_install_url = GitHubConfig.install_url()
    if base_install_url:
        sep = "&" if "?" in base_install_url else "?"
        install_url = f"{base_install_url}{sep}state={state}"
    else:
        # Default GitHub App installation URL format
        app_info = _call_app_api("/app")
        slug = app_info.get("slug")
        if not slug:
            raise RuntimeError("Could not determine GitHub App slug.")
        install_url = f"https://github.com/apps/{slug}/installations/new?state={state}"

    return {
        "install_url": install_url,
        "state": state
    }

def handle_installation_callback(installation_id: int, state: str) -> Dict[str, Any]:
    """Validates installation callback parameters, consumes state, and saves installation."""
    if not verify_and_consume_state(state):
        raise ValueError("Invalid or expired OAuth state parameter. Possible CSRF or replay attempt.")

    # Verify installation identity directly with GitHub App API
    inst_data = _call_app_api(f"/app/installations/{installation_id}")
    account = inst_data.get("account", {})
    inst_record = {
        "id": inst_data.get("id"),
        "account_id": account.get("id"),
        "account_login": account.get("login"),
        "account_type": account.get("type", "User"),
        "avatar_url": account.get("avatar_url"),
        "repository_selection": inst_data.get("repository_selection", "all"),
        "installed_at": inst_data.get("created_at", datetime.now(timezone.utc).isoformat())
    }

    # Persist in SQLite
    storage.save_github_installation(inst_record)
    logger.info(f"Successfully connected GitHub installation {installation_id} for {inst_record['account_login']}")
    return inst_record

def disconnect_github() -> Dict[str, str]:
    """Disconnects the current active GitHub installation."""
    storage.deactivate_github_installations()
    with _token_lock:
        _token_cache.clear()
    return {"status": "disconnected"}

# Repository Discovery
def list_repositories(query: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists repositories accessible to the active installation."""
    active = storage.get_active_github_installation()
    if not active:
        raise ValueError("No GitHub App installation is connected.")

    data = _call_installation_api(active["id"], "/installation/repositories?per_page=100")
    repos = data.get("repositories", [])
    
    results = []
    for r in repos:
        name = r.get("name", "")
        full_name = r.get("full_name", "")
        if query and query.lower() not in full_name.lower():
            continue
        results.append({
            "id": r.get("id"),
            "name": name,
            "full_name": full_name,
            "owner": r.get("owner", {}).get("login", ""),
            "owner_avatar": r.get("owner", {}).get("avatar_url"),
            "private": r.get("private", False),
            "html_url": r.get("html_url", ""),
            "description": r.get("description"),
            "default_branch": r.get("default_branch", "main"),
            "updated_at": r.get("updated_at"),
            "permissions": r.get("permissions", {})
        })
    return results

def get_repository(repo_id: int) -> Dict[str, Any]:
    """Retrieves metadata for a specific repository by GitHub ID."""
    active = storage.get_active_github_installation()
    if not active:
        raise ValueError("No GitHub App installation is connected.")

    r = _call_installation_api(active["id"], f"/repositories/{repo_id}")
    return {
        "id": r.get("id"),
        "name": r.get("name"),
        "full_name": r.get("full_name"),
        "owner": r.get("owner", {}).get("login", ""),
        "owner_avatar": r.get("owner", {}).get("avatar_url"),
        "private": r.get("private", False),
        "html_url": r.get("html_url", ""),
        "description": r.get("description"),
        "default_branch": r.get("default_branch", "main"),
        "updated_at": r.get("updated_at"),
        "permissions": r.get("permissions", {})
    }

def list_branches(repo_id: int) -> List[Dict[str, Any]]:
    """Lists branches for a specific repository."""
    active = storage.get_active_github_installation()
    if not active:
        raise ValueError("No GitHub App installation is connected.")

    repo = get_repository(repo_id)
    default_branch = repo.get("default_branch", "main")

    branches_data = _call_installation_api(active["id"], f"/repositories/{repo_id}/branches?per_page=100")
    results = []
    for b in branches_data:
        name = b.get("name", "")
        commit_sha = b.get("commit", {}).get("sha", "")
        results.append({
            "name": name,
            "commit_sha": commit_sha,
            "is_default": (name == default_branch)
        })
    
    # Sort default branch to the top
    results.sort(key=lambda x: (not x["is_default"], x["name"]))
    return results

def get_branch_commit(repo_id: int, branch: str) -> Dict[str, Any]:
    """Resolves a branch name to an immutable commit SHA and latest commit metadata."""
    active = storage.get_active_github_installation()
    if not active:
        raise ValueError("No GitHub App installation is connected.")

    data = _call_installation_api(active["id"], f"/repositories/{repo_id}/commits/{branch}")
    return {
        "sha": data.get("sha"),
        "message": data.get("commit", {}).get("message", ""),
        "author": data.get("commit", {}).get("author", {}).get("name", ""),
        "date": data.get("commit", {}).get("author", {}).get("date", "")
    }

# Bounded Repository Ingestion
def is_eligible_code_file(path: str) -> bool:
    """Checks whether a relative path points to a supported text/code file."""
    basename = posixpath.basename(path)
    if basename in SUPPORTED_FILENAMES:
        return True
    ext = posixpath.splitext(basename)[1].lower()
    return ext in SUPPORTED_EXTENSIONS

def retrieve_repository_snapshot(
    repo_id: int,
    branch: Optional[str] = None
) -> Tuple[str, Dict[str, str], GitHubMetadata, List[str]]:
    """
    Retrieves repository files bounded by strict security limits:
    - Target branch resolved to immutable commit SHA.
    - Git Trees API with truncated tree detection.
    - Path traversal, secret files, binary files, and exclusions rejected.
    - Ceilings: 250 files, 1 MB per file, 10 MB aggregate snapshot.
    Returns: (repo_full_name, files_dict, github_metadata, warnings).
    """
    active = storage.get_active_github_installation()
    if not active:
        raise ValueError("No GitHub App installation is connected.")

    inst_id = active["id"]
    repo_meta = get_repository(repo_id)
    target_branch = branch or repo_meta.get("default_branch", "main")
    
    # Resolve branch to immutable commit SHA
    commit_info = get_branch_commit(repo_id, target_branch)
    commit_sha = commit_info["sha"]
    if not commit_sha:
        raise ValueError(f"Could not resolve branch '{target_branch}' to a commit SHA.")

    warnings: List[str] = []

    # Retrieve recursive Git Tree
    tree_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/trees/{commit_sha}?recursive=1")
    is_truncated = tree_data.get("truncated", False)
    if is_truncated:
        warnings.append(
            "GitHub Git tree response was truncated (>100,000 entries). Repository coverage is partial."
        )

    tree_entries = tree_data.get("tree", [])
    eligible_blobs: List[Dict[str, Any]] = []

    for entry in tree_entries:
        if entry.get("type") != "blob":
            continue
        raw_path = entry.get("path", "")

        try:
            norm_path = validate_and_normalize_path(raw_path)
        except ValueError:
            # Skip invalid, traversal, excluded dir or secret files
            continue

        if not is_eligible_code_file(norm_path):
            continue

        size = entry.get("size")
        if size is not None and size > MAX_FILE_SIZE:
            warnings.append(f"Skipped '{norm_path}' ({size} bytes): exceeds 1 MB per-file limit.")
            continue

        eligible_blobs.append({
            "path": norm_path,
            "sha": entry.get("sha"),
            "size": size or 0
        })

    if len(eligible_blobs) > MAX_PROJECT_FILES:
        raise ValueError(
            f"Repository contains {len(eligible_blobs)} eligible code files, exceeding the limit of {MAX_PROJECT_FILES} files."
        )

    # Fetch blob contents
    files_dict: Dict[str, str] = {}
    aggregate_bytes = 0

    for blob_info in eligible_blobs:
        path = blob_info["path"]
        blob_sha = blob_info["sha"]

        blob_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/blobs/{blob_sha}")
        content_b64 = blob_data.get("content", "")
        encoding = blob_data.get("encoding", "base64")

        if encoding != "base64":
            warnings.append(f"Skipped '{path}': unsupported encoding '{encoding}'.")
            continue

        try:
            raw_bytes = base64.b64decode(content_b64)
        except Exception:
            warnings.append(f"Skipped '{path}': failed to decode base64 content.")
            continue

        file_len = len(raw_bytes)
        if file_len > MAX_FILE_SIZE:
            warnings.append(f"Skipped '{path}' ({file_len} bytes): exceeds 1 MB limit.")
            continue

        aggregate_bytes += file_len
        if aggregate_bytes > MAX_AGGREGATE_SIZE:
            raise ValueError(
                f"Repository snapshot exceeded aggregate limit of {MAX_AGGREGATE_SIZE} bytes ({aggregate_bytes} bytes)."
            )

        try:
            text_content = raw_bytes.decode('utf-8')
            files_dict[path] = text_content
        except UnicodeDecodeError:
            warnings.append(f"Skipped non-UTF-8 source file '{path}'.")
            continue

    if not files_dict:
        raise ValueError("No supported UTF-8 code or manifest files could be retrieved from this repository.")

    gh_meta = GitHubMetadata(
        repository_id=repo_id,
        repo_name=repo_meta["name"],
        owner=repo_meta["owner"],
        repo_url=repo_meta["html_url"],
        branch=target_branch,
        commit_sha=commit_sha,
        default_branch=repo_meta["default_branch"],
        source_type="github"
    )

    return (repo_meta["full_name"], files_dict, gh_meta, warnings)

# GitHub-Native Autopilot Remediation
def apply_remediation_pull_request(plan: RemediationPlan) -> Dict[str, Any]:
    """
    Applies an approved remediation plan to a GitHub repository:
    1. Pre-flight check: validates target branch reference still matches plan.commit_sha.
    2. Validates original file SHA-256 hashes against current repository tree.
    3. Creates Git blobs for updated and created files.
    4. Creates an atomic Git tree.
    5. Creates a Git commit.
    6. Creates dedicated remediation branch `guardian/remediation/<short-plan-id>`.
    7. Opens a detailed Pull Request.
    8. Records PR details against the remediation plan.
    """
    if not plan.repository_id or not plan.branch or not plan.commit_sha:
        raise ValueError("Remediation plan is missing GitHub repository, branch, or commit SHA context.")

    active = storage.get_active_github_installation()
    if not active:
        raise ValueError("No GitHub App installation is connected.")

    inst_id = active["id"]
    repo_id = plan.repository_id
    repo_meta = get_repository(repo_id)
    owner = repo_meta["owner"]
    repo_name = repo_meta["name"]

    # 1. Pre-flight verification: target branch must not have moved
    branch_ref_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/ref/heads/{plan.branch}")
    current_branch_sha = branch_ref_data.get("object", {}).get("sha")

    if current_branch_sha != plan.commit_sha:
        storage.update_plan_status(plan.plan_id, "stale")
        raise ValueError(
            f"Pre-flight check failed: target branch '{plan.branch}' has moved from scanned commit "
            f"{plan.commit_sha[:7]} to {current_branch_sha[:7] if current_branch_sha else 'unknown'}. "
            f"The remediation plan is stale; please rescan the branch to generate a valid plan."
        )

    # 2. Revalidate file contents and calculate new content
    tree_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/trees/{plan.commit_sha}?recursive=1")
    existing_tree = {item["path"]: item for item in tree_data.get("tree", []) if item.get("type") == "blob"}

    new_blobs_to_create: List[Dict[str, Any]] = []

    for change in plan.proposed_changes:
        path = change.file_path.strip().lstrip('/')
        
        # Verify forbidden paths
        if is_secret_file(path) or any(part in EXCLUDED_DIR_NAMES for part in path.split('/')):
            raise ValueError(f"Forbidden target path in remediation change: '{path}'")

        if change.operation == "create":
            if path in existing_tree:
                raise ValueError(f"Create operation collision: file '{path}' already exists in source tree.")
            new_content = change.created_content or ""
            if compute_sha256(new_content) != change.proposed_sha256:
                raise ValueError(f"Hash mismatch for created content in '{path}'.")
            new_blobs_to_create.append({"path": path, "content": new_content})

        elif change.operation == "update":
            if path not in existing_tree:
                raise ValueError(f"Update target '{path}' does not exist in commit {plan.commit_sha[:7]}.")
            
            # Fetch current blob and verify original sha256
            blob_sha = existing_tree[path]["sha"]
            blob_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/blobs/{blob_sha}")
            raw_bytes = base64.b64decode(blob_data.get("content", ""))
            current_text = raw_bytes.decode('utf-8')
            current_hash = compute_sha256(current_text)

            if current_hash != change.original_sha256:
                raise ValueError(
                    f"File '{path}' content hash mismatch (expected {change.original_sha256[:8]}, found {current_hash[:8]}). "
                    f"File may have been altered."
                )

            # Apply edits to produce new content
            updated_text = current_text
            for edit in change.edits:
                if edit.old_text not in updated_text:
                    raise ValueError(f"Edit anchor not found in '{path}'.")
                if updated_text.count(edit.old_text) > 1:
                    raise ValueError(f"Ambiguous edit anchor occurs multiple times in '{path}'.")
                updated_text = updated_text.replace(edit.old_text, edit.new_text, 1)

            if compute_sha256(updated_text) != change.proposed_sha256:
                raise ValueError(f"Computed content hash for '{path}' does not match proposed hash.")

            new_blobs_to_create.append({"path": path, "content": updated_text})

    # 3. Create Git Blobs
    tree_items: List[Dict[str, Any]] = []
    for item in new_blobs_to_create:
        blob_res = _call_installation_api(
            inst_id,
            f"/repositories/{repo_id}/git/blobs",
            method="POST",
            json_data={"content": item["content"], "encoding": "utf-8"}
        )
        tree_items.append({
            "path": item["path"],
            "mode": "100644",
            "type": "blob",
            "sha": blob_res["sha"]
        })

    # 4. Create Atomic Git Tree
    new_tree_res = _call_installation_api(
        inst_id,
        f"/repositories/{repo_id}/git/trees",
        method="POST",
        json_data={
            "base_tree": plan.commit_sha,
            "tree": tree_items
        }
    )
    new_tree_sha = new_tree_res["sha"]

    # 5. Create Commit
    short_id = plan.plan_id[:8]
    commit_msg = (
        f"Guardian Autopilot: {plan.title}\n\n"
        f"Automated remediation addressing {len(plan.findings_addressed)} finding(s).\n\n"
        f"Summary: {plan.summary}\n"
        f"Source commit: {plan.commit_sha}"
    )
    new_commit_res = _call_installation_api(
        inst_id,
        f"/repositories/{repo_id}/git/commits",
        method="POST",
        json_data={
            "message": commit_msg,
            "tree": new_tree_sha,
            "parents": [plan.commit_sha]
        }
    )
    new_commit_sha = new_commit_res["sha"]

    # 6. Create dedicated remediation branch
    remediation_branch = f"guardian/remediation/{short_id}"
    try:
        _call_installation_api(
            inst_id,
            f"/repositories/{repo_id}/git/refs",
            method="POST",
            json_data={
                "ref": f"refs/heads/{remediation_branch}",
                "sha": new_commit_sha
            }
        )
    except Exception as err:
        # If branch collision, append random suffix
        if "Reference already exists" in str(err):
            remediation_branch = f"guardian/remediation/{short_id}-{secrets.token_hex(2)}"
            _call_installation_api(
                inst_id,
                f"/repositories/{repo_id}/git/refs",
                method="POST",
                json_data={
                    "ref": f"refs/heads/{remediation_branch}",
                    "sha": new_commit_sha
                }
            )
        else:
            raise

    # 7. Create Pull Request
    pr_body = _format_pull_request_body(plan, new_commit_sha, remediation_branch)
    pr_title = f"🛡️ Guardian Autopilot: {plan.title}"
    
    pr_data = _call_installation_api(
        inst_id,
        f"/repositories/{repo_id}/pulls",
        method="POST",
        json_data={
            "title": pr_title,
            "head": remediation_branch,
            "base": plan.branch,
            "body": pr_body
        }
    )

    # 8. Update plan in SQLite
    plan.status = "applied"
    plan.pr_number = pr_data.get("number")
    plan.pr_url = pr_data.get("html_url")
    plan.remediation_branch = remediation_branch
    plan.remediation_commit_sha = new_commit_sha
    plan.pr_state = pr_data.get("state", "open")
    storage.save_plan(plan)

    logger.info(f"Created remediation PR #{plan.pr_number} ({plan.pr_url}) for plan {plan.plan_id}")

    return {
        "plan_id": plan.plan_id,
        "pr_number": plan.pr_number,
        "pr_url": plan.pr_url,
        "remediation_branch": remediation_branch,
        "commit_sha": new_commit_sha,
        "status": "applied"
    }

def close_remediation_pull_request(plan: RemediationPlan) -> Dict[str, Any]:
    """Safely closes a Guardian Autopilot pull request on GitHub."""
    if not plan.repository_id or not plan.pr_number:
        raise ValueError("Remediation plan has no associated GitHub pull request.")

    active = storage.get_active_github_installation()
    if not active:
        raise ValueError("No GitHub App installation is connected.")

    inst_id = active["id"]
    repo_id = plan.repository_id

    res = _call_installation_api(
        inst_id,
        f"/repositories/{repo_id}/pulls/{plan.pr_number}",
        method="PATCH",
        json_data={"state": "closed"}
    )

    plan.status = "reverted"
    plan.pr_state = "closed"
    storage.save_plan(plan)

    return {
        "plan_id": plan.plan_id,
        "pr_number": plan.pr_number,
        "pr_state": "closed",
        "status": "reverted"
    }

def _format_pull_request_body(plan: RemediationPlan, commit_sha: str, remediation_branch: str) -> str:
    """Formats structured, professional markdown for the Pull Request description."""
    lines = [
        f"## 🛡️ Guardian Autopilot Security Remediation",
        "",
        f"**Plan ID:** `{plan.plan_id}`  ",
        f"**Priority:** `{plan.priority.upper()}`  ",
        f"**Source Branch:** `{plan.branch}` (`{plan.commit_sha[:7]}`)  ",
        f"**Remediation Branch:** `{remediation_branch}` (`{commit_sha[:7]}`)  ",
        "",
        f"### Summary",
        f"{plan.summary}",
        "",
        f"### Expected Outcome",
        f"{plan.expected_outcome}",
        "",
        f"### Findings Addressed ({len(plan.findings_addressed)})",
    ]

    for fid in plan.findings_addressed:
        lines.append(f"- Finding ID: `{fid}`")

    lines.extend([
        "",
        f"### Proposed File Changes ({len(plan.proposed_changes)})",
    ])

    for ch in plan.proposed_changes:
        lines.append(f"- **`{ch.file_path}`** (`{ch.operation}`): {ch.rationale}")

    if plan.tradeoffs:
        lines.extend(["", "### Trade-offs & Considerations"])
        for t in plan.tradeoffs:
            lines.append(f"- {t}")

    if plan.potential_risks:
        lines.extend(["", "### Potential Risks"])
        for r in plan.potential_risks:
            lines.append(f"- {r}")

    if plan.manual_steps:
        lines.extend(["", "### Required Manual Steps"])
        for s in plan.manual_steps:
            lines.append(f"- [ ] {s}")

    if plan.recommended_verification:
        lines.extend(["", "### Recommended Verification"])
        for v in plan.recommended_verification:
            lines.append(f"- {v}")

    lines.extend([
        "",
        "---",
        "> [!IMPORTANT]",
        "> **Human Review Required:** These modifications were generated by **Guardian Autopilot** based on static behavioral and vulnerability intelligence. Please inspect the diff, run your project test suite, and ensure application behavior matches expectations before merging.",
        "> ",
        "> *Guardian does not automatically merge pull requests or execute uploaded repository code.*"
    ])

    return "\n".join(lines)
