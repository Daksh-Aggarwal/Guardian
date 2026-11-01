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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlencode, quote

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

try:
    from .advisor import load_dotenv
    load_dotenv()
except Exception:
    pass

logger = logging.getLogger("guardian.github")

# Supported file extensions for repository code scanning
SUPPORTED_EXTENSIONS = {
    '.js', '.mjs', '.cjs', '.jsx',
    '.ts', '.mts', '.cts', '.tsx',
    '.json', '.yaml', '.yml',
    '.py', '.pyw', '.pth', '.start',
    '.toml', '.cfg'
}

# Supported filenames without standard extensions
SUPPORTED_FILENAMES = {
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'tsconfig.json', 'jsconfig.json', '.npmrc',
    'pyproject.toml', 'poetry.lock', 'Pipfile', 'Pipfile.lock', 'requirements.txt',
    'uv.lock', 'pylock.toml', 'setup.cfg', 'setup.py', 'requirements.in'
}

# Protected files that must not be modified by automated remediation
PROTECTED_REMEDIATION_FILES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'Pipfile.lock'
}

STATE_TTL_SECONDS = 600  # 10 minutes
TOKEN_EXPIRY_BUFFER = 60  # Refresh token 60s before expiration

# Ingestion budgets
MAX_SNAPSHOT_REQUESTS = 60
MAX_SNAPSHOT_SECONDS = 30.0

# Independent remediation limits
MAX_REMEDIATION_FILES = 25
MAX_REMEDIATION_FILE_SIZE = 1_048_576  # 1 MB
MAX_REMEDIATION_AGGREGATE_SIZE = 2 * 1024 * 1024  # 2 MB

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
            key_path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH")
            if key_path and os.path.exists(key_path):
                try:
                    return Path(key_path).read_bytes()
                except Exception as err:
                    logger.error(f"Failed to read GitHub App private key from path: {err}")
            return None
        
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

# Server-Managed Session Compatibility Shim (backed by SQLite storage)
class SessionManager:
    """Compatibility shim delegating to SQLite-backed session storage."""
    def create_session(self) -> str:
        return storage.create_session()

    def get_session(self, session_id: Optional[str]) -> Optional[Dict[str, Any]]:
        return storage.get_session(session_id)

    def is_session_valid(self, session_id: Optional[str]) -> bool:
        return storage.get_session(session_id) is not None

    def is_installation_authorized(self, session_id: Optional[str], installation_id: int) -> bool:
        if not self.is_session_valid(session_id):
            return False
        return storage.is_installation_authorized_for_session(session_id, installation_id)

    def get_authorized_installation_ids(self, session_id: Optional[str]) -> Set[int]:
        if not self.is_session_valid(session_id):
            return set()
        return storage.get_session_authorized_installation_ids(session_id)

    def authorize_installation(self, session_id: str, installation_id: int, make_selected: bool = False):
        storage.authorize_installation_for_session(session_id, installation_id, make_selected=make_selected)

    def select_installation(self, session_id: str, installation_id: int) -> bool:
        return storage.set_session_selected_installation(session_id, installation_id)

    def get_selected_installation_id(self, session_id: Optional[str]) -> Optional[int]:
        if session_id:
            if not self.is_session_valid(session_id):
                return None
            sel = storage.get_session_selected_installation(session_id)
            return sel["id"] if sel else None
        active = storage.get_active_github_installation()
        return active["id"] if active else None

    def disconnect_installation(self, session_id: Optional[str], installation_id: int):
        if session_id:
            storage.deauthorize_installation_for_session(session_id, installation_id)

session_manager = SessionManager()

# Thread-safe in-memory state store and token cache
_state_lock = threading.Lock()
_state_store: Dict[str, Any] = {}  # state -> (created_at, session_id) or created_at

_token_lock = threading.Lock()
_token_cache: Dict[int, Tuple[str, float]] = {}  # installation_id -> (token, expires_at_timestamp)

_last_response_headers = threading.local()

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

_http_session: Optional[requests.Session] = None
_http_session_lock = threading.Lock()

def _get_http_session() -> requests.Session:
    """Thread-safe persistent requests Session with connection pooling for GitHub API."""
    global _http_session
    if _http_session is None:
        with _http_session_lock:
            if _http_session is None:
                s = requests.Session()
                adapter = requests.adapters.HTTPAdapter(
                    pool_connections=20,
                    pool_maxsize=20,
                    max_retries=1
                )
                s.mount("https://", adapter)
                s.mount("http://", adapter)
                _http_session = s
    return _http_session

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
        session = _get_http_session()
        resp = session.request(method, url, headers=headers, json=json_data, timeout=15)
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

def get_installation_access_token(
    installation_id: int,
    force_refresh: bool = False,
    session_id: Optional[str] = None
) -> str:
    """Retrieves short-lived installation access token with in-memory caching."""
    if session_id is not None:
        if not storage.is_installation_authorized_for_session(session_id, installation_id):
            raise PermissionError(f"Installation {installation_id} is not authorized for this session.")

    now = time.time()
    if not force_refresh:
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

    try:
        dt = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        expires_at = dt.timestamp()
    except Exception:
        expires_at = now + 3600

    permissions = res.get("permissions", {})
    if permissions.get("contents") not in ("read", "write"):
        logger.warning(f"Installation {installation_id} has insufficient 'contents' permission: {permissions.get('contents')}")

    with _token_lock:
        _token_cache[installation_id] = (token, expires_at)

    return token

def _call_installation_api_raw(
    installation_id: int,
    url_or_endpoint: str,
    method: str = "GET",
    json_data: Any = None
) -> requests.Response:
    """Raw HTTP call to GitHub Installation API with rate limit, retry, and token refresh handling."""
    if url_or_endpoint.startswith("http://") or url_or_endpoint.startswith("https://"):
        url = url_or_endpoint
    else:
        url = f"{GitHubConfig.api_base()}{url_or_endpoint}"

    max_retries = 2
    for attempt in range(max_retries + 1):
        token = get_installation_access_token(installation_id, force_refresh=(attempt > 0))
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Guardian-Security-Engine"
        }

        try:
            session = _get_http_session()
            resp = session.request(method, url, headers=headers, json=json_data, timeout=15)
        except Exception as err:
            if attempt < max_retries:
                time.sleep(0.5 * (2 ** attempt))
                continue
            logger.error(f"GitHub Installation API connection failure ({url_or_endpoint}): {type(err).__name__}")
            raise RuntimeError(f"Failed to communicate with GitHub API: {type(err).__name__}")

        # Check for expired token (401)
        if resp.status_code == 401 and attempt < max_retries:
            with _token_lock:
                _token_cache.pop(installation_id, None)
            continue

        # Check for Rate Limiting / Retry-After
        if resp.status_code in (403, 429):
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    wait_s = int(retry_after)
                    if wait_s <= 3 and attempt < max_retries:
                        time.sleep(wait_s)
                        continue
                    raise RuntimeError(f"GitHub rate limit exceeded. Retry-After {wait_s}s.")
                except ValueError:
                    pass

            # Check primary rate limit
            if resp.headers.get("X-RateLimit-Remaining") == "0":
                reset_ts = resp.headers.get("X-RateLimit-Reset")
                raise RuntimeError(f"GitHub API primary rate limit exceeded. Rate limit resets at {reset_ts}.")

            # Check secondary rate limit message
            try:
                body = resp.json()
                msg = body.get("message", "")
                if "secondary rate limit" in msg.lower() or "rate limit" in msg.lower():
                    raise RuntimeError(f"GitHub secondary rate limit hit: {msg}")
            except Exception:
                pass

        # Transient server errors (500, 502, 503, 504) -> Bounded exponential backoff
        if resp.status_code in (500, 502, 503, 504) and attempt < max_retries:
            time.sleep(0.5 * (2 ** attempt))
            continue

        if resp.status_code >= 400:
            logger.warning(f"GitHub Installation API returned {resp.status_code} for {url_or_endpoint}")
            try:
                err_msg = resp.json().get("message", resp.text)
            except Exception:
                err_msg = resp.text
            raise RuntimeError(f"GitHub API error ({resp.status_code}): {err_msg}")

        _last_response_headers.headers = resp.headers
        return resp

    raise RuntimeError(f"GitHub API request failed after {max_retries} retries: {url_or_endpoint}")

def _call_installation_api(
    installation_id: int,
    endpoint: str,
    method: str = "GET",
    json_data: Any = None
) -> Any:
    """Calls GitHub API authenticated with Installation token and returns parsed JSON content."""
    resp = _call_installation_api_raw(installation_id, endpoint, method=method, json_data=json_data)
    return resp.json() if resp.content else {}

def _parse_next_link(link_header: Optional[str]) -> Optional[str]:
    """Extracts next page URL from standard GitHub HTTP Link header."""
    if not link_header:
        return None
    for part in link_header.split(','):
        match = re.search(r'<([^>]+)>;\s*rel=["\']next["\']', part.strip())
        if match:
            return match.group(1)
    return None

def _paginate_installation_api(
    installation_id: int,
    endpoint: str,
    key: Optional[str] = None,
    max_pages: int = 5
) -> List[Any]:
    """Safely follows GitHub pagination Link headers up to bounded max_pages budget."""
    results: List[Any] = []
    current_url: Optional[str] = endpoint
    pages_fetched = 0

    while current_url and pages_fetched < max_pages:
        data = _call_installation_api(installation_id, current_url)
        pages_fetched += 1

        if key and isinstance(data, dict):
            items = data.get(key, [])
            if isinstance(items, list):
                results.extend(items)
        elif isinstance(data, list):
            results.extend(data)
        else:
            break

        headers = getattr(_last_response_headers, "headers", {})
        link_header = headers.get("Link")
        current_url = _parse_next_link(link_header)

    return results

# State Management for CSRF & Replay Prevention
def create_install_state(session_id: Optional[str] = None) -> str:
    """Creates a cryptographically secure, single-use state token bound to the session."""
    state = secrets.token_urlsafe(32)
    with _state_lock:
        now = time.time()
        # Clean expired states
        expired = [k for k, (ts, _) in _state_store.items() if now - ts > STATE_TTL_SECONDS]
        for k in expired:
            del _state_store[k]
        _state_store[state] = (now, session_id)
    return state

def get_state_session_id(state: Optional[str]) -> Optional[str]:
    """Retrieves session_id bound to state without consuming it."""
    if not state or not isinstance(state, str) or not state.strip():
        return None
    state = state.strip()
    with _state_lock:
        val = _state_store.get(state)
        if val:
            if isinstance(val, (tuple, list)):
                return val[1]
    return None

def verify_and_consume_state(state: Optional[str], session_id: Optional[str] = None) -> bool:
    """Validates state existence, single-use unconsumed status, unexpired TTL, and session binding."""
    if not state or not isinstance(state, str) or not state.strip():
        return False
    state = state.strip()
    with _state_lock:
        if state not in _state_store:
            return False
        val = _state_store.pop(state)
        if isinstance(val, (tuple, list)):
            created_at, bound_session_id = val[0], val[1]
        else:
            created_at, bound_session_id = val, None
        if (time.time() - created_at) > STATE_TTL_SECONDS:
            return False
        if bound_session_id is not None and bound_session_id != session_id:
            return False
        return True

# Authentication & Connection Flow
def sync_installations(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Discovers and synchronizes installations from GitHub App API with SQLite.
    
    Preserves multiple installations and maintains explicit selection.
    """
    if not GitHubConfig.is_configured():
        return {
            "configured": False,
            "connected": False,
            "installation": None,
            "installations": [],
            "reason": "GitHub App ID or private key is not configured in server environment."
        }

    try:
        installations = _call_app_api("/app/installations")
    except Exception as err:
        logger.error(f"Failed to query installations from GitHub App API: {err}")
        active = storage.get_session_selected_installation(session_id) if session_id else storage.get_active_github_installation()
        all_insts = list_installations(session_id)
        return {
            "configured": True,
            "connected": bool(active),
            "installation": active,
            "installations": all_insts,
            "reason": f"Failed to contact GitHub: {err}"
        }

    if not installations or not isinstance(installations, list) or len(installations) == 0:
        # Do not deactivate all installations if GitHub returns empty; report existing
        active = storage.get_session_selected_installation(session_id) if session_id else storage.get_active_github_installation()
        all_insts = list_installations(session_id)
        return {
            "configured": True,
            "connected": bool(active),
            "installation": active,
            "installations": all_insts,
            "reason": "No installations found for this GitHub App on GitHub." if not active else None
        }

    discovered = []
    # Store all discovered installations without overwriting active selection
    for inst in installations:
        account = inst.get("account", {})
        inst_record = {
            "id": inst.get("id"),
            "account_id": account.get("id"),
            "account_login": account.get("login"),
            "account_type": account.get("type", "User"),
            "avatar_url": account.get("avatar_url"),
            "repository_selection": inst.get("repository_selection", "all"),
            "installed_at": inst.get("created_at", datetime.now(timezone.utc).isoformat())
        }
        storage.save_github_installation(inst_record, make_active=False)
        discovered.append(inst_record)

    if session_id:
        existing_auth = storage.get_session_authorized_installation_ids(session_id)
        if not existing_auth:
            return {
                "configured": True,
                "connected": False,
                "installation": None,
                "installations": [],
                "available_installations": discovered,
                "reason": "GitHub App installations detected. Select your account to connect." if discovered else "No installations found for this GitHub App on GitHub."
            }

        active = storage.get_session_selected_installation(session_id)
        all_insts = list_installations(session_id)
        return {
            "configured": True,
            "connected": bool(active),
            "installation": active,
            "installations": all_insts,
            "available_installations": discovered,
            "reason": None
        }

    # If no active installation in SQLite, activate the most recently updated one
    active = storage.get_active_github_installation()
    if not active:
        sorted_insts = sorted(
            installations,
            key=lambda x: x.get("updated_at") or x.get("created_at") or "",
            reverse=True
        )
        first_id = sorted_insts[0].get("id")
        storage.set_active_github_installation(first_id)
        active = storage.get_github_installation(first_id)

    all_insts = list_installations(None)
    return {
        "configured": True,
        "connected": True,
        "installation": active,
        "installations": all_insts,
        "available_installations": discovered,
        "reason": None
    }

def list_installations(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists installations explicitly authorized for this session with selection flag.
    If session_id is None (CLI/testing), lists all installations from storage.
    """
    if session_id:
        return storage.get_session_installations(session_id)

    records = storage.list_github_installations()
    active = storage.get_active_github_installation()
    active_id = active["id"] if active else None
    for r in records:
        r["is_selected"] = (r["id"] == active_id)
    return records

def select_installation(installation_id: int, session_id: Optional[str] = None) -> Dict[str, Any]:
    """Explicitly selects an installation for the session.
    
    Must verify that the installation belongs to the session's authorized installation set.
    """
    if session_id:
        if not storage.get_session(session_id):
            raise ValueError("Session is invalid or expired.")
        if not storage.is_installation_authorized_for_session(session_id, installation_id):
            raise ValueError(f"Installation {installation_id} is not authorized for this session.")
        success = storage.set_session_selected_installation(session_id, installation_id)
        if not success:
            raise ValueError(f"GitHub App installation {installation_id} not found.")
        inst = storage.get_github_installation(installation_id)
        if not inst:
            raise ValueError(f"GitHub App installation {installation_id} not found.")
        inst["is_selected"] = True
        return inst

    inst = storage.get_github_installation(installation_id)
    if not inst:
        raise ValueError(f"GitHub App installation {installation_id} not found.")
    storage.set_active_github_installation(installation_id)
    inst["is_selected"] = True
    return inst

def link_installation(installation_id: int, session_id: Optional[str] = None) -> Dict[str, Any]:
    """Explicitly links/authorizes an existing GitHub App installation for this session."""
    if not session_id:
        raise ValueError("A valid session is required to link an installation.")

    try:
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
        storage.save_github_installation(inst_record, make_active=False)
    except Exception as err:
        logger.warning(f"Could not verify installation with GitHub API: {err}")
        inst_record = storage.get_github_installation(installation_id)
        if not inst_record:
            raise ValueError(f"GitHub App installation {installation_id} not found: {err}")

    storage.authorize_installation_for_session(session_id, installation_id, make_selected=True)
    if hasattr(session_manager, "authorize_installation"):
        session_manager.authorize_installation(session_id, installation_id, make_selected=True)

    inst_record["is_selected"] = True
    return {
        "status": "linked",
        "installation": inst_record
    }

def disconnect_installation(
    installation_id: Optional[int] = None,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Disconnects only the specified installation, preserving other installations."""
    target_id = installation_id
    if session_id:
        if not target_id:
            sel = storage.get_session_selected_installation(session_id)
            target_id = sel["id"] if sel else None
        if not target_id:
            auth_ids = sorted(list(storage.get_session_authorized_installation_ids(session_id)))
            if auth_ids:
                target_id = auth_ids[0]
        if not target_id:
            raise ValueError("No GitHub App installation specified or currently active to disconnect.")
        if not storage.is_installation_authorized_for_session(session_id, target_id):
            raise ValueError(f"Installation {target_id} is not authorized for this session.")

        storage.deauthorize_installation_for_session(session_id, target_id)
        with _token_lock:
            _token_cache.pop(target_id, None)
        return {"status": "disconnected", "installation_id": target_id}

    if not target_id:
        active = storage.get_active_github_installation()
        target_id = active["id"] if active else None
    if not target_id:
        raise ValueError("No GitHub App installation specified or currently active to disconnect.")

    storage.disconnect_github_installation(target_id)
    with _token_lock:
        _token_cache.pop(target_id, None)
    return {"status": "disconnected", "installation_id": target_id}

def disconnect_github(session_id: Optional[str] = None) -> Dict[str, str]:
    """Disconnects the currently selected installation for backwards compatibility."""
    res = disconnect_installation(session_id=session_id)
    return {"status": "disconnected"}

def get_connection_status(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Returns current GitHub App configuration and connection status."""
    configured = GitHubConfig.is_configured()
    if not configured:
        return {
            "configured": False,
            "connected": False,
            "installation": None,
            "installations": [],
            "available_installations": [],
            "reason": "GitHub App ID or private key is not configured in server environment."
        }

    available_installations = [
        inst for inst in storage.list_github_installations()
        if inst.get("id")
    ]

    if session_id:
        active = storage.get_session_selected_installation(session_id)
        all_insts = storage.get_session_installations(session_id)
        if not active:
            return {
                "configured": True,
                "connected": False,
                "installation": None,
                "installations": all_insts,
                "available_installations": available_installations,
                "reason": "No active GitHub App installation connected for this session."
            }
    else:
        active = storage.get_active_github_installation()
        if not active:
            if not storage.has_any_github_installation():
                return sync_installations(session_id=None)
            return {
                "configured": True,
                "connected": False,
                "installation": None,
                "installations": list_installations(None),
                "available_installations": available_installations,
                "reason": "No active GitHub App installation connected."
            }
        all_insts = list_installations(None)

    # Verify installation with GitHub App API with local fallback for offline/test resilience
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
            "installed_at": inst.get("created_at"),
            "is_selected": True
        }
        return {
            "configured": True,
            "connected": True,
            "installation": active_info,
            "installations": all_insts,
            "available_installations": available_installations,
            "reason": None
        }
    except Exception as err:
        logger.warning(f"Connected installation {active['id']} verification notice: {err}")
        err_msg = str(err)
        if "404" in err_msg or "Not Found" in err_msg:
            # Installation was uninstalled on GitHub or is an invalid fixture in SQLite
            if session_id:
                storage.deauthorize_installation_for_session(session_id, active["id"])
            else:
                storage.disconnect_github_installation(active["id"])
            return {
                "configured": True,
                "connected": False,
                "installation": None,
                "installations": list_installations(session_id),
                "available_installations": [i for i in available_installations if i.get("id") != active["id"]],
                "reason": "Connected GitHub installation was not found on GitHub."
            }
        active_info = dict(active)
        active_info["is_selected"] = True
        return {
            "configured": True,
            "connected": True,
            "installation": active_info,
            "installations": all_insts,
            "available_installations": available_installations,
            "reason": None
        }

def create_connect_flow(session_id: Optional[str] = None) -> Dict[str, str]:
    """Generates an installation URL with single-use CSRF state bound to session."""
    if not GitHubConfig.is_configured():
        raise ValueError("GitHub App configuration is missing on server.")

    state = create_install_state(session_id=session_id)
    base_install_url = GitHubConfig.install_url()
    if base_install_url:
        sep = "&" if "?" in base_install_url else "?"
        install_url = f"{base_install_url}{sep}state={state}"
    else:
        app_info = _call_app_api("/app")
        slug = app_info.get("slug")
        if not slug:
            raise RuntimeError("Could not determine GitHub App slug.")
        install_url = f"https://github.com/apps/{slug}/installations/new?state={state}"

    return {
        "install_url": install_url,
        "state": state
    }

def handle_installation_callback(
    installation_id: Optional[int] = None,
    state: Optional[str] = None,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Validates installation callback parameters, strictly requiring and consuming state."""
    if not state or not state.strip():
        raise ValueError("Missing OAuth state parameter. Browser-initiated callback requires valid state.")

    bound_session = get_state_session_id(state)
    effective_session = session_id or bound_session

    if not verify_and_consume_state(state, session_id=session_id):
        raise ValueError("Invalid or expired OAuth state parameter. Possible CSRF or replay attempt.")

    if not installation_id:
        res = sync_installations(session_id=effective_session)
        if not res.get("connected") or not res.get("installation"):
            raise ValueError("No installation ID provided and no installations found on GitHub.")
        return res["installation"]

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

    # Save to SQLite and make active
    storage.save_github_installation(inst_record, make_active=True)

    if effective_session:
        storage.authorize_installation_for_session(effective_session, installation_id, make_selected=True)

    logger.info(f"Successfully connected GitHub installation {installation_id} for {inst_record['account_login']}")
    return inst_record

def _resolve_active_installation_id(session_id: Optional[str] = None) -> int:
    """Helper to resolve active installation ID for GitHub operations.
    
    STRICT: If session_id is provided, strictly enforces that the session is authorized
    and has selected an installation in session_installations. No global fallback permitted.
    If session_id is None (internal/direct Python unit tests), resolves from storage.
    """
    if session_id is not None:
        if not storage.get_session(session_id):
            raise ValueError("Session is invalid or expired. Please reinitialize session.")
        sel = storage.get_session_selected_installation(session_id)
        if not sel or not sel.get("id"):
            raise ValueError("No GitHub App installation is selected or authorized for this session.")
        return sel["id"]

    active = storage.get_active_github_installation()
    if active and active.get("id"):
        return active["id"]
    raise ValueError("No GitHub App installation is configured or active.")

# Repository Discovery
def list_repositories(query: Optional[str] = None, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists repositories accessible to the active installation with bounded pagination."""
    inst_id = _resolve_active_installation_id(session_id)
    try:
        repos = _paginate_installation_api(inst_id, "/installation/repositories?per_page=100", key="repositories", max_pages=5)
    except Exception as err:
        logger.warning(f"Failed to list repositories for installation {inst_id}: {err}")
        if "404" in str(err) or "Not Found" in str(err):
            return []
        raise
    
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

def get_repository(repo_id: int, session_id: Optional[str] = None) -> Dict[str, Any]:
    """Retrieves metadata for a specific repository by GitHub ID."""
    inst_id = _resolve_active_installation_id(session_id)
    r = _call_installation_api(inst_id, f"/repositories/{repo_id}")
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

def list_branches(repo_id: int, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists branches for a specific repository with bounded pagination."""
    inst_id = _resolve_active_installation_id(session_id)
    repo = get_repository(repo_id, session_id=session_id)
    default_branch = repo.get("default_branch", "main")

    branches_data = _paginate_installation_api(inst_id, f"/repositories/{repo_id}/branches?per_page=100", max_pages=5)
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

def get_branch_commit(repo_id: int, branch: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    """Resolves a branch name to an immutable commit SHA and latest commit metadata.
    
    Properly encodes branch names while preserving slash semantics (e.g. feature/auth).
    """
    inst_id = _resolve_active_installation_id(session_id)
    encoded_branch = quote(branch.strip(), safe="/")
    data = _call_installation_api(inst_id, f"/repositories/{repo_id}/commits/{encoded_branch}")
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
    if basename.startswith('requirements') and basename.endswith('.txt'):
        return True
    ext = posixpath.splitext(basename)[1].lower()
    return ext in SUPPORTED_EXTENSIONS

def retrieve_repository_snapshot(
    repo_id: int,
    branch: Optional[str] = None,
    session_id: Optional[str] = None
) -> Tuple[str, Dict[str, str], GitHubMetadata, List[str]]:
    """
    Retrieves repository files bounded by strict security limits:
    - Target branch resolved to immutable commit SHA.
    - Git Trees API with truncated tree detection.
    - Path traversal, secret files, binary files, and exclusions rejected.
    - Budgets: 250 files, 1 MB per file, 10 MB aggregate snapshot, 60 requests, 30s elapsed time.
    Returns: (repo_full_name, files_dict, github_metadata, warnings).
    """
    inst_id = _resolve_active_installation_id(session_id)
    repo_meta = get_repository(repo_id, session_id=session_id)
    target_branch = branch or repo_meta.get("default_branch", "main")
    
    # Resolve branch to immutable commit SHA
    commit_info = get_branch_commit(repo_id, target_branch, session_id=session_id)
    commit_sha = commit_info["sha"]
    if not commit_sha:
        raise ValueError(f"Could not resolve branch '{target_branch}' to a commit SHA.")

    warnings: List[str] = []
    start_time = time.monotonic()
    requests_count = 2  # Already fetched repo_meta and branch_commit

    # Retrieve recursive Git Tree
    tree_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/trees/{commit_sha}?recursive=1")
    requests_count += 1

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

    # Fetch blob contents bounded by request count and time budgets
    files_dict: Dict[str, str] = {}
    aggregate_bytes = 0

    remaining_budget = MAX_SNAPSHOT_REQUESTS - requests_count
    if len(eligible_blobs) > remaining_budget:
        blobs_to_fetch = eligible_blobs[:max(0, remaining_budget)]
        halted_request_budget = True
    else:
        blobs_to_fetch = eligible_blobs
        halted_request_budget = False

    def _fetch_blob_worker(b_info: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]], Optional[Exception]]:
        b_path = b_info["path"]
        b_sha = b_info["sha"]
        try:
            data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/blobs/{b_sha}")
            return (b_path, data, None)
        except Exception as err:
            return (b_path, None, err)

    fetch_results: Dict[str, Tuple[Optional[Dict[str, Any]], Optional[Exception]]] = {}
    if blobs_to_fetch:
        max_workers = min(8, len(blobs_to_fetch))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_blob = {executor.submit(_fetch_blob_worker, b): b for b in blobs_to_fetch}
            for future in future_to_blob:
                b_path, data, err = future.result()
                fetch_results[b_path] = (data, err)
                requests_count += 1

    for blob_info in blobs_to_fetch:
        # Enforce elapsed time budget
        if time.monotonic() - start_time >= MAX_SNAPSHOT_SECONDS:
            warnings.append(
                f"Repository snapshot halted: exceeded elapsed time budget of {MAX_SNAPSHOT_SECONDS}s. Coverage is partial."
            )
            break

        path = blob_info["path"]
        blob_data, err = fetch_results.get(path, (None, None))

        if err is not None:
            warnings.append(f"Failed to fetch blob for '{path}': {err}")
            continue

        if not blob_data:
            continue

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

    if halted_request_budget:
        warnings.append(
            f"Repository snapshot halted: exceeded request budget of {MAX_SNAPSHOT_REQUESTS} requests. Coverage is partial."
        )

    if not files_dict:
        raise ValueError("No supported UTF-8 code or manifest files could be retrieved from this repository.")

    gh_meta = GitHubMetadata(
        installation_id=inst_id,
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
def preflight_validate_remediation(
    inst_id: int,
    plan: RemediationPlan
) -> Tuple[str, Dict[str, str], str]:
    """
    Stage A: Complete preflight validation before any GitHub object creation.
    
    Validates:
    - Target branch still points to plan.commit_sha.
    - Base tree SHA resolved from commit.
    - File count and aggregate size limits.
    - Valid relative paths and secret/excluded directory exclusions.
    - Disallow modification of lockfiles by LLM.
    - Existing vs new file operation semantics.
    - Original file content SHA-256 matches.
    - Edit anchors exist and are unambiguous.
    - Proposed content SHA-256 matches computed content.
    
    Returns: (base_tree_sha, prepared_contents, remediation_branch)
    """
    if not plan.repository_id or not plan.branch or not plan.commit_sha:
        raise ValueError("Remediation plan is missing GitHub repository, branch, or commit SHA context.")

    repo_id = plan.repository_id
    encoded_branch = quote(plan.branch.strip(), safe="/")

    # 1. Target branch must not have moved
    branch_ref_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/ref/heads/{encoded_branch}")
    current_branch_sha = branch_ref_data.get("object", {}).get("sha")

    if current_branch_sha != plan.commit_sha:
        storage.update_plan_status(plan.plan_id, "stale")
        raise ValueError(
            f"Pre-flight check failed: target branch '{plan.branch}' has moved from scanned commit "
            f"{plan.commit_sha[:7]} to {current_branch_sha[:7] if current_branch_sha else 'unknown'}. "
            f"The remediation plan is stale; please rescan the branch to generate a valid plan."
        )

    if not plan.proposed_changes:
        raise ValueError("Remediation plan contains no proposed changes.")

    if len(plan.proposed_changes) > MAX_REMEDIATION_FILES:
        raise ValueError(
            f"Remediation plan proposes changes to {len(plan.proposed_changes)} files, "
            f"exceeding the limit of {MAX_REMEDIATION_FILES} files."
        )

    # 2. Extract base tree SHA from the original commit (Git Trees API expects tree SHA, not commit SHA)
    commit_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/commits/{plan.commit_sha}")
    base_tree_sha = commit_data.get("tree", {}).get("sha")
    if not base_tree_sha:
        raise ValueError(f"Could not determine base tree SHA for commit {plan.commit_sha[:7]}.")

    # 3. Retrieve current repository tree
    tree_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/trees/{base_tree_sha}?recursive=1")
    existing_tree = {item["path"]: item for item in tree_data.get("tree", []) if item.get("type") == "blob"}

    prepared_contents: Dict[str, str] = {}
    seen_paths = set()
    aggregate_proposed_size = 0

    for change in plan.proposed_changes:
        norm_path = validate_and_normalize_path(change.file_path)

        if norm_path in seen_paths:
            raise ValueError(f"Duplicate/conflicting change proposed for file '{norm_path}'.")
        seen_paths.add(norm_path)

        # Forbid modification of lockfiles by LLM
        trusted_npm_lock = (
            norm_path == "package-lock.json" and change.edit_source == "npm_registry"
            and plan.validation_status == "VERIFIED" and change.operation == "update"
            and any(c.file_path == "package.json" for c in plan.proposed_changes)
        )
        if posixpath.basename(norm_path) in PROTECTED_REMEDIATION_FILES and not trusted_npm_lock:
            raise ValueError(f"Modification of lockfile '{norm_path}' by automated remediation is forbidden.")

        if change.operation not in ("create", "update"):
            raise ValueError(f"Unsupported remediation operation '{change.operation}' on '{norm_path}'.")

        if change.operation == "create":
            if norm_path in existing_tree:
                raise ValueError(f"Create operation collision: file '{norm_path}' already exists in source tree.")
            new_content = change.created_content or ""
            content_bytes = len(new_content.encode('utf-8'))
            if content_bytes > MAX_REMEDIATION_FILE_SIZE:
                raise ValueError(f"Created file '{norm_path}' ({content_bytes} bytes) exceeds limit of {MAX_REMEDIATION_FILE_SIZE} bytes.")
            if compute_sha256(new_content) != change.proposed_sha256:
                raise ValueError(f"Hash mismatch for created content in '{norm_path}'.")
            aggregate_proposed_size += content_bytes
            prepared_contents[norm_path] = new_content

        elif change.operation == "update":
            if norm_path not in existing_tree:
                raise ValueError(f"Update target '{norm_path}' does not exist in commit {plan.commit_sha[:7]}.")

            blob_sha = existing_tree[norm_path]["sha"]
            blob_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/git/blobs/{blob_sha}")
            raw_bytes = base64.b64decode(blob_data.get("content", ""))
            current_text = raw_bytes.decode('utf-8')
            current_hash = compute_sha256(current_text)

            if current_hash != change.original_sha256:
                raise ValueError(
                    f"File '{norm_path}' content hash mismatch (expected {change.original_sha256[:8]}, found {current_hash[:8]}). "
                    f"File may have been altered."
                )

            updated_text = current_text
            for edit in change.edits:
                if edit.old_text not in updated_text:
                    raise ValueError(f"Edit anchor not found in '{norm_path}'.")
                if updated_text.count(edit.old_text) > 1:
                    raise ValueError(f"Ambiguous edit anchor occurs multiple times in '{norm_path}'.")
                updated_text = updated_text.replace(edit.old_text, edit.new_text, 1)

            if compute_sha256(updated_text) != change.proposed_sha256:
                raise ValueError(f"Computed content hash for '{norm_path}' does not match proposed hash.")

            content_bytes = len(updated_text.encode('utf-8'))
            if content_bytes > MAX_REMEDIATION_FILE_SIZE:
                raise ValueError(f"Updated file '{norm_path}' ({content_bytes} bytes) exceeds limit of {MAX_REMEDIATION_FILE_SIZE} bytes.")

            aggregate_proposed_size += content_bytes
            prepared_contents[norm_path] = updated_text

    if aggregate_proposed_size > MAX_REMEDIATION_AGGREGATE_SIZE:
        raise ValueError(
            f"Remediation changes aggregate size ({aggregate_proposed_size} bytes) exceeds limit of {MAX_REMEDIATION_AGGREGATE_SIZE} bytes."
        )

    short_id = plan.plan_id[:8]
    remediation_branch = f"guardian/remediation/{short_id}"

    return (base_tree_sha, prepared_contents, remediation_branch)

def apply_remediation_pull_request(
    plan: RemediationPlan,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Applies an approved remediation plan to a GitHub repository:
    Stage A: Preflight validation (rejects entire plan before creating any objects).
    Stage B: Git object creation (blobs, tree with base_tree tree SHA, commit, branch, PR).
    """
    inst_id = _resolve_active_installation_id(session_id)
    repo_id = plan.repository_id

    # Stage A: Preflight Validation
    base_tree_sha, prepared_contents, remediation_branch = preflight_validate_remediation(inst_id, plan)

    # Stage B: GitHub Object Creation (only executes after all validations succeed)
    # 1. Create Git Blobs
    tree_items: List[Dict[str, Any]] = []
    for path, content in prepared_contents.items():
        blob_res = _call_installation_api(
            inst_id,
            f"/repositories/{repo_id}/git/blobs",
            method="POST",
            json_data={"content": content, "encoding": "utf-8"}
        )
        tree_items.append({
            "path": path,
            "mode": "100644",
            "type": "blob",
            "sha": blob_res["sha"]
        })

    # 2. Create Atomic Git Tree using actual base tree SHA (preserves unchanged files)
    new_tree_res = _call_installation_api(
        inst_id,
        f"/repositories/{repo_id}/git/trees",
        method="POST",
        json_data={
            "base_tree": base_tree_sha,
            "tree": tree_items
        }
    )
    new_tree_sha = new_tree_res["sha"]

    # 3. Create Commit
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

    # 4. Create remediation branch
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

    # 5. Create Pull Request
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

    # 6. Update plan in SQLite
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

def close_remediation_pull_request(
    plan: RemediationPlan,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Safely closes a Guardian Autopilot pull request on GitHub with correct lifecycle semantics.
    
    Distinguishes:
    - Merged PR: closing does not revert merged code; preserves 'applied' status and explains revert steps.
    - Unmerged PR: closing sets status to 'pr_closed' (not 'reverted').
    """
    if not plan.repository_id or not plan.pr_number:
        raise ValueError("Remediation plan has no associated GitHub pull request.")

    inst_id = _resolve_active_installation_id(session_id)
    repo_id = plan.repository_id

    # Inspect current PR state on GitHub
    pr_data = _call_installation_api(inst_id, f"/repositories/{repo_id}/pulls/{plan.pr_number}")
    is_merged = pr_data.get("merged", False)
    current_state = pr_data.get("state", "open")

    if is_merged:
        plan.pr_state = "merged"
        storage.save_plan(plan)
        return {
            "plan_id": plan.plan_id,
            "pr_number": plan.pr_number,
            "pr_state": "merged",
            "status": plan.status,
            "message": (
                f"Pull request #{plan.pr_number} was already merged into '{plan.branch}'. "
                "Closing the PR does not undo merged changes. "
                "A separate Git revert commit is required to reverse merged changes."
            )
        }

    # Close unmerged PR on GitHub if still open
    if current_state != "closed":
        _call_installation_api(
            inst_id,
            f"/repositories/{repo_id}/pulls/{plan.pr_number}",
            method="PATCH",
            json_data={"state": "closed"}
        )

    plan.status = "pr_closed"
    plan.pr_state = "closed"
    storage.save_plan(plan)

    return {
        "plan_id": plan.plan_id,
        "pr_number": plan.pr_number,
        "pr_state": "closed",
        "status": "pr_closed",
        "message": f"Pull request #{plan.pr_number} was closed without merging. Changes were not applied to '{plan.branch}'."
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
