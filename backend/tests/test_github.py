"""Comprehensive unit and integration tests for Guardian 4.0 GitHub integration."""
import base64
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from backend.guardian.github import (
    GitHubConfig,
    create_install_state,
    verify_and_consume_state,
    get_installation_access_token,
    list_repositories,
    list_branches,
    get_branch_commit,
    retrieve_repository_snapshot,
    apply_remediation_pull_request,
    close_remediation_pull_request,
    _token_cache,
    _state_store,
)
from backend.guardian.main import app
from backend.guardian.models import Report, GitHubMetadata
from backend.guardian.projects import project_manager, compute_sha256
from backend.guardian.remediation_models import (
    RemediationPlan,
    ProposedFileChange,
    TextEdit
)
from backend.guardian import storage, github

# Generate RSA key for testing
_TEST_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_KEY_PEM = _TEST_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

@pytest.fixture
def test_client():
    return TestClient(app)

@pytest.fixture
def github_env(monkeypatch):
    """Sets up simulated GitHub App configuration."""
    monkeypatch.setenv("GITHUB_APP_ID", "123456")
    monkeypatch.setenv("GITHUB_APP_CLIENT_ID", "Iv1.clientid123")
    monkeypatch.setenv("GITHUB_APP_CLIENT_SECRET", "client_secret_xyz")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", _TEST_KEY_PEM)
    monkeypatch.setenv("GITHUB_APP_INSTALL_URL", "https://github.com/apps/guardian-test/installations/new")
    monkeypatch.setenv("GITHUB_API_BASE", "https://api.github.com")
    _token_cache.clear()
    _state_store.clear()
    yield

# ==========================================
# 1. AUTHENTICATION & CONNECTION TESTS
# ==========================================

def test_github_status_unconfigured(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    client = TestClient(app)
    resp = client.get("/api/github/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["configured"] is False
    assert data["connected"] is False

def test_state_lifecycle():
    state = create_install_state()
    assert len(state) >= 32
    # State is valid once
    assert verify_and_consume_state(state) is True
    # Cannot be replayed
    assert verify_and_consume_state(state) is False

def test_expired_state():
    state = create_install_state()
    # Artificially expire the state
    _state_store[state] = time.time() - 700
    assert verify_and_consume_state(state) is False

def test_connect_flow(github_env, test_client):
    resp = test_client.post("/api/github/connect")
    assert resp.status_code == 200
    data = resp.json()
    assert "install_url" in data
    assert "state=" in data["install_url"]
    assert "state" in data
    assert data["state"] in _state_store

def test_installation_callback_valid(github_env, test_client):
    sess = github.session_manager.create_session()
    state = create_install_state(session_id=sess)
    mock_inst = {
        "id": 999111,
        "account": {
            "id": 444,
            "login": "octocat-org",
            "type": "Organization",
            "avatar_url": "https://avatars.githubusercontent.com/u/444"
        },
        "repository_selection": "all",
        "created_at": "2026-01-01T00:00:00Z"
    }

    with patch("backend.guardian.github._call_app_api", return_value=mock_inst):
        resp = test_client.get(
            f"/api/github/callback?installation_id=999111&state={state}",
            headers={"x-guardian-session": sess},
            follow_redirects=False
        )
        assert resp.status_code == 302
        assert resp.headers["location"] == "/?github=connected"
        assert resp.cookies.get("guardian_session") == sess

        # Verify active installation persisted and authorized for session
        active = storage.get_active_github_installation()
        assert active is not None
        assert active["id"] == 999111
        assert active["account_login"] == "octocat-org"
        assert github.session_manager.is_installation_authorized(sess, 999111) is True

def test_installation_callback_invalid_state(github_env, test_client):
    sess = github.session_manager.create_session()
    resp = test_client.get(
        "/api/github/callback?installation_id=999111&state=bogus_state",
        headers={"x-guardian-session": sess}
    )
    assert resp.status_code == 400
    assert "Invalid or expired OAuth state" in resp.json()["detail"]

def test_installation_callback_without_state(github_env, test_client):
    """Browser-initiated callback without state must be rejected."""
    sess = github.session_manager.create_session()
    resp = test_client.get(
        "/api/github/callback?installation_id=777222&setup_action=install",
        headers={"x-guardian-session": sess},
        follow_redirects=False
    )
    assert resp.status_code == 400
    assert "Missing OAuth state parameter" in resp.json()["detail"]

def test_github_sync_endpoint(github_env, test_client):
    """POST /api/github/sync discovers and persists globally without implicitly authorizing the session."""
    mock_installations = [
        {
            "id": 333444,
            "account": {
                "id": 888,
                "login": "synced-user",
                "type": "User",
                "avatar_url": "https://avatars.githubusercontent.com/u/888"
            },
            "repository_selection": "all",
            "created_at": "2026-10-31T12:00:00Z",
            "updated_at": "2026-10-31T12:30:00Z"
        }
    ]
    with patch("backend.guardian.github._call_app_api", return_value=mock_installations):
        # Direct CLI/internal sync activates globally
        res = github.sync_installations(session_id=None)
        assert res["connected"] is True
        assert res["installation"]["id"] == 333444
        assert res["installation"]["account_login"] == "synced-user"

        active = storage.get_active_github_installation()
        assert active is not None
        assert active["id"] == 333444

        # Browser HTTP sync persists metadata but never expands the session's authorization set
        resp = test_client.post("/api/github/sync")
        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is False
        assert data["installation"] is None

def test_status_auto_discovery(github_env, test_client):
    """Direct get_connection_status discovers and activates; HTTP endpoint creates isolated session without implicit authorization."""
    with storage.connection() as db:
        db.execute("DELETE FROM github_installations")

    mock_installations = [
        {
            "id": 444555,
            "account": {
                "id": 999,
                "login": "discovered-user",
                "type": "User",
                "avatar_url": "https://avatars.githubusercontent.com/u/999"
            },
            "repository_selection": "selected",
            "created_at": "2026-10-31T12:00:00Z",
            "updated_at": "2026-10-31T12:45:00Z"
        }
    ]
    with patch("backend.guardian.github._call_app_api", return_value=mock_installations):
        # Direct CLI/internal invocation without session discovers and connects
        res = github.get_connection_status(session_id=None)
        assert res["connected"] is True
        assert res["installation"]["id"] == 444555
        assert res["installation"]["account_login"] == "discovered-user"

        # HTTP request without prior callback establishes fresh session and does NOT implicitly authorize
        resp = test_client.get("/api/github/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is False

def test_disconnect(github_env, test_client):
    storage.save_github_installation({
        "id": 999111,
        "account_login": "octocat-org",
        "account_type": "Organization"
    })
    sess = github.session_manager.create_session()
    github.session_manager.authorize_installation(sess, 999111)
    assert storage.get_active_github_installation() is not None

    resp = test_client.post("/api/github/disconnect", headers={"x-guardian-session": sess})
    assert resp.status_code == 200
    assert resp.json()["status"] == "disconnected"
    assert github.session_manager.is_installation_authorized(sess, 999111) is False

def test_token_caching_and_refresh(github_env):
    storage.save_github_installation({
        "id": 888,
        "account_login": "test-user",
        "account_type": "User"
    })

    call_count = 0
    def mock_app_api(endpoint, method="GET", json_data=None):
        nonlocal call_count
        call_count += 1
        return {
            "token": f"ghs_token_{call_count}",
            "expires_at": "2030-01-01T00:00:00Z",
            "permissions": {"contents": "write", "pull_requests": "write", "metadata": "read"}
        }

    with patch("backend.guardian.github._call_app_api", side_effect=mock_app_api):
        t1 = get_installation_access_token(888)
        assert t1 == "ghs_token_1"
        assert call_count == 1

        # Second call within validity window should hit memory cache
        t2 = get_installation_access_token(888)
        assert t2 == "ghs_token_1"
        assert call_count == 1

        # Expire cached token manually
        _token_cache[888] = ("ghs_token_1", time.time() - 10)
        t3 = get_installation_access_token(888)
        assert t3 == "ghs_token_2"
        assert call_count == 2

# ==========================================
# 2. REPOSITORY & BRANCH DISCOVERY TESTS
# ==========================================

def test_list_repositories_and_search(github_env, test_client):
    storage.save_github_installation({
        "id": 100,
        "account_login": "acme-corp",
        "account_type": "Organization"
    })
    sess = github.session_manager.create_session()
    github.session_manager.authorize_installation(sess, 100)

    # Unauthenticated request without session must be rejected with 401
    assert test_client.get("/api/github/repositories").status_code == 401

    repos_payload = {
        "repositories": [
            {
                "id": 1,
                "name": "backend-service",
                "full_name": "acme-corp/backend-service",
                "owner": {"login": "acme-corp", "avatar_url": "https://avatar.png"},
                "private": True,
                "html_url": "https://github.com/acme-corp/backend-service",
                "description": "Core backend API",
                "default_branch": "main",
                "permissions": {"push": True}
            },
            {
                "id": 2,
                "name": "frontend-web",
                "full_name": "acme-corp/frontend-web",
                "owner": {"login": "acme-corp", "avatar_url": "https://avatar.png"},
                "private": False,
                "html_url": "https://github.com/acme-corp/frontend-web",
                "description": "Public web app",
                "default_branch": "master",
                "permissions": {"push": True}
            }
        ]
    }

    with patch("backend.guardian.github._call_installation_api", return_value=repos_payload):
        # List all
        resp = test_client.get("/api/github/repositories", headers={"x-guardian-session": sess})
        assert resp.status_code == 200
        repos = resp.json()
        assert len(repos) == 2
        assert repos[0]["name"] == "backend-service"
        assert repos[0]["private"] is True
        assert repos[1]["name"] == "frontend-web"
        assert repos[1]["private"] is False

        # Search query
        resp_q = test_client.get("/api/github/repositories?q=frontend", headers={"x-guardian-session": sess})
        assert resp_q.status_code == 200
        filtered = resp_q.json()
        assert len(filtered) == 1
        assert filtered[0]["name"] == "frontend-web"

def test_list_branches(github_env, test_client):
    storage.save_github_installation({"id": 100, "account_login": "acme", "account_type": "User"})
    sess = github.session_manager.create_session()
    github.session_manager.authorize_installation(sess, 100)

    # Unauthenticated request without session must be rejected with 401
    assert test_client.get("/api/github/repositories/1/branches").status_code == 401

    repo_meta = {
        "id": 1,
        "name": "repo1",
        "full_name": "acme/repo1",
        "owner": {"login": "acme"},
        "default_branch": "main"
    }
    branches_payload = [
        {"name": "feature-x", "commit": {"sha": "sha_feat_x"}},
        {"name": "main", "commit": {"sha": "sha_main"}},
        {"name": "hotfix", "commit": {"sha": "sha_hotfix"}},
    ]

    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if "branches" in endpoint:
            return branches_payload
        return repo_meta

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        resp = test_client.get("/api/github/repositories/1/branches", headers={"x-guardian-session": sess})
        assert resp.status_code == 200
        branches = resp.json()
        assert len(branches) == 3
        # Default branch must be sorted to the top
        assert branches[0]["name"] == "main"
        assert branches[0]["is_default"] is True
        assert branches[1]["name"] == "feature-x"
        assert branches[1]["is_default"] is False

# ==========================================
# 3. BOUNDED REPOSITORY INGESTION TESTS
# ==========================================

def test_retrieve_repository_snapshot_success(github_env):
    storage.save_github_installation({"id": 100, "account_login": "acme", "account_type": "User"})

    pkg_json_content = json.dumps({"name": "secure-app", "version": "1.0.0", "dependencies": {"express": "^4.19.0"}})
    index_js_content = "const express = require('express');\nconst app = express();\napp.listen(3000);"

    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if endpoint == "/repositories/1":
            return {"id": 1, "name": "secure-app", "full_name": "acme/secure-app", "owner": {"login": "acme"}, "default_branch": "main", "html_url": "https://github.com/acme/secure-app"}
        if endpoint == "/repositories/1/commits/main":
            return {"sha": "c0ffee1234567890", "commit": {"message": "Initial commit", "author": {"name": "Dev", "date": "2026-10-31"}}}
        if "git/trees" in endpoint:
            return {
                "sha": "tree_root",
                "truncated": False,
                "tree": [
                    {"path": "package.json", "type": "blob", "sha": "blob_pkg", "size": len(pkg_json_content)},
                    {"path": "src/index.js", "type": "blob", "sha": "blob_index", "size": len(index_js_content)},
                    {"path": ".env", "type": "blob", "sha": "blob_env", "size": 50},  # Must be excluded!
                    {"path": ".git/config", "type": "blob", "sha": "blob_git", "size": 100},  # Excluded!
                    {"path": "node_modules/foo/index.js", "type": "blob", "sha": "blob_dep", "size": 200},  # Excluded!
                    {"path": "image.png", "type": "blob", "sha": "blob_img", "size": 500},  # Excluded!
                ]
            }
        if "git/blobs/blob_pkg" in endpoint:
            return {"content": base64.b64encode(pkg_json_content.encode('utf-8')).decode('utf-8'), "encoding": "base64"}
        if "git/blobs/blob_index" in endpoint:
            return {"content": base64.b64encode(index_js_content.encode('utf-8')).decode('utf-8'), "encoding": "base64"}
        raise ValueError(f"Unexpected endpoint: {endpoint}")

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        full_name, files, meta, warnings = retrieve_repository_snapshot(1, "main")
        assert full_name == "acme/secure-app"
        assert len(files) == 2
        assert "package.json" in files
        assert "src/index.js" in files
        assert ".env" not in files
        assert meta.commit_sha == "c0ffee1234567890"
        assert meta.branch == "main"
        assert meta.source_type == "github"

def test_ingestion_limits_truncated_tree(github_env):
    storage.save_github_installation({"id": 100, "account_login": "acme", "account_type": "User"})

    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if endpoint == "/repositories/1":
            return {"id": 1, "name": "app", "full_name": "acme/app", "owner": {"login": "acme"}, "default_branch": "main", "html_url": "https://github.com/acme/app"}
        if endpoint == "/repositories/1/commits/main":
            return {"sha": "sha123", "commit": {"message": "Test"}}
        if "git/trees" in endpoint:
            return {
                "sha": "tree_root",
                "truncated": True,  # Truncated!
                "tree": [
                    {"path": "package.json", "type": "blob", "sha": "blob_pkg", "size": 20}
                ]
            }
        if "git/blobs" in endpoint:
            return {"content": base64.b64encode(b"{}").decode('utf-8'), "encoding": "base64"}
        raise ValueError(endpoint)

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        _, _, _, warnings = retrieve_repository_snapshot(1, "main")
        assert any("truncated" in w for w in warnings)

def test_ingestion_oversized_file_limit(github_env):
    storage.save_github_installation({"id": 100, "account_login": "acme", "account_type": "User"})

    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if endpoint == "/repositories/1":
            return {"id": 1, "name": "app", "full_name": "acme/app", "owner": {"login": "acme"}, "default_branch": "main", "html_url": "https://github.com/acme/app"}
        if endpoint == "/repositories/1/commits/main":
            return {"sha": "sha123", "commit": {"message": "Test"}}
        if "git/trees" in endpoint:
            return {
                "sha": "tree_root",
                "truncated": False,
                "tree": [
                    {"path": "package.json", "type": "blob", "sha": "blob_pkg", "size": 20},
                    {"path": "giant_bundle.js", "type": "blob", "sha": "blob_giant", "size": 2_000_000}  # > 1 MB
                ]
            }
        if "git/blobs/blob_pkg" in endpoint:
            return {"content": base64.b64encode(b"{}").decode('utf-8'), "encoding": "base64"}
        raise ValueError(endpoint)

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        _, files, _, warnings = retrieve_repository_snapshot(1, "main")
        assert "package.json" in files
        assert "giant_bundle.js" not in files
        assert any("exceeds 1 MB" in w for w in warnings)

# ==========================================
# 4. SCAN INTEGRATION & PERSISTENCE TESTS
# ==========================================

def test_scan_github_repository_endpoint(github_env, test_client):
    storage.save_github_installation({"id": 100, "account_login": "acme", "account_type": "User"})
    sess = github.session_manager.create_session()
    github.session_manager.authorize_installation(sess, 100)

    # Unauthenticated request without session is rejected with 401
    assert test_client.post("/api/scans/github", json={"repository_id": 42, "branch": "main"}).status_code == 401

    pkg_json = json.dumps({"name": "demo-scan", "version": "1.0.0"})
    
    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if endpoint == "/repositories/42":
            return {"id": 42, "name": "demo-scan", "full_name": "acme/demo-scan", "owner": {"login": "acme"}, "default_branch": "main", "html_url": "https://github.com/acme/demo-scan"}
        if endpoint == "/repositories/42/commits/main":
            return {"sha": "abcdef1234567890", "commit": {"message": "Init"}}
        if "git/trees" in endpoint:
            return {
                "sha": "tree_root",
                "truncated": False,
                "tree": [
                    {"path": "package.json", "type": "blob", "sha": "blob_pkg", "size": len(pkg_json)}
                ]
            }
        if "git/blobs" in endpoint:
            return {"content": base64.b64encode(pkg_json.encode('utf-8')).decode('utf-8'), "encoding": "base64"}
        raise ValueError(endpoint)

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        resp = test_client.post("/api/scans/github", json={"repository_id": 42, "branch": "main"}, headers={"x-guardian-session": sess})
        assert resp.status_code == 202
        job_id = resp.json()["id"]

        # Wait for scan job to finish
        for _ in range(30):
            job_resp = test_client.get(f"/api/jobs/{job_id}")
            if job_resp.json()["status"] in ("complete", "failed"):
                break
            time.sleep(0.1)

        assert job_resp.json()["status"] == "complete"

        # Check saved report
        report = storage.get(job_id)
        assert report is not None
        assert report.classification == "real"
        assert report.project_id == "github:42"
        assert report.source_metadata is not None
        assert report.source_metadata.repository_id == 42
        assert report.source_metadata.branch == "main"
        assert report.source_metadata.commit_sha == "abcdef1234567890"

# ==========================================
# 5. AUTOPILOT REMEDIATION TESTS
# ==========================================

def test_apply_remediation_pull_request_success(github_env):
    storage.save_github_installation({"id": 100, "account_login": "acme", "account_type": "User"})

    orig_pkg = json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"vulnerable-pkg": "1.0.0"}}, indent=2)
    proposed_pkg = json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"vulnerable-pkg": "2.0.0"}}, indent=2)

    plan = RemediationPlan(
        plan_id="plan_abc12345",
        scan_id="scan_1",
        title="Upgrade vulnerable-pkg to 2.0.0",
        summary="Fixes remote code execution vulnerability",
        priority="high",
        expected_outcome="Remediates known vulnerability",
        findings_addressed=["finding_1"],
        proposed_changes=[
            ProposedFileChange(
                file_path="package.json",
                operation="update",
                original_sha256=compute_sha256(orig_pkg),
                proposed_sha256=compute_sha256(proposed_pkg),
                edits=[TextEdit(old_text='"vulnerable-pkg": "1.0.0"', new_text='"vulnerable-pkg": "2.0.0"')],
                rationale="Upgrade dependency",
                finding_ids=["finding_1"],
                expected_result="Upgraded"
            )
        ],
        repository_id=99,
        branch="main",
        commit_sha="commit_sha_base_111",
        status="approved",
        created_at="2026-10-31T12:00:00Z"
    )
    storage.save_plan(plan)

    created_tree_payload = None
    created_pr_payload = None

    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        nonlocal created_tree_payload, created_pr_payload
        if endpoint == "/repositories/99":
            return {"id": 99, "name": "app", "full_name": "acme/app", "owner": {"login": "acme"}, "default_branch": "main"}
        if endpoint == "/repositories/99/git/ref/heads/main":
            # Target branch still at the expected commit SHA
            return {"object": {"sha": "commit_sha_base_111"}}
        if endpoint == "/repositories/99/git/commits/commit_sha_base_111":
            return {"sha": "commit_sha_base_111", "tree": {"sha": "tree_sha_base_111"}}
        if "git/trees/tree_sha_base_111" in endpoint:
            return {"tree": [{"path": "package.json", "type": "blob", "sha": "blob_pkg_orig"}]}
        if "git/blobs/blob_pkg_orig" in endpoint:
            return {"content": base64.b64encode(orig_pkg.encode('utf-8')).decode('utf-8'), "encoding": "base64"}
        if endpoint == "/repositories/99/git/blobs" and method == "POST":
            return {"sha": "blob_new_pkg_sha"}
        if endpoint == "/repositories/99/git/trees" and method == "POST":
            created_tree_payload = json_data
            return {"sha": "tree_new_sha"}
        if endpoint == "/repositories/99/git/commits" and method == "POST":
            return {"sha": "commit_new_remediation_sha"}
        if endpoint == "/repositories/99/git/refs" and method == "POST":
            return {"ref": json_data["ref"]}
        if endpoint == "/repositories/99/pulls" and method == "POST":
            created_pr_payload = json_data
            return {"number": 42, "html_url": "https://github.com/acme/app/pull/42", "state": "open"}
        raise ValueError(f"Unexpected endpoint: {endpoint} {method}")

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        res = apply_remediation_pull_request(plan)
        assert res["pr_number"] == 42
        assert res["pr_url"] == "https://github.com/acme/app/pull/42"
        assert res["status"] == "applied"
        assert res["remediation_branch"] == "guardian/remediation/plan_abc"

        # Verify atomic Git tree payload was constructed using the commit's tree SHA (not commit SHA)
        assert created_tree_payload["base_tree"] == "tree_sha_base_111"
        assert created_tree_payload["tree"][0]["path"] == "package.json"
        assert created_tree_payload["tree"][0]["sha"] == "blob_new_pkg_sha"

        # Verify PR metadata
        assert created_pr_payload["head"] == "guardian/remediation/plan_abc"
        assert created_pr_payload["base"] == "main"
        assert "Guardian Autopilot" in created_pr_payload["title"]

        # Verify plan updated in storage
        updated_plan = storage.get_plan("plan_abc12345")
        assert updated_plan.status == "applied"
        assert updated_plan.pr_number == 42
        assert updated_plan.pr_url == "https://github.com/acme/app/pull/42"

def test_remediation_branch_moved_preflight_fails(github_env):
    storage.save_github_installation({"id": 100, "account_login": "acme", "account_type": "User"})

    plan = RemediationPlan(
        plan_id="plan_stale",
        scan_id="scan_1",
        title="Fix issue",
        summary="Summary",
        expected_outcome="Outcome",
        repository_id=99,
        branch="main",
        commit_sha="commit_old_111",
        status="approved",
        created_at="2026-10-31T12:00:00Z"
    )
    storage.save_plan(plan)

    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if endpoint == "/repositories/99":
            return {"id": 99, "name": "app", "full_name": "acme/app", "owner": {"login": "acme"}, "default_branch": "main"}
        if endpoint == "/repositories/99/git/ref/heads/main":
            # Branch has moved to a new commit!
            return {"object": {"sha": "commit_NEW_222"}}
        raise ValueError(endpoint)

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        with pytest.raises(ValueError) as exc:
            apply_remediation_pull_request(plan)
        assert "Pre-flight check failed" in str(exc.value)
        assert "target branch 'main' has moved" in str(exc.value)

        # Plan must be marked stale in storage
        updated_plan = storage.get_plan("plan_stale")
        assert updated_plan.status == "stale"

def test_close_remediation_pull_request(github_env, test_client):
    storage.save_github_installation({"id": 100, "account_login": "acme", "account_type": "User"})
    sess = github.session_manager.create_session()
    github.session_manager.authorize_installation(sess, 100)

    # Unauthenticated request without session is rejected with 401
    assert test_client.post("/api/remediation/plans/plan_to_close/close-github-pr").status_code == 401

    plan = RemediationPlan(
        plan_id="plan_to_close",
        scan_id="scan_1",
        title="Fix issue",
        summary="Summary",
        expected_outcome="Outcome",
        repository_id=99,
        branch="main",
        commit_sha="commit_111",
        pr_number=55,
        pr_url="https://github.com/acme/app/pull/55",
        status="applied",
        created_at="2026-10-31T12:00:00Z"
    )
    storage.save_plan(plan)

    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if endpoint == "/repositories/99/pulls/55" and method == "GET":
            return {"number": 55, "state": "open", "merged": False}
        if endpoint == "/repositories/99/pulls/55" and method == "PATCH":
            return {"number": 55, "state": "closed", "merged": False}
        raise ValueError(endpoint)

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        resp = test_client.post("/api/remediation/plans/plan_to_close/close-github-pr", headers={"x-guardian-session": sess})
        assert resp.status_code == 200
        data = resp.json()
        assert data["pr_state"] == "closed"
        assert data["status"] == "pr_closed"

        # Plan in storage updated
        saved = storage.get_plan("plan_to_close")
        assert saved.status == "pr_closed"
        assert saved.pr_state == "closed"

# ==========================================
# 4. GUARDIAN 4.1 REGRESSION & RELIABILITY TESTS
# ==========================================

def test_multiple_installations_preservation_and_explicit_selection(github_env, test_client):
    """Part 2.1: Preserve multiple installations without silent switching."""
    inst1 = {
        "id": 1001,
        "account_id": 101,
        "account_login": "alice-org",
        "account_type": "Organization",
        "avatar_url": "https://avatar/alice.png",
        "repository_selection": "all"
    }
    inst2 = {
        "id": 1002,
        "account_id": 102,
        "account_login": "bob-team",
        "account_type": "User",
        "avatar_url": "https://avatar/bob.png",
        "repository_selection": "selected"
    }
    storage.save_github_installation(inst1, make_active=True)
    storage.save_github_installation(inst2, make_active=False)

    sess = github.session_manager.create_session()
    github.session_manager.authorize_installation(sess, 1001)
    github.session_manager.authorize_installation(sess, 1002)

    # Active installation must be inst1 (alice-org)
    active = storage.get_active_github_installation()
    assert active["id"] == 1001
    assert active["account_login"] == "alice-org"

    # Synchronizing multiple installations must preserve Alice as active without silent switch
    mock_gh_installations = [
        {"id": 1001, "account": {"id": 101, "login": "alice-org", "type": "Organization"}, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"},
        {"id": 1002, "account": {"id": 102, "login": "bob-team", "type": "User"}, "created_at": "2026-02-01T00:00:00Z", "updated_at": "2026-10-31T20:00:00Z"}
    ]
    with patch("backend.guardian.github._call_app_api", return_value=mock_gh_installations):
        sync_resp = test_client.post("/api/github/sync", headers={"x-guardian-session": sess})
        assert sync_resp.status_code == 200
        # Active account is still alice-org
        active_after_sync = storage.get_active_github_installation()
        assert active_after_sync["id"] == 1001

        # Listing installations exposes both accounts
        list_resp = test_client.get("/api/github/installations", headers={"x-guardian-session": sess})
        assert list_resp.status_code == 200
        inst_list = list_resp.json()
        assert len(inst_list) == 2
        logins = {i["account_login"] for i in inst_list}
        assert "alice-org" in logins
        assert "bob-team" in logins

        # Explicitly switch account to bob-team
        sel_resp = test_client.post("/api/github/installations/1002/select", headers={"x-guardian-session": sess})
        assert sel_resp.status_code == 200
        assert sel_resp.json()["id"] == 1002

        # Active account is now bob-team
        active_now = storage.get_active_github_installation()
        assert active_now["id"] == 1002
        assert active_now["account_login"] == "bob-team"

def test_disconnect_selected_installation_preserves_others(github_env, test_client):
    """Part 2.4: Disconnecting one installation preserves other connected accounts."""
    storage.save_github_installation({"id": 2001, "account_login": "user-one", "account_type": "User"}, make_active=True)
    storage.save_github_installation({"id": 2002, "account_login": "user-two", "account_type": "User"}, make_active=False)

    sess = github.session_manager.create_session()
    github.session_manager.authorize_installation(sess, 2001)
    github.session_manager.authorize_installation(sess, 2002)

    # Disconnect user-two
    resp = test_client.post("/api/github/installations/2002/disconnect", headers={"x-guardian-session": sess})
    assert resp.status_code == 200
    assert resp.json()["installation_id"] == 2002

    # user-one is still active and preserved
    assert github.session_manager.is_installation_authorized(sess, 2001) is True
    assert github.session_manager.is_installation_authorized(sess, 2002) is False

    # Disconnect target user-one
    resp2 = test_client.post("/api/github/installations/2001/disconnect", headers={"x-guardian-session": sess})
    assert resp2.status_code == 200
    assert github.session_manager.is_installation_authorized(sess, 2001) is False

def test_oauth_state_validation_and_session_binding(github_env):
    """Part 2.3: OAuth state requires non-empty, unexpired, single-use, session-bound tokens."""
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()

    # Missing state fails
    assert verify_and_consume_state(None) is False
    assert verify_and_consume_state("") is False

    # Mismatched session fails
    state_mismatch = create_install_state(session_id=sess_A)
    assert verify_and_consume_state(state_mismatch, session_id=sess_B) is False

    # Correct session succeeds and consumes the token
    state_valid = create_install_state(session_id=sess_A)
    assert verify_and_consume_state(state_valid, session_id=sess_A) is True

    # Replay attempt fails (already consumed)
    assert verify_and_consume_state(state_valid, session_id=sess_A) is False

def test_branch_name_encoding(github_env):
    """Part 3.2: Verify Git ref and branch encoding preserves slash semantics while encoding special chars."""
    storage.save_github_installation({"id": 500, "account_login": "repo-owner", "account_type": "User"})

    requested_urls = []
    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        requested_urls.append(endpoint)
        return {
            "sha": "commit_sha_123",
            "commit": {"message": "commit msg", "author": {"name": "Dev", "date": "2026-10-31"}}
        }

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        # Slash-separated branch
        get_branch_commit(99, "feature/auth")
        assert requested_urls[-1] == "/repositories/99/commits/feature/auth"

        # Release branch
        get_branch_commit(99, "release/v2.1")
        assert requested_urls[-1] == "/repositories/99/commits/release/v2.1"

        # Branch with spaces
        get_branch_commit(99, "bugfix/login redirect")
        assert requested_urls[-1] == "/repositories/99/commits/bugfix/login%20redirect"

def test_remediation_preflight_lockfile_protection(github_env):
    """Part 4.1 & AGENTS.md: Automated remediation is strictly forbidden from modifying lockfiles."""
    storage.save_github_installation({"id": 500, "account_login": "repo-owner", "account_type": "User"})

    plan = RemediationPlan(
        plan_id="plan_lockfile_tamper",
        scan_id="scan_1",
        title="Tamper lockfile",
        summary="Should be rejected",
        expected_outcome="Reject",
        repository_id=99,
        branch="main",
        commit_sha="commit_sha_111",
        status="approved",
        created_at="2026-10-31T12:00:00Z",
        proposed_changes=[
            ProposedFileChange(
                file_path="package-lock.json",
                operation="update",
                original_sha256="abc",
                proposed_sha256="def",
                rationale="Should fail",
                finding_ids=["f1"],
                expected_result="Fail"
            )
        ]
    )

    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if endpoint == "/repositories/99/git/ref/heads/main":
            return {"object": {"sha": "commit_sha_111"}}
        if endpoint == "/repositories/99/git/commits/commit_sha_111":
            return {"sha": "commit_sha_111", "tree": {"sha": "tree_sha_111"}}
        if "git/trees/tree_sha_111" in endpoint:
            return {"tree": [{"path": "package-lock.json", "type": "blob", "sha": "blob_lock"}]}
        raise ValueError(endpoint)

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        with pytest.raises(ValueError) as exc:
            apply_remediation_pull_request(plan)
        assert "forbidden" in str(exc.value).lower()
        assert "package-lock.json" in str(exc.value)

def test_close_merged_pull_request_preserves_applied(github_env, test_client):
    """Part 4.4: Closing a merged PR must preserve 'applied' status and explain revert guidance."""
    storage.save_github_installation({"id": 500, "account_login": "repo-owner", "account_type": "User"})

    plan = RemediationPlan(
        plan_id="plan_merged_pr",
        scan_id="scan_1",
        title="Merged plan",
        summary="Already merged into base",
        expected_outcome="Applied",
        repository_id=99,
        branch="main",
        commit_sha="commit_111",
        pr_number=88,
        pr_url="https://github.com/acme/app/pull/88",
        status="applied",
        created_at="2026-10-31T12:00:00Z"
    )
    storage.save_plan(plan)

    sess = github.session_manager.create_session()
    github.session_manager.authorize_installation(sess, 500)

    # GitHub reports PR as merged
    def mock_install_api(inst_id, endpoint, method="GET", json_data=None):
        if endpoint == "/repositories/99/pulls/88" and method == "GET":
            return {"number": 88, "state": "closed", "merged": True}
        raise ValueError(endpoint)

    with patch("backend.guardian.github._call_installation_api", side_effect=mock_install_api):
        resp = test_client.post("/api/remediation/plans/plan_merged_pr/close-github-pr", headers={"x-guardian-session": sess})
        assert resp.status_code == 200
        data = resp.json()
        assert data["pr_state"] == "merged"
        assert data["status"] == "applied"
        assert "already merged" in data["message"]
        assert "separate Git revert commit is required" in data["message"]

        # Ensure plan in storage is NOT marked 'reverted'
        saved = storage.get_plan("plan_merged_pr")
        assert saved.status == "applied"
        assert saved.pr_state == "merged"

# ==========================================
# 5. GUARDIAN 4.2 SESSION ISOLATION & REGRESSION TESTS
# ==========================================

def test_session_isolation_and_authorization_boundary(github_env, test_client):
    """Guardian 4.2 Section 2: Session isolation guarantees that Session B cannot
    access or select installations authorized strictly for Session A.
    """
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()

    # Save an installation
    storage.save_github_installation({
        "id": 7771,
        "account_login": "org-alpha",
        "account_type": "Organization"
    }, make_active=False)

    # Authorize 7771 strictly for Session A
    github.session_manager.authorize_installation(sess_A, 7771)
    assert github.session_manager.is_installation_authorized(sess_A, 7771) is True
    assert github.session_manager.is_installation_authorized(sess_B, 7771) is False

    # Session A lists installations: sees 7771
    resp_A = test_client.get("/api/github/installations", headers={"x-guardian-session": sess_A})
    assert resp_A.status_code == 200
    insts_A = resp_A.json()
    assert any(i["id"] == 7771 for i in insts_A)

    # Session B lists installations: sees nothing authorized for B
    resp_B = test_client.get("/api/github/installations", headers={"x-guardian-session": sess_B})
    assert resp_B.status_code == 200
    insts_B = resp_B.json()
    assert not any(i["id"] == 7771 for i in insts_B)

    # Session B attempts to select 7771: rejected
    sel_B = test_client.post("/api/github/installations/7771/select", headers={"x-guardian-session": sess_B})
    assert sel_B.status_code in (400, 403, 404)

    # Session B attempts to list repositories: rejected with 400 or 403
    repo_B = test_client.get("/api/github/repositories", headers={"x-guardian-session": sess_B})
    assert repo_B.status_code in (400, 403)

    # Session A selects 7771 and lists repositories: succeeds
    with patch("backend.guardian.github._call_installation_api", return_value={"repositories": [{"id": 1, "name": "r1", "full_name": "org-alpha/r1"}]}):
        repo_A = test_client.get("/api/github/repositories", headers={"x-guardian-session": sess_A})
        assert repo_A.status_code == 200

def test_session_disconnect_isolation(github_env, test_client):
    """Guardian 4.2 Section 2.C: Disconnecting in Session A removes it from Session A's
    authorized/selected set, but does not delete the installation globally from SQLite.
    """
    sess_A = github.session_manager.create_session()
    storage.save_github_installation({
        "id": 8881,
        "account_login": "org-shared",
        "account_type": "Organization"
    }, make_active=False)

    github.session_manager.authorize_installation(sess_A, 8881)
    assert github.session_manager.is_installation_authorized(sess_A, 8881) is True

    # Disconnect in Session A
    disc_resp = test_client.post(
        "/api/github/installations/8881/disconnect",
        headers={"x-guardian-session": sess_A}
    )
    assert disc_resp.status_code == 200
    assert github.session_manager.is_installation_authorized(sess_A, 8881) is False

    # Stored record in SQLite still exists (not uninstalled or deleted globally)
    assert storage.get_github_installation(8881) is not None

def test_token_retrieval_enforces_session_authorization(github_env):
    """Guardian 4.2 Section 2.C: get_installation_access_token must reject unauthorized sessions."""
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()

    github.session_manager.authorize_installation(sess_A, 9999)

    # Session A authorized
    with patch("backend.guardian.github._call_app_api", return_value={"token": "ghs_token123", "expires_at": "2026-11-01T12:00:00Z"}):
        token = github.get_installation_access_token(9999, session_id=sess_A)
        assert token == "ghs_token123"

    # Session B unauthorized: PermissionError
    import pytest
    with pytest.raises(PermissionError):
        github.get_installation_access_token(9999, session_id=sess_B)

# ==========================================
# 6. GUARDIAN 4.3 SESSION ISOLATION & LIFECYCLE TESTS (16 OBJECTIVES)
# ==========================================

def test_req_1_to_4_session_isolation_cross_access(github_env, test_client):
    """Req 1-4: Session A authorizes inst 100, Session B authorizes inst 200. Cross access forbidden."""
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()
    storage.save_github_installation({"id": 100, "account_login": "org-100", "account_type": "Organization"}, make_active=False)
    storage.save_github_installation({"id": 200, "account_login": "org-200", "account_type": "Organization"}, make_active=False)

    github.session_manager.authorize_installation(sess_A, 100)
    github.session_manager.authorize_installation(sess_B, 200)

    # Session A sees 100, cannot see 200
    res_A = test_client.get("/api/github/installations", headers={"x-guardian-session": sess_A})
    assert res_A.status_code == 200
    ids_A = [i["id"] for i in res_A.json()]
    assert 100 in ids_A
    assert 200 not in ids_A

    # Session A cannot select 200
    sel_A = test_client.post("/api/github/installations/200/select", headers={"x-guardian-session": sess_A})
    assert sel_A.status_code == 404

    # Session B sees 200, cannot see 100
    res_B = test_client.get("/api/github/installations", headers={"x-guardian-session": sess_B})
    assert res_B.status_code == 200
    ids_B = [i["id"] for i in res_B.json()]
    assert 200 in ids_B
    assert 100 not in ids_B

    # Session B cannot select 100
    sel_B = test_client.post("/api/github/installations/100/select", headers={"x-guardian-session": sess_B})
    assert sel_B.status_code == 404

def test_req_5_and_6_sync_does_not_authorize_or_select_for_session(github_env, test_client):
    """Req 5-6: Sync does not expand session's authorization set nor select globally active installation."""
    sess = github.session_manager.create_session()
    mock_gh_insts = [
        {"id": 300, "account": {"id": 300, "login": "discovered-300", "type": "User"}, "created_at": "2026-01-01T00:00:00Z"}
    ]
    with patch("backend.guardian.github._call_app_api", return_value=mock_gh_insts):
        resp = test_client.post("/api/github/sync", headers={"x-guardian-session": sess})
        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is False
        assert data["installation"] is None
        assert storage.get_github_installation(300) is not None
        assert github.session_manager.is_installation_authorized(sess, 300) is False
        assert github.session_manager.get_selected_installation_id(sess) is None

def test_req_7_missing_http_session_establishes_session_cookie(github_env, test_client):
    """Req 7: Missing HTTP session establishes a new session consistently via HttpOnly cookie."""
    resp = test_client.get("/api/github/status")
    assert resp.status_code == 200
    cookie = resp.cookies.get("guardian_session")
    assert cookie is not None
    assert github.session_manager.is_session_valid(cookie) is True
    data = resp.json()
    assert data["connected"] is False

def test_req_8_protected_endpoint_rejects_invalid_or_expired_session(github_env, test_client):
    """Req 8: Protected HTTP request with invalid or expired session is rejected with 401."""
    # Missing session
    res_missing = test_client.get("/api/github/installations")
    assert res_missing.status_code == 401
    assert "Valid GitHub session is required" in res_missing.json()["detail"]

    # Invalid session
    res_invalid = test_client.get("/api/github/installations", headers={"x-guardian-session": "totally_bogus_session_id"})
    assert res_invalid.status_code == 401

    # Expired session
    sess = github.session_manager.create_session()
    with github.session_manager._lock:
        github.session_manager._sessions[sess]["last_active"] = time.time() - 86400 * 2
    res_expired = test_client.get("/api/github/installations", headers={"x-guardian-session": sess})
    assert res_expired.status_code == 401

def test_req_9_oauth_callback_without_session_rejected(github_env, test_client):
    """Req 9: OAuth callback without a session is rejected with HTTP 400."""
    state = create_install_state()
    resp = test_client.get(f"/api/github/callback?installation_id=100&state={state}")
    assert resp.status_code == 400
    assert "Missing or invalid session for GitHub callback" in resp.json()["detail"]

def test_req_10_oauth_state_cross_session_rejected(github_env, test_client):
    """Req 10: State created by Session A cannot be consumed by Session B."""
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()
    state = create_install_state(session_id=sess_A)

    resp = test_client.get(
        f"/api/github/callback?installation_id=100&state={state}",
        headers={"x-guardian-session": sess_B}
    )
    assert resp.status_code == 400
    assert "Invalid or expired OAuth state parameter" in resp.json()["detail"]

def test_req_11_oauth_state_single_use(github_env, test_client):
    """Req 11: OAuth state cannot be consumed twice."""
    sess = github.session_manager.create_session()
    state = create_install_state(session_id=sess)
    mock_inst = {
        "id": 555,
        "account": {"id": 555, "login": "once-org", "type": "Organization"},
        "repository_selection": "all",
        "created_at": "2026-01-01T00:00:00Z"
    }
    with patch("backend.guardian.github._call_app_api", return_value=mock_inst):
        resp1 = test_client.get(
            f"/api/github/callback?installation_id=555&state={state}",
            headers={"x-guardian-session": sess},
            follow_redirects=False
        )
        assert resp1.status_code == 302

        resp2 = test_client.get(
            f"/api/github/callback?installation_id=555&state={state}",
            headers={"x-guardian-session": sess},
            follow_redirects=False
        )
        assert resp2.status_code == 400
        assert "Invalid or expired OAuth state parameter" in resp2.json()["detail"]

def test_req_12_failed_cross_session_state_validation_prevents_replay(github_env, test_client):
    """Req 12: Failed cross-session attempt pops state and does not permit replay by Session A."""
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()
    state = create_install_state(session_id=sess_A)

    resp_B = test_client.get(
        f"/api/github/callback?installation_id=100&state={state}",
        headers={"x-guardian-session": sess_B}
    )
    assert resp_B.status_code == 400

    mock_inst = {
        "id": 100,
        "account": {"id": 100, "login": "a-org", "type": "Organization"},
        "repository_selection": "all",
        "created_at": "2026-01-01T00:00:00Z"
    }
    with patch("backend.guardian.github._call_app_api", return_value=mock_inst):
        resp_A = test_client.get(
            f"/api/github/callback?installation_id=100&state={state}",
            headers={"x-guardian-session": sess_A}
        )
        assert resp_A.status_code == 400
        assert "Invalid or expired OAuth state parameter" in resp_A.json()["detail"]

def test_req_13_installation_authorization_cannot_create_arbitrary_sessions():
    """Req 13: authorize_installation rejects nonexistent sessions rather than auto-creating them."""
    with pytest.raises(ValueError) as exc:
        github.session_manager.authorize_installation("nonexistent_session_id", 123)
    assert "not valid or has expired" in str(exc.value)

def test_req_14_disconnect_session_isolation(github_env, test_client):
    """Req 14: Disconnecting installation from Session A does not affect Session B."""
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()
    storage.save_github_installation({"id": 600, "account_login": "shared-org", "account_type": "Organization"}, make_active=False)

    github.session_manager.authorize_installation(sess_A, 600)
    github.session_manager.authorize_installation(sess_B, 600)

    # Disconnect in Session A
    resp_A = test_client.post("/api/github/installations/600/disconnect", headers={"x-guardian-session": sess_A})
    assert resp_A.status_code == 200

    # Session A is no longer authorized
    assert github.session_manager.is_installation_authorized(sess_A, 600) is False
    # Session B remains authorized and selected
    assert github.session_manager.is_installation_authorized(sess_B, 600) is True
    assert github.session_manager.get_selected_installation_id(sess_B) == 600

def test_req_15_remediation_pr_session_isolation(github_env, test_client):
    """Req 15: Session cannot apply or close remediation PR using another session's installation."""
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()
    storage.save_github_installation({"id": 700, "account_login": "pr-org", "account_type": "Organization"}, make_active=False)
    github.session_manager.authorize_installation(sess_A, 700)
    # sess_B does not authorize 700

    plan = RemediationPlan(
        plan_id="plan_iso_pr",
        scan_id="scan_1",
        title="Session isolation plan",
        summary="Test",
        expected_outcome="Applied",
        repository_id=99,
        branch="main",
        commit_sha="commit_sha_1",
        pr_number=10,
        pr_url="https://github.com/pr-org/app/pull/10",
        status="approved",
        created_at="2026-10-31T12:00:00Z"
    )
    storage.save_plan(plan)

    # Session B attempts to apply PR -> rejected (400 or 403)
    resp_apply = test_client.post("/api/remediation/plans/plan_iso_pr/apply-github", headers={"x-guardian-session": sess_B})
    assert resp_apply.status_code in (400, 403)

    # Session B attempts to close PR -> rejected (400 or 403)
    resp_close = test_client.post("/api/remediation/plans/plan_iso_pr/close-github-pr", headers={"x-guardian-session": sess_B})
    assert resp_close.status_code in (400, 403)

def test_req_16_token_cache_reuse_cannot_bypass_authorization(github_env, test_client):
    """Req 16: Cached token for installation 800 cannot be used by an unauthorized session."""
    sess_A = github.session_manager.create_session()
    sess_B = github.session_manager.create_session()
    storage.save_github_installation({"id": 800, "account_login": "cached-token-org", "account_type": "Organization"}, make_active=False)
    github.session_manager.authorize_installation(sess_A, 800)

    # Prime token cache using Session A
    with patch("backend.guardian.github._call_app_api", return_value={"token": "ghs_cached_token_800", "expires_at": "2030-01-01T00:00:00Z"}):
        tok = github.get_installation_access_token(800, session_id=sess_A)
        assert tok == "ghs_cached_token_800"

    # Token is now cached in _token_cache for installation 800
    assert 800 in _token_cache

    # Session B (unauthorized) attempts to fetch token directly -> PermissionError
    with pytest.raises(PermissionError):
        github.get_installation_access_token(800, session_id=sess_B)

    # Session B attempts to list repositories -> rejected with 400
    res_b = test_client.get("/api/github/repositories", headers={"x-guardian-session": sess_B})
    assert res_b.status_code == 400
    assert "No GitHub App installation is selected or authorized" in res_b.json()["detail"]

