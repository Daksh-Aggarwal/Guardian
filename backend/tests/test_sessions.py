"""Comprehensive tests for Guardian server-managed SQLite sessions and scoped authorization."""
import os
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.guardian.main import app
from backend.guardian import storage, github
from backend.guardian.models import Report, GitHubMetadata
from backend.guardian.remediation_models import RemediationPlan


@pytest.fixture
def client():
    return TestClient(app)


def make_report(scan_id='test-report'):
    return Report(
        id=scan_id,
        name='sample-pkg',
        version='1.0.0',
        created_at=datetime.now(timezone.utc).isoformat(),
        source='Source',
        risk='No elevated signals',
        rationale='No elevated behavior detected.',
        findings=[],
        dependencies=[],
        files_analyzed=1,
        coverage=[],
        intelligence='not checked',
        duration_ms=10,
    )


def make_github_report(scan_id, installation_id, repo_id=100):
    report = make_report(scan_id)
    report.source_metadata = GitHubMetadata(
        installation_id=installation_id,
        repository_id=repo_id,
        repo_name=f'repo-{repo_id}',
        owner='owner',
        repo_url=f'https://github.com/owner/repo-{repo_id}',
        branch='main',
        commit_sha='a' * 40,
        default_branch='main',
    )
    storage.save(report)
    return report


def test_session_init_creates_new_session(client):
    """POST /api/session/init without cookie creates a new session in SQLite and sets HttpOnly cookie."""
    res = client.post("/api/session/init")
    assert res.status_code == 200
    data = res.json()
    assert data["initialized"] is True
    assert data["new"] is True

    # Check cookie
    assert "guardian_session" in res.cookies
    cookie_val = res.cookies["guardian_session"]
    assert len(cookie_val) >= 32

    # Verify session persisted in SQLite
    sess = storage.get_session(cookie_val)
    assert sess is not None
    assert sess["session_id"] == cookie_val


def test_session_init_existing_valid_session(client):
    """POST /api/session/init with existing valid cookie reuses it and touches last_seen."""
    sid = storage.create_session(ttl_days=30)
    sess_before = storage.get_session(sid)

    client.cookies.set("guardian_session", sid)
    res = client.post("/api/session/init")
    assert res.status_code == 200
    data = res.json()
    assert data["initialized"] is True
    assert data["new"] is False

    # Session is still valid in SQLite
    sess_after = storage.get_session(sid)
    assert sess_after is not None
    assert sess_after["session_id"] == sid


def test_session_init_expired_session_creates_new(client):
    """POST /api/session/init with an expired session replaces it with a new session."""
    sid = storage.create_session(ttl_days=30)
    # Manually expire session in DB
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with storage.connection() as conn:
        conn.execute("UPDATE sessions SET expires_at = ? WHERE session_id = ?", (past, sid))
        conn.commit()

    client.cookies.set("guardian_session", sid)
    res = client.post("/api/session/init")
    assert res.status_code == 200
    data = res.json()
    assert data["initialized"] is True
    assert data["new"] is True

    new_sid = res.cookies.get("guardian_session")
    assert new_sid is not None
    assert new_sid != sid
    assert storage.get_session(new_sid) is not None


def test_session_status_unauthenticated_and_authenticated(client):
    """GET /api/session/status returns correct authentication state."""
    # Without cookie
    res = client.get("/api/session/status")
    assert res.status_code == 200
    assert res.json() == {"valid": False}

    # With non-existent cookie
    client.cookies.set("guardian_session", "sess_fake_12345")
    res = client.get("/api/session/status")
    assert res.status_code == 200
    assert res.json() == {"valid": False}

    # With valid session
    sid = storage.create_session(ttl_days=30)
    client.cookies.set("guardian_session", sid)
    res = client.get("/api/session/status")
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True


def test_session_persistence_in_sqlite(client):
    """Sessions and scoped installation authorizations persist in SQLite."""
    sid = storage.create_session(ttl_days=30)
    inst_id = 88888
    storage.save_github_installation({
        "id": inst_id,
        "account_login": "persisted-org",
        "account_type": "Organization",
    })
    storage.authorize_installation_for_session(sid, inst_id)
    storage.set_session_selected_installation(sid, inst_id)

    # Re-read directly using storage functions
    sess = storage.get_session(sid)
    assert sess is not None
    assert storage.is_installation_authorized_for_session(sid, inst_id) is True
    selected = storage.get_session_selected_installation(sid)
    assert selected is not None
    assert selected["id"] == inst_id
    assert storage.get_session_authorized_installation_ids(sid) == {inst_id}


def test_github_scan_access_unauthorized_rejections(client):
    """Scanning or accessing GitHub scan requires a valid session authorized for that installation."""
    inst_id = 77777
    storage.save_github_installation({
        "id": inst_id,
        "account_login": "secure-org",
        "account_type": "Organization",
    })

    rep = make_github_report("scan_sec_1", installation_id=inst_id, repo_id=123)
    path = f"/api/scans/{rep.id}"

    # 1. No session -> 401
    client.cookies.clear()
    assert client.get(path).status_code == 401

    # 2. Invalid session -> 401
    client.cookies.set("guardian_session", "sess_does_not_exist")
    assert client.get(path).status_code == 401

    # 3. Valid session but unauthorized for this installation -> 403
    other_sid = storage.create_session()
    client.cookies.set("guardian_session", other_sid)
    assert client.get(path).status_code == 403

    # 4. Authorize session for this installation -> 200
    storage.authorize_installation_for_session(other_sid, inst_id)
    assert client.get(path).status_code == 200

    # 5. Deauthorize session -> 403
    storage.deauthorize_installation_for_session(other_sid, inst_id)
    assert client.get(path).status_code == 403


def test_multi_session_isolation(client):
    """Multiple sessions cannot access each other's installations or scans."""
    inst_a = 11111
    inst_b = 22222
    storage.save_github_installation({"id": inst_a, "account_login": "tenant-a", "account_type": "User"})
    storage.save_github_installation({"id": inst_b, "account_login": "tenant-b", "account_type": "User"})

    sid_a = storage.create_session()
    sid_b = storage.create_session()

    storage.authorize_installation_for_session(sid_a, inst_a)
    storage.authorize_installation_for_session(sid_b, inst_b)

    rep_a = make_github_report("scan_tenant_a", installation_id=inst_a, repo_id=101)
    rep_b = make_github_report("scan_tenant_b", installation_id=inst_b, repo_id=102)

    # Session A view
    client.cookies.set("guardian_session", sid_a)
    assert client.get(f"/api/scans/{rep_a.id}").status_code == 200
    assert client.get(f"/api/scans/{rep_b.id}").status_code == 403

    scans_a = client.get("/api/scans").json()
    ids_a = [s["id"] for s in scans_a]
    assert rep_a.id in ids_a
    assert rep_b.id not in ids_a

    # Session B view
    client.cookies.set("guardian_session", sid_b)
    assert client.get(f"/api/scans/{rep_b.id}").status_code == 200
    assert client.get(f"/api/scans/{rep_a.id}").status_code == 403

    scans_b = client.get("/api/scans").json()
    ids_b = [s["id"] for s in scans_b]
    assert rep_b.id in ids_b
    assert rep_a.id not in ids_b


def test_remediation_plan_authorization(client):
    """Remediation plans tied to GitHub scans require authorized installation session."""
    inst_id = 33333
    storage.save_github_installation({"id": inst_id, "account_login": "remed-org", "account_type": "User"})

    sid_owner = storage.create_session()
    storage.authorize_installation_for_session(sid_owner, inst_id)

    sid_other = storage.create_session()

    rep = make_github_report("scan_remed_1", installation_id=inst_id, repo_id=500)

    plan = RemediationPlan(
        plan_id="plan_test_auth",
        scan_id=rep.id,
        finding_id="finding_1",
        title="Upgrade package",
        summary="Fix vulnerability",
        priority="high",
        expected_outcome="Secures package",
        status="proposed",
        created_at=datetime.now(timezone.utc).isoformat(),
        repository_id=500,
        branch="main",
    )
    storage.save_plan(plan)

    # Owner session can access
    client.cookies.set("guardian_session", sid_owner)
    res = client.get(f"/api/remediation/plans/{plan.plan_id}")
    assert res.status_code == 200

    # Other session gets 403
    client.cookies.set("guardian_session", sid_other)
    res = client.get(f"/api/remediation/plans/{plan.plan_id}")
    assert res.status_code == 403

    res_approve = client.post(f"/api/remediation/plans/{plan.plan_id}/approve")
    assert res_approve.status_code == 403


def test_header_injection_ignored(client):
    """The x-guardian-session header is ignored; only guardian_session cookie is honored."""
    sid = storage.create_session()
    inst_id = 44444
    storage.save_github_installation({"id": inst_id, "account_login": "hdr-org", "account_type": "User"})
    storage.authorize_installation_for_session(sid, inst_id)

    rep = make_github_report("scan_hdr_1", installation_id=inst_id, repo_id=600)

    client.cookies.clear()
    # Sending sid in header only should still yield 401
    res = client.get(f"/api/scans/{rep.id}", headers={"x-guardian-session": sid})
    assert res.status_code == 401

    # Sending in cookie succeeds
    client.cookies.set("guardian_session", sid)
    res = client.get(f"/api/scans/{rep.id}")
    assert res.status_code == 200
