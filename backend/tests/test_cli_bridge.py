"""Local import consent and the HTTP authorization boundary around GitHub evidence."""
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.guardian import github, storage
from backend.guardian.main import app, JOB_INSTALLATIONS
from backend.guardian.models import Report, GitHubMetadata
from backend.guardian.remediation_models import RemediationPlan


def make_report(scan_id='local-report'):
    return Report(
        id=scan_id, name='sample', version='1.0.0', created_at='2026-11-01T00:00:00Z',
        source='CLI', risk='No elevated signals', rationale='No elevated behavior detected.',
        findings=[], dependencies=[], files_analyzed=1, coverage=[],
        intelligence='not checked', duration_ms=1,
        cli={'schema_version': '1.0', 'ecosystem': 'npm', 'decision': {'decision': 'ALLOW'},
             'installation': {'status': 'not attempted'}, 'lifecycle_scripts': 'disabled'},
    )


def github_report(scan_id='github-protected', installation_id=100):
    report = make_report(scan_id)
    report.source_metadata = GitHubMetadata(
        installation_id=installation_id, repository_id=42, repo_name='private', owner='owner',
        repo_url='https://github.com/owner/private', branch='main', commit_sha='a' * 40,
        default_branch='main',
    )
    storage.save(report)
    return report


def session(installation_id):
    if not storage.get_github_installation(installation_id):
        storage.save_github_installation({'id': installation_id, 'account_login': f'owner-{installation_id}', 'account_type': 'User'})
    sid = github.session_manager.create_session()
    github.session_manager.authorize_installation(sid, installation_id)
    return {'guardian_session': sid}


def test_capabilities_does_not_pretend_github_is_account_auth():
    result = TestClient(app).get('/api/cli/capabilities').json()
    assert result['local_import'] is True
    assert result['authentication'] is False
    assert result['synchronization'] is False


def test_import_requires_consent_and_supported_cli_schema():
    client = TestClient(app)
    report = make_report()
    assert client.post('/api/cli/reports', json={'report': report.model_dump()}).status_code == 400
    report.cli = {'schema_version': '99'}
    assert client.post('/api/cli/reports', json={'report': report.model_dump(), 'consent': True}).status_code == 400
    assert storage.recent() == []


def test_import_rejects_malformed_cli_decision_instead_of_crashing_viewer():
    payload = make_report().model_dump()
    payload['cli']['decision'] = {'decision': {'unexpected': 'object'}}
    response = TestClient(app).post('/api/cli/reports', json={'report': payload, 'consent': True})
    assert response.status_code == 422
    assert storage.recent() == []


def test_local_import_preserves_original_and_cannot_replace_github_identity():
    client = TestClient(app)
    original = github_report()
    incoming = make_report(original.id)
    incoming.source_metadata = original.source_metadata
    incoming.project_id = 'github:42'
    incoming.rationale = 'api_key="supersecret-value"'
    result = client.post('/api/cli/reports', json={'report': incoming.model_dump(), 'consent': True})
    assert result.status_code == 201
    imported = result.json()
    assert imported['id'] != original.id
    assert imported['source_metadata'] is None
    assert imported['project_id'] is None
    assert imported['cli']['imported'] is True
    assert imported['cli']['imported_scan_id'] == original.id
    assert 'supersecret-value' not in imported['rationale']
    assert 'not reverified' in imported['source']
    assert storage.get(original.id).source_metadata.installation_id == 100
    assert client.get('/api/scans/' + imported['id']).status_code == 200
    assert [r['id'] for r in client.get('/api/scans').json()] == [imported['id']]


@pytest.mark.parametrize('suffix', ['', '/conversation', '/handoff', '/remediation/plans'])
def test_github_report_routes_require_exact_authorized_installation(suffix):
    client = TestClient(app)
    report = github_report()
    path = '/api/scans/' + report.id + suffix
    assert client.get(path).status_code == 401
    assert client.get(path, headers={'x-guardian-session': 'invalid-token'}).status_code == 401
    wrong = session(200)
    assert client.get(path, cookies=wrong).status_code == 403
    own = session(100)
    assert client.get(path, cookies=own).status_code == 200
    github.session_manager.disconnect_installation(own['guardian_session'], 100)
    assert client.get(path, cookies=own).status_code == 403


def test_expired_session_cannot_read_history_or_jobs():
    client = TestClient(app)
    report = github_report()
    headers = session(100)
    sid = headers['guardian_session']
    assert len(client.get('/api/scans', cookies=headers).json()) == 1
    if hasattr(storage, 'get_session'):
        with storage.connection() as db:
            db.execute('UPDATE sessions SET expires_at = ? WHERE session_id = ?', ('2000-01-01T00:00:00+00:00', sid))
    else:
        github.session_manager._sessions[sid]['last_active'] = time.time() - 86401
    assert client.get('/api/scans/' + report.id, cookies=headers).status_code == 401
    assert client.get('/api/scans', cookies=headers).json() == []
    assert client.get('/api/jobs/' + report.id, cookies=headers).status_code == 401


def test_unfinished_github_job_and_snapshot_require_installation():
    client = TestClient(app)
    JOB_INSTALLATIONS['running-github'] = 100
    try:
        for path in ['/api/jobs/running-github', '/api/projects/running-github/metadata']:
            assert client.get(path).status_code == 401
            assert client.get(path, cookies=session(200)).status_code == 403
        assert client.post('/api/jobs/running-github/cancel', cookies=session(200)).status_code == 403
    finally:
        JOB_INSTALLATIONS.pop('running-github', None)


def test_github_plan_routes_use_original_report_installation():
    client = TestClient(app)
    report = github_report()
    plan = RemediationPlan(
        plan_id='protected-plan', scan_id=report.id, title='Fix', summary='Fix',
        expected_outcome='Fix', created_at=report.created_at, repository_id=42,
        branch='main', commit_sha='a' * 40,
    )
    storage.save_plan(plan)
    assert client.get('/api/remediation/plans/protected-plan').status_code == 401
    assert client.post('/api/remediation/plans/protected-plan/approve', cookies=session(200)).status_code == 403
    assert client.get('/api/remediation/plans/protected-plan', cookies=session(100)).status_code == 200


def test_verification_cannot_read_cross_session_rescanned_report():
    client = TestClient(app)
    original = make_report('public-original')
    storage.save(original)
    github_report('private-rescan', installation_id=200)
    plan = RemediationPlan(
        plan_id='verification-plan', scan_id=original.id, title='Fix', summary='Fix',
        expected_outcome='Fix', created_at=original.created_at,
    )
    storage.save_plan(plan)
    response = client.post('/api/remediation/plans/verification-plan/verification',
                           json={'rescanned_scan_id': 'private-rescan'}, cookies=session(100))
    assert response.status_code == 403
    assert storage.get_plan(plan.plan_id).status == 'proposed'


def test_http_never_uses_global_installation_fallback():
    client = TestClient(app)
    storage.save_github_installation({'id': 100, 'account_login': 'private-owner', 'account_type': 'User'})
    assert client.get('/api/github/installations').json() == []
    assert client.post('/api/github/sync').status_code == 401
    assert client.get('/api/github/repositories').status_code == 401
    assert client.post('/api/github/installations/100/disconnect').status_code == 401
    assert storage.get_github_installation(100) is not None


@pytest.mark.parametrize('failure', [False, True])
def test_sync_cannot_claim_sole_global_installation_or_leak_fallback(monkeypatch, failure):
    monkeypatch.setattr(github.GitHubConfig, 'is_configured', lambda: True)
    storage.save_github_installation({'id': 100, 'account_login': 'private-owner', 'account_type': 'User'})
    sid = github.session_manager.create_session()
    payload = [{'id': 100, 'account': {'login': 'private-owner', 'type': 'User'}}]
    with patch.object(github, '_call_app_api', side_effect=RuntimeError('offline') if failure else None, return_value=payload):
        response = TestClient(app).post('/api/github/sync', cookies={'guardian_session': sid})
    assert response.status_code == 200
    assert response.json()['connected'] is False
    assert response.json()['installations'] == []
    assert not github.session_manager.is_installation_authorized(sid, 100)


def test_bound_oauth_state_cannot_be_consumed_without_session():
    sid = github.session_manager.create_session()
    state = github.create_install_state(sid)
    assert github.verify_and_consume_state(state, session_id=None) is False
