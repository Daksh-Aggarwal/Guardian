import time
from pathlib import Path
import httpx
import pytest
from fastapi.testclient import TestClient
from backend.guardian.main import app
from backend.guardian.intelligence import check_osv
from backend.guardian.models import Dependency
client=TestClient(app)
ROOT=Path(__file__).resolve().parents[2]

def completed(response):
    assert response.status_code == 202, response.text
    job_id=response.json()['id']
    for _ in range(100):
        state=client.get('/api/jobs/'+job_id).json()
        if state['status']!='running':break
        time.sleep(.03)
    assert state['status']=='complete',state
    return client.get('/api/scans/'+job_id).json()

def test_health_and_not_found():
    assert client.get('/api/health').json()['status']=='ok'
    assert client.get('/api/scans/unknown').status_code==404
    assert client.post('/api/scans/example/nope').status_code==404

@pytest.mark.parametrize('fixture,expected',[('benign','No elevated signals'),('exfiltration','High concern'),('correlated','High concern')])
def test_example_to_report_and_explanation(fixture,expected):
    report=completed(client.post('/api/scans/example/'+fixture))
    assert report['risk']==expected
    assert report['source']=='synthetic fixture'
    answer=client.post('/api/scans/'+report['id']+'/explain',json={'question':'Is it safe to install?'})
    assert answer.status_code==200
    assert answer.json()['provider']=='deterministic'
    ids={f['id'] for f in report['findings']}
    assert all(c['finding_id'] in ids for c in answer.json()['citations'])
    assert client.get('/api/scans').json()[0]['id']==report['id']
    assert client.post('/api/scans/'+report['id']+'/explain',json={'question':'why?','finding_id':'missing'}).status_code==404

def test_zip_upload():
    report=completed(client.post('/api/scans/upload',files={'files':('exfiltration.zip',(ROOT/'fixtures/exfiltration.zip').read_bytes(),'application/zip')}))
    assert report['risk']=='High concern'

def test_two_manifests_upload():
    report=completed(client.post('/api/scans/upload',files=[('files',('package.json',b'{"name":"project","dependencies":{"react":"^19.0.0"}}','application/json')),('files',('package-lock.json',b'{"packages":{"node_modules/react":{"version":"19.0.0"}}}','application/json'))]))
    assert len(report['dependencies'])==2

def test_bad_upload():
    assert client.post('/api/scans/upload',files={'files':('package.json',b'not json')}).status_code==400
    assert client.post('/api/scans/upload',files={'files':('evil.zip',b'not zip')}).status_code==400

def test_osv_unavailable_is_not_safe(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED','true')
    def fail(*a,**kw):raise httpx.ConnectError('offline')
    monkeypatch.setattr(httpx,'post',fail)
    findings,status,warnings=check_osv([Dependency(name='lodash',version='4.17.0',source='package-lock.json')])
    assert findings==[] and status=='unavailable'
    assert any('unknown' in w for w in warnings)

def test_osv_matches_and_partial_ranges(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED','true')
    def response(*a,**kw):
        assert kw['json']['queries'][0]['version']=='4.17.0'
        return httpx.Response(200,json={'results':[{'vulns':[{'id':'GHSA-synthetic-test'}]}]},request=httpx.Request('POST',a[0]))
    monkeypatch.setattr(httpx,'post',response)
    findings,status,warnings=check_osv([Dependency(name='lodash',version='4.17.0',source='lock'),Dependency(name='react',version='^19.0.0',source='manifest')])
    assert status=='partial'
    assert findings[0].rule=='OSV'
    assert findings[0].confidence=='high'
    assert 'not the advisory' in findings[0].implication

def test_transport_size_limit():
    response=client.post('/api/scans/package',content=b'x'*(11*1024*1024+1),headers={'Content-Type':'application/json'})
    assert response.status_code==413

def test_job_cancellation():
    assert client.post('/api/jobs/nonexistent/cancel').status_code==404
    # Start a scan and cancel it
    res = client.post('/api/scans/example/benign')
    assert res.status_code == 202
    job_id = res.json()['id']
    cancel_res = client.post(f'/api/jobs/{job_id}/cancel')
    assert cancel_res.status_code == 200
    assert cancel_res.json()['status'] in {'cancelling', 'complete'}
    # Wait for worker thread to exit
    for _ in range(50):
        state = client.get(f'/api/jobs/{job_id}').json()
        if state['status'] not in ('queued', 'running', 'cancelling'):
            break
        time.sleep(0.02)
    assert state['status'] in {'cancelled', 'complete'}
    # Subsequent scan can run without deadlock
    next_report = completed(client.post('/api/scans/example/benign'))
    assert next_report['risk'] == 'No elevated signals'

def test_cancellation_aborts_before_save():
    import threading
    pause = threading.Event()
    def slow_loader():
        pause.wait(timeout=2.0)
        return ({'index.js': 'console.log("hello");'}, [])
    from backend.guardian.main import submit
    job_info = submit(slow_loader, 'test')
    job_id = job_info['id']
    cancel_res = client.post(f'/api/jobs/{job_id}/cancel')
    assert cancel_res.status_code == 200
    assert cancel_res.json()['status'] in {'cancelling', 'cancelled'}
    pause.set()
    for _ in range(50):
        state = client.get(f'/api/jobs/{job_id}').json()
        if state['status'] not in ('queued', 'running', 'cancelling'):
            break
        time.sleep(0.02)
    assert state['status'] == 'cancelled'
    # Report must not have been saved
    assert client.get(f'/api/scans/{job_id}').status_code == 404

def test_cancellation_immediately_before_persistence(monkeypatch):
    import threading
    from backend.guardian import main as main_mod
    at_assess = threading.Event()
    proceed = threading.Event()
    original_assess = main_mod.assess
    def hooked_assess(*args, **kwargs):
        at_assess.set()
        proceed.wait(timeout=2.0)
        return original_assess(*args, **kwargs)
    monkeypatch.setattr(main_mod, 'assess', hooked_assess)
    res = client.post('/api/scans/example/benign')
    assert res.status_code == 202
    job_id = res.json()['id']
    assert at_assess.wait(timeout=2.0)
    cancel_res = client.post(f'/api/jobs/{job_id}/cancel')
    assert cancel_res.status_code == 200
    assert cancel_res.json()['status'] == 'cancelling'
    proceed.set()
    for _ in range(50):
        state = client.get(f'/api/jobs/{job_id}').json()
        if state['status'] not in ('queued', 'running', 'cancelling'):
            break
        time.sleep(0.02)
    assert state['status'] == 'cancelled'
    assert client.get(f'/api/scans/{job_id}').status_code == 404

def test_completed_job_cancel_is_idempotent_and_does_not_revert():
    report = completed(client.post('/api/scans/example/benign'))
    job_id = report['id']
    cancel_res = client.post(f'/api/jobs/{job_id}/cancel')
    assert cancel_res.status_code == 200
    assert cancel_res.json()['status'] == 'complete'
    # Repeated calls are idempotent
    cancel_res2 = client.post(f'/api/jobs/{job_id}/cancel')
    assert cancel_res2.status_code == 200
    assert cancel_res2.json()['status'] == 'complete'
    # Report remains intact
    assert client.get(f'/api/scans/{job_id}').status_code == 200

def test_profile_selection(monkeypatch):
    res = client.post('/api/scans/upload', data={'profile': 'deep'}, files={'files': ('package.json', b'{"name":"demo"}', 'application/json')})
    assert res.status_code == 202
    report = completed(res)
    assert report['inspection_summary']['profile'] == 'deep'

def test_dependency_accounting_reconciliation():
    report = completed(client.post('/api/scans/example/benign'))
    summary = report['inspection_summary']
    assert summary is not None
    total = summary['total']
    assert summary['direct'] + summary['transitive'] == total
    assert summary['inspected'] + summary['skipped'] + summary['unavailable'] + summary['unresolved'] + summary['integrity_failed'] + summary['not_attempted'] == total

def test_legacy_report_compatibility():
    import json
    from backend.guardian import storage
    legacy_id = 'legacy-v1-report'
    legacy_json = json.dumps({
        'id': legacy_id,
        'name': 'legacy-package',
        'version': '1.0.0',
        'created_at': '2025-01-01T00:00:00Z',
        'source': 'upload',
        'risk': 'No elevated signals',
        'rationale': 'Legacy report rationale',
        'findings': [],
        'dependencies': [],
        'files_analyzed': 1,
        'coverage': ['Legacy coverage note'],
        'intelligence': 'checked',
        'duration_ms': 50
    })
    with storage.connection() as db:
        db.execute('INSERT OR REPLACE INTO scans VALUES (?, ?, ?)', (legacy_id, '2025-01-01T00:00:00Z', legacy_json))
    fetched = client.get(f'/api/scans/{legacy_id}')
    assert fetched.status_code == 200
    data = fetched.json()
    assert data['id'] == legacy_id
    assert data['name'] == 'legacy-package'
    assert data.get('engine_version') == '1'
    assert data.get('inspections') == []
    assert data.get('assessments') == {}
    # Scan history includes legacy report
    history = client.get('/api/scans').json()
    assert any(r['id'] == legacy_id for r in history)

def test_cancellation_while_persistence_in_progress(monkeypatch):
    import threading
    from backend.guardian import storage
    save_started = threading.Event()
    save_proceed = threading.Event()
    original_save = storage.save

    def delayed_save(report):
        save_started.set()
        save_proceed.wait(timeout=2.0)
        return original_save(report)

    monkeypatch.setattr(storage, 'save', delayed_save)
    res = client.post('/api/scans/example/benign')
    assert res.status_code == 202
    job_id = res.json()['id']

    assert save_started.wait(timeout=2.0)
    cancel_res_holder = []

    def call_cancel():
        cancel_res_holder.append(client.post(f'/api/jobs/{job_id}/cancel'))

    t = threading.Thread(target=call_cancel)
    t.start()
    time.sleep(0.05)  # give thread time to block waiting on LOCK
    save_proceed.set()
    t.join(timeout=2.0)

    assert len(cancel_res_holder) == 1
    assert cancel_res_holder[0].status_code == 200
    assert cancel_res_holder[0].json()['status'] == 'complete'
    assert client.get(f'/api/scans/{job_id}').status_code == 200

def test_osv_outage_does_not_make_source_coverage_incomplete(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    monkeypatch.setattr(httpx, 'post', lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError('OSV offline')))
    report = completed(client.post('/api/scans/example/benign'))
    assert report['assessments']['behavior']['coverage_status'] == 'complete'
    assert report['assessments']['vulnerabilities']['status'] == 'unavailable'
    assert report['risk'] == 'No elevated signals'
    assert 'source inspection was incomplete' not in report['rationale']


def test_pnpm_manifests_upload():
    pnpm_data = b"""lockfileVersion: '6.0'
dependencies:
  react: 19.0.0
packages:
  /react@19.0.0:
    resolution: {integrity: sha512-dummy}
"""
    report = completed(client.post('/api/scans/upload', files=[
        ('files', ('package.json', b'{"name":"project","dependencies":{"react":"^19.0.0"}}', 'application/json')),
        ('files', ('pnpm-lock.yaml', pnpm_data, 'application/x-yaml'))
    ]))
    assert len(report['dependencies']) >= 1
    assert any(d['name'] == 'react' for d in report['dependencies'])

def test_yarn_manifests_upload():
    yarn_data = b"""__metadata:
  version: 6
  cacheKey: 8
"react@npm:^19.0.0":
  version: 19.0.0
  resolution: "react@npm:19.0.0"
"""
    report = completed(client.post('/api/scans/upload', files=[
        ('files', ('package.json', b'{"name":"project","dependencies":{"react":"^19.0.0"}}', 'application/json')),
        ('files', ('yarn.lock', yarn_data, 'text/plain'))
    ]))
    assert len(report['dependencies']) >= 1
    assert any(d['name'] == 'react' for d in report['dependencies'])
