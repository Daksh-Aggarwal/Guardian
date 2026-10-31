"""
Tests for Guardian Handoff 1.0 — AI-Agnostic Remediation & Agent Instruction Export.
"""
import json
import pytest
from fastapi.testclient import TestClient

from backend.guardian.main import app
from backend.guardian.models import Report, Finding, Dependency, Evidence, Advisory, GitHubMetadata, PackageInspection, InspectionSummary
from backend.guardian.handoff import handoff_service, generate_safe_filename, sanitize_markdown_text
from backend.guardian.handoff_models import CanonicalHandoff, HandoffExportResponse
from backend.guardian import storage

client = TestClient(app)

@pytest.fixture
def sample_report():
    f1 = Finding(
        id="FIND-01",
        rule="OSV",
        title="Prototype pollution in lodash",
        category="Vulnerability",
        severity="high",
        confidence="high",
        observed="lodash@4.17.15 contains prototype pollution vulnerability",
        explanation="Untrusted input can modify Object.prototype, leading to denial of service or remote code execution.",
        implication="Remote code execution in node server.",
        recommendation="Upgrade lodash to 4.17.21 or later.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-8203"],
        package="lodash@4.17.15",
        advisory=Advisory(
            id="GHSA-p6mc-m468-83gw",
            summary="Prototype Pollution in lodash",
            severity="high",
            cvss=[{"type": "CVSS_V3", "score": "7.4"}],
            fixed_versions=["4.17.21"],
            aliases=["CVE-2020-8203"],
            detail_status="available"
        ),
        evidence=[
            Evidence(
                file="package.json",
                line=14,
                column=5,
                snippet='"lodash": "4.17.15"',
                detail="Direct dependency specification in package.json"
            )
        ]
    )

    f2 = Finding(
        id="FIND-02",
        rule="INSTALL_SCRIPT",
        title="Dangerous postinstall script detected",
        category="Supply Chain",
        severity="critical",
        confidence="high",
        observed="preinstall script runs curl to external host",
        explanation="Arbitrary code execution during npm install.",
        implication="Compromise of developer machine or build CI pipeline.",
        recommendation="Remove automatic installation script.",
        references=[],
        package=None,
        evidence=[
            Evidence(
                file="package.json",
                line=8,
                column=3,
                snippet='"postinstall": "node scripts/setup.js"',
                detail="Manifest lifecycle script"
            )
        ]
    )

    deps = [
        Dependency(name="lodash", version="4.17.15", direct=True, source="package.json", ecosystem="npm"),
        Dependency(name="express", version="4.18.2", direct=True, source="package.json", ecosystem="npm"),
    ]

    rep = Report(
        id="scan-handoff-test-01",
        name="test-web-app",
        version="1.0.0",
        created_at="2026-10-31T20:00:00Z",
        source="local project",
        risk="critical",
        rationale="Critical supply-chain install script and high-severity prototype pollution.",
        findings=[f1, f2],
        dependencies=deps,
        files_analyzed=24,
        coverage=["Manifest analyzed", "Source files inspected"],
        intelligence="OSV intelligence verified",
        duration_ms=450,
        classification="real",
        project_id="proj_123456"
    )
    return rep

@pytest.fixture
def github_report(sample_report):
    gh = GitHubMetadata(
        repository_id=98765432,
        repo_name="secure-service",
        owner="acme-corp",
        repo_url="https://github.com/acme-corp/secure-service",
        branch="main",
        commit_sha="a1b2c3d4e5f67890123456789abcdef012345678",
        default_branch="main"
    )
    r = sample_report.model_copy(deep=True)
    r.id = "scan-github-test-01"
    r.name = "acme-corp/secure-service"
    r.source = "github repository"
    r.source_metadata = gh
    return r

# 1. Canonical Handoff Construction & Schema Validity
def test_canonical_handoff_construction(sample_report):
    canonical = handoff_service.build_canonical(sample_report, target="universal", mode="focused_fix")
    assert canonical.schema_version == "1.0.0"
    assert canonical.handoff_id.startswith("gho_")
    assert canonical.target_agent == "universal"
    assert canonical.remediation_mode == "focused_fix"
    assert canonical.scope == "scan"
    assert canonical.project.name == "test-web-app"
    assert canonical.project.is_github is False
    assert canonical.scan.scan_id == "scan-handoff-test-01"
    assert len(canonical.findings) == 2
    assert len(canonical.proposed_remediations) >= 2
    assert len(canonical.validation_requirements) >= 3

# 2. Scope Variations: Single finding, Multiple findings, Entire scan
def test_scope_single_finding(sample_report):
    canonical = handoff_service.build_canonical(sample_report, finding_ids=["FIND-01"])
    assert canonical.scope == "finding"
    assert len(canonical.findings) == 1
    assert canonical.findings[0].finding_id == "FIND-01"
    assert len(canonical.dependencies) == 1
    assert canonical.dependencies[0].name == "lodash"

def test_scope_multiple_findings(sample_report):
    f3 = Finding(
        id="FIND-03",
        rule="DANGEROUS_CALL",
        title="Dynamic eval call",
        category="Code Quality",
        severity="medium",
        confidence="medium",
        observed="eval() used in parser",
        explanation="Dynamic code evaluation can execute arbitrary commands.",
        implication="Arbitrary code execution if input is tainted.",
        recommendation="Use JSON.parse instead.",
        evidence=[Evidence(file="lib/parser.js", line=42, column=1, snippet="eval(code)", detail="Dynamic execution")]
    )
    three_finding_report = sample_report.model_copy(deep=True)
    three_finding_report.findings.append(f3)

    canonical = handoff_service.build_canonical(three_finding_report, finding_ids=["FIND-01", "FIND-02"])
    assert canonical.scope == "findings"
    assert len(canonical.findings) == 2
    fids = [f.finding_id for f in canonical.findings]
    assert "FIND-01" in fids and "FIND-02" in fids

def test_scope_entire_scan(sample_report):
    canonical = handoff_service.build_canonical(sample_report, finding_ids=None)
    assert canonical.scope == "scan"
    assert len(canonical.findings) == 2

# 3. Mode Variations: Focused Fix vs Deep Security Remediation
def test_remediation_mode_differences(sample_report):
    focused = handoff_service.build_canonical(sample_report, mode="focused_fix")
    deep = handoff_service.build_canonical(sample_report, mode="deep_remediation")

    assert focused.remediation_mode == "focused_fix"
    assert deep.remediation_mode == "deep_remediation"

    # Deep remediation includes transitive and repository-wide investigations
    deep_topics = [f.topic for f in deep.follow_up_investigations]
    assert any("Transitive" in t for t in deep_topics)
    assert any("Pattern Search" in t for t in deep_topics)
    assert any("Integrity" in t for t in deep_topics)

    # Focused fix emphasizes direct verification and regression tests
    focused_topics = [f.topic for f in focused.follow_up_investigations]
    assert any("presence in current checkout" in t.lower() for t in focused_topics)
    assert any("regression test" in t.lower() for t in focused_topics)

# 4. All Five Target Formats
@pytest.mark.parametrize("target,expected_keyword", [
    ("universal", "Universal AI Remediation"),
    ("claude_code", "Claude Code Remediation Instruction Package"),
    ("cursor", "Cursor IDE Remediation Plan"),
    ("codex", "OpenAI Codex Agent Task Specification"),
    ("github_copilot", "GitHub Copilot Remediation Guide"),
])
def test_target_specific_adapters(sample_report, target, expected_keyword):
    canonical = handoff_service.build_canonical(sample_report, target=target)
    markdown = handoff_service.render_instructions(canonical)
    assert expected_keyword in markdown
    assert "## 1. Executive Summary" in markdown
    assert "## 4. Finding-by-Finding Analysis" in markdown
    assert "## 11. Validation & Regression Testing Requirements" in markdown

# 5. Provenance Handling: GitHub vs Local Project
def test_github_provenance(github_report):
    canonical = handoff_service.build_canonical(github_report)
    assert canonical.project.is_github is True
    assert canonical.project.github_owner == "acme-corp"
    assert canonical.project.github_repo_name == "secure-service"
    assert canonical.project.github_commit_sha == "a1b2c3d4e5f67890123456789abcdef012345678"
    assert canonical.project.github_branch == "main"
    assert canonical.project.is_snapshot_stale_warning is True

    rendered = handoff_service.render_instructions(canonical)
    assert "acme-corp/secure-service" in rendered
    assert "a1b2c3d4e5f67890123456789abcdef012345678" in rendered
    assert "GitHub-backed Repository" in rendered

def test_local_provenance_does_not_fabricate_github(sample_report):
    canonical = handoff_service.build_canonical(sample_report)
    assert canonical.project.is_github is False
    assert canonical.project.github_owner is None
    assert canonical.project.github_repo_name is None
    assert canonical.project.github_commit_sha is None
    assert canonical.project.name == "test-web-app"

    rendered = handoff_service.render_instructions(canonical)
    assert "Local Project Workspace" in rendered
    assert "GitHub Repository:" not in rendered

# 6. JSON Evidence Appendix Validity
def test_json_evidence_appendix_validity(sample_report):
    bundle = handoff_service.export_bundle(sample_report)
    markdown = bundle.markdown

    # Must contain clearly marked appendix heading
    assert "## Guardian Evidence Appendix" in markdown
    assert "```json" in markdown

    # Extract JSON between ```json and ```
    start_marker = "```json\n"
    end_marker = "\n```"
    start_pos = markdown.find(start_marker) + len(start_marker)
    end_pos = markdown.find(end_marker, start_pos)
    assert start_pos > 0 and end_pos > start_pos

    raw_json = markdown[start_pos:end_pos]
    parsed = json.loads(raw_json)

    assert parsed["schema_version"] == "1.0.0"
    assert parsed["scan"]["scan_id"] == sample_report.id
    assert len(parsed["findings"]) == len(sample_report.findings)
    assert parsed["findings"][0]["finding_id"] == "FIND-01"
    assert parsed["findings"][0]["advisory"]["fixed_versions"] == ["4.17.21"]

# 7. Secret Redaction in Handoff
def test_secret_redaction(sample_report):
    # Insert AWS key and GitHub token inside evidence snippet
    secret_evidence = Evidence(
        file="config/keys.js",
        line=5,
        column=1,
        snippet="const key = 'AKIA1234567890ABCDEF'; const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';",
        detail="Credentials exposed in source"
    )
    sample_report.findings[0].evidence.append(secret_evidence)

    bundle = handoff_service.export_bundle(sample_report)
    md = bundle.markdown

    assert "AKIA1234567890ABCDEF" not in md
    assert "[REDACTED_AWS_KEY]" in md
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" not in md
    assert "[REDACTED_GITHUB_TOKEN]" in md

# 8. Markdown Injection Sanitization
def test_markdown_injection_sanitization():
    malicious_text = "<script>alert('xss')</script>Unsafe Package **Injection**"
    sanitized = sanitize_markdown_text(malicious_text)
    assert "<script>" not in sanitized
    assert "[REMOVED_SCRIPT]" in sanitized

# 9. Filename Sanitization
def test_filename_sanitization():
    filename = generate_safe_filename("owner/my-repo:with*chars", "scan_12345678-abcd", "20261031")
    assert filename == "guardian-handoff-owner-my-repo-with-chars-scan_123-20261031.md"
    assert "/" not in filename
    assert ":" not in filename
    assert "*" not in filename

# 10. API Endpoint: POST /api/scans/{scan_id}/handoff
def test_api_generate_handoff(sample_report):
    storage.save(sample_report)

    # Valid request
    res = client.post(f"/api/scans/{sample_report.id}/handoff", json={
        "target": "claude_code",
        "mode": "focused_fix",
        "finding_ids": ["FIND-01"]
    })
    assert res.status_code == 200
    data = res.json()
    assert "canonical" in data
    assert "markdown" in data
    assert "summary" in data
    assert data["summary"]["target_agent"] == "claude_code"
    assert data["summary"]["findings_count"] == 1
    assert data["canonical"]["scope"] == "finding"

def test_api_handoff_scan_not_found():
    res = client.post("/api/scans/nonexistent-scan-id/handoff", json={})
    assert res.status_code == 404

def test_api_handoff_finding_not_found(sample_report):
    storage.save(sample_report)
    res = client.post(f"/api/scans/{sample_report.id}/handoff", json={
        "finding_ids": ["INVALID-FID-999"]
    })
    assert res.status_code == 404
    assert "Findings not found in scan" in res.json()["detail"]

# 11. API Endpoint: GET /api/scans/{scan_id}/handoff
def test_api_get_handoff(sample_report):
    storage.save(sample_report)
    res = client.get(f"/api/scans/{sample_report.id}/handoff?target=cursor&mode=deep_remediation")
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]["target_agent"] == "cursor"
    assert data["summary"]["remediation_mode"] == "deep_remediation"
    assert data["summary"]["findings_count"] == 2

# 12. Real vs Demo Scan Isolation
def test_demo_classification_preserved(sample_report):
    demo_rep = sample_report.model_copy(deep=True)
    demo_rep.id = "demo-scan-123"
    demo_rep.classification = "demo"
    demo_rep.source = "synthetic fixture"
    storage.save(demo_rep)

    bundle = handoff_service.export_bundle(demo_rep)
    assert bundle.canonical.scan.classification == "demo"
    assert "Classification:** `demo`" in bundle.markdown
