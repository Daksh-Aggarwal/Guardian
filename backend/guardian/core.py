"""Server-independent shared static analysis API. Acquisition and intelligence stay outside."""
import hashlib
import time
from datetime import datetime, timezone
from uuid import uuid4
from . import engine
from .models import Dependency, IntegrityResult, PackageInspection, InspectionSummary, Report
from .policy import evaluate


def analyze_sources(files, limits=None, timeout=20):
    """Stable entry used by both website orchestration and CLI package analysis."""
    return engine.analyze(files, limits=limits, timeout=timeout)


def analyze_plan(plan, policy=None):
    started = time.monotonic()
    findings, inspections, coverage, count = [], [], list(plan.limitations), 0
    package_decisions = []
    complete = plan.complete
    identities = {a.identity for a in plan.artifacts}
    missing_edges = [f'{a.identity}: unresolved dependency {child}' for a in plan.artifacts for child in a.dependencies if child not in identities]
    plan_limitations = list(plan.limitations) + missing_edges
    coverage.extend(missing_edges)
    complete = complete and not missing_edges
    for artifact in plan.artifacts:
        if artifact.ecosystem != plan.ecosystem:
            raise ValueError('Artifact ecosystem does not match acquisition plan.')
        if hashlib.sha256(artifact.raw).hexdigest() != artifact.sha256:
            from .supply_models import IntegrityError
            raise IntegrityError('Artifact changed between acquisition and analysis.')
        _, _, observed, _, notes, inspected = analyze_sources(artifact.files)
        # Ordinary static-analysis limitations remain disclosed; actual parser failures
        # and omitted files require review, independently of vulnerability intelligence.
        incomplete_notes = [n for n in notes
                            if not n.startswith(('Static analysis only:', 'Only module initialization', 'Python AST static analysis only:'))
                            and any(marker in n.lower() for marker in
                            ('could not parse', 'unavailable', 'manifest-only', 'truncated', 'limit reached',
                             'evidence capped', 'deadline', 'unsupported', 'uninspected', 'not modeled', 'unresolved'))]
        omitted = [n for n in artifact.warnings if n.lower().startswith('skipped')]
        build = ['Source distributions require an untrusted build; installation is deferred.'] if artifact.kind == 'sdist' else []
        limitations = incomplete_notes + omitted + build
        source_complete = not limitations and inspected > 0
        complete = complete and source_complete
        coverage.extend(f'{artifact.identity}: {n}' for n in artifact.warnings + notes + build)
        for f in observed:
            # Keep the website/Handoff package-specifier contract; ecosystem has
            # its own field, while graph locations retain fully qualified IDs.
            f.package = f'{artifact.name}@{artifact.version}'
            f.ecosystem = artifact.ecosystem
            f.artifact_sha256 = artifact.sha256
        findings.extend(observed)
        count += inspected
        result = evaluate(observed, verified=artifact.verified, complete=source_complete,
                          limitations=limitations, policy=policy)
        package_decisions.append({'identity': artifact.identity, 'sha256': artifact.sha256,
                                  'kind': artifact.kind, **result})
        inspections.append(PackageInspection(
            name=artifact.name, version=artifact.version, ecosystem=artifact.ecosystem,
            artifact_sha256=artifact.sha256, location=artifact.identity, direct=artifact.direct,
            status='inspected' if source_complete else 'skipped', reason='; '.join(limitations),
            integrity=IntegrityResult(status='verified' if artifact.verified else 'missing',
                                      source='acquisition', computed=['sha256:' + artifact.sha256]),
            dependencies=artifact.dependencies, finding_ids=[f.id for f in observed]))
    if not plan.artifacts:
        complete = False
        coverage.append('No acquired package artifacts were inspected.')
    findings.sort(key=lambda f: engine.RANK[f.severity], reverse=True)
    verified = bool(plan.artifacts) and all(a.verified for a in plan.artifacts)
    decision = evaluate(findings, verified=verified, complete=complete,
                        limitations=plan_limitations + [r for p in package_decisions for r in p['review_reasons']], policy=policy)
    risk, rationale = engine.assess(findings, source_coverage_incomplete=not complete)
    summary = InspectionSummary(total=len(inspections), direct=sum(n.direct for n in inspections),
                                transitive=sum(not n.direct for n in inspections),
                                inspected=sum(n.status == 'inspected' for n in inspections),
                                skipped=sum(n.status == 'skipped' for n in inspections),
                                packages_with_findings=sum(bool(n.finding_ids) for n in inspections), profile='cli')
    root = plan.artifacts[0] if len(plan.artifacts) == 1 else None
    return Report(
        id=uuid4().hex, name=root.name if root else 'Dependency installation',
        version=root.version if root else 'resolved', created_at=datetime.now(timezone.utc).isoformat(),
        source='Guardian CLI', risk=risk, rationale=rationale, findings=findings,
        dependencies=[Dependency(name=n.name, version=n.version, direct=n.direct, source=n.location, ecosystem=n.ecosystem) for n in inspections],
        files_analyzed=count, coverage=coverage + ['Vulnerability intelligence not checked; local static analysis is independent.'],
        intelligence='not checked', duration_ms=int((time.monotonic() - started) * 1000), engine_version='2',
        inspections=inspections, inspection_summary=summary,
        assessments={'behavior': {'risk': risk, 'rationale': rationale, 'coverage_status': 'complete' if complete else 'incomplete', 'files_inspected': count},
                     'vulnerabilities': {'count': 0, 'status': 'not checked'},
                     'integrity': {'concerns': sum(not a.verified for a in plan.artifacts), 'root_status': 'verified' if verified else 'missing'},
                     'inspection': {**summary.model_dump(), 'status': 'complete' if complete else 'incomplete'}},
        cli={'schema_version': '1.0', 'ecosystem': plan.ecosystem, 'roots': plan.roots,
             'packages': package_decisions, 'decision': decision, 'installation': {'status': 'not attempted'},
             'overrides': [], 'sync': 'disabled', 'lifecycle_scripts': 'disabled'})
