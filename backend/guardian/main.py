import asyncio
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from fastapi import FastAPI, File, HTTPException, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from . import ingestion, storage
from .engine import analyze, assess, RANK, finding
from .explanations import EvidenceExplainer
from .intelligence import check_osv
from .models import Dependency, PackageRequest, Question, Report, Evidence
from .limits import RequestSizeLimit
from .dependencies import RegistrySession, Retrieved, inspect_dependencies
from .config import Budget
from typing import Literal

app = FastAPI(title='Guardian', version='0.1.0')
app.add_middleware(RequestSizeLimit)
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:3000','http://127.0.0.1:3000'], allow_methods=['GET','POST'], allow_headers=['Content-Type'])
JOBS = {}
CANCELLATIONS = {}
LOCK = threading.Lock()
SLOTS = threading.BoundedSemaphore(2)
FIXTURES = Path(__file__).resolve().parents[2] / 'fixtures'

def stage(job_id, label):
    with LOCK:
        if job_id in JOBS and JOBS[job_id]['status'] in ('queued', 'running'):
            JOBS[job_id]['stage'] = label

def run(job_id, loader, source, profile):
    started = time.monotonic()
    try:
        with LOCK:
            cancel = CANCELLATIONS[job_id]
            if cancel.is_set() or JOBS[job_id]['status'] in ('cancelling', 'cancelled'):
                return
            JOBS[job_id]['status'] = 'running'
        stage(job_id, 'Inspecting input')
        loaded = loader()
        root_integrity = None
        root_result = loaded if isinstance(loaded, Retrieved) else None
        if root_result:
            files, warnings = root_result.files, root_result.warnings
            root_integrity = root_result.registry_integrity
        else:
            files, warnings = loaded
        if cancel.is_set(): return
        stage(job_id, 'Analyzing source & dependencies')
        name, version, findings, deps, coverage, count = analyze(files)
        if root_result:
            name = root_result.metadata.get('name', name)
            version = root_result.metadata.get('version', version)
            if root_integrity.status not in {'verified','missing'}:
                f = finding('PACKAGE_INTEGRITY', 'Published tarball failed integrity verification', 'Package integrity', 'high', 'high', root_integrity.detail,
                    'The package contents were not inspected because their checksum could not be validated.', 'Different or invalid bytes do not establish malicious intent.', 'Verify the published digest and package provenance before use.',
                    [Evidence(file='registry metadata',snippet=root_integrity.expected or '',detail=root_integrity.detail)])
                f.domain = 'integrity'
                findings.append(f)
        if cancel.is_set(): return
        stage(job_id, 'Inspecting dependency sources')
        inspections, inspection_summary, dep_findings, dep_warnings, dep_count = inspect_dependencies(files, analyze, profile, cancel=cancel)
        findings += dep_findings
        coverage += dep_warnings
        count += dep_count
        if cancel.is_set(): return
        stage(job_id, 'Checking vulnerability intelligence')
        query_deps = list(deps)
        if version != 'unversioned':
            query_deps.append(Dependency(name=name, version=version, source='package.json'))
        query_deps += [Dependency(name=n.name, version=n.version, direct=n.direct, source=n.location) for n in inspections]
        known, intelligence, intel_warnings = check_osv(query_deps)
        if cancel.is_set(): return
        findings += known
        findings.sort(key=lambda f: RANK[f.severity], reverse=True)
        stage(job_id, 'Building evidence-backed report')
        source_warnings = [w for w in warnings if 'Skipped non-UTF-8' in w or 'Skipped unsupported' in w or 'No supported source' in w]
        parser_issues = [c for c in coverage if 'JavaScript parser unavailable' in c or 'Could not parse' in c]
        is_manifest_only = any('Manifest-only scan' in c for c in coverage)
        dep_source_failures = bool(inspection_summary and (inspection_summary.unavailable > 0 or inspection_summary.integrity_failed > 0))
        source_coverage_incomplete = bool(source_warnings or parser_issues or is_manifest_only or dep_source_failures)

        risk, rationale = assess(findings, source_coverage_incomplete=source_coverage_incomplete)

        source_coverage_status = 'incomplete' if source_coverage_incomplete else ('manifest_only' if is_manifest_only else 'complete')
        inspection_status = (
            'complete' if (inspection_summary and inspection_summary.total > 0 and inspection_summary.inspected == inspection_summary.total)
            else ('no dependencies' if (not inspection_summary or inspection_summary.total == 0) else 'incomplete')
        )

        report = Report(
            id=job_id,
            name=name,
            version=version,
            created_at=datetime.now(timezone.utc).isoformat(),
            source=source,
            risk=risk,
            rationale=rationale,
            findings=findings,
            dependencies=deps,
            files_analyzed=count,
            coverage=warnings[:30] + coverage + intel_warnings,
            intelligence=intelligence,
            duration_ms=int((time.monotonic() - started) * 1000),
            engine_version='2',
            inspections=inspections,
            inspection_summary=inspection_summary,
            root_integrity=root_integrity,
            assessments={
                'behavior': {
                    'risk': risk,
                    'rationale': rationale,
                    'coverage_status': source_coverage_status,
                    'files_inspected': count,
                },
                'vulnerabilities': {
                    'count': len(known),
                    'status': intelligence,
                    'rationale': (
                        'Known vulnerabilities were checked against OSV.' if intelligence == 'checked'
                        else ('Vulnerability intelligence is partial; some advisories or versions were uninspected.' if intelligence == 'partial'
                        else ('Vulnerability intelligence was unavailable; known vulnerabilities could not be checked.' if intelligence == 'unavailable'
                        else 'Vulnerability intelligence was not checked.'))
                    ),
                },
                'integrity': {
                    'concerns': sum(f.domain == 'integrity' for f in findings),
                    'root_status': root_integrity.status if root_integrity else 'not applicable',
                },
                'inspection': {
                    'total': inspection_summary.total if inspection_summary else 0,
                    'direct': inspection_summary.direct if inspection_summary else 0,
                    'transitive': inspection_summary.transitive if inspection_summary else 0,
                    'inspected': inspection_summary.inspected if inspection_summary else 0,
                    'skipped': inspection_summary.skipped if inspection_summary else 0,
                    'unavailable': inspection_summary.unavailable if inspection_summary else 0,
                    'unresolved': inspection_summary.unresolved if inspection_summary else 0,
                    'integrity_failed': inspection_summary.integrity_failed if inspection_summary else 0,
                    'not_attempted': inspection_summary.not_attempted if inspection_summary else 0,
                    'status': inspection_status,
                    'rationale': (
                        f'{inspection_summary.inspected}/{inspection_summary.total} dependencies inspected.' if inspection_summary and inspection_summary.total > 0
                        else 'No external dependencies to inspect.'
                    ),
                },
            }
        )
        with LOCK:
            if cancel.is_set() or JOBS[job_id]['status'] in ('cancelling', 'cancelled'):
                return
            storage.save(report)
            JOBS[job_id].update(status='complete', stage='Complete')
    except Exception as error:
        # Do not include server paths, credentials, or raw upstream responses.
        message = str(error) if isinstance(error, ValueError) else 'Could not inspect this input. Check the archive, package name, version, and network access.'
        with LOCK:
            if not (CANCELLATIONS[job_id].is_set() or JOBS[job_id]['status'] in ('cancelling', 'cancelled')):
                JOBS[job_id].update(status='failed', stage='Stopped', error=message[:400])
    finally:
        with LOCK:
            if CANCELLATIONS.get(job_id) and CANCELLATIONS[job_id].is_set():
                JOBS[job_id].update(status='cancelled', stage='Scan cancelled')
        SLOTS.release()

def submit(loader, source, profile="fast"):
    if not SLOTS.acquire(blocking=False):
        raise HTTPException(429, 'Two scans are already running. Try again shortly.')
    job_id = uuid4().hex
    with LOCK:
        # Only retain the most recent completed job states; reports stay in SQLite.
        if len(JOBS) >= 100:
            for old in list(JOBS):
                if JOBS[old]['status'] not in ('queued', 'running', 'cancelling'):
                    del JOBS[old]
                    CANCELLATIONS.pop(old, None)
                    break
        JOBS[job_id] = {'id':job_id, 'status':'queued', 'stage':'Queued'}
        CANCELLATIONS[job_id] = threading.Event()
    threading.Thread(target=run, args=(job_id, loader, source, profile), daemon=True).start()
    return {'id':job_id}

@app.get('/api/health')
def health():
    return {'status':'ok', 'engine':'guardian-static-v2'}

@app.get('/api/scans')
def scans():
    return storage.recent()

@app.post('/api/scans/upload', status_code=202)
async def upload(files: list[UploadFile] = File(...), profile: Literal["fast", "deep"] = Form("fast")):
    if len(files) > 2:
        raise HTTPException(400, 'Upload one ZIP or up to two manifest files.')
    if len(files) > 1 and any((f.filename or '').endswith('.zip') for f in files):
        raise HTTPException(400, 'Upload a ZIP on its own.')
    contents, warnings = {}, []
    total = 0
    try:
        for file in files:
            data = await file.read(ingestion.MAX_UPLOAD + 1)
            total += len(data)
            if total > ingestion.MAX_UPLOAD:
                raise ValueError('Combined upload exceeds 10 MB.')
            parsed, skipped = await asyncio.to_thread(ingestion.uploaded, file.filename or '', data)
            if contents.keys() & parsed.keys():
                raise ValueError('Duplicate input names.')
            contents.update(parsed)
            warnings += skipped
    except Exception as error:
        raise HTTPException(400, str(error)[:300] if isinstance(error, ValueError) else 'Invalid or unsupported archive.')
    return submit(lambda: (contents, warnings), 'upload', profile)

@app.post('/api/scans/package', status_code=202)
def package(request: PackageRequest):
    return submit(lambda: RegistrySession(Budget.from_env(request.profile)).retrieve(request.name, request.version), 'npm registry', request.profile)

@app.get('/api/examples')
def examples():
    return [{'id':p.name,'name':json.loads((p/'package.json').read_text())['name']} for p in sorted(FIXTURES.iterdir()) if p.is_dir() and (p/'package.json').exists()]

@app.post('/api/scans/example/{example}', status_code=202)
def example(example: str):
    available = {p.name:p for p in FIXTURES.iterdir() if p.is_dir()}
    if example not in available:
        raise HTTPException(404, 'Example not found')
    return submit(lambda: ({str(p.relative_to(available[example])):p.read_text() for p in available[example].rglob('*') if p.is_file()}, ['Synthetic demonstration fixture; this is not a real-world malware sample.']), 'synthetic fixture')

@app.get('/api/jobs/{job_id}')
def job(job_id: str):
    with LOCK:
        state = JOBS.get(job_id)
        if state:
            return dict(state)
    if storage.get(job_id):
        return {'id':job_id,'status':'complete','stage':'Complete'}
    raise HTTPException(404, 'Scan not found; an unfinished scan may have been interrupted by a server restart.')

@app.get('/api/scans/{scan_id}')
def report(scan_id: str):
    result = storage.get(scan_id)
    if not result:
        raise HTTPException(404, 'Report not found')
    return result

@app.post('/api/scans/{scan_id}/explain')
def explain(scan_id: str, question: Question):
    result = report(scan_id)
    if question.finding_id and not any(f.id == question.finding_id for f in result.findings):
        raise HTTPException(404, 'Finding not found')
    return EvidenceExplainer().answer(result, question.question, question.finding_id)

@app.post('/api/jobs/{job_id}/cancel')
def cancel_job(job_id: str):
    with LOCK:
        state = JOBS.get(job_id)
        if not state:
            raise HTTPException(404, 'Scan job not found')
        if state['status'] in ('complete', 'failed', 'cancelled'):
            return dict(state)
        if state['status'] in ('queued', 'running'):
            CANCELLATIONS[job_id].set()
            state.update(status='cancelling', stage='Cancelling scan...')
            return dict(state)
        if state['status'] == 'cancelling':
            return dict(state)
        return dict(state)
