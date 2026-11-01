import asyncio
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from fastapi import FastAPI, File, HTTPException, UploadFile, Form, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from . import ingestion, storage, advisor, github
from .core import analyze_sources as analyze
from .engine import assess, RANK, finding
from .cli_bridge import router as cli_router
from .account_api import router as account_router
from .explanations import EvidenceExplainer
from .intelligence import check_osv
from .models import Dependency, PackageRequest, Question, Report, Evidence, AskRequest, AdvisorResponse, FindingCitation, AIStatus
from .remediation_models import (
    ProjectIngestRequest,
    PlanGenerationRequest,
    PlanApprovalRequest,
    PlanAppliedRecord,
    PlanRevertedRecord,
    VerificationResult,
    VerificationRequest,
    RemediationPlan,
    ProjectMetadata
)
from .projects import project_manager
from .remediation import remediation_planner
from .handoff import handoff_service
from .handoff_models import HandoffRequest, HandoffExportResponse, HandoffTarget, RemediationMode
from .limits import RequestSizeLimit
from .dependencies import RegistrySession, Retrieved, inspect_dependencies
from .config import Budget
from typing import Literal, Optional

app = FastAPI(title='Guardian', version='0.1.0')
app.include_router(cli_router)
app.include_router(account_router)
app.add_middleware(RequestSizeLimit)
app.add_middleware(CORSMiddleware, allow_origins=[origin.strip() for origin in os.getenv('GUARDIAN_ALLOWED_ORIGINS','http://localhost:3000,http://127.0.0.1:3000').split(',') if origin.strip()], allow_credentials=True, allow_methods=['GET','POST','DELETE','PATCH'], allow_headers=['Authorization','Content-Type','X-Guardian-Session'])
JOBS = {}
CANCELLATIONS = {}
JOB_INSTALLATIONS = {}
REMEDIATION_JOBS = {}
LOCK = threading.Lock()
SLOTS = threading.BoundedSemaphore(2)
FIXTURES = Path(__file__).resolve().parents[2] / 'fixtures'

def stage(job_id, label):
    with LOCK:
        if job_id in JOBS and JOBS[job_id]['status'] in ('queued', 'running'):
            JOBS[job_id]['stage'] = label

def run(job_id, loader, source, profile, classification='real', project_id=None, source_metadata=None):
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
        elif isinstance(loaded, tuple) and len(loaded) == 4:
            files, warnings, dyn_meta, dyn_source = loaded
            if dyn_meta is not None:
                source_metadata = dyn_meta
            if dyn_source:
                source = dyn_source
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
            eco = 'pypi' if (source == 'pypi registry' or (root_result and root_result.metadata.get('ecosystem') == 'pypi')) else 'npm'
            query_deps.append(Dependency(name=name, version=version, source='pypi' if eco == 'pypi' else 'package.json', ecosystem=eco))
        query_deps += [Dependency(name=n.name, version=n.version, direct=n.direct, source=n.location, ecosystem=getattr(n, 'ecosystem', 'npm')) for n in inspections]
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

        elevated_behavioral = [f for f in findings if f.domain == 'behavior' and f.rule != 'OSV' and f.severity != 'info']
        if elevated_behavioral:
            behavior_headline = risk
        elif count == 0 or is_manifest_only or (inspection_summary and inspection_summary.total > 0 and inspection_summary.inspected == 0 and count == 0):
            behavior_headline = "Behavioral assessment unavailable."
            rationale = "No package or dependency source code was inspected. Review coverage and dependency details before making a trust decision."
        elif source_coverage_incomplete:
            behavior_headline = "No elevated signals in inspected content."
        else:
            behavior_headline = "No elevated behavioral signals."

        report = Report(
            id=job_id,
            name=name,
            version=version,
            created_at=datetime.now(timezone.utc).isoformat(),
            source=source,
            classification=classification,
            project_id=project_id,
            source_metadata=source_metadata,
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
                    'headline': behavior_headline,
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
        project_manager.discard_snapshot(job_id)
        # Do not include server paths, credentials, or raw upstream responses.
        message = str(error) if isinstance(error, ValueError) else 'Could not inspect this input. Check the archive, package name, version, and network access.'
        with LOCK:
            if not (CANCELLATIONS[job_id].is_set() or JOBS[job_id]['status'] in ('cancelling', 'cancelled')):
                JOBS[job_id].update(status='failed', stage='Stopped', error=message[:400])
    finally:
        with LOCK:
            if CANCELLATIONS.get(job_id) and CANCELLATIONS[job_id].is_set():
                project_manager.discard_snapshot(job_id)
                JOBS[job_id].update(status='cancelled', stage='Scan cancelled')
        SLOTS.release()

def submit(loader, source, profile="fast", job_id=None, classification=None, project_id=None, source_metadata=None):
    if not SLOTS.acquire(blocking=False):
        raise HTTPException(429, 'Two scans are already running. Try again shortly.')
    if not job_id:
        job_id = uuid4().hex
    if classification is None:
        classification = 'demo' if source == 'synthetic fixture' else 'real'
    with LOCK:
        # Only retain the most recent completed job states; reports stay in SQLite.
        if len(JOBS) >= 100:
            for old in list(JOBS):
                if JOBS[old]['status'] not in ('queued', 'running', 'cancelling'):
                    del JOBS[old]
                    CANCELLATIONS.pop(old, None)
                    JOB_INSTALLATIONS.pop(old, None)
                    break
        JOBS[job_id] = {'id':job_id, 'status':'queued', 'stage':'Queued'}
        CANCELLATIONS[job_id] = threading.Event()
    threading.Thread(target=run, args=(job_id, loader, source, profile, classification, project_id, source_metadata), daemon=True).start()
    return {'id':job_id}

@app.get('/api/health')
def health():
    return {'status':'ok', 'engine':'guardian-static-v2'}

@app.post('/api/session/init')
def session_init(request: Request, response: Response):
    sid = request.cookies.get("guardian_session")
    is_new = True
    if sid:
        sess = storage.get_session(sid)
        if sess:
            storage.touch_session(sid)
            is_new = False
        else:
            sid = storage.create_session(ttl_days=30)
    else:
        sid = storage.create_session(ttl_days=30)

    response.set_cookie(
        key="guardian_session",
        value=sid,
        max_age=86400 * 30,
        httponly=True,
        samesite="lax",
        path="/"
    )
    return {"initialized": True, "new": is_new}

@app.get('/api/session/status')
def session_status(request: Request):
    sid = request.cookies.get("guardian_session")
    if sid and storage.get_session(sid):
        storage.touch_session(sid)
        return {"valid": True}
    return {"valid": False}

@app.post('/api/session/adopt')
def session_adopt(body: dict):
    session_token = body.get("session_token")
    if not session_token or not storage.get_session(session_token):
        raise HTTPException(400, "Invalid or expired session token")
    storage.touch_session(session_token)
    response = JSONResponse(content={"status": "ok", "session_id": session_token})
    response.set_cookie(
        key="guardian_session",
        value=session_token,
        max_age=86400 * 30,
        httponly=True,
        samesite="lax",
        path="/"
    )
    return response

@app.get('/api/scans')
def scans(request: Request):
    accessible = []
    for rep in storage.recent():
        try:
            _verify_scan_access(rep, request)
            accessible.append(rep)
        except HTTPException:
            continue
    return accessible

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
    return submit(lambda: (contents, warnings), 'upload', profile, classification='real')

@app.post('/api/scans/package', status_code=202)
def package(request: PackageRequest):
    if getattr(request, 'ecosystem', 'npm') == 'pypi':
        from .pypi import PyPISession
        return submit(
            lambda: PyPISession(Budget.from_env(request.profile)).retrieve(request.name, request.version),
            'pypi registry',
            request.profile,
            classification='real',
            project_id=f"pypi:{request.name}"
        )
    return submit(lambda: RegistrySession(Budget.from_env(request.profile)).retrieve(request.name, request.version), 'npm registry', request.profile, classification='real', project_id=f"pkg:{request.name}")

@app.get('/api/examples')
def examples():
    result = []
    for p in sorted(FIXTURES.iterdir()):
        if not p.is_dir():
            continue
        if (p / 'package.json').exists():
            try:
                name = json.loads((p / 'package.json').read_text(encoding='utf-8'))['name']
                result.append({'id': p.name, 'name': name})
            except Exception:
                pass
        elif (p / 'pyproject.toml').exists() or (p / 'requirements.txt').exists():
            result.append({'id': p.name, 'name': f'{p.name} (PyPI)'})
    return result

@app.post('/api/scans/example/{example}', status_code=202)
def example(example: str):
    available = {p.name:p for p in FIXTURES.iterdir() if p.is_dir()}
    if example not in available:
        raise HTTPException(404, 'Example not found')
    return submit(lambda: ({str(p.relative_to(available[example])):p.read_text() for p in available[example].rglob('*') if p.is_file()}, ['Synthetic demonstration fixture; this is not a real-world malware sample.']), 'synthetic fixture', classification='demo', project_id=f"demo:{example}")

@app.get('/api/jobs/{job_id}')
def job(job_id: str):
    with LOCK:
        state = JOBS.get(job_id)
        if state:
            return dict(state)
    if storage.get(job_id):
        return {'id':job_id,'status':'complete','stage':'Complete'}
    raise HTTPException(404, 'Scan not found; an unfinished scan may have been interrupted by a server restart.')

class BatchDeleteScansRequest(BaseModel):
    scan_ids: list[str]

@app.get('/api/scans/{scan_id}')
def report(scan_id: str):
    result = storage.get(scan_id)
    if not result:
        raise HTTPException(404, 'Report not found')
    return result

@app.delete('/api/scans/{scan_id}')
def delete_scan(scan_id: str, request: Request):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Scan not found')
    _verify_scan_access(rep, request)

    with LOCK:
        if scan_id in JOBS:
            del JOBS[scan_id]
        CANCELLATIONS.pop(scan_id, None)
    JOB_INSTALLATIONS.pop(scan_id, None)
    project_manager.discard_snapshot(scan_id)

    success = storage.delete_scan(scan_id)
    if not success:
        raise HTTPException(404, 'Scan not found')
    return {'status': 'deleted', 'id': scan_id}

@app.post('/api/scans/delete-batch')
def delete_scans_batch(batch_req: BatchDeleteScansRequest, request: Request):
    if not batch_req.scan_ids:
        raise HTTPException(400, 'scan_ids list cannot be empty')

    to_delete = []
    unauthorized = False
    for sid in batch_req.scan_ids:
        rep = storage.get(sid)
        if not rep:
            continue
        try:
            _verify_scan_access(rep, request)
            to_delete.append(sid)
        except HTTPException:
            unauthorized = True

    if unauthorized and not to_delete:
        raise HTTPException(403, 'Unauthorized to delete the requested scans')

    for sid in to_delete:
        with LOCK:
            if sid in JOBS:
                del JOBS[sid]
            CANCELLATIONS.pop(sid, None)
        JOB_INSTALLATIONS.pop(sid, None)
        project_manager.discard_snapshot(sid)

    deleted = storage.delete_scans(to_delete)
    return {'status': 'deleted', 'deleted_count': len(deleted), 'deleted_ids': deleted}

@app.get('/api/ai/status')
def ai_status():
    return advisor.get_ai_status()

@app.get('/api/scans/{scan_id}/conversation')
def get_conversation(scan_id: str):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')
    return storage.get_or_create_conversation(scan_id)

@app.post('/api/scans/{scan_id}/conversation/message')
def conversation_message(scan_id: str, request: AskRequest):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')
    if request.finding_id and not any(f.id == request.finding_id for f in rep.findings):
        raise HTTPException(404, 'Finding not found')

    conv = storage.get_or_create_conversation(scan_id, request.conversation_id)
    cfg = advisor.get_ai_config()
    if len(conv.messages) >= cfg['max_turns'] * 2:
        raise HTTPException(429, f"Conversation limit of {cfg['max_turns']} turns reached for this session. Please start a new conversation.")

    # Save user message locally
    storage.save_message(
        scan_id=scan_id,
        conversation_id=conv.id,
        role='user',
        content=request.question
    )

    # Generate answer from selected advisor (Gemini or Deterministic)
    adv = advisor.get_advisor(consent=request.consent)
    ans = adv.answer(
        report=rep,
        question=request.question,
        finding_id=request.finding_id,
        history=conv.messages,
        mode=request.mode
    )

    # Save assistant message locally
    citations = [FindingCitation.model_validate(c) for c in ans.get('citations', [])]
    assistant_msg = storage.save_message(
        scan_id=scan_id,
        conversation_id=conv.id,
        role='assistant',
        content=ans.get('answer', ''),
        citations=citations,
        limitations=ans.get('limitations', []),
        suggested_followups=ans.get('suggested_followups', []),
        provider=ans.get('provider', 'deterministic'),
        model=ans.get('model')
    )

    return AdvisorResponse(
        answer=ans.get('answer', ''),
        citations=citations,
        limitations=ans.get('limitations', []),
        suggested_followups=ans.get('suggested_followups', []),
        provider=ans.get('provider', 'deterministic'),
        model=ans.get('model'),
        conversation_id=conv.id,
        message_id=assistant_msg.id
    )

@app.delete('/api/scans/{scan_id}/conversation')
def clear_conversation(scan_id: str):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')
    storage.clear_conversation(scan_id)
    return {'status': 'cleared'}

@app.post('/api/scans/{scan_id}/conversation/new')
def new_conversation(scan_id: str):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')
    return storage.new_conversation(scan_id)

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

@app.post('/api/scans/project', status_code=202)
def scan_project(request: ProjectIngestRequest):
    if not request.files:
        raise HTTPException(400, 'Project must contain at least one file.')
    job_id = uuid4().hex
    try:
        snapshot = project_manager.save_snapshot(job_id, request.name, request.files, project_id=request.project_id)
    except ValueError as err:
        raise HTTPException(400, str(err))

    try:
        return submit(lambda: (dict(snapshot.files), []), f"local project: {request.name}", profile=request.profile, job_id=job_id, classification='real', project_id=snapshot.project_id)
    except Exception:
        project_manager.discard_snapshot(job_id)
        raise

@app.get('/api/projects/{scan_id}/metadata')
def project_metadata(scan_id: str):
    snap = project_manager.get_snapshot(scan_id)
    if not snap:
        raise HTTPException(404, 'Project snapshot not found or has expired.')
    return snap.metadata

@app.delete('/api/projects/{scan_id}')
def discard_project(scan_id: str):
    discarded = project_manager.discard_snapshot(scan_id)
    return {'status': 'discarded' if discarded else 'not_found'}

def _get_session_id(request: Request) -> Optional[str]:
    """Reads session ID strictly from the HttpOnly guardian_session cookie and validates it in SQLite."""
    sid = request.cookies.get("guardian_session")
    if not sid:
        return None
    sess = storage.get_session(sid)
    if not sess:
        return None
    storage.touch_session(sid)
    return sid

def _verify_scan_access(rep: Report, request: Request) -> None:
    """Ensures GitHub-backed reports respect session installation authorization."""
    if rep.source_metadata and rep.source_metadata.source_type == "github":
        session_id = _require_github_session(request)
        installation_id = rep.source_metadata.installation_id
        if installation_id is None:
            raise HTTPException(403, 'This legacy GitHub report lacks installation authorization metadata. Rescan the repository to bind access securely.')
        if not storage.is_installation_authorized_for_session(session_id, installation_id):
            raise HTTPException(403, 'This session is not authorized for the installation associated with this GitHub report.')


def _require_github_session(request: Request) -> str:
    session_id = _get_session_id(request)
    if not session_id:
        raise HTTPException(401, 'GitHub session is missing, invalid or expired. Connect GitHub in this browser session.')
    return session_id


@app.middleware('http')
async def account_deployment_boundary(request: Request, call_next):
    path = request.url.path
    if path.startswith('/api/account/') and request.method == 'POST':
        limit = 8 * 1024 * 1024 + 262144 if path == '/api/account/scans' else 65536
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > limit:
                return JSONResponse({'detail':'Account request exceeded its size limit.'},status_code=413)
        request._body = bytes(body)
    if os.getenv('GUARDIAN_CLOUD_MODE', 'false').lower() == 'true':
        if not (path == '/api/health' or path.startswith('/api/account/') or request.method == 'OPTIONS'):
            return JSONResponse({'detail': 'This deployment serves account/device/report sync. Use the local Guardian service for source uploads and GitHub App workspaces.'}, status_code=403)
    response = await call_next(request)
    if request.url.path.startswith('/api/account/'):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.middleware('http')
async def protect_github_resources(request: Request, call_next):
    """One HTTP boundary protects reports, exports, plans, snapshots and active jobs."""
    parts = request.url.path.strip('/').split('/')
    try:
        if len(parts) >= 3 and parts[:2] == ['api', 'github']:
            is_link = (len(parts) == 5 and parts[2] == 'installations' and parts[4] == 'link')
            if not is_link and (parts[2] not in {'status', 'installations', 'connect', 'callback'} or len(parts) > 3):
                _require_github_session(request)
        if parts[:3] == ['api', 'scans', 'github']:
            _require_github_session(request)
        scan_id = None
        if len(parts) >= 3 and parts[:2] in (['api', 'scans'], ['api', 'jobs']):
            scan_id = parts[2]
        elif len(parts) >= 3 and parts[:2] == ['api', 'projects']:
            scan_id = parts[2]
        elif len(parts) >= 4 and parts[:3] == ['api', 'remediation', 'plans']:
            plan = storage.get_plan(parts[3])
            if plan:
                scan_id = plan.scan_id
                if plan.repository_id and not storage.get(scan_id):
                    # Orphan plans cannot fall back to global installation credentials.
                    session_id = _require_github_session(request)
                    try:
                        github.get_repository(plan.repository_id, session_id=session_id)
                    except Exception:
                        raise HTTPException(403, 'This session cannot access the plan repository.')
        if scan_id:
            rep = storage.get(scan_id)
            if rep:
                _verify_scan_access(rep, request)
            installation_id = JOB_INSTALLATIONS.get(scan_id)
            if installation_id is not None:
                session_id = _require_github_session(request)
                if not storage.is_installation_authorized_for_session(session_id, installation_id):
                    raise HTTPException(403, 'This GitHub scan belongs to another installation.')
    except HTTPException as error:
        return JSONResponse({'detail': error.detail}, status_code=error.status_code)
    return await call_next(request)

@app.post('/api/scans/{scan_id}/handoff', response_model=HandoffExportResponse)
def generate_handoff(scan_id: str, request_body: HandoffRequest, request: Request):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')

    _verify_scan_access(rep, request)

    # Phase 1: Strict input validation on finding_ids
    if request_body.finding_ids is not None:
        if len(request_body.finding_ids) == 0:
            raise HTTPException(400, "finding_ids cannot be an empty list. Specify valid finding IDs or omit the field to include the entire scan.")
        valid_ids = {f.id for f in rep.findings}
        invalid = [fid for fid in request_body.finding_ids if fid not in valid_ids]
        if invalid:
            raise HTTPException(404, f"Findings not found in scan: {invalid}")

    # Optional project metadata if available
    snap = project_manager.get_snapshot(scan_id)
    proj_meta = snap.metadata if snap else None

    try:
        return handoff_service.export_bundle(
            report=rep,
            target=request_body.target,
            mode=request_body.mode,
            finding_ids=request_body.finding_ids,
            project_metadata=proj_meta,
        )
    except ValueError as err:
        raise HTTPException(400, str(err))

@app.get('/api/scans/{scan_id}/handoff', response_model=HandoffExportResponse)
def get_handoff(
    scan_id: str,
    request: Request,
    target: HandoffTarget = 'universal',
    mode: RemediationMode = 'focused_fix',
    finding_id: Optional[str] = None
):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')

    _verify_scan_access(rep, request)

    finding_ids = [finding_id] if finding_id else None
    if finding_ids:
        valid_ids = {f.id for f in rep.findings}
        if finding_id not in valid_ids:
            raise HTTPException(404, f"Finding '{finding_id}' not found in scan")

    snap = project_manager.get_snapshot(scan_id)
    proj_meta = snap.metadata if snap else None

    try:
        return handoff_service.export_bundle(
            report=rep,
            target=target,
            mode=mode,
            finding_ids=finding_ids,
            project_metadata=proj_meta,
        )
    except ValueError as err:
        raise HTTPException(400, str(err))

@app.post('/api/scans/{scan_id}/remediation/jobs', status_code=202)
def queue_remediation_plan(scan_id: str, request: PlanGenerationRequest, req: Request):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')
    _verify_scan_access(rep, req)
    if request.finding_ids and set(request.finding_ids) - {f.id for f in rep.findings}:
        raise HTTPException(404, 'Findings not found in report')
    if not SLOTS.acquire(blocking=False):
        raise HTTPException(429, 'Two analysis jobs are already running. Try again shortly.')
    identifier = uuid4().hex
    with LOCK:
        if len(REMEDIATION_JOBS) >= 100:
            for old, state in list(REMEDIATION_JOBS.items()):
                if state['status'] in ('complete', 'failed'):
                    del REMEDIATION_JOBS[old]
                    break
        REMEDIATION_JOBS[identifier] = {'id': identifier, 'scan_id': scan_id, 'status': 'queued', 'stage': 'Queued'}

    def work():
        try:
            with LOCK:
                REMEDIATION_JOBS[identifier].update(status='running', stage='Resolving published versions, advisories and dependency graph')
            plan = create_remediation_plan(scan_id, request, req)
            with LOCK:
                REMEDIATION_JOBS[identifier].update(status='complete', stage='Complete', plan=plan.model_dump())
        except Exception as error:
            detail = str(error.detail) if isinstance(error, HTTPException) else f'Remediation planning failed ({type(error).__name__}): {error}'
            with LOCK:
                REMEDIATION_JOBS[identifier].update(status='failed', stage='Stopped', error=detail)
        finally:
            SLOTS.release()
    threading.Thread(target=work, daemon=True).start()
    return {'id': identifier, 'status': 'queued'}


@app.get('/api/remediation/jobs/{identifier}')
def get_remediation_job(identifier: str, req: Request):
    with LOCK:
        state = dict(REMEDIATION_JOBS.get(identifier, {}))
    if not state:
        raise HTTPException(404, 'Remediation job expired or backend restarted. Generate a fresh plan.')
    rep = storage.get(state['scan_id'])
    if not rep:
        raise HTTPException(404, 'Report not found')
    _verify_scan_access(rep, req)
    return state


@app.post('/api/scans/{scan_id}/remediation/plan')
def create_remediation_plan(scan_id: str, request: PlanGenerationRequest, req: Request):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')
    _verify_scan_access(rep, req)
    snap = project_manager.get_snapshot(scan_id)
    if not snap and rep.source_metadata and rep.source_metadata.source_type == "github":
        try:
            session_id = _get_session_id(req)
            if session_id:
                repo_full_name, files_dict, gh_meta, warnings = github.retrieve_repository_snapshot(
                    repo_id=rep.source_metadata.repository_id,
                    branch=rep.source_metadata.branch,
                    session_id=session_id
                )
                snap = project_manager.save_snapshot(
                    scan_id=scan_id,
                    name=repo_full_name,
                    raw_files=files_dict,
                    project_id=f"github:{rep.source_metadata.repository_id}"
                )
        except Exception as err:
            logger.warning(f"Could not re-retrieve GitHub snapshot for scan {scan_id}: {err}")

    if not snap:
        raise HTTPException(400, 'Project snapshot is not available or has expired (30-minute inactivity limit). Please rescan or reconnect the project to prepare a remediation plan.')

    # Validate finding_ids if passed
    if request.finding_ids:
        valid_ids = {f.id for f in rep.findings}
        invalid = [fid for fid in request.finding_ids if fid not in valid_ids]
        if invalid:
            raise HTTPException(404, f"Findings not found in report: {invalid}")

    plan = remediation_planner.generate_plan(
        report=rep,
        snapshot=snap,
        finding_ids=request.finding_ids,
        consent=request.consent,
        instructions=request.instructions
    )
    if rep.source_metadata:
        plan.repository_id = rep.source_metadata.repository_id
        plan.branch = rep.source_metadata.branch
        plan.commit_sha = rep.source_metadata.commit_sha
    storage.save_plan(plan)
    return plan

@app.get('/api/remediation/plans/{plan_id}')
def get_remediation_plan(plan_id: str, req: Request):
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(404, 'Remediation plan not found')
    rep = storage.get(plan.scan_id)
    if rep:
        _verify_scan_access(rep, req)
    return plan

@app.post('/api/remediation/plans/{plan_id}/approve')
def approve_remediation_plan(plan_id: str, req: Request):
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(404, 'Remediation plan not found')
    rep = storage.get(plan.scan_id)
    if rep:
        _verify_scan_access(rep, req)
    if getattr(plan, "validation_status", "VERIFIED") != "VERIFIED":
        reasons = "; ".join(getattr(plan, "validation_reasons", [])) or f"Plan validation status is '{plan.validation_status}'."
        raise HTTPException(400, f"Cannot approve remediation plan: {reasons}")
    try:
        plan = storage.update_plan_status(plan_id, 'approved')
    except ValueError as err:
        raise HTTPException(400, str(err))
    return plan

@app.post('/api/remediation/plans/{plan_id}/reject')
def reject_remediation_plan(plan_id: str, req: Request):
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(404, 'Remediation plan not found')
    rep = storage.get(plan.scan_id)
    if rep:
        _verify_scan_access(rep, req)
    try:
        plan = storage.update_plan_status(plan_id, 'rejected')
    except ValueError as err:
        raise HTTPException(400, str(err))
    return plan

@app.post('/api/remediation/plans/{plan_id}/applied')
def mark_plan_applied(plan_id: str, record: PlanAppliedRecord, req: Request):
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(404, 'Remediation plan not found')
    rep = storage.get(plan.scan_id)
    if rep:
        _verify_scan_access(rep, req)
    status = 'applied' if record.success else 'failed'
    try:
        plan = storage.update_plan_status(plan_id, status)
    except ValueError as err:
        raise HTTPException(400, str(err))
    return plan

@app.post('/api/remediation/plans/{plan_id}/revert')
@app.post('/api/remediation/plans/{plan_id}/reverted')
def mark_plan_reverted(plan_id: str, req: Request, record: Optional[PlanRevertedRecord] = None):
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(404, 'Remediation plan not found')
    rep = storage.get(plan.scan_id)
    if rep:
        _verify_scan_access(rep, req)
    try:
        plan = storage.update_plan_status(plan_id, 'reverted')
    except ValueError as err:
        raise HTTPException(400, str(err))
    return plan

@app.post('/api/remediation/plans/{plan_id}/verification')
def verify_remediation_plan(plan_id: str, req: VerificationRequest, request: Request):
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(404, 'Remediation plan not found')
    orig_rep = storage.get(plan.scan_id)
    if not orig_rep:
        raise HTTPException(404, 'Original report not found')
    _verify_scan_access(orig_rep, request)
    rescanned_rep = storage.get(req.rescanned_scan_id)
    if not rescanned_rep:
        raise HTTPException(404, 'Rescanned report not found')
    _verify_scan_access(rescanned_rep, request)

    rescanned_snapshot = project_manager.get_snapshot(req.rescanned_scan_id)
    if rescanned_snapshot:
        for change in plan.proposed_changes:
            if rescanned_snapshot.file_hashes.get(change.file_path) != change.proposed_sha256:
                raise HTTPException(400, f"Rescanned file '{change.file_path}' does not match the applied plan SHA-256. Rescan the modified project before verification.")

    try:
        storage.update_plan_status(plan_id, 'verified')
    except ValueError as err:
        raise HTTPException(400, str(err))

    verification = remediation_planner.verify_plan(plan, orig_rep, rescanned_rep)
    storage.save_verification(verification)
    return verification

@app.get('/api/remediation/plans/{plan_id}/verification')
def get_plan_verification(plan_id: str, req: Request):
    verification = storage.get_verification(plan_id)
    if not verification:
        raise HTTPException(404, 'Verification record not found')
    rep = storage.get(verification.scan_id)
    if rep:
        _verify_scan_access(rep, req)
    return verification

@app.get('/api/scans/{scan_id}/remediation/plans')
def get_scan_remediation_plans(scan_id: str, req: Request):
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')
    _verify_scan_access(rep, req)
    return storage.get_plans_for_scan(scan_id)
    rep = storage.get(scan_id)
    if not rep:
        raise HTTPException(404, 'Report not found')
    return storage.get_plans_for_scan(scan_id)

@app.get('/api/projects/{name:path}/remediation/history')
def get_project_remediation_history(name: str, request: Request):
    plans = storage.get_plans_for_project(name)
    history = []
    for plan in plans:
        rep = storage.get(plan.scan_id)
        if rep:
            try:
                _verify_scan_access(rep, request)
            except HTTPException:
                continue
        elif plan.repository_id:
            continue
        verification = storage.get_verification(plan.plan_id)
        history.append({
            'plan': plan,
            'verification': verification
        })
    return history

class GitHubScanRequest(BaseModel):
    repository_id: int
    branch: Optional[str] = None
    profile: Literal['fast', 'deep'] = 'fast'

@app.get('/api/github/status')
def github_status(request: Request):
    session_id = _get_session_id(request) or 'unauthenticated-http-session'
    return github.get_connection_status(session_id=session_id)

@app.get('/api/github/installations')
def github_installations(request: Request):
    session_id = _get_session_id(request) or 'unauthenticated-http-session'
    return github.list_installations(session_id=session_id)

@app.post('/api/github/installations/{installation_id}/select')
def select_github_installation(installation_id: int, request: Request):
    session_id = _get_session_id(request)
    try:
        return github.select_installation(installation_id, session_id=session_id)
    except ValueError as err:
        raise HTTPException(404, str(err))

@app.post('/api/github/installations/{installation_id}/link')
def link_github_installation(installation_id: int, request: Request):
    session_id = _get_session_id(request) or storage.create_session(ttl_days=30)
    try:
        res = github.link_installation(installation_id, session_id=session_id)
        response = JSONResponse(content=res)
        response.set_cookie(
            key="guardian_session",
            value=session_id,
            max_age=86400 * 30,
            httponly=True,
            samesite="lax",
            path="/"
        )
        return response
    except Exception as err:
        logger.error(f"Failed to link installation {installation_id}: {err}")
        raise HTTPException(400, f"Failed to link installation: {err}")

@app.post('/api/github/installations/{installation_id}/disconnect')
def disconnect_github_installation_endpoint(installation_id: int, request: Request):
    session_id = _get_session_id(request)
    try:
        return github.disconnect_installation(installation_id, session_id=session_id)
    except ValueError as err:
        raise HTTPException(400, str(err))

@app.post('/api/github/connect')
def github_connect(request: Request, response: Response):
    session_id = _get_session_id(request) or storage.create_session(ttl_days=30)
    try:
        result = github.create_connect_flow(session_id=session_id)
        response.set_cookie('guardian_session', session_id, max_age=86400 * 30, httponly=True, samesite='lax', path='/')
        return result
    except Exception as err:
        raise HTTPException(400, str(err))

@app.get('/api/github/callback')
def github_callback(
    request: Request,
    installation_id: Optional[int] = None,
    state: Optional[str] = None,
    setup_action: Optional[str] = None,
    code: Optional[str] = None
):
    session_id = _get_session_id(request) or github.get_state_session_id(state)
    if not session_id:
        session_id = storage.create_session(ttl_days=30)
    try:
        github.handle_installation_callback(installation_id=installation_id, state=state, session_id=session_id)
        host = request.headers.get("host", "")
        if ":8000" in host:
            session_token_param = f"&session_token={session_id}"
            redirect_url = os.getenv("GUARDIAN_FRONTEND_URL", "http://localhost:3000").rstrip('/') + f"/?github=connected{session_token_param}"
        else:
            redirect_url = "/?github=connected"
        response = RedirectResponse(url=redirect_url, status_code=302)
        response.set_cookie(
            key="guardian_session",
            value=session_id,
            max_age=86400 * 30,
            httponly=True,
            samesite="lax",
            path="/"
        )
        return response
    except Exception as err:
        raise HTTPException(400, f"GitHub installation callback failed: {err}")

@app.post('/api/github/sync')
def github_sync(request: Request):
    session_id = _require_github_session(request)
    try:
        res = github.sync_installations(session_id=session_id)
        response = JSONResponse(content=res)
        response.set_cookie(
            key="guardian_session",
            value=session_id,
            max_age=86400 * 30,
            httponly=True,
            samesite="lax",
            path="/"
        )
        return response
    except Exception as err:
        raise HTTPException(400, f"GitHub synchronization failed: {err}")

@app.post('/api/github/disconnect')
def github_disconnect(request: Request):
    session_id = _get_session_id(request)
    return github.disconnect_github(session_id=session_id)

@app.get('/api/github/repositories')
def github_repositories(request: Request, q: Optional[str] = None):
    session_id = _get_session_id(request)
    try:
        return github.list_repositories(query=q, session_id=session_id)
    except ValueError as err:
        raise HTTPException(400, str(err))
    except Exception as err:
        raise HTTPException(500, f"Failed to list repositories: {err}")

@app.get('/api/github/repositories/{repo_id}')
def github_repository(repo_id: int, request: Request):
    session_id = _get_session_id(request)
    try:
        return github.get_repository(repo_id, session_id=session_id)
    except ValueError as err:
        raise HTTPException(400, str(err))
    except Exception as err:
        raise HTTPException(500, f"Failed to retrieve repository metadata: {err}")

@app.get('/api/github/repositories/{repo_id}/branches')
def github_branches(repo_id: int, request: Request):
    session_id = _get_session_id(request)
    try:
        return github.list_branches(repo_id, session_id=session_id)
    except ValueError as err:
        raise HTTPException(400, str(err))
    except Exception as err:
        raise HTTPException(500, f"Failed to list branches: {err}")

@app.post('/api/scans/github', status_code=202)
def scan_github_repository(scan_req: GitHubScanRequest, request: Request):
    session_id = _require_github_session(request)
    # Pre-flight check: verify active GitHub installation exists
    try:
        github._resolve_active_installation_id(session_id)
    except ValueError as err:
        raise HTTPException(400, str(err))
    except Exception as err:
        raise HTTPException(502, f"GitHub connection error: {err}")

    job_id = uuid4().hex
    JOB_INSTALLATIONS[job_id] = github._resolve_active_installation_id(session_id)
    project_id = f"github:{scan_req.repository_id}"

    def github_loader():
        try:
            repo_full_name, files_dict, gh_meta, warnings = github.retrieve_repository_snapshot(
                repo_id=scan_req.repository_id,
                branch=scan_req.branch,
                session_id=session_id
            )
        except Exception as err:
            raise ValueError(f"GitHub repository retrieval failed: {err}") from err

        snapshot = project_manager.save_snapshot(
            scan_id=job_id,
            name=repo_full_name,
            raw_files=files_dict,
            project_id=project_id
        )
        return dict(snapshot.files), warnings, gh_meta, f"github: {repo_full_name}@{gh_meta.branch}"

    try:
        return submit(
            loader=github_loader,
            source=f"github: {scan_req.repository_id}@{scan_req.branch or 'default'}",
            profile=scan_req.profile,
            job_id=job_id,
            classification='real',
            project_id=project_id,
        )
    except Exception:
        JOB_INSTALLATIONS.pop(job_id, None)
        project_manager.discard_snapshot(job_id)
        raise

@app.post('/api/remediation/plans/{plan_id}/apply-github')
def apply_remediation_github(plan_id: str, request: Request):
    session_id = _get_session_id(request)
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(404, 'Remediation plan not found.')
    rep = storage.get(plan.scan_id)
    if rep:
        _verify_scan_access(rep, request)
    if not plan.repository_id:
        raise HTTPException(400, 'Remediation plan is not associated with a GitHub repository.')
    if getattr(plan, "validation_status", "VERIFIED") != "VERIFIED":
        reasons = "; ".join(getattr(plan, "validation_reasons", [])) or f"Plan validation status is '{plan.validation_status}'."
        raise HTTPException(400, f"Cannot apply remediation plan: {reasons}")

    try:
        res = github.apply_remediation_pull_request(plan, session_id=session_id)
        return res
    except ValueError as err:
        raise HTTPException(409 if "Pre-flight check failed" in str(err) else 400, str(err))
    except Exception as err:
        raise HTTPException(502, f"Failed to apply GitHub remediation: {err}")

@app.post('/api/remediation/plans/{plan_id}/close-github-pr')
def close_remediation_github_pr(plan_id: str, request: Request):
    session_id = _get_session_id(request)
    plan = storage.get_plan(plan_id)
    if not plan:
        raise HTTPException(404, 'Remediation plan not found.')
    rep = storage.get(plan.scan_id)
    if rep:
        _verify_scan_access(rep, request)
    if not plan.repository_id or not plan.pr_number:
        raise HTTPException(400, 'Remediation plan does not have an active GitHub pull request.')

    try:
        return github.close_remediation_pull_request(plan, session_id=session_id)
    except ValueError as err:
        raise HTTPException(400, str(err))
    except Exception as err:
        raise HTTPException(502, f"Failed to close pull request: {err}")



