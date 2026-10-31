"""Explicit local report import. This module is not an account or cloud service."""
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from .models import Report
from .redact import redact_data
from . import storage

router = APIRouter(prefix='/api/cli', tags=['CLI'])


@router.get('/capabilities')
def capabilities():
    return {
        'local_import': True,
        'authentication': False,
        'synchronization': False,
        'reason': 'Guardian has no account identity or revocable device-token service. '
                  'Export a CLI JSON report and explicitly import it into the local website. '
                  'GitHub installation sessions are not Guardian accounts.',
    }


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    report: Report
    consent: bool = False


@router.post('/reports', status_code=201)
def import_report(request: ImportRequest):
    if not request.consent:
        raise HTTPException(400, 'Explicit consent is required to save a CLI report in this local website.')
    incoming = request.report
    if not incoming.cli or incoming.cli.get('schema_version') != '1.0':
        raise HTTPException(400, 'Expected a Guardian CLI report with supported schema version 1.0.')
    if len(incoming.model_dump_json().encode('utf-8')) > 8 * 1024 * 1024:
        raise HTTPException(413, 'CLI report exceeds the 8 MB import limit.')
    # Imported JSON is evidence supplied by the user, never a new trusted scan.
    # Allocate a new identity so it cannot replace an existing scan or GitHub report.
    report = Report.model_validate(redact_data(incoming.model_dump()))
    report.id = uuid4().hex
    report.source = 'CLI report import (local; not reverified)'
    report.source_metadata = None
    report.project_id = None
    report.cli = dict(report.cli or {})
    report.cli['imported_scan_id'] = incoming.id
    report.cli['imported'] = True
    report.cli['sync'] = 'local import by explicit consent'
    report.coverage.insert(0, 'Imported CLI report: findings, hashes and installation claims were not independently reverified by this website. Potential credentials were redacted.')
    storage.save(report)
    return report
