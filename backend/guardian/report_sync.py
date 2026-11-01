"""Allowlisted, idempotent cloud representation of the existing report contract."""
from .models import Report
from .redact import redact_data

NOTICE = 'Explicit account sync: source snippets were withheld and potential credentials redacted. Submitted evidence was not independently rescanned.'


def prepare_report(report):
    data = report.model_dump(mode='json')
    for finding in data['findings']:
        for evidence in finding['evidence']:
            evidence['snippet'] = '[Source snippet withheld during synchronization]'
        for flow in finding['data_flows']:
            for step in flow['steps']:
                step['snippet'] = '[Source snippet withheld during synchronization]'
    # These flexible dictionaries are not a source-code or arbitrary-data upload channel.
    allowed = {
        'behavior': {'risk','headline','rationale','coverage_status','files_inspected'},
        'vulnerabilities': {'count','status','rationale'},
        'integrity': {'concerns','root_status'},
        'inspection': {'total','direct','transitive','inspected','skipped','unavailable','unresolved','integrity_failed','not_attempted','status','rationale','packages_with_findings','profile','registry_requests','downloaded_bytes','elapsed_ms'},
    }
    data['assessments'] = {area: {key:value for key,value in values.items() if key in allowed[area] and isinstance(value,(str,int,float,bool,type(None)))} for area,values in data['assessments'].items() if area in allowed and isinstance(values,dict)}
    if data.get('cli'):
        for decision in [data['cli'].get('decision',{})] + data['cli'].get('packages',[]):
            if 'policy' not in decision: continue
            policy = decision['policy']
            decision['policy'] = {key:value for key,value in policy.items() if key in {'block_severity','block_confidence','require_intelligence'} and isinstance(value,(str,bool))}
        data['cli']['sync'] = 'explicit account synchronization'
    data['project_id'] = None  # browser filesystem handles/project access never cross this boundary
    if NOTICE not in data['coverage']:
        data['coverage'].insert(0,NOTICE)
    return Report.model_validate(redact_data(data))
