"""Exact-version batch matches with bounded, cached advisory enrichment."""
import os
import re
import time
from urllib.parse import quote, urlparse
import httpx
from .engine import finding
from .models import Evidence, Advisory

EXACT = re.compile(r'^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')
SEVERITIES = {'LOW': 'low', 'MODERATE': 'medium', 'MEDIUM': 'medium', 'HIGH': 'high', 'CRITICAL': 'critical'}
VALID_CVSS_TYPES = {'CVSS_V2', 'CVSS_V3', 'CVSS_V4'}

def check_osv(dependencies):
    if os.getenv('GUARDIAN_OSV_ENABLED', 'true').lower() != 'true':
        return [], 'disabled', ['OSV intelligence disabled; known vulnerabilities were not checked.']
    unique = {(d.name, d.version): d for d in dependencies}
    eligible = [d for d in unique.values() if EXACT.fullmatch(d.version)]
    warnings = []
    if len(eligible) != len(unique):
        warnings.append('OSV checks only exact versions. Upload a lockfile to resolve dependency ranges.')
    if not eligible:
        return [], 'not checked', warnings + ['No exact package versions available for OSV.']
    if len(eligible) > 100:
        warnings.append('OSV checks limited to the first 100 exact dependency versions.')
    started = time.monotonic()
    details = {}
    findings = []
    try:
        response = httpx.post(
            'https://api.osv.dev/v1/querybatch',
            json={'queries': [{'package': {'name': d.name, 'ecosystem': 'npm'}, 'version': d.version} for d in eligible[:100]]},
            timeout=12,
            follow_redirects=False
        )
        response.raise_for_status()
        if len(response.content) > 4 * 1024 * 1024:
            raise ValueError('OSV batch response exceeded 4 MB limit.')
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get('results'), list):
            raise ValueError('Invalid OSV batch response structure.')
        results = data['results']
        if len(results) != len(eligible[:100]):
            raise ValueError('Incomplete OSV query-to-result response count.')
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return [], 'unavailable', warnings + ['OSV could not be reached or returned an invalid response. Vulnerability status is unknown.']

    for dep, result in zip(eligible[:100], results):
        if not isinstance(result, dict):
            warnings.append(f'Invalid OSV batch entry for {dep.name}; status unknown.')
            continue
        if result.get('next_page_token'):
            warnings.append(f'{dep.name}: OSV reported additional unpaginated advisories; vulnerability assessment is partial.')
        vulns = result.get('vulns', [])
        if not isinstance(vulns, list):
            warnings.append(f'Invalid advisory list for {dep.name}; status unknown.')
            continue
        if len(vulns) > 30:
            warnings.append(f'OSV findings capped at 30 advisories for {dep.name}.')
        for vuln in vulns[:30]:
            vid = vuln.get('id') if isinstance(vuln, dict) else None
            if not isinstance(vid, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,150}', vid):
                warnings.append('OSV returned an unsupported advisory ID.')
                continue
            if vid not in details:
                details[vid] = None
                remaining_time = 20 - (time.monotonic() - started)
                if sum(v is not None for v in details.values()) < 12 and len(details) <= 12 and remaining_time > 0.5:
                    try:
                        r = httpx.get(
                            'https://api.osv.dev/v1/vulns/' + quote(vid, safe=''),
                            timeout=max(0.1, min(5.0, remaining_time)),
                            follow_redirects=False
                        )
                        r.raise_for_status()
                        if len(r.content) > 2 * 1024 * 1024:
                            raise ValueError('Advisory response too large')
                        detail = r.json()
                        if not isinstance(detail, dict) or detail.get('id') != vid:
                            raise ValueError('Advisory ID mismatch')
                        details[vid] = detail
                    except (httpx.HTTPError, ValueError, TypeError):
                        warnings.append(f'{vid}: advisory details unavailable; batch match retained.')
                else:
                    warnings.append(f'{vid}: advisory enrichment budget reached; batch match retained.')
            detail = details[vid]
            advisory = Advisory(id=vid)
            refs = ['https://osv.dev/vulnerability/' + vid]
            priority = 'medium'
            confidence = 'high'
            observed_desc = f'{vid} matches {dep.name}@{dep.version}'
            action = 'Read the advisory and upgrade to a verified fixed version. Test compatibility before deploying.'
            if detail:
                if detail.get('withdrawn'):
                    warnings.append(f'{vid} is withdrawn; not counted as an active vulnerability.')
                    continue
                affected = [
                    a for a in detail.get('affected', [])
                    if isinstance(a, dict)
                    and isinstance(a.get('package'), dict)
                    and a.get('package', {}).get('name') == dep.name
                    and a.get('package', {}).get('ecosystem') == 'npm'
                ]
                if not affected:
                    warnings.append(f'{vid}: advisory detail package mismatch (expected npm package {dep.name}); details refused.')
                    observed_desc = f'{vid} (unverified details) matches {dep.name}@{dep.version}'
                else:
                    advisory.detail_status = 'available'
                    confidence = 'high'
                    advisory.summary = str(detail.get('summary', ''))[:2000] or None
                    severity_records = [s for s in detail.get('severity', []) if isinstance(s, dict)]
                    for entry in affected:
                        severity_records.extend(s for s in entry.get('severity', []) if isinstance(s, dict))
                    advisory.cvss = [
                        {'type': str(s['type'])[:40], 'score': str(s['score'])[:300]}
                        for s in severity_records
                        if isinstance(s.get('type'), str) and s.get('type') in VALID_CVSS_TYPES and isinstance(s.get('score'), str) and bool(s.get('score').strip())
                    ][:10]
                    supplied = detail.get('database_specific', {}).get('severity') if isinstance(detail.get('database_specific'), dict) else None
                    if not supplied:
                        supplied = next((a.get('database_specific', {}).get('severity') for a in affected if isinstance(a.get('database_specific'), dict) and a.get('database_specific', {}).get('severity')), None)
                    if isinstance(supplied, str) and supplied.upper() in SEVERITIES:
                        advisory.severity = supplied.upper()
                        priority = SEVERITIES[supplied.upper()]
                    advisory.affected_ranges = [r for a in affected for r in a.get('ranges', []) if isinstance(r, dict)][:20]
                    advisory.fixed_versions = sorted({
                        str(event['fixed'])[:50]
                        for r in advisory.affected_ranges
                        for event in r.get('events', [])
                        if isinstance(event, dict) and isinstance(event.get('fixed'), str) and 1 <= len(event['fixed']) <= 50 and re.fullmatch(r'[0-9A-Za-z.+_-]+', event['fixed'])
                    })[:20]
                    advisory.aliases = [a[:100] for a in detail.get('aliases', []) if isinstance(a, str) and 1 <= len(a) <= 100][:20]
                    for r in detail.get('references', []):
                        if isinstance(r, dict) and isinstance(r.get('url'), str):
                            u = r['url']
                            parsed_u = urlparse(u)
                            if parsed_u.scheme == 'https' and bool(parsed_u.netloc):
                                refs.append(u)
                    refs = list(dict.fromkeys(refs))[:15]
                    if advisory.fixed_versions:
                        action = 'The advisory lists fixed release boundaries: ' + ', '.join(advisory.fixed_versions) + '. Confirm which affected range applies to your version and test a compatible upgrade.'
            f = finding(
                'OSV',
                f'{dep.name}: known vulnerability',
                'Known vulnerability',
                priority,
                confidence,
                observed_desc,
                advisory.summary or 'A vulnerability database lists a published security issue for this exact package version.',
                'Impact depends on the advisory and how the package is used. Guardian review priority is not the advisory’s CVSS severity; absent advisory severity uses a medium review default.',
                action,
                [Evidence(file=dep.source, snippet=f'{dep.name}@{dep.version}', detail=vid)],
                refs
            )
            f.domain = 'vulnerability'
            f.advisory = advisory
            f.package = f'{dep.name}@{dep.version}'
            f.limitations = [
                'Exact version batch match does not prove exploitability in this project.',
                'Fixed boundaries can belong to different affected ranges; no upgrade compatibility is inferred.'
            ]
            if advisory.detail_status != 'available':
                f.limitations.append('Advisory enrichment was unavailable; affected ranges and fixed versions could not be verified.')
            findings.append(f)
    unique_warnings = list(dict.fromkeys(warnings))
    status = 'partial' if unique_warnings else 'checked'
    return findings, status, unique_warnings
