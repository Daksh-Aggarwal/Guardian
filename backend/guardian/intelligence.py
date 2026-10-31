"""Exact-version batch matches with bounded, cached advisory enrichment."""
import os
import re
import time
from urllib.parse import quote, urlparse
import httpx
from .engine import finding
from .models import Evidence, Advisory

try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    Version = None

NPM_EXACT = re.compile(r'^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')
PYPI_EXACT = re.compile(r'^\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.+-]+)?$')
FORBIDDEN_VERSION_CHARS = re.compile(r'[><=~*^]|!=|,')

def is_exact_resolved_version(version: str, ecosystem: str = 'npm') -> bool:
    """Verifies that a version string represents an exact resolved version and not a range/constraint."""
    if not version or not isinstance(version, str):
        return False
    clean = version.strip()
    if clean in ('unresolved', 'latest', '*', '') or FORBIDDEN_VERSION_CHARS.search(clean):
        return False
    if ecosystem.lower() == 'pypi':
        if Version is not None:
            try:
                Version(clean)
                return True
            except InvalidVersion:
                return False
        return bool(PYPI_EXACT.fullmatch(clean))
    return bool(NPM_EXACT.fullmatch(clean))

EXACT = NPM_EXACT
SEVERITIES = {'LOW': 'low', 'MODERATE': 'medium', 'MEDIUM': 'medium', 'HIGH': 'high', 'CRITICAL': 'critical'}
VALID_CVSS_TYPES = {'CVSS_V2', 'CVSS_V3', 'CVSS_V4'}
MAX_BATCH_SIZE = 4 * 1024 * 1024
MAX_AGGREGATE_BATCH_BYTES = 8 * 1024 * 1024
MAX_PAGES = 5

def check_osv(dependencies):
    if os.getenv('GUARDIAN_OSV_ENABLED', 'true').lower() != 'true':
        return [], 'disabled', ['OSV intelligence disabled; known vulnerabilities were not checked.']
    unique = {(d.name, d.version): d for d in dependencies}
    eligible = [
        d for d in unique.values()
        if is_exact_resolved_version(d.version, getattr(d, 'ecosystem', 'npm'))
    ]
    warnings = []
    has_partial = False
    if len(eligible) != len(unique):
        warnings.append('OSV checks only exact versions. Upload a lockfile to resolve dependency ranges.')
        has_partial = True
    if not eligible:
        return [], 'not checked', warnings + ['No exact package versions available for OSV.']
    if len(eligible) > 100:
        warnings.append('OSV checks limited to the first 100 exact dependency versions.')
        has_partial = True

    started = time.monotonic()
    submitted = eligible[:100]
    batch_bytes = 0

    try:
        response = httpx.post(
            'https://api.osv.dev/v1/querybatch',
            json={'queries': [{'package': {'name': d.name, 'ecosystem': 'PyPI' if getattr(d, 'ecosystem', '').lower() == 'pypi' else 'npm'}, 'version': d.version} for d in submitted]},
            timeout=12,
            follow_redirects=False
        )
        response.raise_for_status()
        if len(response.content) > MAX_BATCH_SIZE:
            raise ValueError('OSV batch response exceeded 4 MB limit.')
        batch_bytes += len(response.content)
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get('results'), list):
            raise ValueError('Invalid OSV batch response structure.')
        results = data['results']
        if len(results) != len(submitted):
            raise ValueError('Incomplete OSV query-to-result response count.')
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as err:
        return [], 'unavailable', warnings + [f'OSV could not be reached or returned an invalid response ({err}). Vulnerability status is unknown.']

    dep_vulns = [[] for _ in submitted]
    dep_tokens = [None for _ in submitted]
    dep_pages = [1 for _ in submitted]
    seen_tokens = [set() for _ in submitted]

    for idx, (dep, result) in enumerate(zip(submitted, results)):
        if not isinstance(result, dict):
            warnings.append(f'Invalid OSV batch entry for {dep.name}; status unknown.')
            has_partial = True
            continue
        vulns = result.get('vulns', [])
        if vulns is None:
            vulns = []
        if not isinstance(vulns, list):
            warnings.append(f'Invalid advisory list for {dep.name}; status unknown.')
            has_partial = True
            continue
        for v in vulns:
            if not isinstance(v, dict):
                warnings.append(f'{dep.name}: malformed advisory record.')
                has_partial = True
                continue
            vid = v.get('id')
            if not isinstance(vid, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,150}', vid):
                warnings.append(f'{dep.name}: OSV returned an unsupported advisory ID.')
                has_partial = True
                continue
            if vid not in {existing['id'] for existing in dep_vulns[idx]}:
                dep_vulns[idx].append(v)
        token = result.get('next_page_token')
        if isinstance(token, str) and token.strip():
            dep_tokens[idx] = token.strip()
        elif token is not None and not (isinstance(token, str) and token.strip()):
            warnings.append(f'{dep.name}: invalid page token; status partial.')
            has_partial = True

    # Handle pagination
    while any(dep_tokens[idx] is not None for idx in range(len(submitted))):
        active_indices = [idx for idx in range(len(submitted)) if dep_tokens[idx] is not None]
        to_query = []
        for idx in active_indices:
            d = submitted[idx]
            tok = dep_tokens[idx]
            if dep_pages[idx] >= MAX_PAGES:
                warnings.append(f'{d.name}: OSV pagination limit ({MAX_PAGES} pages) reached; vulnerability assessment is partial.')
                has_partial = True
                dep_tokens[idx] = None
                continue
            if tok in seen_tokens[idx]:
                warnings.append(f'{d.name}: OSV pagination loop detected; vulnerability assessment is partial.')
                has_partial = True
                dep_tokens[idx] = None
                continue
            seen_tokens[idx].add(tok)
            to_query.append((idx, d, tok))

        if not to_query:
            break

        remaining_time = 15 - (time.monotonic() - started)
        if remaining_time <= 0.5:
            warnings.append('OSV pagination time budget reached; vulnerability assessment is partial.')
            has_partial = True
            break
        if batch_bytes >= MAX_AGGREGATE_BATCH_BYTES:
            warnings.append('OSV pagination response-size budget reached; vulnerability assessment is partial.')
            has_partial = True
            break

        try:
            sub_payload = {
                'queries': [
                    {'package': {'name': d.name, 'ecosystem': 'npm'}, 'version': d.version, 'page_token': tok}
                    for _, d, tok in to_query
                ]
            }
            sub_res = httpx.post(
                'https://api.osv.dev/v1/querybatch',
                json=sub_payload,
                timeout=min(6.0, remaining_time),
                follow_redirects=False
            )
            sub_res.raise_for_status()
            if len(sub_res.content) > MAX_BATCH_SIZE:
                warnings.append('OSV pagination response exceeded 4 MB limit; vulnerability assessment is partial.')
                has_partial = True
                break
            batch_bytes += len(sub_res.content)
            sub_data = sub_res.json()
            if not isinstance(sub_data, dict) or not isinstance(sub_data.get('results'), list):
                warnings.append('OSV pagination returned invalid structure; vulnerability assessment is partial.')
                has_partial = True
                break
            sub_results = sub_data['results']
            if len(sub_results) != len(to_query):
                warnings.append('OSV pagination query-to-result count mismatch; vulnerability assessment is partial.')
                has_partial = True
                break

            for (idx, d, _), s_result in zip(to_query, sub_results):
                dep_pages[idx] += 1
                dep_tokens[idx] = None
                if not isinstance(s_result, dict):
                    warnings.append(f'{d.name}: invalid pagination entry; status partial.')
                    has_partial = True
                    continue
                s_vulns = s_result.get('vulns', [])
                if s_vulns is None:
                    s_vulns = []
                if not isinstance(s_vulns, list):
                    warnings.append(f'{d.name}: invalid advisory list in pagination; status partial.')
                    has_partial = True
                    continue
                for v in s_vulns:
                    if not isinstance(v, dict):
                        warnings.append(f'{d.name}: malformed advisory record in pagination.')
                        has_partial = True
                        continue
                    vid = v.get('id')
                    if not isinstance(vid, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,150}', vid):
                        warnings.append(f'{d.name}: unsupported advisory ID in pagination.')
                        has_partial = True
                        continue
                    if vid not in {existing['id'] for existing in dep_vulns[idx]}:
                        dep_vulns[idx].append(v)
                new_tok = s_result.get('next_page_token')
                if isinstance(new_tok, str) and new_tok.strip():
                    dep_tokens[idx] = new_tok.strip()
                elif new_tok is not None and not (isinstance(new_tok, str) and new_tok.strip()):
                    warnings.append(f'{d.name}: invalid page token; status partial.')
                    has_partial = True
        except Exception:
            warnings.append('OSV pagination request failed; vulnerabilities may be incomplete.')
            has_partial = True
            break

    details = {}
    findings = []

    for idx, dep in enumerate(submitted):
        vulns = dep_vulns[idx]
        if len(vulns) > 30:
            warnings.append(f'OSV findings capped at 30 advisories for {dep.name}.')
            has_partial = True
        for vuln in vulns[:30]:
            vid = vuln['id']
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
                        has_partial = True
                else:
                    warnings.append(f'{vid}: advisory enrichment budget reached; batch match retained.')
                    has_partial = True
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
                    has_partial = True
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
    status = 'partial' if has_partial else 'checked'
    return findings, status, unique_warnings
