"""Context minimization, duplicate advisory aggregation, and prompt context building."""
from typing import List, Optional, Dict, Any
from .models import Report, Finding, ConversationMessage
from .redact import redact_text, redact_data

def aggregate_advisories(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Groups duplicate advisory identifiers intelligently.
    Distinguishes unique advisories, affected package instances, and affected versions.
    """
    osv_findings = [f for f in findings if f.rule == 'OSV' or f.advisory is not None]
    if not osv_findings:
        return []

    grouped: Dict[str, Dict[str, Any]] = {}
    for f in osv_findings:
        adv = f.advisory
        adv_id = adv.id if adv else f.title
        pkg_name = f.package or 'unknown'

        if adv_id not in grouped:
            grouped[adv_id] = {
                'id': adv_id,
                'summary': (adv.summary if adv and adv.summary else f.observed) or f.title,
                'severity': (adv.severity if adv and adv.severity else f.severity),
                'guardian_priority': f.severity,
                'cvss': adv.cvss if adv else [],
                'fixed_versions': adv.fixed_versions if adv else [],
                'affected_instances': [],
                'affected_versions': set(),
                'finding_ids': [],
                'detail_status': adv.detail_status if adv else 'unavailable',
                'references': f.references[:3]
            }

        # Extract version if present in observation or package
        version_spec = 'unspecified'
        if adv and adv.affected_ranges:
            version_spec = 'in affected range'
        elif '@' in pkg_name:
            version_spec = pkg_name.split('@')[-1]

        grouped[adv_id]['finding_ids'].append(f.id)
        grouped[adv_id]['affected_instances'].append({
            'package': pkg_name,
            'finding_id': f.id
        })
        if version_spec != 'unspecified':
            grouped[adv_id]['affected_versions'].add(version_spec)

    result = []
    for adv_id, item in grouped.items():
        result.append({
            'id': adv_id,
            'summary': item['summary'],
            'severity': item['severity'],
            'guardian_priority': item['guardian_priority'],
            'cvss': item['cvss'],
            'fixed_versions': item['fixed_versions'],
            'instance_count': len(item['affected_instances']),
            'unique_packages': sorted(list({inst['package'] for inst in item['affected_instances']})),
            'unique_versions': sorted(list(item['affected_versions'])),
            'finding_ids': item['finding_ids'],
            'detail_status': item['detail_status'],
            'references': item['references']
        })
    return result

def select_relevant_findings(
    findings: List[Finding],
    question: str,
    finding_id: Optional[str] = None,
    max_findings: int = 6
) -> List[Finding]:
    """Selects the most relevant findings for the question to avoid bloating context."""
    if finding_id:
        target = [f for f in findings if f.id == finding_id]
        if target:
            # Include targeted finding first, plus up to 2 others for comparison
            others = [f for f in findings if f.id != finding_id][:2]
            return target + others

    q_lower = question.lower()
    q_words = set(w for w in q_lower.split() if len(w) > 3)

    # Keyword matching against rule, title, category, package
    scored = []
    for f in findings:
        score = 0
        searchable = f"{f.rule} {f.title} {f.category} {f.package or ''} {f.observed}".lower()
        for w in q_words:
            if w in searchable:
                score += 2

        # Priority boost for high severities
        sev_boost = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(f.severity, 0)
        score += sev_boost
        scored.append((score, f))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    selected = [pair[1] for pair in scored[:max_findings]]
    return selected or findings[:max_findings]

def build_conversation_context(
    report: Report,
    question: str,
    history: Optional[List[ConversationMessage]] = None,
    finding_id: Optional[str] = None,
    mode: str = 'simple'
) -> Dict[str, Any]:
    """
    Constructs a compact, privacy-safe context payload for LLM analysis.
    Applies secret redaction to all strings.
    """
    history = history or []
    selected_findings = select_relevant_findings(report.findings, question, finding_id=finding_id)
    advisory_groups = aggregate_advisories(report.findings)

    # Prepare findings summary
    findings_context = []
    for f in selected_findings:
        evidence_summary = []
        for ev in f.evidence[:2]:  # at most 2 evidence items
            snippet = ev.snippet.strip()
            if len(snippet) > 200:
                snippet = snippet[:197] + "..."
            evidence_summary.append({
                'file': ev.file,
                'line': ev.line,
                'snippet': redact_text(snippet),
                'detail': redact_text(ev.detail)
            })

        findings_context.append({
            'id': f.id,
            'rule': f.rule,
            'title': f.title,
            'category': f.category,
            'severity': f.severity,
            'confidence': f.confidence,
            'domain': f.domain,
            'observed': redact_text(f.observed),
            'explanation': f.explanation,
            'implication': f.implication,
            'recommendation': f.recommendation,
            'package': f.package,
            'evidence': evidence_summary,
            'limitations': f.limitations[:2]
        })

    # Prepare previous turns (bounded to last 6 messages)
    bounded_history = []
    for msg in history[-6:]:
        bounded_history.append({
            'role': msg.role,
            'content': redact_text(msg.content[:500])
        })

    # Assessments summary
    assessments_summary = {
        'behavior': {
            'risk': report.assessments.get('behavior', {}).get('risk', report.risk),
            'headline': report.assessments.get('behavior', {}).get('headline', report.risk),
            'coverage_status': report.assessments.get('behavior', {}).get('coverage_status', 'complete'),
            'files_inspected': report.files_analyzed
        },
        'vulnerabilities': {
            'status': report.assessments.get('vulnerabilities', {}).get('status', report.intelligence),
            'total_matches': len([f for f in report.findings if f.rule == 'OSV']),
            'unique_advisories': len(advisory_groups)
        },
        'integrity': {
            'concerns': report.assessments.get('integrity', {}).get('concerns', 0),
            'root_status': report.assessments.get('integrity', {}).get('root_status', 'not applicable')
        },
        'inspection': {
            'total': report.inspection_summary.total if report.inspection_summary else len(report.dependencies),
            'inspected': report.inspection_summary.inspected if report.inspection_summary else 0,
            'skipped': report.inspection_summary.skipped if report.inspection_summary else 0,
            'unavailable': report.inspection_summary.unavailable if report.inspection_summary else 0,
            'status': report.assessments.get('inspection', {}).get('status', 'complete' if report.files_analyzed > 0 else 'incomplete')
        }
    }

    context = {
        'project': {
            'name': report.name,
            'version': report.version,
            'source': report.source,
            'files_analyzed': report.files_analyzed,
            'total_dependencies': len(report.dependencies)
        },
        'assessments': assessments_summary,
        'findings': findings_context,
        'advisory_summary': advisory_groups[:5],
        'coverage_notices': report.coverage[:5],
        'recent_conversation': bounded_history,
        'mode': mode
    }

    return redact_data(context)
