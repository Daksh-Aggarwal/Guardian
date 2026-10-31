from typing import Protocol, Optional, List, Dict, Any
from .models import Report, ConversationMessage
from .context import aggregate_advisories

class ExplanationProvider(Protocol):
    def answer(
        self,
        report: Report,
        question: str,
        finding_id: Optional[str] = None,
        history: Optional[List[ConversationMessage]] = None,
        mode: str = 'simple'
    ) -> Dict[str, Any]: ...

class EvidenceExplainer:
    """Deterministic provider. Every answer is derived from stored report fields."""
    def answer(
        self,
        report: Report,
        question: str,
        finding_id: Optional[str] = None,
        history: Optional[List[ConversationMessage]] = None,
        mode: str = 'simple'
    ) -> Dict[str, Any]:
        candidates = [f for f in report.findings if f.id == finding_id] if finding_id else report.findings
        q = question.lower()

        # Handle questions about duplicate advisories
        advisories = aggregate_advisories(report.findings)
        is_vuln_query = any(word in q for word in ['vulnerability', 'advisory', 'osv', 'cve', 'ghsa'])

        if not finding_id:
            if is_vuln_query and advisories:
                # Group duplicate advisory explanation
                vuln_findings = [f for f in report.findings if f.rule == 'OSV' or f.advisory is not None]
                candidates = vuln_findings or candidates[:3]
            else:
                matches = [f for f in candidates if any(word in (f.title + ' ' + f.category).lower() for word in q.split() if len(word) > 4)]
                candidates = matches or candidates[:4]

        # Formulate answer intro
        if any(word in q for word in ['safe', 'trust', 'install']):
            if mode == 'advanced':
                intro = (
                    f"{report.rationale} Guardian evaluation indicates a risk profile of '{report.risk}' "
                    f"across {report.files_analyzed} inspected source files. Static data-flow does not certify runtime safety."
                )
            else:
                intro = f"{report.rationale} Guardian cannot certify safety from static analysis alone."
        elif any(word in q for word in ['fix', 'next', 'action', 'should', 'remediat']):
            if mode == 'advanced':
                intro = "Prioritize remediation using these evidence-backed findings and published fixed version boundaries."
            else:
                intro = "Start with these evidence-backed actions."
        elif is_vuln_query and advisories:
            total_matches = len([f for f in report.findings if f.rule == 'OSV'])
            intro = (
                f"Guardian identified {len(advisories)} unique vulnerability advisories across {total_matches} "
                f"package instances in the dependency graph."
            )
        else:
            if mode == 'advanced':
                intro = (
                    f"Technical evidence summary for {report.name}@{report.version}. "
                    f"Source coverage: {report.assessments.get('behavior', {}).get('coverage_status', 'complete')}; "
                    f"Vulnerability intelligence: {report.intelligence}."
                )
            else:
                intro = "Here is what the inspected evidence supports."

        sections = []
        for f in candidates[:4]:
            if mode == 'advanced':
                rule_text = f"[{f.rule}] " if f.rule else ""
                obs = f" Observed: {f.observed}." if f.observed else ""
                locs = ", ".join(f"{e.file}:{e.line}" for e in f.evidence[:2])
                loc_text = f" Located at {locs}." if locs else ""
                text = f"{rule_text}{f.explanation}{obs} Implication: {f.implication}{loc_text} Action: {f.recommendation}"
            else:
                text = f"{f.explanation} {f.implication} Next step: {f.recommendation}"

            sections.append({
                'finding_id': f.id,
                'title': f.title,
                'text': text
            })

        if not sections:
            intro = 'No matching finding was recorded. Absence of a finding is not proof of safety.'

        # Contextual follow-up suggestions based on findings
        suggested = []
        if candidates:
            top_f = candidates[0]
            suggested.append(f"Why is '{top_f.title}' dangerous?")
            suggested.append(f"What should I do about '{top_f.title}'?")
        if advisories:
            suggested.append("Are these vulnerabilities fixed in a newer release?")
        if not suggested:
            suggested = [
                "What is the most serious finding?",
                "Can I fix this without changing frameworks?",
                "Explain this in plain language"
            ]

        return {
            'provider': 'deterministic',
            'model': None,
            'answer': intro,
            'citations': sections,
            'limitations': report.coverage[:5],
            'suggested_followups': suggested[:3]
        }
