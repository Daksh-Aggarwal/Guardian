from typing import Protocol
from .models import Report

class ExplanationProvider(Protocol):
    def answer(self, report: Report, question: str, finding_id: str = None) -> dict: ...

class EvidenceExplainer:
    """Deterministic provider. Every answer is derived from stored report fields."""
    def answer(self, report, question, finding_id=None):
        candidates = [f for f in report.findings if f.id == finding_id] if finding_id else report.findings
        q = question.lower()
        if not finding_id:
            matches = [f for f in candidates if any(word in (f.title + ' ' + f.category).lower() for word in q.split() if len(word) > 4)]
            candidates = matches or candidates[:3]
        if any(word in q for word in ['safe', 'trust', 'install']):
            intro = report.rationale + ' Guardian cannot certify safety from static analysis.'
        elif any(word in q for word in ['fix', 'next', 'action', 'should']):
            intro = 'Start with these evidence-backed actions.'
        else:
            intro = 'Here is what the inspected evidence supports.'
        sections = [{'finding_id':f.id, 'title':f.title, 'text':f.explanation + ' ' + f.implication + ' Next step: ' + f.recommendation} for f in candidates[:4]]
        if not sections:
            intro = 'No matching finding was recorded. Absence of a finding is not proof of safety.'
        return {'provider':'deterministic', 'answer':intro, 'citations':sections, 'limitations':report.coverage}
