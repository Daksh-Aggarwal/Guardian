from __future__ import annotations
from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator

Severity = Literal['info', 'low', 'medium', 'high', 'critical']
class Evidence(BaseModel):
    file: str
    line: int = 1
    column: int = 1
    snippet: str
    detail: str
class Finding(BaseModel):
    id: str
    rule: str
    title: str
    category: str
    severity: Severity
    confidence: Literal['low', 'medium', 'high']
    observed: str
    explanation: str
    implication: str
    recommendation: str
    evidence: List[Evidence]
    references: List[str] = Field(default_factory=list)
    domain: str = 'behavior'
    limitations: List[str] = Field(default_factory=list)
    data_flows: List[DataFlow] = Field(default_factory=list)
    package: Optional[str] = None
    advisory: Optional[Advisory] = None
class Dependency(BaseModel):
    name: str
    version: str
    direct: bool = True
    source: str

class GitHubMetadata(BaseModel):
    repository_id: int
    repo_name: str
    owner: str
    repo_url: str
    branch: str
    commit_sha: str
    default_branch: str
    source_type: Literal['github'] = 'github'

class Report(BaseModel):
    id: str
    name: str
    version: str
    created_at: str
    source: str
    risk: str
    rationale: str
    findings: List[Finding]
    dependencies: List[Dependency]
    files_analyzed: int
    coverage: List[str]
    intelligence: str
    duration_ms: int
    engine_version: str = "1"
    classification: Literal['real', 'demo'] = 'real'
    project_id: Optional[str] = None
    source_metadata: Optional[GitHubMetadata] = None
    inspections: List[PackageInspection] = Field(default_factory=list)
    inspection_summary: Optional[InspectionSummary] = None
    root_integrity: Optional[IntegrityResult] = None
    assessments: dict = Field(default_factory=dict)

    @model_validator(mode='before')
    @classmethod
    def set_default_classification(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if 'classification' not in data or not data.get('classification'):
                if data.get('source') == 'synthetic fixture':
                    data['classification'] = 'demo'
                else:
                    data['classification'] = 'real'
        return data

    def get_finding_breakdown(self) -> FindingBreakdown:
        actionable = [f for f in self.findings if f.severity != 'info']
        informational = [f for f in self.findings if f.severity == 'info']
        advisories = [f for f in self.findings if f.rule == 'OSV' or f.domain == 'vulnerability' or bool(f.advisory)]
        behavioral = [f for f in self.findings if (not f.domain or f.domain == 'behavior') and f.rule != 'OSV' and not f.advisory]
        integrity = [f for f in self.findings if f.domain == 'integrity' or f.rule == 'PACKAGE_INTEGRITY']
        data_flows = [f for f in self.findings if f.data_flows]
        return FindingBreakdown(
            total=len(self.findings),
            actionable=len(actionable),
            informational=len(informational),
            advisories=len(advisories),
            critical_advisories=sum(f.severity == 'critical' for f in advisories),
            high_advisories=sum(f.severity == 'high' for f in advisories),
            behavioral=len(behavioral),
            actionable_behavioral=sum(f.severity != 'info' for f in behavioral),
            integrity=len(integrity),
            data_flows=len(data_flows),
        )

    def get_dependency_accounting(self) -> DependencyAccounting:
        summary = self.inspection_summary
        if summary:
            unique_names = len(set(n.name for n in self.inspections).union(d.name for d in self.dependencies))
            return DependencyAccounting(
                declared_direct=summary.direct,
                total_resolved=summary.total,
                transitive=summary.transitive,
                unique_names=unique_names,
                inspected=summary.inspected,
                skipped=summary.skipped,
                unavailable=summary.unavailable,
                unresolved=summary.unresolved,
                integrity_failed=summary.integrity_failed,
                not_attempted=summary.not_attempted,
            )
        declared_direct = sum(bool(d.direct) for d in self.dependencies)
        transitive = sum(not d.direct for d in self.dependencies)
        unique_names = len(set(d.name for d in self.dependencies))
        return DependencyAccounting(
            declared_direct=declared_direct,
            total_resolved=len(self.dependencies),
            transitive=transitive,
            unique_names=unique_names,
            inspected=len(self.dependencies) if self.files_analyzed > 0 else 0,
            skipped=0,
            unavailable=0,
            unresolved=0,
            integrity_failed=0,
            not_attempted=0,
        )

class FindingBreakdown(BaseModel):
    total: int = 0
    actionable: int = 0
    informational: int = 0
    advisories: int = 0
    critical_advisories: int = 0
    high_advisories: int = 0
    behavioral: int = 0
    actionable_behavioral: int = 0
    integrity: int = 0
    data_flows: int = 0

class DependencyAccounting(BaseModel):
    declared_direct: int = 0
    total_resolved: int = 0
    transitive: int = 0
    unique_names: int = 0
    inspected: int = 0
    skipped: int = 0
    unavailable: int = 0
    unresolved: int = 0
    integrity_failed: int = 0
    not_attempted: int = 0
class PackageRequest(BaseModel):
    name: str = Field(min_length=1, max_length=214)
    version: str = Field(default='latest', min_length=1, max_length=100)
    profile: Literal['fast', 'deep'] = 'fast'
class Question(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    finding_id: Optional[str] = None

class FlowStep(Evidence):
    kind: str
    binding: Optional[str] = None

class DataFlow(BaseModel):
    status: str = 'statically inferred'
    context: str = 'payload'
    steps: List[FlowStep]
    limitations: List[str] = Field(default_factory=list)

class IntegrityResult(BaseModel):
    status: Literal['verified', 'missing', 'invalid', 'unsupported', 'mismatch'] = 'missing'
    source: str = 'not supplied'
    expected: Optional[str] = None
    computed: List[str] = Field(default_factory=list)
    algorithm: Optional[str] = None
    detail: str = 'Integrity verification was not performed.'

class PackageInspection(BaseModel):
    name: str
    version: str
    location: str
    direct: bool
    depth: Optional[int] = None
    status: str = 'uninspected'
    reason: str = ''
    integrity: IntegrityResult = Field(default_factory=IntegrityResult)
    registry_integrity: Optional[IntegrityResult] = None
    finding_ids: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)

class InspectionSummary(BaseModel):
    total: int = 0
    direct: int = 0
    transitive: int = 0
    inspected: int = 0
    skipped: int = 0
    unavailable: int = 0
    unresolved: int = 0
    integrity_failed: int = 0
    not_attempted: int = 0
    packages_with_findings: int = 0
    profile: str = 'fast'
    registry_requests: int = 0
    downloaded_bytes: int = 0
    elapsed_ms: int = 0

class Advisory(BaseModel):
    id: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    cvss: List[dict] = Field(default_factory=list)
    affected_ranges: List[dict] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)
    aliases: List[str] = Field(default_factory=list)
    detail_status: str = 'unavailable'

class FindingCitation(BaseModel):
    finding_id: str
    title: str
    text: str
    evidence_ref: Optional[str] = None

class ConversationMessage(BaseModel):
    id: str
    conversation_id: str
    scan_id: str
    role: Literal['user', 'assistant']
    content: str
    citations: List[FindingCitation] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    suggested_followups: List[str] = Field(default_factory=list)
    provider: str
    model: Optional[str] = None
    created_at: str

class ConversationSession(BaseModel):
    id: str
    scan_id: str
    messages: List[ConversationMessage] = Field(default_factory=list)
    created_at: str
    updated_at: str

class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    finding_id: Optional[str] = None
    mode: Literal['simple', 'advanced'] = 'simple'
    consent: bool = False
    conversation_id: Optional[str] = None

class AdvisorResponse(BaseModel):
    answer: str
    citations: List[FindingCitation] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    suggested_followups: List[str] = Field(default_factory=list)
    provider: str
    model: Optional[str] = None
    conversation_id: str
    message_id: str

class AIStatus(BaseModel):
    enabled: bool
    provider: str
    model: str
    has_key: bool
    timeout_seconds: int
    max_turns: int

Finding.model_rebuild()
FindingBreakdown.model_rebuild()
DependencyAccounting.model_rebuild()
Report.model_rebuild()
