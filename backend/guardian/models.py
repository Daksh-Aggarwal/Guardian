from __future__ import annotations
from typing import List, Literal, Optional
from pydantic import BaseModel, Field

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
    inspections: List[PackageInspection] = Field(default_factory=list)
    inspection_summary: Optional[InspectionSummary] = None
    root_integrity: Optional[IntegrityResult] = None
    assessments: dict = Field(default_factory=dict)
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

Finding.model_rebuild()
Report.model_rebuild()
