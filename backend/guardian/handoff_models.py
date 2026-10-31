from __future__ import annotations
from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field

HandoffTarget = Literal['universal', 'claude_code', 'cursor', 'codex', 'github_copilot']
RemediationMode = Literal['focused_fix', 'deep_remediation']
HandoffScope = Literal['finding', 'findings', 'scan']

class EvidenceLocation(BaseModel):
    file: str
    line: int = 1
    column: int = 1
    snippet: str
    detail: str

class AdvisoryDetail(BaseModel):
    id: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    cvss: List[Dict[str, str]] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)
    aliases: List[str] = Field(default_factory=list)

class FindingSummary(BaseModel):
    finding_id: str
    rule: str
    title: str
    category: str
    severity: str
    confidence: str
    observed: str
    explanation: str
    implication: str
    recommendation: str
    references: List[str] = Field(default_factory=list)
    domain: str = 'behavior'
    package: Optional[str] = None
    ecosystem: Optional[str] = None
    artifact_sha256: Optional[str] = None
    advisory: Optional[AdvisoryDetail] = None
    evidence: List[EvidenceLocation] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    data_flows_count: int = 0

class DependencyContext(BaseModel):
    name: str
    version: str
    direct: bool = True
    source: str
    ecosystem: str = 'npm'
    advisory_ids: List[str] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)
    integrity_status: str = 'uninspected'

class ProposedRemediation(BaseModel):
    id: str
    finding_ids: List[str]
    title: str
    action_type: Literal['upgrade_dependency', 'remove_script', 'source_patch', 'investigate_manual']
    description: str
    rationale: str
    affected_version: Optional[str] = None
    candidate_upgrade: Optional[str] = None
    compatibility_status: str = 'unverified'
    evidence_classification: Dict[str, str] = Field(default_factory=dict)
    expected_benefits: List[str] = Field(default_factory=list)
    risks_and_tradeoffs: List[str] = Field(default_factory=list)
    alternatives: List[str] = Field(default_factory=list)
    verification_steps: List[str] = Field(default_factory=list)

class ValidationRequirement(BaseModel):
    category: Literal['test_suite', 'integrity_check', 'build_and_typecheck', 'manual_verification']
    title: str
    description: str
    suggested_command: Optional[str] = None

class FollowUpInvestigation(BaseModel):
    topic: str
    description: str
    reason: str
    investigation_steps: List[str] = Field(default_factory=list)

class ProjectProvenance(BaseModel):
    project_id: Optional[str] = None
    name: str
    ecosystem: str = 'npm'
    framework: Optional[str] = None
    runtime: Optional[str] = None
    language: Optional[str] = None
    is_github: bool = False
    github_repository_id: Optional[int] = None
    github_owner: Optional[str] = None
    github_repo_name: Optional[str] = None
    github_branch: Optional[str] = None
    github_commit_sha: Optional[str] = None
    github_repo_url: Optional[str] = None
    is_snapshot_stale_warning: bool = False
    snapshot_verification_status: Literal['verified_match', 'unverified_against_workspace', 'snapshot_expired'] = 'unverified_against_workspace'
    staleness_detail: str = "Findings reflect the scan snapshot. Current workspace synchronization is unverified."

class ScanProvenance(BaseModel):
    scan_id: str
    scan_timestamp: str
    risk_level: str
    files_analyzed: int
    duration_ms: int
    engine_version: str = "1"
    classification: Literal['real', 'demo'] = 'real'
    source_description: str

class CoverageProvenance(BaseModel):
    coverage_status: str
    coverage_notes: List[str] = Field(default_factory=list)
    total_dependencies: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0
    unique_names_count: int = 0
    inspected_count: int = 0
    skipped_count: int = 0
    unavailable_count: int = 0
    unresolved_count: int = 0
    integrity_failed_count: int = 0
    not_attempted_count: int = 0
    limitations: List[str] = Field(default_factory=list)

class CanonicalHandoff(BaseModel):
    schema_version: str = "1.0.0"
    handoff_id: str
    generated_at: str
    target_agent: HandoffTarget
    remediation_mode: RemediationMode
    scope: HandoffScope
    project: ProjectProvenance
    scan: ScanProvenance
    coverage: CoverageProvenance
    findings: List[FindingSummary] = Field(default_factory=list)
    dependencies: List[DependencyContext] = Field(default_factory=list)
    impact_assessment: Dict[str, Any] = Field(default_factory=dict)
    root_cause_hypotheses: List[Dict[str, str]] = Field(default_factory=list)
    proposed_remediations: List[ProposedRemediation] = Field(default_factory=list)
    alternative_solutions: List[Dict[str, str]] = Field(default_factory=list)
    implementation_constraints: List[str] = Field(default_factory=list)
    validation_requirements: List[ValidationRequirement] = Field(default_factory=list)
    follow_up_investigations: List[FollowUpInvestigation] = Field(default_factory=list)
    safety_instructions: List[str] = Field(default_factory=list)
    output_reporting_requirements: List[str] = Field(default_factory=list)

class HandoffSummaryStats(BaseModel):
    title: str
    target_agent: HandoffTarget
    remediation_mode: RemediationMode
    scope: HandoffScope
    findings_count: int
    severity_breakdown: Dict[str, int]
    evidence_locations_count: int
    affected_dependencies_count: int
    validation_checks_count: int
    limitations_count: int
    suggested_filename: str

class HandoffExportResponse(BaseModel):
    canonical: CanonicalHandoff
    markdown: str
    json_appendix: Dict[str, Any]
    summary: HandoffSummaryStats

class HandoffRequest(BaseModel):
    target: HandoffTarget = 'universal'
    mode: RemediationMode = 'focused_fix'
    finding_ids: Optional[List[str]] = None
