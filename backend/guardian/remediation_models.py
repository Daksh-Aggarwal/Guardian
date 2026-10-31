from __future__ import annotations
from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field

PlanPriority = Literal['critical', 'high', 'medium', 'low']
PlanStatus = Literal[
    'proposed',
    'approved',
    'rejected',
    'applying',
    'applied',
    'reverted',
    'verified',
    'failed',
    'stale'
]
OperationType = Literal['update', 'create']

class TextEdit(BaseModel):
    old_text: str = Field(description="Exact snippet of existing text to replace. Must occur exactly once.")
    new_text: str = Field(description="Exact replacement text.")

class ProposedFileChange(BaseModel):
    file_path: str = Field(description="Project-relative file path.")
    operation: OperationType = Field(default='update', description="File operation: 'update' or 'create'.")
    original_sha256: str = Field(description="SHA-256 hash of original file content before modification.")
    proposed_sha256: str = Field(description="SHA-256 hash of proposed file content after modification.")
    edits: List[TextEdit] = Field(default_factory=list, description="Ordered list of non-overlapping exact text edits.")
    diff: str = Field(default="", description="Unified diff of the proposed modification.")
    rationale: str = Field(description="Explanation of why this change addresses the security finding.")
    finding_ids: List[str] = Field(default_factory=list, description="IDs of Guardian findings addressed by this file change.")
    expected_result: str = Field(description="Expected behavior or security improvement after change.")
    created_content: Optional[str] = Field(default=None, description="Full content for newly created text file if operation is 'create'.")

class RemediationPlan(BaseModel):
    plan_id: str
    scan_id: str
    title: str
    summary: str
    priority: PlanPriority = 'medium'
    expected_outcome: str
    findings_addressed: List[str] = Field(default_factory=list)
    proposed_changes: List[ProposedFileChange] = Field(default_factory=list)
    tradeoffs: List[str] = Field(default_factory=list)
    potential_risks: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)
    manual_steps: List[str] = Field(default_factory=list)
    recommended_verification: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    status: PlanStatus = 'proposed'
    created_at: str

class PlanGenerationRequest(BaseModel):
    finding_ids: Optional[List[str]] = None
    consent: bool = False
    instructions: Optional[str] = None

class PlanApprovalRequest(BaseModel):
    approved: bool

class PlanAppliedRecord(BaseModel):
    applied_at: str
    modified_files: List[str] = Field(default_factory=list)
    success: bool
    error: Optional[str] = None

class PlanRevertedRecord(BaseModel):
    reverted_at: Optional[str] = None
    restored_files: List[str] = Field(default_factory=list)

class VerificationResult(BaseModel):
    plan_id: str
    scan_id: str
    rescanned_scan_id: str
    verified_at: str
    resolved_findings: List[str] = Field(default_factory=list, description="Finding IDs or titles no longer detected.")
    persistent_findings: List[str] = Field(default_factory=list, description="Finding IDs or titles still detected.")
    new_findings: List[str] = Field(default_factory=list, description="Newly detected finding IDs or titles.")
    coverage_changed: bool = False
    source_coverage_status: str = 'complete'
    summary: str = ""
    outstanding_manual_steps: List[str] = Field(default_factory=list)

class VerificationRequest(BaseModel):
    rescanned_scan_id: str

class ProjectIngestRequest(BaseModel):
    name: str = Field(min_length=1, max_length=214)
    profile: Literal['fast', 'deep'] = 'fast'
    files: Dict[str, str] = Field(description="Dictionary of project-relative paths to text file contents.")

class ProjectMetadata(BaseModel):
    scan_id: str
    name: str
    framework: Optional[str] = None
    runtime: Optional[str] = None
    language: Optional[str] = None
    test_framework: Optional[str] = None
    total_files: int = 0
    total_bytes: int = 0
    manifest_paths: List[str] = Field(default_factory=list)
    created_at: str
    expires_at: str
