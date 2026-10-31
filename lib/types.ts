export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Evidence = {
  file: string;
  line: number;
  column: number;
  snippet: string;
  detail: string;
};
export type ScanJob = {
  id: string;
  status: string;
  stage: string;
  error?: string;
};
export type ReportAssessments = {
  behavior?: {
    risk: string;
    headline?: string;
    rationale: string;
    coverage_status?: string;
    files_inspected?: number;
  };
  vulnerabilities?: { count: number; status: string; rationale?: string };
  integrity?: { concerns: number; root_status: string };
  inspection?: {
    total: number;
    direct: number;
    transitive: number;
    inspected: number;
    skipped: number;
    unavailable: number;
    unresolved: number;
    integrity_failed: number;
    not_attempted: number;
    status: string;
    rationale?: string;
  };
};
export type Finding = {
  id: string;
  rule: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: "low" | "medium" | "high" | string;
  observed: string;
  explanation: string;
  implication: string;
  recommendation: string;
  evidence: Evidence[];
  references: string[];
  domain?: string;
  limitations?: string[];
  data_flows?: DataFlow[];
  package?: string | null;
  advisory?: Advisory | null;
  ecosystem?: string | null;
  artifact_sha256?: string | null;
};
export type Report = {
  id: string;
  name: string;
  version: string;
  created_at: string;
  source: string;
  risk: string;
  rationale: string;
  findings: Finding[];
  dependencies: {
    name: string;
    version: string;
    direct: boolean;
    source: string;
    ecosystem?: string;
  }[];
  files_analyzed: number;
  coverage: string[];
  intelligence: string;
  duration_ms: number;
  engine_version?: string;
  classification?: "real" | "demo";
  project_id?: string | null;
  source_metadata?: GitHubMetadata | null;
  inspections?: Inspection[];
  inspection_summary?: InspectionSummary | null;
  root_integrity?: Integrity | null;
  assessments?: ReportAssessments;
  cli?: {
    schema_version: string;
    ecosystem?: string;
    decision?: {
      decision: string;
      reasons?: string[];
      review_reasons?: string[];
    };
    installation?: { status: string; detail?: string };
    lifecycle_scripts?: string;
    imported?: boolean;
    packages?: {
      identity: string;
      sha256: string;
      kind: string;
      decision: string;
    }[];
  } | null;
};
export type Answer = {
  provider: string;
  answer: string;
  citations: { finding_id: string; title: string; text: string }[];
  limitations: string[];
};

export type FindingCitation = {
  finding_id: string;
  title: string;
  text: string;
  evidence_ref?: string | null;
};

export type ConversationMessage = {
  id: string;
  conversation_id: string;
  scan_id: string;
  role: "user" | "assistant";
  content: string;
  citations: FindingCitation[];
  limitations: string[];
  suggested_followups: string[];
  provider: string;
  model?: string | null;
  created_at: string;
};

export type ConversationSession = {
  id: string;
  scan_id: string;
  messages: ConversationMessage[];
  created_at: string;
  updated_at: string;
};

export type AdvisorResponse = {
  answer: string;
  citations: FindingCitation[];
  limitations: string[];
  suggested_followups: string[];
  provider: string;
  model?: string | null;
  conversation_id: string;
  message_id: string;
};

export type AIStatus = {
  enabled: boolean;
  provider: string;
  model: string;
  has_key: boolean;
  timeout_seconds: number;
  max_turns: number;
};
export async function initSession(): Promise<{ initialized: boolean; new: boolean }> {
  try {
    const res = await fetch("/api/session/init", {
      method: "POST",
      credentials: "include",
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {}
  return { initialized: false, new: false };
}

export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const mergedOptions: RequestInit = {
    credentials: "include",
    ...options,
  };
  const res = await fetch("/api" + path, mergedOptions);
  if (!res.ok) {
    let message =
      "The service is unavailable. Check that the backend is running.";
    try {
      const data = await res.json();
      message = typeof data.detail === "string" ? data.detail : message;
    } catch {}
    const err = new Error(message);
    (err as any).status = res.status;
    throw err;
  }
  return res.json();
}

export type FlowStep = Evidence & { kind: string; binding?: string };
export type DataFlow = {
  status: string;
  context: string;
  steps: FlowStep[];
  limitations: string[];
};
export type Integrity = {
  status: "verified" | "missing" | "invalid" | "unsupported" | "mismatch";
  source: string;
  expected?: string | null;
  computed: string[];
  algorithm?: string | null;
  detail: string;
};
export type Inspection = {
  ecosystem?: string;
  artifact_sha256?: string | null;
  name: string;
  version: string;
  location: string;
  direct: boolean;
  depth?: number | null;
  status: string;
  reason: string;
  integrity: Integrity;
  registry_integrity?: Integrity | null;
  finding_ids: string[];
  dependencies: string[];
};
export type InspectionSummary = {
  total: number;
  direct: number;
  transitive: number;
  inspected: number;
  skipped: number;
  unavailable: number;
  unresolved: number;
  integrity_failed: number;
  not_attempted: number;
  packages_with_findings: number;
  profile: string;
  registry_requests: number;
  downloaded_bytes: number;
  elapsed_ms: number;
};
export type Advisory = {
  id: string;
  summary?: string | null;
  severity?: string | null;
  cvss: { type: string; score: string }[];
  affected_ranges: Record<string, unknown>[];
  fixed_versions: string[];
  aliases: string[];
  detail_status: string;
};

export type TextEdit = {
  old_text: string;
  new_text: string;
};

export type ProposedFileChange = {
  file_path: string;
  operation: "update" | "create";
  original_sha256: string;
  proposed_sha256: string;
  edits: TextEdit[];
  diff: string;
  rationale: string;
  finding_ids: string[];
  expected_result: string;
  created_content?: string | null;
};

export type RemediationPlan = {
  plan_id: string;
  scan_id: string;
  title: string;
  summary: string;
  priority: "critical" | "high" | "medium" | "low";
  expected_outcome: string;
  findings_addressed: string[];
  proposed_changes: ProposedFileChange[];
  tradeoffs: string[];
  potential_risks: string[];
  assumptions: string[];
  manual_steps: string[];
  recommended_verification: string[];
  limitations: string[];
  status:
    | "proposed"
    | "approved"
    | "rejected"
    | "applying"
    | "applied"
    | "reverted"
    | "verified"
    | "failed"
    | "stale"
    | "pr_closed";
  created_at: string;
  repository_id?: number | null;
  branch?: string | null;
  commit_sha?: string | null;
  pr_number?: number | null;
  pr_url?: string | null;
  remediation_branch?: string | null;
  remediation_commit_sha?: string | null;
  pr_state?: string | null;
};

export type GitHubMetadata = {
  installation_id?: number | null;
  repository_id: number;
  repo_name: string;
  owner: string;
  repo_url: string;
  branch: string;
  commit_sha: string;
  default_branch: string;
  source_type: "github";
};

export type GitHubInstallation = {
  id: number;
  account_id: number;
  account_login: string;
  account_type: string;
  avatar_url?: string | null;
  repository_selection: string;
  installed_at?: string | null;
  is_selected?: boolean;
  is_active?: boolean;
};

export type GitHubStatus = {
  configured: boolean;
  connected: boolean;
  installation?: GitHubInstallation | null;
  installations?: GitHubInstallation[];
  reason?: string | null;
};

export type GitHubRepository = {
  id: number;
  name: string;
  full_name: string;
  owner: string;
  owner_avatar?: string | null;
  private: boolean;
  html_url: string;
  description?: string | null;
  default_branch: string;
  updated_at?: string | null;
  permissions?: Record<string, boolean>;
};

export type GitHubBranch = {
  name: string;
  commit_sha: string;
  is_default: boolean;
};

export type GitHubRemediationResponse = {
  plan_id: string;
  pr_number: number;
  pr_url: string;
  remediation_branch: string;
  commit_sha: string;
  status: string;
};

export type PlanGenerationRequest = {
  finding_ids?: string[] | null;
  consent?: boolean;
  instructions?: string | null;
};

export type PlanAppliedRecord = {
  applied_at: string;
  modified_files: string[];
  success: boolean;
  error?: string | null;
};

export type PlanRevertedRecord = {
  reverted_at?: string;
  restored_files: string[];
};

export type VerificationResult = {
  plan_id: string;
  scan_id: string;
  rescanned_scan_id: string;
  verified_at: string;
  resolved_findings: string[];
  persistent_findings: string[];
  new_findings: string[];
  coverage_changed: boolean;
  source_coverage_status: string;
  summary: string;
  outstanding_manual_steps: string[];
};

export type ProjectMetadata = {
  scan_id: string;
  name: string;
  framework?: string | null;
  runtime?: string | null;
  language?: string | null;
  test_framework?: string | null;
  total_files: number;
  total_bytes: number;
  manifest_paths: string[];
  created_at: string;
  expires_at: string;
};

export type HandoffTarget =
  "universal" | "claude_code" | "cursor" | "codex" | "github_copilot";

export type RemediationMode = "focused_fix" | "deep_remediation";
export type HandoffScope = "finding" | "findings" | "scan";

export type EvidenceLocation = {
  file: string;
  line: number;
  column: number;
  snippet: string;
  detail: string;
};

export type AdvisoryDetail = {
  id: string;
  summary?: string | null;
  severity?: string | null;
  cvss: { type: string; score: string }[];
  fixed_versions: string[];
  aliases: string[];
};

export type FindingSummary = {
  ecosystem?: string | null;
  artifact_sha256?: string | null;
  finding_id: string;
  rule: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: string;
  observed: string;
  explanation: string;
  implication: string;
  recommendation: string;
  references: string[];
  domain: string;
  package?: string | null;
  advisory?: AdvisoryDetail | null;
  evidence: EvidenceLocation[];
  limitations: string[];
  data_flows_count: number;
};

export type DependencyContext = {
  name: string;
  version: string;
  direct: boolean;
  source: string;
  ecosystem: string;
  advisory_ids: string[];
  fixed_versions: string[];
  integrity_status: string;
};

export type ProposedRemediation = {
  id: string;
  finding_ids: string[];
  title: string;
  action_type:
    | "upgrade_dependency"
    | "remove_script"
    | "source_patch"
    | "investigate_manual";
  description: string;
  rationale: string;
  affected_version?: string | null;
  candidate_upgrade?: string | null;
  compatibility_status?: string;
  evidence_classification?: Record<string, string>;
  expected_benefits: string[];
  risks_and_tradeoffs: string[];
  alternatives: string[];
  verification_steps: string[];
};

export type ValidationRequirement = {
  category:
    | "test_suite"
    | "integrity_check"
    | "build_and_typecheck"
    | "manual_verification";
  title: string;
  description: string;
  suggested_command?: string | null;
};

export type FollowUpInvestigation = {
  topic: string;
  description: string;
  reason: string;
  investigation_steps: string[];
};

export type ProjectProvenance = {
  project_id?: string | null;
  name: string;
  ecosystem?: string;
  framework?: string | null;
  runtime?: string | null;
  language?: string | null;
  is_github: boolean;
  github_repository_id?: number | null;
  github_owner?: string | null;
  github_repo_name?: string | null;
  github_branch?: string | null;
  github_commit_sha?: string | null;
  github_repo_url?: string | null;
  is_snapshot_stale_warning: boolean;
  snapshot_verification_status?:
    "verified_match" | "unverified_against_workspace" | "snapshot_expired";
  staleness_detail?: string;
};

export type ScanProvenance = {
  scan_id: string;
  scan_timestamp: string;
  risk_level: string;
  files_analyzed: number;
  duration_ms: number;
  engine_version: string;
  classification: "real" | "demo";
  source_description: string;
};

export type CoverageProvenance = {
  coverage_status: string;
  coverage_notes: string[];
  total_dependencies: number;
  direct_dependencies: number;
  transitive_dependencies: number;
  unique_names_count?: number;
  inspected_count: number;
  skipped_count: number;
  unavailable_count: number;
  unresolved_count?: number;
  integrity_failed_count: number;
  not_attempted_count?: number;
  limitations: string[];
};

export type CanonicalHandoff = {
  schema_version: string;
  handoff_id: string;
  generated_at: string;
  target_agent: HandoffTarget;
  remediation_mode: RemediationMode;
  scope: HandoffScope;
  project: ProjectProvenance;
  scan: ScanProvenance;
  coverage: CoverageProvenance;
  findings: FindingSummary[];
  dependencies: DependencyContext[];
  impact_assessment: Record<string, unknown>;
  root_cause_hypotheses: Array<Record<string, string>>;
  proposed_remediations: ProposedRemediation[];
  alternative_solutions: Array<{ name: string; description: string }>;
  implementation_constraints: string[];
  validation_requirements: ValidationRequirement[];
  follow_up_investigations: FollowUpInvestigation[];
  safety_instructions: string[];
  output_reporting_requirements: string[];
};

export type HandoffSummaryStats = {
  title: string;
  target_agent: HandoffTarget;
  remediation_mode: RemediationMode;
  scope: HandoffScope;
  findings_count: number;
  severity_breakdown: Record<string, number>;
  evidence_locations_count: number;
  affected_dependencies_count: number;
  validation_checks_count: number;
  limitations_count: number;
  suggested_filename: string;
};

export type HandoffExportResponse = {
  canonical: CanonicalHandoff;
  markdown: string;
  json_appendix: Record<string, unknown>;
  summary: HandoffSummaryStats;
};

export type HandoffRequest = {
  target?: HandoffTarget;
  mode?: RemediationMode;
  finding_ids?: string[] | null;
};

export type { DependencyAccounting, FindingBreakdown } from "./accounting";
export { getDependencyAccounting, getFindingBreakdown } from "./accounting";
export * from "./package-utils";
