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
export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch("/api" + path, options);
  if (!res.ok) {
    let message =
      "The service is unavailable. Check that the backend is running.";
    try {
      const data = await res.json();
      message = typeof data.detail === "string" ? data.detail : message;
    } catch {}
    throw new Error(message);
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
    | "stale";
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
};

export type GitHubStatus = {
  configured: boolean;
  connected: boolean;
  installation?: GitHubInstallation | null;
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

export type { DependencyAccounting, FindingBreakdown } from "./accounting";
export { getDependencyAccounting, getFindingBreakdown } from "./accounting";
export * from "./package-utils";
