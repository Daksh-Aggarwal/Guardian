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
  }[];
  files_analyzed: number;
  coverage: string[];
  intelligence: string;
  duration_ms: number;
  engine_version?: string;
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
