import type { Report, Finding } from "./types";

export type DependencyAccounting = {
  declaredDirect: number;
  totalResolved: number;
  transitive: number;
  uniqueNames: number;
  inspected: number;
  skipped: number;
  unavailable: number;
  unresolved: number;
  integrityFailed: number;
  notAttempted: number;
};

export type FindingBreakdown = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  actionable: number;
  informational: number;
  advisories: number;
  criticalAdvisories: number;
  highAdvisories: number;
  behavioral: number;
  actionableBehavioral: number;
  integrity: number;
  dataFlows: number;
};

export function getDependencyAccounting(report: Report): DependencyAccounting {
  const summary = report.inspection_summary;
  if (summary && summary.total > 0) {
    const inspectedNames = new Set(
      (report.inspections || []).map((n) => n.name),
    );
    report.dependencies.forEach((d) => inspectedNames.add(d.name));
    return {
      declaredDirect: summary.direct,
      totalResolved: summary.total,
      transitive: summary.transitive,
      uniqueNames: inspectedNames.size || summary.total,
      inspected: summary.inspected,
      skipped: summary.skipped,
      unavailable: summary.unavailable,
      unresolved: summary.unresolved ?? 0,
      integrityFailed: summary.integrity_failed ?? 0,
      notAttempted: summary.not_attempted ?? 0,
    };
  }

  const direct = report.dependencies.filter((d) => d.direct).length;
  const transitive = report.dependencies.filter((d) => !d.direct).length;
  const uniqueNames = new Set(report.dependencies.map((d) => d.name)).size;
  const inspected = report.files_analyzed > 0 ? report.dependencies.length : 0;

  return {
    declaredDirect: direct,
    totalResolved: report.dependencies.length,
    transitive: transitive,
    uniqueNames: uniqueNames || report.dependencies.length,
    inspected: inspected,
    skipped: 0,
    unavailable: 0,
    unresolved: 0,
    integrityFailed: 0,
    notAttempted: 0,
  };
}

export function getFindingBreakdown(findings: Finding[]): FindingBreakdown {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;
  const actionable = findings.filter((f) => f.severity !== "info");
  const informational = findings.filter((f) => f.severity === "info");
  const advisories = findings.filter(
    (f) => f.rule === "OSV" || f.domain === "vulnerability" || !!f.advisory,
  );
  const criticalAdvisories = advisories.filter(
    (f) => f.severity === "critical",
  ).length;
  const highAdvisories = advisories.filter((f) => f.severity === "high").length;
  const behavioral = findings.filter(
    (f) =>
      (!f.domain || f.domain === "behavior") && f.rule !== "OSV" && !f.advisory,
  );
  const actionableBehavioral = behavioral.filter(
    (f) => f.severity !== "info",
  ).length;
  const integrity = findings.filter(
    (f) => f.domain === "integrity" || f.rule === "PACKAGE_INTEGRITY",
  ).length;
  const dataFlows = findings.filter(
    (f) => f.data_flows && f.data_flows.length > 0,
  ).length;

  return {
    total: findings.length,
    critical,
    high,
    medium,
    low,
    actionable: actionable.length,
    informational: informational.length,
    advisories: advisories.length,
    criticalAdvisories,
    highAdvisories,
    behavioral: behavioral.length,
    actionableBehavioral,
    integrity,
    dataFlows,
  };
}
