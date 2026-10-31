"use client";

import React, { useState, useMemo } from "react";
import {
  Clock,
  ShieldCheck,
  FileCode2,
  Network,
  Layers,
  ArrowRight,
  TrendingDown,
  TrendingUp,
  Minus,
  CheckCircle2,
  AlertTriangle,
  Info,
  GitBranch,
} from "lucide-react";
import { Report, getFindingSignature, compareSemver } from "@/lib/types";
import { getDependencyAccounting, getFindingBreakdown } from "@/lib/accounting";
import { Eyebrow, Badge } from "./ui";

export default function SecurityTimeline({
  projectScans,
  currentReportId,
  onSelectScan,
}: {
  projectScans: Report[];
  currentReportId: string;
  onSelectScan?: (scanId: string) => void;
}) {
  // Sort scans chronological ascending
  const sortedScans = useMemo(() => {
    return [...projectScans].sort(
      (a, b) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    );
  }, [projectScans]);

  const [compareBaseId, setCompareBaseId] = useState<string>(
    sortedScans[0]?.id || currentReportId,
  );
  const [compareTargetId, setCompareTargetId] = useState<string>(
    sortedScans[sortedScans.length - 1]?.id || currentReportId,
  );

  const baseReport = useMemo(
    () => sortedScans.find((s) => s.id === compareBaseId) || sortedScans[0],
    [sortedScans, compareBaseId],
  );

  const targetReport = useMemo(
    () =>
      sortedScans.find((s) => s.id === compareTargetId) ||
      sortedScans[sortedScans.length - 1],
    [sortedScans, compareTargetId],
  );

  // Comparison metrics
  const comparison = useMemo(() => {
    if (!baseReport || !targetReport || baseReport.id === targetReport.id) {
      return null;
    }

    const baseBreakdown = getFindingBreakdown(baseReport.findings);
    const targetBreakdown = getFindingBreakdown(targetReport.findings);

    const baseDeps = getDependencyAccounting(baseReport);
    const targetDeps = getDependencyAccounting(targetReport);

    // Finding diffs
    const baseFindingIds = new Set(baseReport.findings.map((f) => f.id));
    const targetFindingIds = new Set(targetReport.findings.map((f) => f.id));

    // Stable finding signatures for cross-scan tracking
    const baseSignatures = new Set(
      baseReport.findings.map(getFindingSignature),
    );
    const targetSignatures = new Set(
      targetReport.findings.map(getFindingSignature),
    );

    const resolvedFindings = baseReport.findings.filter(
      (f) => !targetSignatures.has(getFindingSignature(f)),
    );
    const newFindings = targetReport.findings.filter(
      (f) => !baseSignatures.has(getFindingSignature(f)),
    );
    const persistentFindings = targetReport.findings.filter((f) =>
      baseSignatures.has(getFindingSignature(f)),
    );

    // Dependency diffs: separate identity from version
    const baseDepMap = new Map<string, { version: string; direct: boolean }>();
    baseReport.dependencies.forEach((d) =>
      baseDepMap.set(d.name, { version: d.version, direct: d.direct }),
    );
    const targetDepMap = new Map<
      string,
      { version: string; direct: boolean }
    >();
    targetReport.dependencies.forEach((d) =>
      targetDepMap.set(d.name, { version: d.version, direct: d.direct }),
    );

    const addedDependencies: Array<{
      name: string;
      version: string;
      direct: boolean;
    }> = [];
    const removedDependencies: Array<{
      name: string;
      version: string;
      direct: boolean;
    }> = [];
    const upgradedDependencies: Array<{
      name: string;
      fromVersion: string;
      toVersion: string;
      direct: boolean;
    }> = [];
    const downgradedDependencies: Array<{
      name: string;
      fromVersion: string;
      toVersion: string;
      direct: boolean;
    }> = [];
    const unchangedDependencies: Array<{
      name: string;
      version: string;
      direct: boolean;
    }> = [];

    targetDepMap.forEach((targetInfo, name) => {
      const baseInfo = baseDepMap.get(name);
      if (!baseInfo) {
        addedDependencies.push({
          name,
          version: targetInfo.version,
          direct: targetInfo.direct,
        });
      } else {
        const cmp = compareSemver(targetInfo.version, baseInfo.version);
        if (cmp > 0) {
          upgradedDependencies.push({
            name,
            fromVersion: baseInfo.version,
            toVersion: targetInfo.version,
            direct: targetInfo.direct,
          });
        } else if (cmp < 0) {
          downgradedDependencies.push({
            name,
            fromVersion: baseInfo.version,
            toVersion: targetInfo.version,
            direct: targetInfo.direct,
          });
        } else {
          unchangedDependencies.push({
            name,
            version: targetInfo.version,
            direct: targetInfo.direct,
          });
        }
      }
    });

    baseDepMap.forEach((baseInfo, name) => {
      if (!targetDepMap.has(name)) {
        removedDependencies.push({
          name,
          version: baseInfo.version,
          direct: baseInfo.direct,
        });
      }
    });

    const isCrossBranch = Boolean(
      baseReport.source_metadata?.branch &&
      targetReport.source_metadata?.branch &&
      baseReport.source_metadata.branch !== targetReport.source_metadata.branch
    );

    return {
      isCrossBranch,
      baseBranch: baseReport.source_metadata?.branch,
      targetBranch: targetReport.source_metadata?.branch,
      baseCommit: baseReport.source_metadata?.commit_sha,
      targetCommit: targetReport.source_metadata?.commit_sha,
      resolvedFindings,
      newFindings,
      persistentFindings,
      addedDependencies,
      removedDependencies,
      upgradedDependencies,
      downgradedDependencies,
      unchangedDependencies,
      actionableDiff: targetBreakdown.actionable - baseBreakdown.actionable,
      advisoryDiff: targetBreakdown.advisories - baseBreakdown.advisories,
      behavioralDiff: targetBreakdown.behavioral - baseBreakdown.behavioral,
      dependencyDiff: targetDeps.totalResolved - baseDeps.totalResolved,
    };
  }, [baseReport, targetReport]);

  if (sortedScans.length <= 1) {
    const current = sortedScans[0];
    const breakdown = current ? getFindingBreakdown(current.findings) : null;
    const deps = current ? getDependencyAccounting(current) : null;

    return (
      <div
        className="card"
        style={{
          padding: "32px 24px",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}
      >
        <div style={{ display: "flex", alignItems: "flex-start", gap: "12px" }}>
          <Info
            size={22}
            color="#818cf8"
            style={{ flexShrink: 0, marginTop: "2px" }}
          />
          <div>
            <Eyebrow>HISTORICAL SECURITY POSTURE</Eyebrow>
            <h3 style={{ margin: "4px 0", fontSize: "16px" }}>
              Initial Project Baseline Established
            </h3>
            <p
              style={{
                margin: 0,
                fontSize: "13px",
                color: "var(--muted)",
                lineHeight: "1.6",
                maxWidth: "600px",
              }}
            >
              This is the first recorded scan for this project. Longitudinal
              comparisons, finding resolution deltas, and dependency tree diffs
              will become available automatically after subsequent scans.
            </p>
          </div>
        </div>

        {current && breakdown && deps && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: "12px",
              marginTop: "8px",
            }}
          >
            <div
              style={{
                padding: "12px",
                borderRadius: "8px",
                background: "var(--surface-muted, rgba(255,255,255,0.03))",
                border: "1px solid var(--line)",
              }}
            >
              <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                Baseline Date
              </span>
              <strong
                style={{ display: "block", fontSize: "13px", marginTop: "2px" }}
              >
                {new Date(current.created_at).toLocaleDateString()}
              </strong>
            </div>

            <div
              style={{
                padding: "12px",
                borderRadius: "8px",
                background: "var(--surface-muted, rgba(255,255,255,0.03))",
                border: "1px solid var(--line)",
              }}
            >
              <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                Actionable Findings
              </span>
              <strong
                style={{
                  display: "block",
                  fontSize: "13px",
                  marginTop: "2px",
                  color: breakdown.actionable > 0 ? "#f87171" : "#10b981",
                }}
              >
                {breakdown.actionable} actionable
              </strong>
            </div>

            <div
              style={{
                padding: "12px",
                borderRadius: "8px",
                background: "var(--surface-muted, rgba(255,255,255,0.03))",
                border: "1px solid var(--line)",
              }}
            >
              <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                Total Dependencies
              </span>
              <strong
                style={{ display: "block", fontSize: "13px", marginTop: "2px" }}
              >
                {deps.totalResolved} ({deps.declaredDirect} direct)
              </strong>
            </div>

            <div
              style={{
                padding: "12px",
                borderRadius: "8px",
                background: "var(--surface-muted, rgba(255,255,255,0.03))",
                border: "1px solid var(--line)",
              }}
            >
              <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                Inspection Coverage
              </span>
              <strong
                style={{ display: "block", fontSize: "13px", marginTop: "2px" }}
              >
                {deps.inspected} / {deps.totalResolved} inspected
              </strong>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Header */}
      <div
        className="card"
        style={{
          padding: "18px 22px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
        }}
      >
        <div>
          <Eyebrow>LONGITUDINAL PROJECT TIMELINE</Eyebrow>
          <h2 style={{ fontSize: "18px", margin: "2px 0 0" }}>
            Security Posture Across Scans
          </h2>
          <p
            style={{
              margin: "2px 0 0",
              fontSize: "12px",
              color: "var(--muted)",
            }}
          >
            Tracking independent assessment dimensions across{" "}
            {sortedScans.length} historical scans. No artificial combined score.
          </p>
        </div>

        <span
          style={{
            fontSize: "12px",
            color: "var(--muted)",
            padding: "4px 10px",
            borderRadius: "6px",
            background: "var(--surface-muted, rgba(255,255,255,0.03))",
            border: "1px solid var(--line)",
          }}
        >
          {sortedScans.length} historical scans recorded
        </span>
      </div>

      {/* Chronological Timeline Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: `repeat(${Math.min(sortedScans.length, 4)}, 1fr)`,
          gap: "12px",
          overflowX: "auto",
        }}
      >
        {sortedScans.map((scan, idx) => {
          const isCurrent = scan.id === currentReportId;
          const breakdown = getFindingBreakdown(scan.findings);
          const deps = getDependencyAccounting(scan);

          return (
            <div
              key={scan.id}
              className="card"
              style={{
                padding: "16px",
                border: isCurrent
                  ? "2px solid #818cf8"
                  : "1px solid var(--line)",
                background: isCurrent
                  ? "var(--surface-muted, rgba(255,255,255,0.05))"
                  : "var(--surface)",
                display: "flex",
                flexDirection: "column",
                gap: "10px",
                cursor: onSelectScan ? "pointer" : "default",
              }}
              onClick={() => onSelectScan && onSelectScan(scan.id)}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <span
                  style={{
                    fontSize: "10px",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    color: isCurrent ? "#818cf8" : "var(--muted)",
                  }}
                >
                  Scan #{idx + 1} {isCurrent && "(Active)"}
                </span>
                <span style={{ fontSize: "10px", color: "var(--muted)" }}>
                  {new Date(scan.created_at).toLocaleDateString()}
                </span>
              </div>

              <div>
                <strong style={{ fontSize: "13px" }}>v{scan.version}</strong>
                {scan.source_metadata?.branch && (
                  <span
                    style={{
                      marginLeft: "6px",
                      fontSize: "10px",
                      padding: "1px 5px",
                      borderRadius: "3px",
                      background: "rgba(99, 102, 241, 0.15)",
                      color: "var(--accent, #6366f1)",
                    }}
                  >
                    {scan.source_metadata.branch} @ {scan.source_metadata.commit_sha.slice(0, 7)}
                  </span>
                )}
                <p
                  style={{
                    margin: "2px 0 0",
                    fontSize: "11px",
                    color: "var(--muted)",
                  }}
                >
                  {scan.source} &bull; {scan.files_analyzed} files
                </p>
              </div>

              {/* Dimension Metrics */}
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "6px",
                  fontSize: "11px",
                  borderTop: "1px solid var(--line)",
                  paddingTop: "8px",
                }}
              >
                <div
                  style={{ display: "flex", justifyContent: "space-between" }}
                >
                  <span style={{ color: "var(--muted)" }}>Actionable:</span>
                  <strong
                    style={{
                      color: breakdown.actionable > 0 ? "#f87171" : "#10b981",
                    }}
                  >
                    {breakdown.actionable}
                  </strong>
                </div>

                <div
                  style={{ display: "flex", justifyContent: "space-between" }}
                >
                  <span style={{ color: "var(--muted)" }}>Advisories:</span>
                  <strong>{breakdown.advisories}</strong>
                </div>

                <div
                  style={{ display: "flex", justifyContent: "space-between" }}
                >
                  <span style={{ color: "var(--muted)" }}>Dependencies:</span>
                  <strong>{deps.totalResolved}</strong>
                </div>

                <div
                  style={{ display: "flex", justifyContent: "space-between" }}
                >
                  <span style={{ color: "var(--muted)" }}>Inspected:</span>
                  <span>
                    {deps.inspected}/{deps.totalResolved}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Two-Scan Comparison Tool */}
      <div
        className="card"
        style={{
          padding: "20px",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "12px",
            borderBottom: "1px solid var(--line)",
            paddingBottom: "14px",
          }}
        >
          <div>
            <Eyebrow>DELTA ANALYSIS</Eyebrow>
            <h3 style={{ margin: "2px 0 0", fontSize: "16px" }}>
              Compare Two Project Scans
            </h3>
            <p style={{ margin: 0, fontSize: "12px", color: "var(--muted)" }}>
              Inspect finding resolution, newly introduced signals, and
              dependency tree changes.
            </p>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                Base:
              </span>
              <select
                value={compareBaseId}
                onChange={(e) => setCompareBaseId(e.target.value)}
                style={{
                  padding: "4px 8px",
                  borderRadius: "6px",
                  background: "var(--surface)",
                  border: "1px solid var(--line)",
                  color: "var(--text)",
                  fontSize: "11px",
                }}
              >
                {sortedScans.map((s, i) => (
                  <option key={s.id} value={s.id}>
                    #{i + 1} {s.source_metadata?.branch ? `[${s.source_metadata.branch}] ` : ""}- v{s.version} (
                    {new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>

            <ArrowRight size={14} color="var(--muted)" />

            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                Compare:
              </span>
              <select
                value={compareTargetId}
                onChange={(e) => setCompareTargetId(e.target.value)}
                style={{
                  padding: "4px 8px",
                  borderRadius: "6px",
                  background: "var(--surface)",
                  border: "1px solid var(--line)",
                  color: "var(--text)",
                  fontSize: "11px",
                }}
              >
                {sortedScans.map((s, i) => (
                  <option key={s.id} value={s.id}>
                    #{i + 1} {s.source_metadata?.branch ? `[${s.source_metadata.branch}] ` : ""}- v{s.version} (
                    {new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Comparison Results */}
        {comparison && (
          <div
            style={{ display: "flex", flexDirection: "column", gap: "14px" }}
          >
            {/* Cross-Branch Comparison Notice */}
            {comparison.isCrossBranch && (
              <div
                style={{
                  padding: "12px 16px",
                  borderRadius: "6px",
                  background: "rgba(245, 158, 11, 0.12)",
                  border: "1px solid rgba(245, 158, 11, 0.3)",
                  fontSize: "12px",
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                }}
              >
                <GitBranch size={16} style={{ color: "#f59e0b", flexShrink: 0 }} />
                <span>
                  <strong>Cross-Branch Comparison:</strong> Comparing branch{" "}
                  <code>{comparison.baseBranch}</code> ({comparison.baseCommit?.slice(0, 7)}) with branch{" "}
                  <code>{comparison.targetBranch}</code> ({comparison.targetCommit?.slice(0, 7)}).
                  Findings may reflect divergent branch histories rather than sequential fixes.
                </span>
              </div>
            )}

            {/* Diff Counters */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                gap: "12px",
              }}
            >
              <div
                style={{
                  padding: "12px",
                  borderRadius: "8px",
                  background: "var(--surface-muted, rgba(255,255,255,0.03))",
                  border: "1px solid var(--line)",
                }}
              >
                <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                  Resolved Findings
                </span>
                <strong
                  style={{
                    display: "block",
                    fontSize: "16px",
                    color: "#10b981",
                    marginTop: "2px",
                  }}
                >
                  {comparison.resolvedFindings.length} resolved
                </strong>
              </div>

              <div
                style={{
                  padding: "12px",
                  borderRadius: "8px",
                  background: "var(--surface-muted, rgba(255,255,255,0.03))",
                  border: "1px solid var(--line)",
                }}
              >
                <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                  New Findings
                </span>
                <strong
                  style={{
                    display: "block",
                    fontSize: "16px",
                    color:
                      comparison.newFindings.length > 0 ? "#f87171" : "#10b981",
                    marginTop: "2px",
                  }}
                >
                  {comparison.newFindings.length} new
                </strong>
              </div>

              <div
                style={{
                  padding: "12px",
                  borderRadius: "8px",
                  background: "var(--surface-muted, rgba(255,255,255,0.03))",
                  border: "1px solid var(--line)",
                }}
              >
                <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                  Upgraded Packages
                </span>
                <strong
                  style={{
                    display: "block",
                    fontSize: "16px",
                    color:
                      comparison.upgradedDependencies.length > 0
                        ? "#10b981"
                        : "var(--text)",
                    marginTop: "2px",
                  }}
                >
                  {comparison.upgradedDependencies.length} upgraded
                </strong>
              </div>

              <div
                style={{
                  padding: "12px",
                  borderRadius: "8px",
                  background: "var(--surface-muted, rgba(255,255,255,0.03))",
                  border: "1px solid var(--line)",
                }}
              >
                <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                  Dependency Net Change
                </span>
                <strong
                  style={{
                    display: "block",
                    fontSize: "16px",
                    color: "var(--text)",
                    marginTop: "2px",
                  }}
                >
                  {comparison.dependencyDiff >= 0
                    ? `+${comparison.dependencyDiff}`
                    : `${comparison.dependencyDiff}`}{" "}
                  packages
                </strong>
              </div>
            </div>

            {/* Resolved findings breakdown */}
            {comparison.resolvedFindings.length > 0 && (
              <div>
                <strong
                  style={{
                    fontSize: "12px",
                    color: "#10b981",
                    display: "block",
                    marginBottom: "6px",
                  }}
                >
                  ✓ Findings Resolved in Newer Scan:
                </strong>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px",
                  }}
                >
                  {comparison.resolvedFindings.map((f) => (
                    <div
                      key={f.id}
                      style={{
                        padding: "6px 10px",
                        borderRadius: "6px",
                        background: "rgba(16, 185, 129, 0.08)",
                        fontSize: "11px",
                        display: "flex",
                        justifyContent: "space-between",
                      }}
                    >
                      <span>{f.advisory?.summary || f.title}</span>
                      <span style={{ color: "var(--muted)" }}>{f.rule}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* New findings */}
            {comparison.newFindings.length > 0 && (
              <div>
                <strong
                  style={{
                    fontSize: "12px",
                    color: "#f87171",
                    display: "block",
                    marginBottom: "6px",
                  }}
                >
                  ⚠ New Findings Detected in Newer Scan:
                </strong>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px",
                  }}
                >
                  {comparison.newFindings.map((f) => (
                    <div
                      key={f.id}
                      style={{
                        padding: "6px 10px",
                        borderRadius: "6px",
                        background: "rgba(239, 68, 68, 0.08)",
                        fontSize: "11px",
                        display: "flex",
                        justifyContent: "space-between",
                      }}
                    >
                      <span>{f.advisory?.summary || f.title}</span>
                      <Badge severity={f.severity} size="sm" />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Dependency Lifecycle Changes */}
            {(comparison.upgradedDependencies.length > 0 ||
              comparison.downgradedDependencies.length > 0 ||
              comparison.addedDependencies.length > 0 ||
              comparison.removedDependencies.length > 0) && (
              <div style={{ marginTop: "6px" }}>
                <strong
                  style={{
                    fontSize: "12px",
                    color: "var(--text)",
                    display: "block",
                    marginBottom: "8px",
                  }}
                >
                  📦 Dependency Lifecycle Transitions:
                </strong>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px",
                  }}
                >
                  {comparison.upgradedDependencies.map((d) => (
                    <div
                      key={"upg-" + d.name}
                      style={{
                        padding: "6px 10px",
                        borderRadius: "6px",
                        background: "rgba(16, 185, 129, 0.08)",
                        fontSize: "11px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <span>
                        <strong style={{ color: "#10b981" }}>↑ Upgraded</strong>{" "}
                        <code>{d.name}</code>{" "}
                        {d.direct ? "(direct)" : "(transitive)"}
                      </span>
                      <span
                        style={{
                          fontFamily: "var(--font-mono, monospace)",
                          color: "var(--muted)",
                        }}
                      >
                        {d.fromVersion} →{" "}
                        <strong style={{ color: "var(--text)" }}>
                          {d.toVersion}
                        </strong>
                      </span>
                    </div>
                  ))}

                  {comparison.downgradedDependencies.map((d) => (
                    <div
                      key={"down-" + d.name}
                      style={{
                        padding: "6px 10px",
                        borderRadius: "6px",
                        background: "rgba(245, 158, 11, 0.08)",
                        fontSize: "11px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <span>
                        <strong style={{ color: "#f59e0b" }}>
                          ↓ Downgraded
                        </strong>{" "}
                        <code>{d.name}</code>{" "}
                        {d.direct ? "(direct)" : "(transitive)"}
                      </span>
                      <span
                        style={{
                          fontFamily: "var(--font-mono, monospace)",
                          color: "var(--muted)",
                        }}
                      >
                        {d.fromVersion} →{" "}
                        <strong style={{ color: "var(--text)" }}>
                          {d.toVersion}
                        </strong>
                      </span>
                    </div>
                  ))}

                  {comparison.addedDependencies.map((d) => (
                    <div
                      key={"add-" + d.name}
                      style={{
                        padding: "6px 10px",
                        borderRadius: "6px",
                        background: "rgba(99, 102, 241, 0.08)",
                        fontSize: "11px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <span>
                        <strong style={{ color: "#818cf8" }}>+ Added</strong>{" "}
                        <code>{d.name}</code>{" "}
                        {d.direct ? "(direct)" : "(transitive)"}
                      </span>
                      <span
                        style={{
                          fontFamily: "var(--font-mono, monospace)",
                          color: "var(--muted)",
                        }}
                      >
                        v{d.version}
                      </span>
                    </div>
                  ))}

                  {comparison.removedDependencies.map((d) => (
                    <div
                      key={"rem-" + d.name}
                      style={{
                        padding: "6px 10px",
                        borderRadius: "6px",
                        background: "rgba(100, 116, 139, 0.08)",
                        fontSize: "11px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <span>
                        <strong style={{ color: "var(--muted)" }}>
                          - Removed
                        </strong>{" "}
                        <code>{d.name}</code>{" "}
                        {d.direct ? "(direct)" : "(transitive)"}
                      </span>
                      <span
                        style={{
                          fontFamily: "var(--font-mono, monospace)",
                          color: "var(--muted)",
                        }}
                      >
                        was v{d.version}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
