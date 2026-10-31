"use client";

import React, { useState, useMemo } from "react";
import {
  ShieldAlert,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Wrench,
  GitBranch,
  Info,
  Filter,
  CheckCircle2,
  Package,
} from "lucide-react";
import { Report, Finding, parsePackageSpecifier } from "@/lib/types";
import { Eyebrow, Badge } from "./ui";

export default function VulnerabilitiesExplorer({
  report,
  onSelectGraphPackage,
  onAskIntelligence,
  onRemediateFinding,
  onViewFindingEvidence,
}: {
  report: Report;
  onSelectGraphPackage?: (packageName: string) => void;
  onAskIntelligence?: (findingId: string) => void;
  onRemediateFinding?: (findingId: string) => void;
  onViewFindingEvidence?: (findingId: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [selectedAdvisoryId, setSelectedAdvisoryId] = useState<string | null>(
    null,
  );

  // Extract OSV advisory findings
  const osvFindings = useMemo(() => {
    return report.findings.filter(
      (f) => f.rule === "OSV" || f.domain === "vulnerability" || !!f.advisory,
    );
  }, [report.findings]);

  // Group by affected package identity and version
  const packageGroups = useMemo(() => {
    const groups: Record<
      string,
      {
        key: string;
        packageName: string;
        version: string;
        findings: Finding[];
        highestSeverity: string;
      }
    > = {};

    osvFindings.forEach((f) => {
      const parsed = parsePackageSpecifier(f.package);
      const name = parsed.name || f.package || "Unknown Package";
      const ver = parsed.version || "resolved";
      const groupKey = `${name}@${ver}`;

      if (!groups[groupKey]) {
        groups[groupKey] = {
          key: groupKey,
          packageName: name,
          version: ver,
          findings: [],
          highestSeverity: "low",
        };
      }
      groups[groupKey].findings.push(f);
    });

    return Object.values(groups);
  }, [osvFindings, report.version]);

  // Filter package groups
  const filteredGroups = useMemo(() => {
    return packageGroups.filter((g) => {
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesPkg = g.packageName.toLowerCase().includes(q);
        const matchesAdv = g.findings.some(
          (f) =>
            (f.advisory?.id || "").toLowerCase().includes(q) ||
            (f.advisory?.summary || f.title).toLowerCase().includes(q),
        );
        if (!matchesPkg && !matchesAdv) return false;
      }

      if (severityFilter !== "all") {
        const matchesSev = g.findings.some(
          (f) => f.severity === severityFilter,
        );
        if (!matchesSev) return false;
      }

      return true;
    });
  }, [packageGroups, search, severityFilter]);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "16px",
      }}
    >
      {/* Header and Toolbar */}
      <div
        className="card"
        style={{
          padding: "16px 20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
        }}
      >
        <div>
          <Eyebrow>UPSTREAM OSV VULNERABILITY DATABASE</Eyebrow>
          <h2 style={{ fontSize: "18px", margin: "2px 0 0" }}>
            Vulnerability Relationships & Impact
          </h2>
          <p
            style={{
              margin: "2px 0 0",
              fontSize: "12px",
              color: "var(--muted)",
            }}
          >
            Project &rarr; Dependency &rarr; Advisory &rarr; Evidence. Separate
            published CVE severity from Guardian review priority.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {/* Search */}
          <div
            style={{
              position: "relative",
              display: "flex",
              alignItems: "center",
            }}
          >
            <Search
              size={14}
              style={{
                position: "absolute",
                left: "10px",
                color: "var(--muted)",
              }}
            />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search CVE, package..."
              style={{
                padding: "6px 12px 6px 30px",
                borderRadius: "6px",
                background: "var(--surface)",
                border: "1px solid var(--line)",
                color: "var(--text)",
                fontSize: "12px",
                width: "170px",
              }}
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{
              padding: "6px 10px",
              borderRadius: "6px",
              background: "var(--surface)",
              border: "1px solid var(--line)",
              color: "var(--text)",
              fontSize: "12px",
            }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Empty State */}
      {osvFindings.length === 0 ? (
        <div
          className="card"
          style={{
            padding: "40px 24px",
            textAlign: "center",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "12px",
          }}
        >
          <CheckCircle2 size={36} color="#10b981" />
          <h3 style={{ margin: 0, fontSize: "16px" }}>
            No Known Vulnerabilities Detected
          </h3>
          <p
            style={{
              fontSize: "13px",
              color: "var(--muted)",
              maxWidth: "460px",
              margin: 0,
            }}
          >
            Queried the OSV database against all exact resolved dependency
            versions. No published CVE or GHSA advisories match the current
            dependency inventory.
          </p>
        </div>
      ) : filteredGroups.length === 0 ? (
        <div
          className="card"
          style={{
            padding: "30px",
            textAlign: "center",
            color: "var(--muted)",
          }}
        >
          No vulnerabilities match the active search or severity filter.
        </div>
      ) : (
        /* Package List */
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {filteredGroups.map((group) => (
            <div
              key={group.key}
              className="card"
              style={{ padding: "18px 20px" }}
            >
              {/* Package Header Row */}
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: "10px",
                  paddingBottom: "12px",
                  borderBottom: "1px solid var(--line)",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "10px" }}
                >
                  <Package size={18} color="#60a5fa" />
                  <div>
                    <h3
                      style={{ margin: 0, fontSize: "16px", fontWeight: 600 }}
                    >
                      {group.packageName}
                    </h3>
                    <span
                      style={{
                        fontSize: "12px",
                        color: "var(--muted)",
                        fontFamily: "monospace",
                      }}
                    >
                      Resolved version: {group.version}
                    </span>
                  </div>
                </div>

                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <span
                    style={{
                      fontSize: "11px",
                      padding: "2px 8px",
                      borderRadius: "4px",
                      background: "rgba(239, 68, 68, 0.12)",
                      color: "#f87171",
                      fontWeight: 600,
                    }}
                  >
                    {group.findings.length} advisory{" "}
                    {group.findings.length === 1 ? "match" : "matches"}
                  </span>

                  {onSelectGraphPackage && (
                    <button
                      onClick={() => onSelectGraphPackage(group.packageName)}
                      className="button secondary compact"
                      style={{
                        fontSize: "11px",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "4px",
                      }}
                      title="Locate package in interactive dependency graph"
                    >
                      <GitBranch size={12} />
                      <span>View in Graph</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Advisories under this package */}
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "12px",
                  marginTop: "12px",
                }}
              >
                {group.findings.map((f) => {
                  const advisory = f.advisory;
                  const isExpanded = selectedAdvisoryId === f.id;
                  const fixedGuidance =
                    advisory?.fixed_versions &&
                    advisory.fixed_versions.length > 0
                      ? `Upgrade to version ${advisory.fixed_versions.join(", ")} or later`
                      : "No official fix published yet; monitor upstream repository.";

                  return (
                    <div
                      key={f.id}
                      style={{
                        borderRadius: "8px",
                        background:
                          "var(--surface-muted, rgba(255, 255, 255, 0.02))",
                        border: "1px solid var(--line)",
                        padding: "14px 16px",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "flex-start",
                          flexWrap: "wrap",
                          gap: "8px",
                        }}
                      >
                        <div>
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: "8px",
                              marginBottom: "4px",
                            }}
                          >
                            <strong
                              style={{ fontSize: "14px", color: "#f87171" }}
                            >
                              {advisory?.id || f.title}
                            </strong>
                            <Badge severity={f.severity} size="sm" />
                            {advisory?.severity && (
                              <span
                                style={{
                                  fontSize: "10px",
                                  padding: "1px 6px",
                                  borderRadius: "4px",
                                  background: "rgba(255,255,255,0.06)",
                                  color: "var(--muted)",
                                }}
                              >
                                Published CVSS: {advisory.severity}
                              </span>
                            )}
                          </div>

                          <h4
                            style={{
                              margin: "2px 0 6px",
                              fontSize: "13px",
                              fontWeight: 500,
                            }}
                          >
                            {advisory?.summary || f.title}
                          </h4>
                        </div>

                        {/* Actions */}
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "8px",
                          }}
                        >
                          {onAskIntelligence && (
                            <button
                              onClick={() => onAskIntelligence(f.id)}
                              className="button secondary compact"
                              style={{
                                fontSize: "11px",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "4px",
                              }}
                            >
                              <Sparkles size={12} />
                              <span>Ask Intelligence</span>
                            </button>
                          )}

                          {onRemediateFinding && (
                            <button
                              onClick={() => onRemediateFinding(f.id)}
                              className="button primary compact"
                              style={{
                                fontSize: "11px",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "4px",
                              }}
                            >
                              <Wrench size={12} />
                              <span>Fix with Autopilot</span>
                            </button>
                          )}

                          <button
                            onClick={() =>
                              setSelectedAdvisoryId(isExpanded ? null : f.id)
                            }
                            style={{
                              background: "none",
                              border: "none",
                              color: "var(--muted)",
                              cursor: "pointer",
                              display: "flex",
                              alignItems: "center",
                              padding: "4px",
                            }}
                          >
                            {isExpanded ? (
                              <ChevronDown size={16} />
                            ) : (
                              <ChevronRight size={16} />
                            )}
                          </button>
                        </div>
                      </div>

                      {/* Explanation */}
                      <p
                        style={{
                          margin: "6px 0 0",
                          fontSize: "12px",
                          color: "var(--muted)",
                          lineHeight: "1.5",
                        }}
                      >
                        {f.explanation}
                      </p>

                      {/* Expanded Technical Details */}
                      {isExpanded && (
                        <div
                          style={{
                            marginTop: "12px",
                            paddingTop: "12px",
                            borderTop: "1px dashed var(--line)",
                            display: "flex",
                            flexDirection: "column",
                            gap: "8px",
                            fontSize: "12px",
                          }}
                        >
                          <div>
                            <strong style={{ color: "var(--text)" }}>
                              Fix Guidance:{" "}
                            </strong>
                            <span style={{ color: "#10b981" }}>
                              {fixedGuidance}
                            </span>
                          </div>

                          {f.implication && (
                            <div>
                              <strong style={{ color: "var(--text)" }}>
                                Security Implication:{" "}
                              </strong>
                              <span style={{ color: "var(--muted)" }}>
                                {f.implication}
                              </span>
                            </div>
                          )}

                          {/* References */}
                          {f.references && f.references.length > 0 && (
                            <div style={{ marginTop: "4px" }}>
                              <strong
                                style={{
                                  display: "block",
                                  marginBottom: "4px",
                                  color: "var(--text)",
                                }}
                              >
                                Upstream References:
                              </strong>
                              <div
                                style={{
                                  display: "flex",
                                  flexDirection: "column",
                                  gap: "3px",
                                }}
                              >
                                {f.references.map((ref, idx) => (
                                  <a
                                    key={idx}
                                    href={ref}
                                    target="_blank"
                                    rel="noreferrer"
                                    style={{
                                      color: "#818cf8",
                                      fontSize: "11px",
                                      textDecoration: "underline",
                                      display: "inline-flex",
                                      alignItems: "center",
                                      gap: "4px",
                                    }}
                                  >
                                    <span>{ref}</span>
                                    <ExternalLink size={10} />
                                  </a>
                                ))}
                              </div>
                            </div>
                          )}

                          {onViewFindingEvidence && (
                            <div style={{ marginTop: "6px" }}>
                              <button
                                onClick={() => onViewFindingEvidence(f.id)}
                                style={{
                                  background: "none",
                                  border: "none",
                                  color: "#818cf8",
                                  cursor: "pointer",
                                  padding: 0,
                                  fontSize: "11px",
                                  textDecoration: "underline",
                                }}
                              >
                                Jump to full report evidence
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
