"use client";

import React, { useState, useEffect } from "react";
import {
  Wrench,
  CheckCircle2,
  Clock,
  RotateCcw,
  AlertTriangle,
  XCircle,
  FileCode2,
  Sparkles,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  Loader2,
} from "lucide-react";
import { api, Report, RemediationPlan, VerificationResult } from "@/lib/types";
import { Eyebrow, Badge } from "./ui";

type RemediationEvent = {
  plan: RemediationPlan;
  verification?: VerificationResult | null;
};

export default function RemediationHistory({
  report,
  onOpenPlan,
}: {
  report: Report;
  onOpenPlan?: (planId: string) => void;
}) {
  const [history, setHistory] = useState<RemediationEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedPlanId, setExpandedPlanId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchHistory() {
      setLoading(true);
      setError(null);
      try {
        const projectKey = report.project_id || report.name;
        const data = await api<RemediationEvent[]>(
          `/projects/${encodeURIComponent(projectKey)}/remediation/history`,
        );
        if (!cancelled) setHistory(data);
      } catch {
        // Fallback: try scan plans
        try {
          const plans = await api<RemediationPlan[]>(
            `/scans/${report.id}/remediation/plans`,
          );
          if (!cancelled) {
            setHistory(plans.map((p) => ({ plan: p, verification: null })));
          }
        } catch {
          if (!cancelled) setHistory([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchHistory();
    return () => {
      cancelled = true;
    };
  }, [report.name, report.id]);

  function getStatusBadge(status: string) {
    switch (status) {
      case "verified":
        return (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              background: "rgba(16, 185, 129, 0.15)",
              color: "#10b981",
              fontSize: "11px",
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <CheckCircle2 size={12} />
            Verified Clean
          </span>
        );
      case "applied":
        return (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              background: "rgba(59, 130, 246, 0.15)",
              color: "#60a5fa",
              fontSize: "11px",
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <CheckCircle2 size={12} />
            Applied (Awaiting Rescan)
          </span>
        );
      case "reverted":
        return (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              background: "rgba(148, 163, 184, 0.15)",
              color: "#94a3b8",
              fontSize: "11px",
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <RotateCcw size={12} />
            Undone / Reverted
          </span>
        );
      case "approved":
        return (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              background: "rgba(245, 158, 11, 0.15)",
              color: "#fbbf24",
              fontSize: "11px",
              fontWeight: 600,
            }}
          >
            Approved
          </span>
        );
      case "rejected":
        return (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              background: "rgba(239, 68, 68, 0.15)",
              color: "#f87171",
              fontSize: "11px",
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <XCircle size={12} />
            Rejected
          </span>
        );
      case "failed":
        return (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              background: "rgba(239, 68, 68, 0.15)",
              color: "#f87171",
              fontSize: "11px",
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <AlertTriangle size={12} />
            Application Failed
          </span>
        );
      default:
        return (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              background: "rgba(168, 85, 247, 0.15)",
              color: "#c084fc",
              fontSize: "11px",
              fontWeight: 600,
            }}
          >
            Proposed Plan
          </span>
        );
    }
  }

  if (loading) {
    return (
      <div
        className="card"
        style={{
          padding: "40px",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          gap: "10px",
          color: "var(--muted)",
        }}
      >
        <Loader2 size={18} className="animate-spin" />
        <span>Loading project remediation lifecycle history...</span>
      </div>
    );
  }

  if (history.length === 0) {
    return (
      <div
        className="card"
        style={{
          padding: "48px 24px",
          textAlign: "center",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: "14px",
        }}
      >
        <div
          style={{
            width: "52px",
            height: "52px",
            borderRadius: "14px",
            background: "rgba(99, 102, 241, 0.12)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--accent, #6366f1)",
          }}
        >
          <Wrench size={26} />
        </div>
        <div>
          <h3 style={{ margin: "0 0 4px", fontSize: "17px" }}>
            No Remediation Plans Recorded for this Project
          </h3>
          <p
            style={{
              margin: 0,
              fontSize: "13px",
              color: "var(--muted)",
              maxWidth: "480px",
              lineHeight: "1.6",
            }}
          >
            When Guardian Autopilot proposes precision code fixes, tracks user
            approval, and monitors rescan verification, the complete audit trail
            is recorded here.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      {/* Overview Banner */}
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
          <Eyebrow>GUARDIAN AUTOPILOT AUDIT LOG</Eyebrow>
          <h2 style={{ fontSize: "18px", margin: "2px 0 0" }}>
            Project Remediation History
          </h2>
          <p
            style={{
              margin: "2px 0 0",
              fontSize: "12px",
              color: "var(--muted)",
            }}
          >
            Lifecycle record of proposed plans, diff reviews, approvals,
            filesystem modifications, and subsequent rescan verifications.
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
          <strong>{history.length}</strong> recorded{" "}
          {history.length === 1 ? "plan" : "plans"}
        </span>
      </div>

      {/* Events List */}
      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        {history.map(({ plan, verification }) => {
          const isExpanded = expandedPlanId === plan.plan_id;
          return (
            <div
              key={plan.plan_id}
              className="card"
              style={{
                padding: "16px 20px",
                display: "flex",
                flexDirection: "column",
                gap: "12px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  flexWrap: "wrap",
                  gap: "10px",
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
                    <strong style={{ fontSize: "15px" }}>{plan.title}</strong>
                    {getStatusBadge(plan.status)}
                  </div>
                  <p
                    style={{
                      margin: "2px 0 0",
                      fontSize: "12px",
                      color: "var(--muted)",
                    }}
                  >
                    {plan.summary}
                  </p>
                </div>

                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <span
                    style={{
                      fontSize: "11px",
                      color: "var(--muted)",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "4px",
                    }}
                  >
                    <Clock size={12} />
                    {new Date(plan.created_at).toLocaleString()}
                  </span>

                  <button
                    onClick={() =>
                      setExpandedPlanId(isExpanded ? null : plan.plan_id)
                    }
                    style={{
                      background: "none",
                      border: "none",
                      color: "var(--muted)",
                      cursor: "pointer",
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

              {/* Addressed findings & affected files */}
              <div
                style={{
                  display: "flex",
                  gap: "16px",
                  fontSize: "11px",
                  color: "var(--muted)",
                  flexWrap: "wrap",
                }}
              >
                <span>
                  <strong>{plan.findings_addressed.length}</strong> findings
                  addressed
                </span>
                <span>
                  <strong>{plan.proposed_changes.length}</strong> files modified
                </span>
                {verification && (
                  <span style={{ color: "#10b981", fontWeight: 500 }}>
                    ✓ Rescan Verified: {verification.resolved_findings.length}{" "}
                    resolved
                  </span>
                )}
              </div>

              {/* Expanded details */}
              {isExpanded && (
                <div
                  style={{
                    paddingTop: "12px",
                    borderTop: "1px dashed var(--line)",
                    display: "flex",
                    flexDirection: "column",
                    gap: "10px",
                    fontSize: "12px",
                  }}
                >
                  <div>
                    <strong style={{ display: "block", marginBottom: "4px" }}>
                      Proposed File Changes:
                    </strong>
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "4px",
                      }}
                    >
                      {plan.proposed_changes.map((c, i) => (
                        <div
                          key={i}
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            fontSize: "11px",
                            fontFamily: "var(--font-mono, monospace)",
                            background: "rgba(255,255,255,0.02)",
                            padding: "4px 8px",
                            borderRadius: "4px",
                          }}
                        >
                          <span>{c.file_path}</span>
                          <span style={{ color: "#818cf8" }}>
                            {c.operation}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Verification outcome details */}
                  {verification && (
                    <div
                      style={{
                        padding: "10px",
                        borderRadius: "6px",
                        background: "rgba(16, 185, 129, 0.08)",
                        border: "1px solid rgba(16, 185, 129, 0.2)",
                      }}
                    >
                      <strong
                        style={{
                          color: "#10b981",
                          display: "block",
                          marginBottom: "4px",
                        }}
                      >
                        Verification Outcome:
                      </strong>
                      <p style={{ margin: "0 0 6px", fontSize: "11px" }}>
                        {verification.summary ||
                          "All target findings resolved."}
                      </p>
                      <div
                        style={{
                          display: "flex",
                          gap: "12px",
                          fontSize: "11px",
                          color: "var(--muted)",
                        }}
                      >
                        <span>
                          Resolved findings:{" "}
                          <strong>
                            {verification.resolved_findings.length}
                          </strong>
                        </span>
                        <span>
                          Persistent findings:{" "}
                          <strong>
                            {verification.persistent_findings.length}
                          </strong>
                        </span>
                        <span>
                          New findings:{" "}
                          <strong>{verification.new_findings.length}</strong>
                        </span>
                      </div>
                    </div>
                  )}

                  <div style={{ marginTop: "4px" }}>
                    <span style={{ fontSize: "10px", color: "var(--muted)" }}>
                      Plan ID: {plan.plan_id} &bull; Scan reference:{" "}
                      {plan.scan_id}
                    </span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
