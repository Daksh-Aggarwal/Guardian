"use client";

import { useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  FileCode2,
  Info,
} from "lucide-react";
import {
  CheckCircle2,
  Terminal,
  ArrowRight,
  Layers,
  ShieldCheck,
  CopyIcon,
  CheckIcon,
} from "@/components/icons";
import { RemediationPlan, Finding, VerificationResult } from "@/lib/types";
import DiffViewer from "./diff-viewer";
import { downloadPatchFile } from "@/lib/fs-access";

export default function RemediationPlanView({
  plan,
  findings = [],
  verification = null,
  onFindingClick,
}: {
  plan: RemediationPlan;
  findings?: Finding[];
  verification?: VerificationResult | null;
  onFindingClick?: (findingId: string) => void;
}) {
  const [activeTab, setActiveTab] = useState<"diff" | "safety" | "commands">("diff");
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [allCopied, setAllCopied] = useState(false);

  const priorityColors = {
    critical: "var(--accent-red, #ef4444)",
    high: "var(--accent-orange, #f97316)",
    medium: "var(--accent-yellow, #eab308)",
    low: "var(--accent-blue, #3b82f6)",
  };

  const statusBadges: Record<
    string,
    { label: string; bg: string; color: string }
  > = {
    proposed: {
      label: "Proposed",
      bg: "rgba(59, 130, 246, 0.15)",
      color: "#3b82f6",
    },
    approved: {
      label: "Approved by User",
      bg: "rgba(16, 185, 129, 0.15)",
      color: "#10b981",
    },
    applying: {
      label: "Applying to Disk...",
      bg: "rgba(234, 179, 8, 0.15)",
      color: "#eab308",
    },
    applied: {
      label: "Applied to Disk",
      bg: "rgba(16, 185, 129, 0.2)",
      color: "#10b981",
    },
    reverted: {
      label: "Reverted (Undone)",
      bg: "rgba(249, 115, 22, 0.15)",
      color: "#f97316",
    },
    verified: {
      label: "Verified by Rescan",
      bg: "rgba(16, 185, 129, 0.25)",
      color: "#10b981",
    },
    rejected: {
      label: "Rejected",
      bg: "rgba(239, 68, 68, 0.15)",
      color: "#ef4444",
    },
    failed: {
      label: "Application Failed",
      bg: "rgba(239, 68, 68, 0.2)",
      color: "#ef4444",
    },
    stale: {
      label: "Stale (Files Changed)",
      bg: "rgba(107, 114, 128, 0.2)",
      color: "#9ca3af",
    },
    pr_closed: {
      label: "PR Closed",
      bg: "rgba(107, 114, 128, 0.2)",
      color: "#9ca3af",
    },
  };

  const validationBadges: Record<
    string,
    { label: string; bg: string; color: string; border: string }
  > = {
    VERIFIED: {
      label: "Gate: Verified",
      bg: "rgba(16, 185, 129, 0.15)",
      color: "#10b981",
      border: "rgba(16, 185, 129, 0.3)",
    },
    UNVERIFIED: {
      label: "Gate: Unverified",
      bg: "rgba(234, 179, 8, 0.15)",
      color: "#eab308",
      border: "rgba(234, 179, 8, 0.3)",
    },
    REJECTED: {
      label: "Gate: Rejected",
      bg: "rgba(239, 68, 68, 0.15)",
      color: "#ef4444",
      border: "rgba(239, 68, 68, 0.3)",
    },
    VALIDATION_FAILED: {
      label: "Gate: Validation Failed",
      bg: "rgba(239, 68, 68, 0.15)",
      color: "#ef4444",
      border: "rgba(239, 68, 68, 0.3)",
    },
  };

  const currentStatus = statusBadges[plan.status] || statusBadges.proposed;

  // Build lookup map for findings
  const findingsMap = new Map(findings.map((f) => [f.id, f]));

  const copyCommand = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd.replace(/^`|`$/g, ""));
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const copyAllCommands = () => {
    const all = plan.manual_steps.map((s) => s.replace(/^`|`$/g, "")).join("\n");
    navigator.clipboard.writeText(all);
    setAllCopied(true);
    setTimeout(() => setAllCopied(false), 2000);
  };

  return (
    <div
      className="remediation-plan-view"
      style={{ display: "flex", flexDirection: "column", gap: "16px" }}
    >
      {/* Solution Executive Summary Header */}
      <div
        className="plan-header card"
        style={{
          padding: "16px 18px",
          display: "flex",
          flexDirection: "column",
          gap: "12px",
          background: "var(--surface-card)",
          border: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            gap: "10px",
            flexWrap: "wrap",
          }}
        >
          <div style={{ flex: 1, minWidth: "260px" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                marginBottom: "6px",
                flexWrap: "wrap",
              }}
            >
              <span
                style={{
                  fontSize: "10px",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  padding: "2px 8px",
                  borderRadius: "4px",
                  background: currentStatus.bg,
                  color: currentStatus.color,
                }}
              >
                {currentStatus.label}
              </span>
              {plan.validation_status &&
                validationBadges[plan.validation_status] && (
                  <span
                    style={{
                      fontSize: "10px",
                      fontWeight: 600,
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      padding: "2px 8px",
                      borderRadius: "4px",
                      background: validationBadges[plan.validation_status].bg,
                      color: validationBadges[plan.validation_status].color,
                      border: `1px solid ${validationBadges[plan.validation_status].border}`,
                    }}
                  >
                    {validationBadges[plan.validation_status].label}
                  </span>
                )}
              <span
                style={{
                  fontSize: "10px",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  padding: "2px 8px",
                  borderRadius: "4px",
                  background: `rgba(255,255,255,0.06)`,
                  color: priorityColors[plan.priority] || "var(--foreground)",
                }}
              >
                Priority: {plan.priority}
              </span>
              <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                Plan {plan.plan_id.substring(0, 8)}
              </span>
            </div>

            <h2
              style={{
                fontSize: "17px",
                fontWeight: 600,
                margin: "0 0 6px",
                color: "var(--foreground)",
              }}
            >
              {plan.title}
            </h2>
            <p
              style={{
                margin: 0,
                color: "var(--muted)",
                fontSize: "13px",
                lineHeight: "1.5",
              }}
            >
              {plan.summary}
            </p>
          </div>
        </div>

        {/* Expected Outcome Callout */}
        <div
          style={{
            padding: "10px 14px",
            background: "rgba(16, 185, 129, 0.08)",
            borderRadius: "6px",
            border: "1px solid rgba(16, 185, 129, 0.22)",
            display: "flex",
            alignItems: "flex-start",
            gap: "10px",
          }}
        >
          <CheckCircle2
            size={16}
            color="var(--accent-green, #10b981)"
            style={{ marginTop: "2px", flexShrink: 0 }}
          />
          <div style={{ flex: 1 }}>
            <div
              style={{
                fontSize: "11px",
                fontWeight: 600,
                color: "var(--accent-green, #10b981)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                marginBottom: "2px",
              }}
            >
              Expected Outcome
            </div>
            <p
              style={{
                margin: 0,
                fontSize: "12px",
                color: "var(--foreground)",
                opacity: 0.9,
                lineHeight: "1.5",
              }}
            >
              {plan.expected_outcome}
            </p>
          </div>
        </div>

        {/* Target Findings & Manual Command Prompts */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "10px",
            paddingTop: "6px",
            borderTop: "1px solid var(--border)",
          }}
        >
          {plan.findings_addressed.length > 0 && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                flexWrap: "wrap",
              }}
            >
              <span
                style={{
                  fontSize: "11px",
                  color: "var(--muted)",
                  fontWeight: 600,
                }}
              >
                Addressed Issues ({plan.findings_addressed.length}):
              </span>
              <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                {plan.findings_addressed.map((fid) => {
                  const f = findingsMap.get(fid);
                  const sev = f?.severity || "info";
                  const sevColor =
                    sev === "critical"
                      ? "var(--accent-red, #ef4444)"
                      : sev === "high"
                        ? "var(--accent-orange, #f97316)"
                        : sev === "medium"
                          ? "var(--accent-yellow, #eab308)"
                          : "var(--accent-blue, #3b82f6)";

                  return (
                    <button
                      key={fid}
                      onClick={() => onFindingClick && onFindingClick(fid)}
                      className="button secondary compact"
                      style={{
                        fontSize: "11px",
                        padding: "3px 8px",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                        borderRadius: "5px",
                      }}
                      title={f ? `${f.title} (${f.rule})` : `Finding ${fid}`}
                    >
                      <span
                        style={{
                          width: "6px",
                          height: "6px",
                          borderRadius: "50%",
                          background: sevColor,
                          flexShrink: 0,
                        }}
                      />
                      <span style={{ fontWeight: 500 }}>
                        {f?.package ? `${f.package}: ` : ""}
                        {f?.title || fid.substring(0, 8)}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {plan.manual_steps.length > 0 && activeTab !== "commands" && (
            <button
              onClick={() => setActiveTab("commands")}
              className="button secondary compact"
              style={{
                fontSize: "11px",
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                color: "var(--accent-yellow, #eab308)",
                borderColor: "rgba(234, 179, 8, 0.3)",
                background: "rgba(234, 179, 8, 0.08)",
              }}
            >
              <Terminal size={12} />
              <span>{plan.manual_steps.length} terminal {plan.manual_steps.length === 1 ? "step" : "steps"} needed</span>
              <ArrowRight size={11} />
            </button>
          )}
        </div>
      </div>

      {/* Validation Gate Alert Box (if not verified) */}
      {plan.validation_status !== "VERIFIED" && (
        <div
          style={{
            padding: "14px 16px",
            borderRadius: "8px",
            background:
              plan.validation_status === "UNVERIFIED"
                ? "rgba(234, 179, 8, 0.08)"
                : "rgba(239, 68, 68, 0.08)",
            border: `1px solid ${
              plan.validation_status === "UNVERIFIED"
                ? "rgba(234, 179, 8, 0.3)"
                : "rgba(239, 68, 68, 0.3)"
            }`,
            display: "flex",
            flexDirection: "column",
            gap: "8px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <ShieldAlert
              size={17}
              color={
                plan.validation_status === "UNVERIFIED"
                  ? "var(--accent-yellow, #eab308)"
                  : "var(--accent-red, #ef4444)"
              }
            />
            <strong
              style={{
                fontSize: "13px",
                color:
                  plan.validation_status === "UNVERIFIED"
                    ? "var(--accent-yellow, #eab308)"
                    : "var(--accent-red, #ef4444)",
              }}
            >
              {plan.validation_status === "UNVERIFIED"
                ? "Deterministic Validation Gate: UNVERIFIED — Application Blocked"
                : "Deterministic Validation Gate: REJECTED — Application Blocked"}
            </strong>
          </div>
          <p
            style={{
              margin: 0,
              fontSize: "12px",
              color: "var(--foreground)",
              opacity: 0.9,
              lineHeight: 1.5,
            }}
          >
            {plan.validation_status === "UNVERIFIED"
              ? "External package registry or vulnerability intelligence is currently unavailable. Guardian strictly forbids applying unverified dependency modifications."
              : "Proposed dependency modifications violated Guardian's mandatory security validation rules. Incomplete, vulnerable, inconsistent, or fabricated dependency changes cannot be approved or applied."}
          </p>
          {plan.validation_reasons && plan.validation_reasons.length > 0 && (
            <ul
              style={{
                margin: "4px 0 0 16px",
                padding: 0,
                fontSize: "12px",
                color: "var(--foreground)",
                display: "flex",
                flexDirection: "column",
                gap: "2px",
              }}
            >
              {plan.validation_reasons.map((reason, idx) => (
                <li key={idx}>{reason}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Segmented Control Tabs */}
      <div
        className="workspace-segmented-control"
        role="tablist"
        style={{
          width: "100%",
          display: "flex",
          padding: "3px",
          gap: "4px",
        }}
      >
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "diff"}
          onClick={() => setActiveTab("diff")}
          className={`workspace-segmented-tab ${activeTab === "diff" ? "active" : ""}`}
          style={{ flex: 1, justifyContent: "center", padding: "7px 12px" }}
        >
          <FileCode2 size={14} />
          <span>Code Changes</span>
          <span className="workspace-tab-badge">
            {plan.proposed_changes.length} {plan.proposed_changes.length === 1 ? "file" : "files"}
          </span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "safety"}
          onClick={() => setActiveTab("safety")}
          className={`workspace-segmented-tab ${activeTab === "safety" ? "active" : ""}`}
          style={{ flex: 1, justifyContent: "center", padding: "7px 12px" }}
        >
          <ShieldAlert size={14} />
          <span>Safety & Trade-offs</span>
          <span className="workspace-tab-badge">
            {plan.tradeoffs.length + plan.potential_risks.length}
          </span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "commands"}
          onClick={() => setActiveTab("commands")}
          className={`workspace-segmented-tab ${activeTab === "commands" ? "active" : ""}`}
          style={{ flex: 1, justifyContent: "center", padding: "7px 12px" }}
        >
          <Terminal size={14} />
          <span>Next Steps & Commands</span>
          {plan.manual_steps.length > 0 ? (
            <span
              className="workspace-tab-badge"
              style={{
                background: "rgba(234, 179, 8, 0.2)",
                color: "#eab308",
                fontWeight: 600,
              }}
            >
              {plan.manual_steps.length}
            </span>
          ) : verification ? (
            <span
              className="workspace-tab-badge"
              style={{
                background: "rgba(16, 185, 129, 0.2)",
                color: "#10b981",
                fontWeight: 600,
              }}
            >
              Verified
            </span>
          ) : (
            <span className="workspace-tab-badge">0</span>
          )}
        </button>
      </div>

      {/* Tab 1: Code Changes / Diff */}
      {activeTab === "diff" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          <DiffViewer
            changes={plan.proposed_changes}
            onDownloadPatch={() => downloadPatchFile(plan)}
          />
        </div>
      )}

      {/* Tab 2: Safety & Trade-offs */}
      {activeTab === "safety" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div
            className="grid-2-col"
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
              gap: "12px",
            }}
          >
            {/* Trade-offs */}
            <div className="card" style={{ padding: "16px" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  marginBottom: "10px",
                }}
              >
                <Layers size={16} color="var(--accent-blue, #3b82f6)" />
                <strong style={{ fontSize: "13px" }}>
                  Trade-offs & Considerations
                </strong>
              </div>
              {plan.tradeoffs.length > 0 ? (
                <ul
                  style={{
                    margin: 0,
                    paddingLeft: "18px",
                    fontSize: "12px",
                    color: "var(--foreground)",
                    opacity: 0.85,
                    lineHeight: "1.6",
                  }}
                >
                  {plan.tradeoffs.map((item, idx) => (
                    <li key={idx} style={{ marginBottom: "4px" }}>
                      {item}
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ margin: 0, fontSize: "12px", color: "var(--muted)" }}>
                  No significant architectural trade-offs identified.
                </p>
              )}
            </div>

            {/* Potential Risks & Regressions */}
            <div className="card" style={{ padding: "16px" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  marginBottom: "10px",
                }}
              >
                <AlertTriangle size={16} color="var(--accent-orange, #f97316)" />
                <strong style={{ fontSize: "13px" }}>
                  Potential Regressions & Risks
                </strong>
              </div>
              {plan.potential_risks.length > 0 ? (
                <ul
                  style={{
                    margin: 0,
                    paddingLeft: "18px",
                    fontSize: "12px",
                    color: "var(--foreground)",
                    opacity: 0.85,
                    lineHeight: "1.6",
                  }}
                >
                  {plan.potential_risks.map((item, idx) => (
                    <li key={idx} style={{ marginBottom: "4px" }}>
                      {item}
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ margin: 0, fontSize: "12px", color: "var(--muted)" }}>
                  No elevated regression risks detected.
                </p>
              )}
            </div>
          </div>

          {/* Verification Strategy */}
          {plan.recommended_verification.length > 0 && (
            <div className="card" style={{ padding: "16px" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  marginBottom: "8px",
                }}
              >
                <ShieldCheck size={16} color="var(--accent-blue, #3b82f6)" />
                <strong style={{ fontSize: "13px" }}>Verification Strategy</strong>
              </div>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: "18px",
                  fontSize: "12px",
                  color: "var(--foreground)",
                  opacity: 0.85,
                  lineHeight: "1.6",
                }}
              >
                {plan.recommended_verification.map((v, idx) => (
                  <li key={idx} style={{ marginBottom: "4px" }}>
                    {v}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Limitations Disclosures */}
          {plan.limitations.length > 0 && (
            <div
              style={{
                padding: "12px 14px",
                borderRadius: "6px",
                background: "rgba(255,255,255,0.02)",
                border: "1px solid var(--border)",
                fontSize: "11px",
                color: "var(--muted)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  marginBottom: "4px",
                }}
              >
                <Info size={14} />
                <strong>Limitations & Uncertainty Disclosures:</strong>
              </div>
              <ul style={{ margin: 0, paddingLeft: "18px", lineHeight: "1.5" }}>
                {plan.limitations.map((lim, idx) => (
                  <li key={idx}>{lim}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Next Steps & Commands */}
      {activeTab === "commands" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {/* Recommended Manual Commands */}
          <div
            className="card"
            style={{
              padding: "16px",
              background: "var(--surface)",
              border: "1px solid var(--border)",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "8px",
                flexWrap: "wrap",
                gap: "8px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Terminal size={16} color="var(--accent-green, #10b981)" />
                <strong style={{ fontSize: "13px" }}>
                  Terminal Commands (Post-Application)
                </strong>
              </div>
              {plan.manual_steps.length > 1 && (
                <button
                  type="button"
                  onClick={copyAllCommands}
                  className="button secondary compact"
                  style={{ fontSize: "11px", padding: "3px 8px" }}
                >
                  {allCopied ? (
                    <CheckIcon size={12} className="text-emerald-400" />
                  ) : (
                    <CopyIcon size={12} />
                  )}
                  <span>{allCopied ? "All copied" : "Copy all commands"}</span>
                </button>
              )}
            </div>

            <p
              style={{
                fontSize: "12px",
                color: "var(--muted)",
                margin: "0 0 12px",
                lineHeight: "1.5",
              }}
            >
              Guardian strictly respects local safety boundaries and never executes
              terminal shell commands or package scripts automatically. Run these in your project terminal after applying changes:
            </p>

            {plan.manual_steps.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {plan.manual_steps.map((step, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "8px 12px",
                      background: "var(--surface-subtle, rgba(0, 0, 0, 0.25))",
                      borderRadius: "6px",
                      border: "1px solid var(--border)",
                      fontSize: "12px",
                      fontFamily: "var(--font-mono, monospace)",
                      gap: "10px",
                    }}
                  >
                    <span style={{ flex: 1, wordBreak: "break-all" }}>{step}</span>
                    <button
                      type="button"
                      onClick={() => copyCommand(step, idx)}
                      className="button secondary compact"
                      style={{ fontSize: "11px", padding: "3px 8px", flexShrink: 0 }}
                      title="Copy command to clipboard"
                    >
                      {copiedIdx === idx ? (
                        <CheckIcon size={12} className="text-emerald-400" />
                      ) : (
                        <CopyIcon size={12} />
                      )}
                      <span>{copiedIdx === idx ? "Copied" : "Copy"}</span>
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  padding: "12px",
                  borderRadius: "6px",
                  background: "rgba(16, 185, 129, 0.05)",
                  border: "1px solid rgba(16, 185, 129, 0.2)",
                  color: "var(--accent-green, #10b981)",
                  fontSize: "12px",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                }}
              >
                <CheckCircle2 size={15} />
                <span>No manual shell commands required. File modifications are fully self-contained.</span>
              </div>
            )}
          </div>

          {/* Verification Outcome (if rescan verification was performed) */}
          {verification && (
            <div
              id="remediation-verification-outcome"
              className="card"
              style={{
                padding: "16px",
                background: "rgba(16, 185, 129, 0.05)",
                border: "1px solid rgba(16, 185, 129, 0.3)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  marginBottom: "8px",
                }}
              >
                <ShieldCheck size={18} color="var(--accent-green, #10b981)" />
                <strong
                  style={{
                    fontSize: "14px",
                    color: "var(--accent-green, #10b981)",
                  }}
                >
                  Rescan Verification Outcome
                </strong>
              </div>
              <p
                style={{
                  margin: "0 0 12px",
                  fontSize: "12px",
                  color: "var(--foreground)",
                  lineHeight: "1.5",
                }}
              >
                {verification.summary}
              </p>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
                  gap: "12px",
                  fontSize: "12px",
                }}
              >
                <div
                  style={{
                    padding: "10px 12px",
                    background: "rgba(16, 185, 129, 0.08)",
                    border: "1px solid rgba(16, 185, 129, 0.2)",
                    borderRadius: "6px",
                  }}
                >
                  <strong style={{ color: "var(--accent-green, #10b981)", display: "block", marginBottom: "4px" }}>
                    Resolved ({verification.resolved_findings.length}):
                  </strong>
                  <ul
                    style={{
                      margin: 0,
                      paddingLeft: "16px",
                      color: "var(--foreground)",
                      opacity: 0.9,
                    }}
                  >
                    {verification.resolved_findings.map((f, i) => (
                      <li key={i}>{f}</li>
                    ))}
                  </ul>
                </div>

                <div
                  style={{
                    padding: "10px 12px",
                    background: "rgba(249, 115, 22, 0.08)",
                    border: "1px solid rgba(249, 115, 22, 0.2)",
                    borderRadius: "6px",
                  }}
                >
                  <strong style={{ color: "var(--accent-orange, #f97316)", display: "block", marginBottom: "4px" }}>
                    Persistent / Remaining ({verification.persistent_findings.length}):
                  </strong>
                  {verification.persistent_findings.length > 0 ? (
                    <ul
                      style={{
                        margin: 0,
                        paddingLeft: "16px",
                        color: "var(--muted)",
                      }}
                    >
                      {verification.persistent_findings.map((f, i) => (
                        <li key={i}>{f}</li>
                      ))}
                    </ul>
                  ) : (
                    <span style={{ color: "var(--muted)", fontSize: "11px" }}>
                      Zero remaining vulnerabilities from targeted set.
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

          {!verification && (
            <div
              style={{
                padding: "12px 14px",
                borderRadius: "6px",
                background: "var(--surface-muted, rgba(255,255,255,0.02))",
                border: "1px solid var(--border)",
                fontSize: "12px",
                color: "var(--muted)",
                display: "flex",
                alignItems: "center",
                gap: "10px",
              }}
            >
              <ShieldCheck size={16} color="var(--muted)" />
              <span>
                After applying modifications to your project, use <strong>Rescan & verify outcome</strong> in the footer to verify that the vulnerability has been completely resolved.
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
