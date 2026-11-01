"use client";

import { ShieldAlert, AlertTriangle, FileCode2, Info } from "lucide-react";
import {
  CheckCircle2,
  Terminal,
  HelpCircle,
  ArrowRight,
  Layers,
  Sparkles,
} from "@/components/icons";
import { RemediationPlan } from "@/lib/types";
import { Eyebrow, Badge } from "./ui";
import DiffViewer from "./diff-viewer";
import { downloadPatchFile } from "@/lib/fs-access";

export default function RemediationPlanView({
  plan,
  onFindingClick,
}: {
  plan: RemediationPlan;
  onFindingClick?: (findingId: string) => void;
}) {
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

  return (
    <div
      className="remediation-plan-view"
      style={{ display: "flex", flexDirection: "column", gap: "20px" }}
    >
      {/* Plan Header */}
      <div className="plan-header card" style={{ padding: "18px 20px" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            gap: "12px",
            flexWrap: "wrap",
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                marginBottom: "6px",
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
            <h2 style={{ fontSize: "18px", margin: "0 0 6px" }}>
              {plan.title}
            </h2>
            <p
              style={{
                margin: "0",
                color: "var(--foreground)",
                opacity: 0.85,
                fontSize: "13px",
                lineHeight: "1.6",
              }}
            >
              {plan.summary}
            </p>
          </div>
        </div>

        {/* Expected Outcome */}
        <div
          style={{
            marginTop: "14px",
            padding: "10px 14px",
            background: "rgba(16, 185, 129, 0.08)",
            borderRadius: "6px",
            border: "1px solid rgba(16, 185, 129, 0.2)",
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
          <div>
            <strong
              style={{
                fontSize: "12px",
                color: "var(--accent-green, #10b981)",
              }}
            >
              Expected Outcome:
            </strong>
            <p
              style={{
                margin: "2px 0 0",
                fontSize: "12px",
                color: "var(--foreground)",
                opacity: 0.9,
              }}
            >
              {plan.expected_outcome}
            </p>
          </div>
        </div>

        {/* Findings Addressed */}
        {plan.findings_addressed.length > 0 && (
          <div style={{ marginTop: "14px" }}>
            <div
              style={{
                fontSize: "11px",
                color: "var(--muted)",
                marginBottom: "6px",
                fontWeight: 600,
              }}
            >
              FINDINGS ADDRESSED ({plan.findings_addressed.length}):
            </div>
            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
              {plan.findings_addressed.map((fid) => (
                <button
                  key={fid}
                  onClick={() => onFindingClick && onFindingClick(fid)}
                  className="button secondary compact"
                  style={{
                    fontSize: "11px",
                    padding: "3px 8px",
                    fontFamily: "var(--font-mono, monospace)",
                  }}
                  title="View finding in report"
                >
                  Finding {fid}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Validation Gate Alert Box */}
      {plan.validation_status !== "VERIFIED" && (
        <div
          style={{
            padding: "16px 18px",
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
            gap: "10px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <ShieldAlert
              size={18}
              color={
                plan.validation_status === "UNVERIFIED"
                  ? "var(--accent-yellow, #eab308)"
                  : "var(--accent-red, #ef4444)"
              }
            />
            <h4
              style={{
                margin: 0,
                fontSize: "14px",
                fontWeight: 600,
                color:
                  plan.validation_status === "UNVERIFIED"
                    ? "var(--accent-yellow, #eab308)"
                    : "var(--accent-red, #ef4444)",
              }}
            >
              {plan.validation_status === "UNVERIFIED"
                ? "Deterministic Validation Gate: UNVERIFIED — Application Blocked"
                : "Deterministic Validation Gate: REJECTED — Application Blocked"}
            </h4>
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
            <div style={{ marginTop: "4px" }}>
              <div
                style={{
                  fontSize: "11px",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "var(--muted)",
                  marginBottom: "6px",
                }}
              >
                Validation failure reasons:
              </div>
              <ul
                style={{
                  margin: "0 0 0 16px",
                  padding: 0,
                  fontSize: "12px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "4px",
                }}
              >
                {plan.validation_reasons.map((reason, idx) => (
                  <li key={idx} style={{ color: "var(--foreground)" }}>
                    {reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Proposed File Changes & Diff Viewer */}
      <div>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "8px",
          }}
        >
          <Eyebrow>
            PROPOSED CODE MODIFICATIONS ({plan.proposed_changes.length} FILES)
          </Eyebrow>
          <span style={{ fontSize: "11px", color: "var(--muted)" }}>
            Review every diff before approval
          </span>
        </div>
        <DiffViewer
          changes={plan.proposed_changes}
          onDownloadPatch={() => downloadPatchFile(plan)}
        />
      </div>

      {/* Trade-offs & Potential Risks Grid */}
      <div
        className="grid-2-col"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: "14px",
        }}
      >
        {/* Tradeoffs */}
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
                margin: "0",
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
                margin: "0",
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

      {/* Manual Steps Required */}
      {plan.manual_steps.length > 0 && (
        <div
          className="card"
          style={{
            padding: "16px",
            background: "var(--surface-muted, rgba(255,255,255,0.02))",
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
            <Terminal size={16} color="var(--accent-green, #10b981)" />
            <strong style={{ fontSize: "13px" }}>
              Recommended Manual Commands
            </strong>
          </div>
          <p
            style={{
              fontSize: "12px",
              color: "var(--muted)",
              margin: "0 0 10px",
            }}
          >
            Guardian adheres to strict security boundaries and does NOT execute
            package manager commands or shell scripts automatically. Run these
            commands in your project terminal after applying changes:
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {plan.manual_steps.map((step, idx) => (
              <div
                key={idx}
                style={{
                  padding: "8px 12px",
                  background: "var(--surface)",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  fontSize: "12px",
                  fontFamily:
                    step.includes("`") || step.startsWith("npm")
                      ? "var(--font-mono, monospace)"
                      : "inherit",
                }}
              >
                {step}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Verification */}
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
            <ShieldAlert size={16} color="var(--accent-blue, #3b82f6)" />
            <strong style={{ fontSize: "13px" }}>Verification Strategy</strong>
          </div>
          <ul
            style={{
              margin: "0",
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
            padding: "10px 14px",
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
  );
}
