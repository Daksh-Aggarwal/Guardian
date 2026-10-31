"use client";

import React, { useState, useMemo } from "react";
import {
  FileCode2,
  AlertTriangle,
  Info,
  Code,
  ShieldAlert,
} from "lucide-react";
import {
  GitBranch,
  ArrowRight,
  Sparkles,
  ExternalLink,
  CheckCircle2,
} from "@/components/icons";
import { Report, Finding, FlowStep, DataFlow } from "@/lib/types";
import { Eyebrow, Badge } from "./ui";

export default function BehavioralFlowExplorer({
  report,
  onSelectFinding,
  onAskIntelligence,
}: {
  report: Report;
  onSelectFinding?: (findingId: string) => void;
  onAskIntelligence?: (findingId: string) => void;
}) {
  // Find all findings with structured data flows
  const flowFindings = useMemo(() => {
    return report.findings.filter(
      (f) => f.data_flows && f.data_flows.length > 0,
    );
  }, [report.findings]);

  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    flowFindings[0]?.id || null,
  );
  const [selectedFlowIndex, setSelectedFlowIndex] = useState<number>(0);
  const [selectedStepIndex, setSelectedStepIndex] = useState<number>(0);

  const activeFinding = useMemo(() => {
    return (
      flowFindings.find((f) => f.id === selectedFindingId) ||
      flowFindings[0] ||
      null
    );
  }, [flowFindings, selectedFindingId]);

  const activeFlow = useMemo(() => {
    if (!activeFinding || !activeFinding.data_flows) return null;
    return (
      activeFinding.data_flows[selectedFlowIndex] ||
      activeFinding.data_flows[0] ||
      null
    );
  }, [activeFinding, selectedFlowIndex]);

  const activeStep = useMemo(() => {
    if (!activeFlow || !activeFlow.steps) return null;
    return activeFlow.steps[selectedStepIndex] || activeFlow.steps[0] || null;
  }, [activeFlow, selectedStepIndex]);

  // Meaningful empty state if no flows exist
  if (flowFindings.length === 0) {
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
            background: "rgba(16, 185, 129, 0.12)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#10b981",
          }}
        >
          <CheckCircle2 size={26} />
        </div>
        <div>
          <h3 style={{ margin: "0 0 4px", fontSize: "17px" }}>
            No Data Exfiltration Propagation Flows Detected
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
            Static AST analysis traced data flow throughout inspected source
            code and found no paths connecting private credentials, environment
            tokens, or sensitive files to outbound network requests.
          </p>
        </div>
        <div
          style={{
            fontSize: "12px",
            color: "var(--muted)",
            display: "flex",
            alignItems: "center",
            gap: "6px",
            marginTop: "6px",
          }}
        >
          <Info size={14} />
          <span>
            Static analysis establishes syntactic reachability, not proof of
            runtime safety.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      {/* Disclaimer Banner */}
      <div
        className="card"
        style={{
          padding: "14px 18px",
          background: "rgba(245, 158, 11, 0.08)",
          border: "1px solid rgba(245, 158, 11, 0.25)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "10px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <AlertTriangle size={18} color="#f59e0b" style={{ flexShrink: 0 }} />
          <span style={{ fontSize: "12px", color: "var(--text)" }}>
            <strong>Static Reachability Notice:</strong> Static analysis
            establishes syntactic propagation pathways through abstract syntax
            trees. It does not prove runtime execution or malicious intent.
          </span>
        </div>
        {activeFinding && onAskIntelligence && (
          <button
            onClick={() => onAskIntelligence(activeFinding.id)}
            className="button secondary compact"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              fontSize: "11px",
            }}
          >
            <Sparkles size={12} />
            <span>Ask Guardian Intelligence about this flow</span>
          </button>
        )}
      </div>

      {/* Main Flow Inspector Layout */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "320px 1fr",
          gap: "16px",
        }}
      >
        {/* Left Col: Finding & Flow Selector */}
        <div
          className="card"
          style={{
            padding: "16px",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
            maxHeight: "680px",
            overflowY: "auto",
          }}
        >
          <Eyebrow>IDENTIFIED DATA FLOW FINDINGS</Eyebrow>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {flowFindings.map((f) => {
              const isSelected = f.id === activeFinding?.id;
              return (
                <button
                  key={f.id}
                  onClick={() => {
                    setSelectedFindingId(f.id);
                    setSelectedFlowIndex(0);
                    setSelectedStepIndex(0);
                  }}
                  style={{
                    padding: "10px 12px",
                    borderRadius: "8px",
                    background: isSelected
                      ? "var(--surface-muted, rgba(255,255,255,0.08))"
                      : "transparent",
                    border: isSelected
                      ? "1px solid var(--accent, #6366f1)"
                      : "1px solid var(--line)",
                    textAlign: "left",
                    cursor: "pointer",
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px",
                    transition: "all 0.15s ease",
                  }}
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
                        fontWeight: 600,
                        fontSize: "13px",
                        color: isSelected ? "#818cf8" : "var(--text)",
                      }}
                    >
                      {f.title}
                    </span>
                    <Badge severity={f.severity} size="sm" />
                  </div>
                  <span
                    style={{
                      fontSize: "11px",
                      color: "var(--muted)",
                      fontFamily: "monospace",
                    }}
                  >
                    {f.evidence[0]?.file || "source file"}
                  </span>
                  <span
                    style={{
                      fontSize: "10px",
                      color: "#10b981",
                      marginTop: "2px",
                    }}
                  >
                    {f.data_flows?.length || 0} propagation{" "}
                    {f.data_flows?.length === 1 ? "path" : "paths"}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Col: Visual Source-to-Sink Progression */}
        {activeFinding && activeFlow && (
          <div
            className="card"
            style={{
              padding: "20px",
              display: "flex",
              flexDirection: "column",
              gap: "18px",
            }}
          >
            {/* Header info */}
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                flexWrap: "wrap",
                gap: "10px",
                paddingBottom: "14px",
                borderBottom: "1px solid var(--line)",
              }}
            >
              <div>
                <span
                  style={{
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    color: "var(--muted)",
                    fontWeight: 600,
                  }}
                >
                  SOURCE-TO-SINK PROPAGATION SEQUENCE
                </span>
                <h3 style={{ margin: "4px 0 2px", fontSize: "16px" }}>
                  {activeFinding.title}
                </h3>
                <p
                  style={{ margin: 0, fontSize: "12px", color: "var(--muted)" }}
                >
                  {activeFinding.explanation}
                </p>
              </div>

              {activeFinding.data_flows &&
                activeFinding.data_flows.length > 1 && (
                  <div
                    style={{
                      display: "flex",
                      gap: "6px",
                      alignItems: "center",
                    }}
                  >
                    <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                      Path:
                    </span>
                    {activeFinding.data_flows.map((_, idx) => (
                      <button
                        key={idx}
                        onClick={() => {
                          setSelectedFlowIndex(idx);
                          setSelectedStepIndex(0);
                        }}
                        className={`dataset-filter-btn ${selectedFlowIndex === idx ? "active" : ""}`}
                        style={{ padding: "4px 8px", fontSize: "11px" }}
                      >
                        {idx + 1}
                      </button>
                    ))}
                  </div>
                )}
            </div>

            {/* Visual Step Chain Progression */}
            <div>
              <span
                style={{
                  fontSize: "11px",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  color: "var(--muted)",
                  display: "block",
                  marginBottom: "10px",
                }}
              >
                Steps ({activeFlow.steps.length})
              </span>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  overflowX: "auto",
                  paddingBottom: "10px",
                }}
              >
                {activeFlow.steps.map((step, idx) => {
                  const isCurrent = idx === selectedStepIndex;
                  const isSource = step.kind === "source";
                  const isSink = step.kind === "sink";

                  return (
                    <React.Fragment key={idx}>
                      <button
                        onClick={() => setSelectedStepIndex(idx)}
                        style={{
                          padding: "10px 14px",
                          borderRadius: "8px",
                          background: isCurrent
                            ? "var(--surface-muted, rgba(255,255,255,0.1))"
                            : "#0f172a",
                          border: isCurrent
                            ? "2px solid #818cf8"
                            : isSource
                              ? "1px solid #3b82f6"
                              : isSink
                                ? "1px solid #ef4444"
                                : "1px solid var(--line)",
                          cursor: "pointer",
                          display: "flex",
                          flexDirection: "column",
                          alignItems: "flex-start",
                          gap: "4px",
                          minWidth: "140px",
                          transition: "all 0.15s ease",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                            width: "100%",
                            justifyContent: "space-between",
                          }}
                        >
                          <span
                            style={{
                              fontSize: "10px",
                              fontWeight: 700,
                              color: isSource
                                ? "#60a5fa"
                                : isSink
                                  ? "#f87171"
                                  : "#94a3b8",
                              textTransform: "uppercase",
                            }}
                          >
                            Step {idx + 1}: {step.kind}
                          </span>
                          {step.binding && (
                            <span
                              style={{
                                fontSize: "9px",
                                color: "#c084fc",
                                fontFamily: "monospace",
                              }}
                            >
                              {step.binding}
                            </span>
                          )}
                        </div>
                        <span
                          style={{
                            fontSize: "11px",
                            color: "var(--foreground)",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            maxWidth: "130px",
                          }}
                        >
                          {step.detail}
                        </span>
                      </button>

                      {idx < activeFlow.steps.length - 1 && (
                        <ArrowRight
                          size={14}
                          color="#64748b"
                          style={{ flexShrink: 0 }}
                        />
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            {/* Selected Step Code & Location Inspector */}
            {activeStep && (
              <div
                style={{
                  borderRadius: "8px",
                  background: "#090d16",
                  border: "1px solid var(--line)",
                  padding: "16px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "10px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                    }}
                  >
                    <Code size={15} color="#818cf8" />
                    <span
                      style={{
                        fontFamily: "var(--font-mono, monospace)",
                        fontSize: "12px",
                        color: "var(--text)",
                      }}
                    >
                      {activeStep.file} : line {activeStep.line}, col{" "}
                      {activeStep.column}
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: "11px",
                      textTransform: "capitalize",
                      padding: "2px 8px",
                      borderRadius: "4px",
                      background: "rgba(99, 102, 241, 0.15)",
                      color: "#818cf8",
                    }}
                  >
                    Kind: {activeStep.kind}
                  </span>
                </div>

                {/* Snippet box */}
                <pre
                  style={{
                    margin: 0,
                    padding: "12px",
                    borderRadius: "6px",
                    background: "#040711",
                    color: "#f8fafc",
                    fontSize: "12px",
                    fontFamily: "var(--font-mono, monospace)",
                    overflowX: "auto",
                    lineHeight: "1.5",
                    border: "1px solid rgba(255, 255, 255, 0.08)",
                  }}
                >
                  <code>
                    {activeStep.snippet || "(No code snippet recorded)"}
                  </code>
                </pre>

                {activeStep.detail && (
                  <p
                    style={{
                      margin: "8px 0 0",
                      fontSize: "11px",
                      color: "var(--muted)",
                    }}
                  >
                    Observation: {activeStep.detail}
                  </p>
                )}
              </div>
            )}

            {/* Analysis Limitations for this flow */}
            {activeFlow.limitations && activeFlow.limitations.length > 0 && (
              <div
                style={{
                  padding: "10px 14px",
                  borderRadius: "6px",
                  background: "var(--surface-muted, rgba(255,255,255,0.02))",
                  border: "1px solid var(--line)",
                  fontSize: "11px",
                  color: "var(--muted)",
                }}
              >
                <strong style={{ color: "var(--text)" }}>
                  Flow Limitations:{" "}
                </strong>
                {activeFlow.limitations.join("; ")}
              </div>
            )}

            {/* Jump to finding */}
            {onSelectFinding && (
              <div>
                <button
                  onClick={() => onSelectFinding(activeFinding.id)}
                  style={{
                    background: "none",
                    border: "none",
                    color: "#818cf8",
                    cursor: "pointer",
                    padding: 0,
                    fontSize: "12px",
                    textDecoration: "underline",
                  }}
                >
                  Jump to finding in standard report view &rarr;
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
