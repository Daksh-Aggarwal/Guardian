"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Share2,
  Loader2,
  AlertTriangle,
  ShieldAlert,
  FileCode2,
  Code,
  Info,
} from "lucide-react";
import {
  Copy,
  Check,
  Download,
  X,
  ShieldCheck,
  GitBranch,
  Terminal,
  Cpu,
  Layers,
  Sparkles,
  ExternalLink,
  FileText,
} from "@/components/icons";
import {
  Report,
  HandoffTarget,
  RemediationMode,
  HandoffExportResponse,
  api,
} from "@/lib/types";
import { Eyebrow, Badge } from "./ui";

interface HandoffModalProps {
  report: Report;
  isOpen: boolean;
  onClose: () => void;
  initialFindingId?: string | null;
  initialFindingIds?: string[] | null;
  initialMode?: RemediationMode;
  initialTarget?: HandoffTarget;
  request?: typeof api;
}

const TARGET_OPTIONS: {
  id: HandoffTarget;
  label: string;
  badge: string;
  icon: React.ComponentType<{ size?: number; className?: string; color?: string }>;
  description: string;
}[] = [
  {
    id: "universal",
    label: "Universal Markdown",
    badge: "Portable",
    icon: FileText,
    description: "Self-contained package for ChatGPT, Gemini, Claude, or any web/desktop agent",
  },
  {
    id: "claude_code",
    label: "Claude Code",
    badge: "CLI Agent",
    icon: Terminal,
    description: "Autonomous CLI workflow: pre-inspection, minimal safe edits, and test validation",
  },
  {
    id: "cursor",
    label: "Cursor",
    badge: "IDE Composer",
    icon: Code,
    description: "Interactive IDE pair programming: scoped workspace edits and inline review",
  },
  {
    id: "codex",
    label: "OpenAI Codex",
    badge: "Code Agent",
    icon: Cpu,
    description: "Agentic repo repair: architecture conventions, deterministic steps, command outputs",
  },
  {
    id: "github_copilot",
    label: "GitHub Copilot",
    badge: "Copilot Chat",
    icon: Layers,
    description: "GitHub-aligned remediation: repo standards, regression tests, and PR readiness",
  },
];

export default function HandoffModal({
  report,
  isOpen,
  onClose,
  initialFindingId,
  initialFindingIds,
  initialMode = "focused_fix",
  initialTarget = "universal",
  request = api,
}: HandoffModalProps) {
  const [target, setTarget] = useState<HandoffTarget>(initialTarget);
  const [mode, setMode] = useState<RemediationMode>(initialMode);
  
  // Scope state: 'single' | 'selected' | 'all'
  const defaultScopeType = initialFindingId
    ? "single"
    : initialFindingIds && initialFindingIds.length > 0
    ? "selected"
    : "all";
  const [scopeType, setScopeType] = useState<"single" | "selected" | "all">(
    defaultScopeType
  );

  const [activeTab, setActiveTab] = useState<"preview" | "raw" | "json">(
    "preview"
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportData, setExportData] = useState<HandoffExportResponse | null>(
    null
  );
  const [copied, setCopied] = useState(false);
  const requestIdRef = React.useRef(0);

  // Lock background scroll and pause Lenis when modal is open
  useEffect(() => {
    if (isOpen) {
      const prevBodyOverflow = document.body.style.overflow;
      const prevHtmlOverflow = document.documentElement.style.overflow;
      document.body.style.overflow = "hidden";
      document.documentElement.style.overflow = "hidden";

      const lenis = (window as any).__lenis;
      if (lenis && typeof lenis.stop === "function") {
        lenis.stop();
      }

      return () => {
        document.body.style.overflow = prevBodyOverflow;
        document.documentElement.style.overflow = prevHtmlOverflow;
        if (lenis && typeof lenis.start === "function") {
          lenis.start();
        }
      };
    }
  }, [isOpen]);

  // Compute active finding IDs based on scopeType
  const activeFindingIds = useMemo(() => {
    if (scopeType === "single" && initialFindingId) {
      return [initialFindingId];
    }
    if (scopeType === "selected" && initialFindingIds && initialFindingIds.length > 0) {
      return initialFindingIds;
    }
    return null; // Entire scan
  }, [scopeType, initialFindingId, initialFindingIds]);

  // Fetch handoff data when target, mode, or finding IDs change with race-condition guard
  const fetchHandoff = useCallback(async () => {
    if (!isOpen || !report?.id) return;
    const currentReqId = ++requestIdRef.current;
    setLoading(true);
    setError(null);

    try {
      const response = await request<HandoffExportResponse>(
        `/scans/${report.id}/handoff`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target,
            mode,
            finding_ids: activeFindingIds,
          }),
        }
      );
      if (currentReqId === requestIdRef.current) {
        setExportData(response);
      }
    } catch (err) {
      if (currentReqId === requestIdRef.current) {
        setError((err as Error).message || "Failed to generate handoff bundle.");
      }
    } finally {
      if (currentReqId === requestIdRef.current) {
        setLoading(false);
      }
    }
  }, [isOpen, report?.id, target, mode, activeFindingIds, request]);

  useEffect(() => {
    if (isOpen) {
      fetchHandoff();
    }
  }, [isOpen, fetchHandoff]);

  // Handle escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  // Copy full generated instructions to clipboard
  const handleCopy = async () => {
    if (!exportData?.markdown) return;
    try {
      await navigator.clipboard.writeText(exportData.markdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Fallback for older browsers
      const el = document.createElement("textarea");
      el.value = exportData.markdown;
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  // Download markdown file
  const handleDownload = () => {
    if (!exportData?.markdown) return;
    const filename =
      exportData.summary?.suggested_filename ||
      `guardian-handoff-${report.name}-${report.id.slice(0, 8)}.md`;
    const blob = new Blob([exportData.markdown], {
      type: "text/markdown;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  if (!isOpen) return null;

  const summary = exportData?.summary;
  const canonical = exportData?.canonical;

  return (
    <AnimatePresence>
      <div
        data-lenis-prevent="true"
        onWheel={(e) => e.stopPropagation()}
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 9999,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "16px",
          background: "rgba(0, 0, 0, 0.72)",
          backdropFilter: "blur(4px)",
        }}
        onClick={(e) => {
          if (e.target === e.currentTarget) onClose();
        }}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 12 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 12 }}
          transition={{ duration: 0.18, ease: "easeOut" }}
          style={{
            background: "var(--surface)",
            border: "1px solid var(--line)",
            borderRadius: "14px",
            width: "100%",
            maxWidth: "960px",
            maxHeight: "92vh",
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
            boxShadow: "0 24px 48px -12px rgba(0, 0, 0, 0.5)",
          }}
        >
          {/* Header */}
          <div
            style={{
              padding: "16px 20px",
              borderBottom: "1px solid var(--line)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "12px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <div
                style={{
                  width: "36px",
                  height: "36px",
                  borderRadius: "8px",
                  background: "var(--accent-dim, rgba(59, 130, 246, 0.12))",
                  color: "var(--accent)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Share2 size={20} />
              </div>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <h2 style={{ fontSize: "17px", fontWeight: 600, margin: 0 }}>
                    Guardian Handoff 1.0
                  </h2>
                  <span
                    style={{
                      fontSize: "11px",
                      padding: "2px 8px",
                      borderRadius: "12px",
                      background: "rgba(59, 130, 246, 0.15)",
                      color: "var(--accent)",
                      fontWeight: 500,
                    }}
                  >
                    AI-Agnostic Instruction Export
                  </span>
                </div>
                <p
                  style={{
                    fontSize: "12px",
                    color: "var(--muted)",
                    margin: "2px 0 0",
                  }}
                >
                  Transfer authoritative security context, findings, and evidence to your receiving coding agent.
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              style={{
                background: "none",
                border: "none",
                color: "var(--muted)",
                cursor: "pointer",
                padding: "6px",
                borderRadius: "6px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
              title="Close (Esc)"
            >
              <X size={18} />
            </button>
          </div>

          {/* Configuration Controls Bar */}
          <div
            style={{
              padding: "12px 20px",
              background: "rgba(0, 0, 0, 0.15)",
              borderBottom: "1px solid var(--line)",
              display: "flex",
              flexDirection: "column",
              gap: "10px",
            }}
          >
            {/* Top row: Target Agent Selection */}
            <div>
              <span
                style={{
                  fontSize: "11px",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "var(--muted)",
                  fontWeight: 600,
                  display: "block",
                  marginBottom: "6px",
                }}
              >
                Target Coding Agent
              </span>
              <div
                style={{
                  display: "flex",
                  gap: "6px",
                  flexWrap: "wrap",
                }}
              >
                {TARGET_OPTIONS.map((opt) => {
                  const Icon = opt.icon;
                  const isSelected = target === opt.id;
                  return (
                    <button
                      key={opt.id}
                      onClick={() => setTarget(opt.id)}
                      style={{
                        padding: "6px 12px",
                        borderRadius: "8px",
                        fontSize: "12px",
                        fontWeight: 500,
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        cursor: "pointer",
                        border: isSelected
                          ? "1px solid var(--accent)"
                          : "1px solid var(--line)",
                        background: isSelected
                          ? "rgba(59, 130, 246, 0.16)"
                          : "var(--surface)",
                        color: isSelected ? "var(--text)" : "var(--muted)",
                        transition: "all 0.15s ease",
                      }}
                      title={opt.description}
                    >
                      <Icon size={14} color={isSelected ? "var(--accent)" : "currentColor"} />
                      <span>{opt.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Bottom row: Mode & Scope */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                flexWrap: "wrap",
                gap: "12px",
              }}
            >
              {/* Remediation Mode Selector */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span
                  style={{
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                    color: "var(--muted)",
                    fontWeight: 600,
                  }}
                >
                  Mode:
                </span>
                <div
                  style={{
                    display: "inline-flex",
                    borderRadius: "6px",
                    background: "var(--surface)",
                    border: "1px solid var(--line)",
                    padding: "2px",
                  }}
                >
                  <button
                    onClick={() => setMode("focused_fix")}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      fontSize: "12px",
                      fontWeight: 500,
                      border: "none",
                      cursor: "pointer",
                      background:
                        mode === "focused_fix"
                          ? "var(--accent)"
                          : "transparent",
                      color:
                        mode === "focused_fix" ? "var(--on-accent)" : "var(--muted)",
                    }}
                  >
                    Focused Fix
                  </button>
                  <button
                    onClick={() => setMode("deep_remediation")}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      fontSize: "12px",
                      fontWeight: 500,
                      border: "none",
                      cursor: "pointer",
                      background:
                        mode === "deep_remediation"
                          ? "var(--accent)"
                          : "transparent",
                      color:
                        mode === "deep_remediation" ? "var(--on-accent)" : "var(--muted)",
                    }}
                  >
                    Deep Security Remediation
                  </button>
                </div>
              </div>

              {/* Scope Selector */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span
                  style={{
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                    color: "var(--muted)",
                    fontWeight: 600,
                  }}
                >
                  Scope:
                </span>
                <div
                  style={{
                    display: "inline-flex",
                    borderRadius: "6px",
                    background: "var(--surface)",
                    border: "1px solid var(--line)",
                    padding: "2px",
                  }}
                >
                  {initialFindingId && (
                    <button
                      onClick={() => setScopeType("single")}
                      style={{
                        padding: "4px 10px",
                        borderRadius: "4px",
                        fontSize: "12px",
                        fontWeight: 500,
                        border: "none",
                        cursor: "pointer",
                        background:
                          scopeType === "single"
                            ? "var(--accent)"
                            : "transparent",
                        color:
                          scopeType === "single" ? "var(--on-accent)" : "var(--muted)",
                      }}
                    >
                      Finding ({initialFindingId})
                    </button>
                  )}
                  {initialFindingIds && initialFindingIds.length > 1 && (
                    <button
                      onClick={() => setScopeType("selected")}
                      style={{
                        padding: "4px 10px",
                        borderRadius: "4px",
                        fontSize: "12px",
                        fontWeight: 500,
                        border: "none",
                        cursor: "pointer",
                        background:
                          scopeType === "selected"
                            ? "var(--accent)"
                            : "transparent",
                        color:
                          scopeType === "selected" ? "var(--on-accent)" : "var(--muted)",
                      }}
                    >
                      {initialFindingIds.length} Selected Findings
                    </button>
                  )}
                  <button
                    onClick={() => setScopeType("all")}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      fontSize: "12px",
                      fontWeight: 500,
                      border: "none",
                      cursor: "pointer",
                      background:
                        scopeType === "all" ? "var(--accent)" : "transparent",
                      color: scopeType === "all" ? "var(--on-accent)" : "var(--muted)",
                    }}
                  >
                    Entire Scan ({report.findings?.length || 0})
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Summary Strip */}
          {summary && (
            <div
              style={{
                padding: "8px 20px",
                background: "rgba(255, 255, 255, 0.02)",
                borderBottom: "1px solid var(--line)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontSize: "12px",
                flexWrap: "wrap",
                gap: "8px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <span>
                  <strong>{summary.findings_count}</strong> finding(s) in scope
                </span>
                <span style={{ color: "var(--line)" }}>|</span>
                <div style={{ display: "flex", gap: "6px" }}>
                  {summary.severity_breakdown.critical > 0 && (
                    <span className="badge critical badge-sm">
                      <i className="badge-dot" />
                      {summary.severity_breakdown.critical} Critical
                    </span>
                  )}
                  {summary.severity_breakdown.high > 0 && (
                    <span className="badge high badge-sm">
                      <i className="badge-dot" />
                      {summary.severity_breakdown.high} High
                    </span>
                  )}
                  {summary.severity_breakdown.medium > 0 && (
                    <span className="badge medium badge-sm">
                      <i className="badge-dot" />
                      {summary.severity_breakdown.medium} Medium
                    </span>
                  )}
                  {summary.severity_breakdown.low > 0 && (
                    <span className="badge low badge-sm">
                      <i className="badge-dot" />
                      {summary.severity_breakdown.low} Low
                    </span>
                  )}
                </div>
                <span style={{ color: "var(--line)" }}>|</span>
                <span style={{ color: "var(--muted)" }}>
                  {summary.evidence_locations_count} evidence location(s)
                </span>
                <span style={{ color: "var(--line)" }}>|</span>
                <span style={{ color: "var(--muted)" }}>
                  {summary.affected_dependencies_count} dependency context(s)
                </span>
              </div>

              {canonical?.project.is_github ? (
                <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--muted)" }}>
                  <GitBranch size={13} />
                  <span>
                    {canonical.project.github_repo_name} @{" "}
                    <code>{canonical.project.github_commit_sha?.slice(0, 7)}</code>
                  </span>
                </div>
              ) : (
                <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--muted)" }}>
                  <FileCode2 size={13} />
                  <span>Local scan: {report.name}</span>
                </div>
              )}
            </div>
          )}

          {/* View Tab Selector */}
          <div
            style={{
              padding: "6px 20px",
              borderBottom: "1px solid var(--line)",
              display: "flex",
              alignItems: "center",
              gap: "12px",
              fontSize: "12px",
            }}
          >
            <button
              onClick={() => setActiveTab("preview")}
              style={{
                background: "none",
                border: "none",
                padding: "6px 0",
                cursor: "pointer",
                fontWeight: 500,
                color: activeTab === "preview" ? "var(--accent)" : "var(--muted)",
                borderBottom:
                  activeTab === "preview"
                    ? "2px solid var(--accent)"
                    : "2px solid transparent",
              }}
            >
              Instruction Preview
            </button>
            <button
              onClick={() => setActiveTab("raw")}
              style={{
                background: "none",
                border: "none",
                padding: "6px 0",
                cursor: "pointer",
                fontWeight: 500,
                color: activeTab === "raw" ? "var(--accent)" : "var(--muted)",
                borderBottom:
                  activeTab === "raw"
                    ? "2px solid var(--accent)"
                    : "2px solid transparent",
              }}
            >
              Raw Markdown
            </button>
            <button
              onClick={() => setActiveTab("json")}
              style={{
                background: "none",
                border: "none",
                padding: "6px 0",
                cursor: "pointer",
                fontWeight: 500,
                color: activeTab === "json" ? "var(--accent)" : "var(--muted)",
                borderBottom:
                  activeTab === "json"
                    ? "2px solid var(--accent)"
                    : "2px solid transparent",
              }}
            >
              JSON Appendix (Machine-Readable)
            </button>
          </div>

          {/* Main Body */}
          <div
            style={{
              flex: 1,
              overflowY: "auto",
              padding: "20px",
              minHeight: "360px",
              maxHeight: "560px",
            }}
          >
            {loading ? (
              <div
                style={{
                  height: "300px",
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "12px",
                  color: "var(--muted)",
                }}
              >
                <Loader2 size={32} className="spin" />
                <p style={{ margin: 0, fontSize: "13px" }}>
                  Generating {target} handoff specification...
                </p>
              </div>
            ) : error ? (
              <div
                style={{
                  padding: "16px",
                  borderRadius: "8px",
                  background: "rgba(239, 68, 68, 0.1)",
                  border: "1px solid rgba(239, 68, 68, 0.2)",
                  color: "var(--critical)",
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "10px",
                }}
              >
                <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
                <div>
                  <h4 style={{ margin: "0 0 4px", fontSize: "14px" }}>
                    Failed to Generate AI Handoff
                  </h4>
                  <p style={{ margin: 0, fontSize: "12px" }}>{error}</p>
                </div>
              </div>
            ) : exportData ? (
              activeTab === "preview" ? (
                <div
                  style={{
                    fontSize: "13px",
                    lineHeight: "1.65",
                    color: "var(--text)",
                  }}
                >
                  <div
                    style={{
                      marginBottom: "16px",
                      padding: "12px 16px",
                      borderRadius: "8px",
                      background: "rgba(59, 130, 246, 0.08)",
                      border: "1px solid rgba(59, 130, 246, 0.2)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <div>
                      <span style={{ fontWeight: 600, color: "var(--accent)" }}>
                        {summary?.title}
                      </span>
                      <p
                        style={{
                          margin: "2px 0 0",
                          fontSize: "12px",
                          color: "var(--muted)",
                        }}
                      >
                        Copy or download this instruction document. Paste it directly into{" "}
                        <strong>
                          {TARGET_OPTIONS.find((t) => t.id === target)?.label}
                        </strong>{" "}
                        to begin remediation.
                      </p>
                    </div>
                  </div>

                  {/* Formatted Markdown Content Preview */}
                  <pre
                    style={{
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      fontFamily: "var(--font-mono, monospace)",
                      fontSize: "12px",
                      lineHeight: "1.6",
                      background: "var(--background, #0b1120)",
                      padding: "16px",
                      borderRadius: "8px",
                      border: "1px solid var(--line)",
                      color: "var(--text)",
                    }}
                  >
                    {exportData.markdown}
                  </pre>
                </div>
              ) : activeTab === "raw" ? (
                <textarea
                  readOnly
                  value={exportData.markdown}
                  style={{
                    width: "100%",
                    height: "460px",
                    background: "var(--background, #0b1120)",
                    color: "var(--text)",
                    border: "1px solid var(--line)",
                    borderRadius: "8px",
                    padding: "14px",
                    fontFamily: "var(--font-mono, monospace)",
                    fontSize: "12px",
                    lineHeight: "1.5",
                    resize: "none",
                  }}
                />
              ) : (
                <pre
                  style={{
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    fontFamily: "var(--font-mono, monospace)",
                    fontSize: "12px",
                    lineHeight: "1.5",
                    background: "var(--background, #0b1120)",
                    padding: "14px",
                    borderRadius: "8px",
                    border: "1px solid var(--line)",
                    color: "var(--text)",
                    maxHeight: "460px",
                    overflowY: "auto",
                  }}
                >
                  {JSON.stringify(exportData.json_appendix, null, 2)}
                </pre>
              )
            ) : null}
          </div>

          {/* Footer Actions */}
          <div
            style={{
              padding: "12px 20px",
              borderTop: "1px solid var(--line)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              background: "var(--surface)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "12px", color: "var(--muted)" }}>
                Filename:{" "}
                <code style={{ fontSize: "11px", color: "var(--text)" }}>
                  {summary?.suggested_filename}
                </code>
              </span>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <button
                onClick={handleCopy}
                disabled={loading || !exportData}
                className="button secondary"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  fontSize: "13px",
                  padding: "8px 14px",
                }}
              >
                {copied ? <Check size={14} color="var(--accent)" /> : <Copy size={14} />}
                <span>{copied ? "Copied to Clipboard!" : "Copy Instructions"}</span>
              </button>

              <button
                onClick={handleDownload}
                disabled={loading || !exportData}
                className="button primary"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  fontSize: "13px",
                  padding: "8px 16px",
                }}
              >
                <Download size={14} />
                <span>Download .md</span>
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
