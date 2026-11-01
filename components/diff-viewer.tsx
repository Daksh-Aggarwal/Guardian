"use client";

import { useState } from "react";
import { FileCode } from "lucide-react";
import { Download, CopyIcon, CheckIcon } from "@/components/icons";
import { ProposedFileChange } from "@/lib/types";

export default function DiffViewer({
  changes,
  onDownloadPatch,
}: {
  changes: ProposedFileChange[];
  onDownloadPatch?: () => void;
}) {
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [copied, setCopied] = useState(false);

  if (!changes || changes.length === 0) {
    return (
      <div
        className="empty-diff-state"
        style={{ padding: "24px", textAlign: "center", color: "var(--muted)" }}
      >
        <p>No file modifications proposed in this plan.</p>
      </div>
    );
  }

  const activeChange = changes[selectedIdx] || changes[0];

  function copyDiff() {
    navigator.clipboard.writeText(activeChange.diff);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function getLineStats(diff: string) {
    let add = 0;
    let del = 0;
    for (const line of diff.split("\n")) {
      if (line.startsWith("+") && !line.startsWith("+++")) add++;
      else if (line.startsWith("-") && !line.startsWith("---")) del++;
    }
    return { add, del };
  }

  // Parse unified diff into structured lines
  const lines = activeChange.diff.split("\n");

  return (
    <div
      className="diff-viewer-container card"
      style={{
        padding: "0",
        overflow: "hidden",
        border: "1px solid var(--border)",
      }}
    >
      {/* File selector header if multiple files */}
      <div
        className="diff-file-tabs"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          background: "var(--surface-muted, rgba(255,255,255,0.03))",
          borderBottom: "1px solid var(--border)",
          padding: "8px 14px",
          gap: "8px",
          flexWrap: "wrap",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            overflowX: "auto",
          }}
        >
          {changes.map((c, i) => {
            const { add, del } = getLineStats(c.diff);
            return (
              <button
                key={c.file_path}
                onClick={() => setSelectedIdx(i)}
                className={`button compact ${selectedIdx === i ? "primary" : "secondary"}`}
                style={{
                  fontSize: "12px",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "4px 10px",
                }}
              >
                <FileCode size={14} />
                <span>{c.file_path}</span>
                <span
                  style={{
                    fontSize: "10px",
                    padding: "1px 5px",
                    borderRadius: "4px",
                    background:
                      c.operation === "create"
                        ? "rgba(16, 185, 129, 0.2)"
                        : "rgba(59, 130, 246, 0.2)",
                    color:
                      c.operation === "create"
                        ? "var(--accent-green, #10b981)"
                        : "var(--accent-blue, #3b82f6)",
                  }}
                >
                  {c.operation}
                </span>
                {(add > 0 || del > 0) && (
                  <span
                    style={{
                      fontSize: "10px",
                      fontFamily: "var(--font-mono, monospace)",
                      display: "inline-flex",
                      gap: "3px",
                      fontWeight: 600,
                    }}
                  >
                    {add > 0 && <span style={{ color: "#10b981" }}>+{add}</span>}
                    {del > 0 && <span style={{ color: "#ef4444" }}>-{del}</span>}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <button
            onClick={copyDiff}
            className="button secondary compact"
            style={{ fontSize: "11px", padding: "4px 8px" }}
            title="Copy diff to clipboard"
          >
            {copied ? (
              <CheckIcon
                size={13}
                className="inline-flex items-center justify-center text-emerald-400"
              />
            ) : (
              <CopyIcon
                size={13}
                className="inline-flex items-center justify-center"
              />
            )}
            {copied ? "Copied" : "Copy diff"}
          </button>
          {onDownloadPatch && (
            <button
              onClick={onDownloadPatch}
              className="button secondary compact"
              style={{ fontSize: "11px", padding: "4px 8px" }}
              title="Download unified .patch file"
            >
              <Download size={13} />
              Download .patch
            </button>
          )}
        </div>
      </div>

      {/* File rationale and details banner */}
      <div
        style={{
          padding: "10px 16px",
          background: "var(--surface)",
          borderBottom: "1px solid var(--border)",
          fontSize: "12px",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "4px",
            flexWrap: "wrap",
            gap: "6px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <FileCode size={14} color="var(--accent-blue, #3b82f6)" />
            <strong>{activeChange.file_path}</strong>
          </div>
          <span
            style={{
              color: "var(--muted)",
              fontFamily: "var(--font-mono, monospace)",
              fontSize: "11px",
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              background: "var(--surface-muted, rgba(255, 255, 255, 0.04))",
              padding: "2px 8px",
              borderRadius: "4px",
              border: "1px solid var(--border)",
            }}
          >
            <span>SHA:</span>
            <span>
              {activeChange.original_sha256
                ? activeChange.original_sha256.substring(0, 8)
                : "none"}
            </span>
            <span style={{ opacity: 0.6 }}>→</span>
            <span style={{ color: "var(--accent-green, #10b981)" }}>
              {activeChange.proposed_sha256.substring(0, 8)}
            </span>
          </span>
        </div>
        <p style={{ margin: "2px 0 0", color: "var(--foreground)", opacity: 0.85, lineHeight: "1.5" }}>
          {activeChange.rationale}
        </p>
        {activeChange.expected_result && (
          <p
            style={{
              margin: "4px 0 0",
              color: "var(--muted)",
              fontSize: "11px",
            }}
          >
            <strong style={{ color: "var(--foreground)" }}>Outcome:</strong>{" "}
            {activeChange.expected_result}
          </p>
        )}
      </div>

      {/* Unified diff code block */}
      <div
        className="diff-content"
        style={{
          fontFamily: "var(--font-mono, monospace)",
          fontSize: "12px",
          lineHeight: "1.6",
          overflowX: "auto",
          maxHeight: "440px",
          background: "var(--diff-bg, rgba(0, 0, 0, 0.25))",
          padding: "8px 0",
        }}
      >
        {lines.map((line, idx) => {
          let bg = "transparent";
          let color = "inherit";
          let prefix = " ";

          if (line.startsWith("+") && !line.startsWith("+++")) {
            bg = "rgba(16, 185, 129, 0.15)";
            color = "#10b981";
            prefix = "+";
          } else if (line.startsWith("-") && !line.startsWith("---")) {
            bg = "rgba(239, 68, 68, 0.15)";
            color = "#ef4444";
            prefix = "-";
          } else if (line.startsWith("@@")) {
            bg = "rgba(139, 92, 246, 0.1)";
            color = "#a78bfa";
          } else if (line.startsWith("---") || line.startsWith("+++")) {
            color = "var(--muted)";
          }

          return (
            <div
              key={idx}
              style={{
                display: "flex",
                background: bg,
                color: color,
                padding: "1px 16px",
                whiteSpace: "pre",
              }}
            >
              <span
                style={{
                  width: "36px",
                  textAlign: "right",
                  paddingRight: "16px",
                  color: "var(--muted)",
                  userSelect: "none",
                  opacity: 0.5,
                  fontSize: "11px",
                }}
              >
                {idx + 1}
              </span>
              <span style={{ flex: 1 }}>{line}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
