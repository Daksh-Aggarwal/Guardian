"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FolderOpen,
  FolderSync,
  Layers,
  Code2,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronRight,
  Loader2,
  X,
  FileCode2,
  Wrench,
  Sparkles,
  ArrowRight,
  HardDrive,
  Upload,
} from "lucide-react";
import { api, Report, ScanJob, ProjectMetadata } from "@/lib/types";
import { Eyebrow, Note, Badge } from "./ui";
import RemediationPanel from "./remediation-panel";
import ReportView from "./report";
import {
  openProjectDirectory,
  isFileSystemAccessSupported,
  ProjectDirectoryResult,
  ExcludedFileEntry,
} from "@/lib/fs-access";

export default function ProjectWorkspace({
  onBack,
  onReportGenerated,
  onDirectoryHandleChange,
}: {
  onBack: () => void;
  onReportGenerated?: (report: Report) => void;
  onDirectoryHandleChange?: (handle: FileSystemDirectoryHandle | null) => void;
}) {
  const [projectData, setProjectData] = useState<ProjectDirectoryResult | null>(
    null,
  );
  const [report, setReport] = useState<Report | null>(null);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showExclusions, setShowExclusions] = useState(false);
  const [remediationOpen, setRemediationOpen] = useState(false);
  const [targetFindingId, setTargetFindingId] = useState<string | null>(null);
  const [profile, setProfile] = useState<"fast" | "deep">("fast");

  const supported = isFileSystemAccessSupported();

  // Connect local folder via File System Access API
  async function handleConnectProject() {
    setError(null);
    setLoading(true);
    try {
      const result = await openProjectDirectory();
      setProjectData(result);
      if (onDirectoryHandleChange)
        onDirectoryHandleChange(result.directoryHandle);
      setReport(null);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError((err as Error).message);
      }
    } finally {
      setLoading(false);
    }
  }

  function handleDisconnect() {
    if (projectData && report) {
      api(`/projects/${report.id}`, { method: "DELETE" }).catch(() => {});
    }
    if (onDirectoryHandleChange) onDirectoryHandleChange(null);
    setProjectData(null);
    setReport(null);
    setJob(null);
    setError(null);
  }

  // Trigger project scan
  async function runProjectScan(): Promise<Report | void> {
    if (!projectData) return;
    setError(null);
    setLoading(true);

    try {
      const res = await api<{ id: string }>("/scans/project", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: projectData.projectName,
          profile: profile,
          files: projectData.files,
        }),
      });

      const jobId = res.id;
      setJob({ id: jobId, status: "queued", stage: "Queued" });

      // Poll until scan completes
      return new Promise<Report>((resolve, reject) => {
        const interval = setInterval(async () => {
          try {
            const state = await api<ScanJob>(`/jobs/${jobId}`);
            setJob(state);

            if (state.status === "complete") {
              clearInterval(interval);
              const rep = await api<Report>(`/scans/${jobId}`);
              setReport(rep);
              if (onReportGenerated) onReportGenerated(rep);
              setLoading(false);
              resolve(rep);
            } else if (
              state.status === "failed" ||
              state.status === "cancelled"
            ) {
              clearInterval(interval);
              setLoading(false);
              const errMsg = state.error || "Scan failed.";
              setError(errMsg);
              reject(new Error(errMsg));
            }
          } catch (e) {
            clearInterval(interval);
            setLoading(false);
            setError((e as Error).message);
            reject(e);
          }
        }, 650);
      });
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
    }
  }

  // Rescan modified project (called after remediation)
  async function handleRescan(): Promise<Report | void> {
    if (!projectData) return;
    // Re-read changed files from local directory handle
    const reloaded = await openProjectDirectory();
    setProjectData(reloaded);
    return await runProjectScan();
  }

  function openRemediationForFinding(findingId?: string) {
    setTargetFindingId(findingId || null);
    setRemediationOpen(true);
  }

  return (
    <div
      className="project-workspace-container"
      style={{ display: "flex", flexDirection: "column", gap: "24px" }}
    >
      {/* Top Banner & Navigation */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
        }}
      >
        <div>
          <Eyebrow>GUARDIAN AUTOPILOT / LOCAL WORKSPACE</Eyebrow>
          <h1 style={{ fontSize: "24px", margin: "4px 0 0" }}>
            Local Project Remediation
          </h1>
          <p
            style={{
              color: "var(--muted)",
              margin: "4px 0 0",
              fontSize: "13px",
            }}
          >
            Connect an existing local codebase, detect supply chain
            vulnerabilities, generate precision diffs, and apply approved fixes.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          {projectData && (
            <button
              onClick={handleDisconnect}
              className="button secondary compact"
            >
              Disconnect project
            </button>
          )}
          <button onClick={onBack} className="button secondary compact">
            Scan history
          </button>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div
          style={{
            padding: "12px 16px",
            borderRadius: "8px",
            background: "rgba(239, 68, 68, 0.12)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            color: "#ef4444",
            fontSize: "13px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <AlertTriangle size={16} />
            <span>{error}</span>
          </div>
          <button
            onClick={() => setError(null)}
            style={{
              background: "none",
              border: "none",
              color: "#ef4444",
              cursor: "pointer",
            }}
          >
            <X size={15} />
          </button>
        </div>
      )}

      {/* Browser compatibility banner if showDirectoryPicker not supported */}
      {!supported && (
        <div
          className="card"
          style={{
            padding: "16px 20px",
            background: "rgba(234, 179, 8, 0.1)",
            border: "1px solid rgba(234, 179, 8, 0.3)",
          }}
        >
          <div
            style={{ display: "flex", alignItems: "flex-start", gap: "12px" }}
          >
            <Info
              size={20}
              color="var(--accent-yellow, #eab308)"
              style={{ flexShrink: 0, marginTop: "2px" }}
            />
            <div>
              <strong
                style={{
                  fontSize: "14px",
                  color: "var(--accent-yellow, #eab308)",
                }}
              >
                Browser File System Access API Notice
              </strong>
              <p
                style={{
                  margin: "4px 0 8px",
                  fontSize: "12px",
                  lineHeight: "1.6",
                  color: "var(--foreground)",
                  opacity: 0.85,
                }}
              >
                Direct local folder access and in-place file application require
                a browser supporting the File System Access API (such as Google
                Chrome, Microsoft Edge, or Chromium). In Firefox and Safari,
                direct disk modification is unsupported by design.
              </p>
              <p style={{ margin: 0, fontSize: "12px", color: "var(--muted)" }}>
                You can still inspect projects via ZIP upload and download
                unified <code>.patch</code> bundles to apply manually with{" "}
                <code>git apply</code>.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Empty State: Prompt to Connect Local Directory */}
      {!projectData && (
        <div
          className="card"
          style={{
            padding: "48px 24px",
            textAlign: "center",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "16px",
            border: "1px dashed var(--border)",
          }}
        >
          <div
            style={{
              width: "56px",
              height: "56px",
              borderRadius: "16px",
              background: "rgba(59, 130, 246, 0.15)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "var(--accent-blue, #3b82f6)",
            }}
          >
            <FolderOpen size={28} />
          </div>

          <div style={{ maxWidth: "480px" }}>
            <h3 style={{ fontSize: "18px", margin: "0 0 6px" }}>
              Connect a local software project
            </h3>
            <p
              style={{
                fontSize: "13px",
                color: "var(--muted)",
                margin: 0,
                lineHeight: "1.6",
              }}
            >
              Select an existing folder on your computer. Guardian indexes
              manifests, dependencies, and eligible source files locally. No
              source files are uploaded or stored in cloud databases.
            </p>
          </div>

          <div
            style={{
              display: "flex",
              gap: "12px",
              marginTop: "8px",
              flexWrap: "wrap",
              justifyContent: "center",
            }}
          >
            <button
              onClick={handleConnectProject}
              disabled={loading}
              className="button primary"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "8px",
                padding: "10px 20px",
              }}
            >
              {loading ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <FolderOpen size={16} />
              )}
              <span>
                {loading ? "Reading folder..." : "Select local project folder"}
              </span>
            </button>
          </div>

          <div
            style={{
              display: "flex",
              gap: "16px",
              marginTop: "16px",
              fontSize: "11px",
              color: "var(--muted)",
            }}
          >
            <span>✓ Safe loopback execution</span>
            <span>✓ Redacts secret files & .env</span>
            <span>✓ Read-only permission initially</span>
          </div>
        </div>
      )}

      {/* Connected Project Dashboard */}
      {projectData && (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Project Summary Card */}
          <div className="card" style={{ padding: "20px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                flexWrap: "wrap",
                gap: "14px",
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
                  <HardDrive size={16} color="var(--accent-blue, #3b82f6)" />
                  <span
                    style={{
                      fontSize: "11px",
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "var(--muted)",
                      fontWeight: 600,
                    }}
                  >
                    CONNECTED LOCAL PROJECT
                  </span>
                </div>
                <h2 style={{ margin: "0 0 4px", fontSize: "20px" }}>
                  {projectData.projectName}
                </h2>
                <p
                  style={{ margin: 0, fontSize: "12px", color: "var(--muted)" }}
                >
                  {projectData.stats.eligible} eligible text files analyzed
                  &bull; {(projectData.stats.totalBytes / 1024).toFixed(1)} KB
                  snapshot &bull; {projectData.stats.excluded} items excluded
                </p>
              </div>

              <div
                style={{ display: "flex", alignItems: "center", gap: "10px" }}
              >
                <div className="mode-switch" style={{ margin: 0 }}>
                  <button
                    className={profile === "fast" ? "active" : ""}
                    onClick={() => setProfile("fast")}
                  >
                    Fast
                  </button>
                  <button
                    className={profile === "deep" ? "active" : ""}
                    onClick={() => setProfile("deep")}
                  >
                    Deep
                  </button>
                </div>

                <button
                  onClick={runProjectScan}
                  disabled={loading}
                  className="button primary"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  {loading ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    <FolderSync size={16} />
                  )}
                  <span>
                    {loading
                      ? job?.stage || "Scanning..."
                      : report
                        ? "Rescan project"
                        : "Inspect project"}
                  </span>
                </button>

                {report && (
                  <button
                    onClick={() => openRemediationForFinding()}
                    className="button primary"
                    style={{
                      background: "var(--accent-green, #10b981)",
                      borderColor: "var(--accent-green, #10b981)",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    <Wrench size={16} />
                    <span>Autopilot remediation</span>
                  </button>
                )}
              </div>
            </div>

            {/* Excluded files collapsible accordion */}
            <div
              style={{
                marginTop: "16px",
                paddingTop: "14px",
                borderTop: "1px solid var(--border)",
              }}
            >
              <button
                onClick={() => setShowExclusions(!showExclusions)}
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--muted)",
                  fontSize: "12px",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: 0,
                }}
              >
                {showExclusions ? (
                  <ChevronDown size={14} />
                ) : (
                  <ChevronRight size={14} />
                )}
                <span>
                  View {projectData.stats.excluded} excluded files & standard
                  safety filters
                </span>
              </button>

              {showExclusions && (
                <div
                  style={{
                    marginTop: "10px",
                    maxHeight: "180px",
                    overflowY: "auto",
                    background: "var(--surface-muted, rgba(255,255,255,0.02))",
                    borderRadius: "6px",
                    padding: "10px 14px",
                    fontSize: "11px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                  }}
                >
                  {projectData.stats.excludedList.map((exc, i) => (
                    <div
                      key={i}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        color: "var(--muted)",
                      }}
                    >
                      <span
                        style={{ fontFamily: "var(--font-mono, monospace)" }}
                      >
                        {exc.path}
                      </span>
                      <span>{exc.reason}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Active Job Progress */}
          {loading && job && (
            <div
              className="card"
              style={{ padding: "18px", textAlign: "center" }}
            >
              <Loader2
                size={24}
                className="animate-spin"
                color="var(--accent-blue, #3b82f6)"
                style={{ margin: "0 auto 10px" }}
              />
              <strong style={{ fontSize: "14px" }}>
                Scanning local project...
              </strong>
              <p
                style={{
                  margin: "4px 0 0",
                  fontSize: "12px",
                  color: "var(--muted)",
                }}
              >
                {job.stage}
              </p>
            </div>
          )}

          {/* Report View after scan */}
          {report && !loading && (
            <div>
              <div
                style={{
                  padding: "12px 18px",
                  background: "var(--surface-muted, rgba(255,255,255,0.03))",
                  borderRadius: "8px",
                  border: "1px solid var(--border)",
                  marginBottom: "16px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: "10px",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <ShieldCheck size={18} color="var(--accent-green, #10b981)" />
                  <span style={{ fontSize: "13px" }}>
                    Scan complete:{" "}
                    <strong>{report.findings.length} findings</strong> detected
                    across <strong>{report.files_analyzed} files</strong>.
                  </span>
                </div>
                <button
                  onClick={() => openRemediationForFinding()}
                  className="button primary compact"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <Wrench size={14} />
                  Prepare a fix with Guardian
                </button>
              </div>

              <ReportView
                report={report}
                onBack={onBack}
                onPrepareFix={(f) => openRemediationForFinding(f.id)}
              />
            </div>
          )}
        </div>
      )}

      {/* Remediation Workspace Overlay */}
      {remediationOpen && report && (
        <RemediationPanel
          report={report}
          directoryHandle={projectData?.directoryHandle}
          targetFindingId={targetFindingId}
          onClose={() => setRemediationOpen(false)}
          onDirectoryHandleChange={(h) => {
            if (onDirectoryHandleChange) onDirectoryHandleChange(h);
          }}
          onFindingClick={(fid) => {
            setRemediationOpen(false);
            setTimeout(() => {
              document
                .getElementById("finding-" + fid)
                ?.scrollIntoView({ behavior: "smooth", block: "center" });
            }, 100);
          }}
          onRescanRequested={handleRescan}
        />
      )}
    </div>
  );
}
