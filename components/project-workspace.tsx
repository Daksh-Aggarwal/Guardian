"use client";

import { useState, useMemo, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Code2,
  ShieldAlert,
  AlertTriangle,
  Info,
  Loader2,
  FileCode2,
  HardDrive,
  Share2,
} from "lucide-react";
import {
  FolderOpen,
  FolderSync,
  Layers,
  Terminal,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  X,
  Wrench,
  Sparkles,
  ArrowRight,
  Upload,
  GitBranch,
  Clock,
  Eye,
  FileText,
  Search,
  Package,
  RefreshCw,
  ExternalLink,
  GitPullRequest,
} from "@/components/icons";
import { api, Report, ScanJob, ProjectMetadata, Finding } from "@/lib/types";
import { getDependencyAccounting, getFindingBreakdown } from "@/lib/accounting";
import {
  Eyebrow,
  Note,
  Badge,
  ClassificationBadge,
} from "./ui";
import RemediationPanel from "./remediation-panel";
import ReportView from "./report";
import DependencyGraph from "./dependency-graph";
import VulnerabilitiesExplorer from "./vulnerabilities-explorer";
import BehavioralFlowExplorer from "./behavioral-flow-explorer";
import RemediationHistory from "./remediation-history";
import SecurityTimeline from "./security-timeline";
import IntelligencePanel from "./intelligence-panel";
import HandoffModal from "./handoff-modal";
import {
  openProjectDirectory,
  reloadProjectDirectory,
  isFileSystemAccessSupported,
  ProjectDirectoryResult,
  ExcludedFileEntry,
} from "@/lib/fs-access";
import { resolveProjectDirectoryId } from "@/lib/project-identity";

export type WorkspaceTab =
  | "Overview"
  | "Vulnerabilities"
  | "Behavioral Flows"
  | "Remediation History"
  | "Security Timeline";

export default function ProjectWorkspace({
  onBack,
  onReportGenerated,
  onDirectoryHandleChange,
  initialReport,
  initialProjectName,
  initialProjectId,
  allReports = [],
  onOpenReportView,
}: {
  onBack?: () => void;
  onReportGenerated?: (report: Report) => void;
  onDirectoryHandleChange?: (handle: FileSystemDirectoryHandle | null) => void;
  initialReport?: Report | null;
  initialProjectName?: string | null;
  initialProjectId?: string | null;
  allReports?: Report[];
  onOpenReportView?: (report: Report) => void;
}) {
  // Stable project identity helper (preserves backward compatibility with legacy reports)
  const getProjectKey = (r: Report) => r.project_id || r.name;

  // Unique projects deduplicated by stable project key
  const uniqueProjects = useMemo(() => {
    const map = new Map<
      string,
      { id: string; name: string; latestScan: Report }
    >();
    for (const r of allReports) {
      const key = getProjectKey(r);
      if (!map.has(key)) {
        map.set(key, { id: key, name: r.name, latestScan: r });
      }
    }
    return Array.from(map.values());
  }, [allReports]);

  // Current active project key
  const [selectedProjectId, setSelectedProjectId] = useState<string>(
    initialProjectId ||
      (initialReport ? getProjectKey(initialReport) : "") ||
      (initialProjectName
        ? allReports.find((r) => r.name === initialProjectName)?.project_id ||
          initialProjectName
        : "") ||
      uniqueProjects[0]?.id ||
      "",
  );

  // Reconcile selectedProjectId when allReports changes (e.g. dataset filter switches)
  useEffect(() => {
    if (uniqueProjects.length > 0) {
      if (!uniqueProjects.some((p) => p.id === selectedProjectId)) {
        setSelectedProjectId(uniqueProjects[0].id);
      }
    } else {
      setSelectedProjectId("");
    }
  }, [uniqueProjects, selectedProjectId]);

  // Scans belonging to this project identity
  const projectScans = useMemo(() => {
    if (!selectedProjectId) return [];
    return allReports
      .filter((r) => getProjectKey(r) === selectedProjectId)
      .sort(
        (a, b) =>
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      );
  }, [allReports, selectedProjectId]);

  // Active scan report (defaults to latest scan of this project or initialReport)
  const [activeReportId, setActiveReportId] = useState<string>(
    initialReport?.id || projectScans[0]?.id || "",
  );

  const activeReport = useMemo(() => {
    return (
      projectScans.find((s) => s.id === activeReportId) ||
      projectScans[0] ||
      null
    );
  }, [projectScans, activeReportId]);

  const [activeTab, setActiveTab] = useState<WorkspaceTab>("Overview");
  const [graphFocusPackage, setGraphFocusPackage] = useState<
    string | undefined
  >(undefined);

  // Local filesystem directory connection state
  const [projectData, setProjectData] = useState<ProjectDirectoryResult | null>(
    null,
  );
  const [localFolderProjectId, setLocalFolderProjectId] = useState<
    string | null
  >(null);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [rescanSuccess, setRescanSuccess] = useState<string | null>(null);
  const [showExclusions, setShowExclusions] = useState(false);
  const [remediationOpen, setRemediationOpen] = useState(false);
  const [targetFindingId, setTargetFindingId] = useState<string | null>(null);
  const [profile, setProfile] = useState<"fast" | "deep">("fast");

  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const rescanTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
      if (rescanTimerRef.current) {
        clearTimeout(rescanTimerRef.current);
      }
    };
  }, []);

  function notifyRescanSuccess(msg: string) {
    setRescanSuccess(msg);
    if (rescanTimerRef.current) {
      clearTimeout(rescanTimerRef.current);
    }
    rescanTimerRef.current = setTimeout(() => {
      setRescanSuccess(null);
    }, 8000);
  }

  // Guardian Intelligence drawer state
  const [intelligenceOpen, setIntelligenceOpen] = useState(false);
  const [intelligenceFindingId, setIntelligenceFindingId] = useState<
    string | null
  >(null);

  // Guardian Handoff 1.0 modal state
  const [handoffOpen, setHandoffOpen] = useState(false);
  const [handoffFindingId, setHandoffFindingId] = useState<string | null>(null);
  const [handoffFindingIds, setHandoffFindingIds] = useState<string[] | null>(null);

  const openHandoff = (findingId?: string) => {
    setHandoffFindingId(findingId || null);
    setHandoffFindingIds(null);
    setHandoffOpen(true);
  };

  const openHandoffSelected = (findingIds: string[]) => {
    setHandoffFindingId(null);
    setHandoffFindingIds(findingIds);
    setHandoffOpen(true);
  };

  const supported = isFileSystemAccessSupported();

  // Keep activeReportId in sync when project changes
  useEffect(() => {
    if (projectScans.length > 0) {
      if (!projectScans.some((s) => s.id === activeReportId)) {
        setActiveReportId(projectScans[0].id);
      }
    }
  }, [projectScans, activeReportId]);

  // Derived metrics
  const breakdown = useMemo(
    () => (activeReport ? getFindingBreakdown(activeReport.findings) : null),
    [activeReport],
  );

  const deps = useMemo(
    () => (activeReport ? getDependencyAccounting(activeReport) : null),
    [activeReport],
  );

  // Connect local folder via File System Access API
  async function handleConnectProject() {
    setError(null);
    setLoading(true);
    try {
      const result = await openProjectDirectory();
      setProjectData(result);
      const stableId = await resolveProjectDirectoryId(
        result.directoryHandle,
        result.projectName,
      );
      setSelectedProjectId(stableId);
      setLocalFolderProjectId(stableId);
      if (onDirectoryHandleChange) {
        onDirectoryHandleChange(result.directoryHandle);
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError((err as Error).message);
      }
    } finally {
      setLoading(false);
    }
  }

  function handleDisconnect() {
    if (projectData && activeReport) {
      api(`/projects/${activeReport.id}`, { method: "DELETE" }).catch(() => {});
    }
    if (onDirectoryHandleChange) onDirectoryHandleChange(null);
    setProjectData(null);
    setJob(null);
    setError(null);
  }

  // Polling helper that waits for job completion, updates state, and resolves Report
  async function pollScanJob(jobId: string): Promise<Report> {
    return new Promise<Report>((resolve, reject) => {
      const interval = setInterval(async () => {
        try {
          const state = await api<ScanJob>(`/jobs/${jobId}`);
          setJob(state);

          if (state.status === "complete") {
            clearInterval(interval);
            pollIntervalRef.current = null;
            const rep = await api<Report>(`/scans/${jobId}`);
            setSelectedProjectId(rep.project_id || rep.name);
            setActiveReportId(rep.id);
            if (onReportGenerated) onReportGenerated(rep);
            setLoading(false);
            setJob(null);
            resolve(rep);
          } else if (
            state.status === "failed" ||
            state.status === "cancelled"
          ) {
            clearInterval(interval);
            pollIntervalRef.current = null;
            setLoading(false);
            setJob(null);
            const errMsg = state.error || "Scan failed.";
            setError(errMsg);
            reject(new Error(errMsg));
          }
        } catch (e) {
          clearInterval(interval);
          pollIntervalRef.current = null;
          setLoading(false);
          setJob(null);
          setError((e as Error).message);
          reject(e);
        }
      }, 650);
      pollIntervalRef.current = interval;
    });
  }

  // Trigger project scan
  async function runProjectScan(scanProfile?: "fast" | "deep"): Promise<Report | void> {
    if (!projectData) return;
    const activeProfile = scanProfile || profile;
    setError(null);
    setRescanSuccess(null);
    setLoading(true);

    try {
      const stableId =
        activeReport?.project_id ||
        localFolderProjectId ||
        (await resolveProjectDirectoryId(
          projectData.directoryHandle,
          projectData.projectName,
        ));
      if (!localFolderProjectId) {
        setLocalFolderProjectId(stableId);
      }

      const res = await api<{ id: string }>("/scans/project", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: projectData.projectName,
          profile: activeProfile,
          files: projectData.files,
          project_id: stableId,
        }),
      });

      const jobId = res.id;
      setJob({ id: jobId, status: "queued", stage: "Queued" });
      const rep = await pollScanJob(jobId);
      const b = getFindingBreakdown(rep.findings);
      notifyRescanSuccess(
        `Project rescanned (${rep.findings.length} findings: ${b.critical + b.high} high/crit, ${b.medium} med) under ${activeProfile} profile.`
      );
      return rep;
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
      setJob(null);
    }
  }

  async function handleRescan(targetProfile?: "fast" | "deep"): Promise<Report | void> {
    const scanProfile = targetProfile || profile;
    if (targetProfile && targetProfile !== profile) {
      setProfile(targetProfile);
    }
    setError(null);
    setRescanSuccess(null);
    setLoading(true);

    try {
      // 1. GitHub rescan
      if (activeReport?.source_metadata?.source_type === "github") {
        const res = await api<{ id: string }>("/scans/github", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repository_id: activeReport.source_metadata.repository_id,
            branch: activeReport.source_metadata.branch,
            profile: scanProfile,
          }),
        });
        setJob({ id: res.id, status: "queued", stage: "Queued" });
        const rep = await pollScanJob(res.id);
        const b = getFindingBreakdown(rep.findings);
        notifyRescanSuccess(
          `Repository rescanned (${rep.findings.length} findings: ${b.critical + b.high} high/crit, ${b.medium} med) under ${scanProfile} profile.`
        );
        return rep;
      }

      // 2. Connected local directory
      if (projectData?.directoryHandle) {
        let currentProjectData = projectData;
        try {
          currentProjectData = await reloadProjectDirectory(
            projectData.directoryHandle,
          );
          setProjectData(currentProjectData);
        } catch {
          // If permission lost or handle stale, fallback to open picker
          currentProjectData = await openProjectDirectory();
          setProjectData(currentProjectData);
        }

        const stableId =
          activeReport?.project_id ||
          localFolderProjectId ||
          (await resolveProjectDirectoryId(
            currentProjectData.directoryHandle,
            currentProjectData.projectName,
          ));
        if (!localFolderProjectId) {
          setLocalFolderProjectId(stableId);
        }

        const res = await api<{ id: string }>("/scans/project", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: currentProjectData.projectName,
            profile: scanProfile,
            files: currentProjectData.files,
            project_id: stableId,
          }),
        });

        setJob({ id: res.id, status: "queued", stage: "Queued" });
        const rep = await pollScanJob(res.id);
        const b = getFindingBreakdown(rep.findings);
        notifyRescanSuccess(
          `Project rescanned (${rep.findings.length} findings: ${b.critical + b.high} high/crit, ${b.medium} med) under ${scanProfile} profile.`
        );
        return rep;
      }

      // 3. Demo / synthetic fixture rescan
      if (
        activeReport?.project_id?.startsWith("demo:") ||
        activeReport?.source === "synthetic fixture"
      ) {
        const exampleId =
          activeReport?.project_id?.replace("demo:", "") ||
          activeReport?.name ||
          "benign";
        const res = await api<{ id: string }>(
          `/scans/example/${encodeURIComponent(exampleId)}`,
          { method: "POST" },
        );
        setJob({ id: res.id, status: "queued", stage: "Queued" });
        const rep = await pollScanJob(res.id);
        const b = getFindingBreakdown(rep.findings);
        notifyRescanSuccess(
          `Demo fixture rescanned (${rep.findings.length} findings) under ${scanProfile} profile.`
        );
        return rep;
      }

      // 4. Fallback if no directory or GitHub context: prompt to connect local folder
      const result = await openProjectDirectory();
      setProjectData(result);
      const stableId = await resolveProjectDirectoryId(
        result.directoryHandle,
        result.projectName,
      );
      setSelectedProjectId(stableId);
      setLocalFolderProjectId(stableId);
      if (onDirectoryHandleChange) {
        onDirectoryHandleChange(result.directoryHandle);
      }

      const res = await api<{ id: string }>("/scans/project", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: result.projectName,
          profile: scanProfile,
          files: result.files,
          project_id: stableId,
        }),
      });
      setJob({ id: res.id, status: "queued", stage: "Queued" });
      const rep = await pollScanJob(res.id);
      const b = getFindingBreakdown(rep.findings);
      notifyRescanSuccess(
        `Project connected & scanned (${rep.findings.length} findings) under ${scanProfile} profile.`
      );
      return rep;
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError((err as Error).message);
      }
      setLoading(false);
      setJob(null);
    }
  }

  function openRemediationForFinding(findingId?: string) {
    setTargetFindingId(findingId || null);
    setRemediationOpen(true);
  }

  function openIntelligenceForFinding(findingId?: string) {
    setIntelligenceFindingId(findingId || null);
    setIntelligenceOpen(true);
  }

  function handleNavigateToGraph(packageName: string) {
    setGraphFocusPackage(packageName);
    setActiveTab("Overview");
  }

  return (
    <div className="project-workspace-container">
      {/* Top Workspace Header with Integrated Navigation */}
      <div className="workspace-top-bar">
        {/* Top Row: Project Identity & Actions */}
        <div className="workspace-header-top-row">
          <div className="workspace-project-info">
            <Eyebrow>GUARDIAN 3.1 / PROJECT INVESTIGATION WORKSPACE</Eyebrow>

            <div className="workspace-project-title-row">
              <h1 className="workspace-project-title">
                {activeReport?.name ||
                  uniqueProjects.find((p) => p.id === selectedProjectId)?.name ||
                  "Local Project"}
              </h1>

              {activeReport && (
                <ClassificationBadge
                  classification={
                    activeReport.classification ||
                    (activeReport.source === "synthetic fixture"
                      ? "demo"
                      : "real")
                  }
                />
              )}

              {activeReport && (
                <span
                  style={{
                    fontSize: "12px",
                    color: "var(--muted)",
                    fontFamily: "var(--font-mono, monospace)",
                  }}
                >
                  v{activeReport.version}
                </span>
              )}

              {activeReport?.source_metadata?.source_type === "github" && (
                <>
                  <span
                    style={{
                      background: "rgba(99, 102, 241, 0.15)",
                      color: "var(--accent, #6366f1)",
                      padding: "2px 6px",
                      borderRadius: "4px",
                      fontSize: "11px",
                      fontWeight: 600,
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "4px",
                    }}
                  >
                    <GitBranch size={11} /> {activeReport.source_metadata.branch}
                  </span>

                  <span
                    style={{
                      background: "rgba(255, 255, 255, 0.05)",
                      padding: "2px 6px",
                      borderRadius: "4px",
                      fontSize: "11px",
                      fontFamily: "monospace",
                      color: "var(--muted)",
                    }}
                  >
                    {activeReport.source_metadata.commit_sha.slice(0, 7)}
                  </span>

                  <a
                    href={activeReport.source_metadata.repo_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "3px",
                      fontSize: "11px",
                      color: "var(--accent)",
                      textDecoration: "none",
                    }}
                  >
                    <span>GitHub</span>
                    <ExternalLink size={10} />
                  </a>
                </>
              )}
            </div>

            <p
              style={{
                margin: 0,
                fontSize: "12px",
                color: "var(--muted)",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                flexWrap: "wrap",
              }}
            >
              {activeReport && (
                <>
                  <span>Source: {activeReport.source}</span>
                  <span>&bull;</span>
                  <span>{activeReport.files_analyzed} files analyzed</span>
                  <span>&bull;</span>
                  <span>{deps?.totalResolved || 0} dependencies mapped</span>
                  <span>&bull;</span>
                  <span>
                    Last scanned:{" "}
                    {new Date(activeReport.created_at).toLocaleDateString()}
                  </span>
                </>
              )}
            </p>
          </div>

          {/* Primary Action Buttons */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              flexWrap: "wrap",
            }}
          >
            {/* Rescan Profile Selector (Fast vs Deep) */}
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                background: "var(--surface-2, rgba(255, 255, 255, 0.05))",
                border: "1px solid var(--border, rgba(255, 255, 255, 0.12))",
                borderRadius: "6px",
                padding: "2px",
                gap: "2px",
              }}
              title={
                profile === "fast"
                  ? "Fast Profile: Direct dependencies and top-level packages (faster budget)"
                  : "Deep Profile: Up to 20 packages and 4 levels deep (thorough inspection)"
              }
            >
              <button
                type="button"
                onClick={() => setProfile("fast")}
                disabled={loading}
                aria-label="Set fast rescan profile"
                style={{
                  padding: "3px 8px",
                  fontSize: "11px",
                  fontWeight: profile === "fast" ? 600 : 400,
                  borderRadius: "4px",
                  border: "none",
                  cursor: loading ? "not-allowed" : "pointer",
                  background:
                    profile === "fast" ? "var(--accent, #c5f467)" : "transparent",
                  color:
                    profile === "fast"
                      ? "var(--on-accent, #111c08)"
                      : "var(--muted, #94a3b8)",
                  transition: "all 0.15s ease",
                }}
              >
                Fast
              </button>
              <button
                type="button"
                onClick={() => setProfile("deep")}
                disabled={loading}
                aria-label="Set deep rescan profile"
                style={{
                  padding: "3px 8px",
                  fontSize: "11px",
                  fontWeight: profile === "deep" ? 600 : 400,
                  borderRadius: "4px",
                  border: "none",
                  cursor: loading ? "not-allowed" : "pointer",
                  background:
                    profile === "deep" ? "var(--accent, #c5f467)" : "transparent",
                  color:
                    profile === "deep"
                      ? "var(--on-accent, #111c08)"
                      : "var(--muted, #94a3b8)",
                  transition: "all 0.15s ease",
                }}
              >
                Deep
              </button>
            </div>

            {/* GitHub Rescan or Local folder rescan/connect/disconnect */}
            {activeReport?.source_metadata?.source_type === "github" ? (
              <button
                onClick={() => handleRescan()}
                disabled={loading}
                className="button secondary compact"
                style={{
                  fontSize: "12px",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                {loading ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    <span>{job?.stage || "Rescanning..."}</span>
                  </>
                ) : rescanSuccess ? (
                  <>
                    <CheckCircle2 size={14} color="#10b981" />
                    <span>Rescan Complete</span>
                  </>
                ) : (
                  <>
                    <RefreshCw size={14} />
                    <span>Rescan Repository</span>
                  </>
                )}
              </button>
            ) : projectData ? (
              <>
                <button
                  onClick={() => handleRescan()}
                  disabled={loading}
                  className="button secondary compact"
                  style={{
                    fontSize: "12px",
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  {loading ? (
                    <>
                      <RefreshCw size={14} className="animate-spin" />
                      <span>{job?.stage || "Rescanning..."}</span>
                    </>
                  ) : rescanSuccess ? (
                    <>
                      <CheckCircle2 size={14} color="#10b981" />
                      <span>Rescan Complete</span>
                    </>
                  ) : (
                    <>
                      <RefreshCw size={14} />
                      <span>Rescan Project</span>
                    </>
                  )}
                </button>
                <button
                  onClick={handleDisconnect}
                  disabled={loading}
                  className="button secondary compact"
                  style={{ fontSize: "12px" }}
                >
                  Disconnect Folder
                </button>
              </>
            ) : activeReport?.project_id?.startsWith("demo:") ||
              activeReport?.source === "synthetic fixture" ? (
              <button
                onClick={() => handleRescan()}
                disabled={loading}
                className="button secondary compact"
                style={{
                  fontSize: "12px",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                {loading ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    <span>{job?.stage || "Rescanning..."}</span>
                  </>
                ) : rescanSuccess ? (
                  <>
                    <CheckCircle2 size={14} color="#10b981" />
                    <span>Rescan Complete</span>
                  </>
                ) : (
                  <>
                    <RefreshCw size={14} />
                    <span>Rescan Example</span>
                  </>
                )}
              </button>
            ) : (
              <button
                onClick={handleConnectProject}
                disabled={loading}
                className="button secondary compact"
                style={{
                  fontSize: "12px",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <FolderOpen size={14} />
                <span>Connect Local Folder</span>
              </button>
            )}

            {/* Remediation trigger */}
            {activeReport && (
              <button
                onClick={() => openRemediationForFinding()}
                className="button primary compact"
                style={{
                  fontSize: "12px",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <Wrench size={14} />
                <span>Guardian Autopilot</span>
              </button>
            )}

            {/* Guardian Handoff 1.0 */}
            {activeReport && (
              <button
                onClick={() => openHandoff()}
                className="button secondary compact"
                style={{
                  fontSize: "12px",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
                title="Export AI-agnostic remediation instructions for coding agents"
              >
                <Share2 size={14} color="var(--accent)" />
                <span>Get AI Fix Instructions</span>
              </button>
            )}

            {/* Intelligence trigger */}
            {activeReport && (
              <button
                onClick={() => openIntelligenceForFinding()}
                className="button secondary compact"
                style={{
                  fontSize: "12px",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <Sparkles size={14} />
                <span>Guardian Intelligence</span>
              </button>
            )}

            {onOpenReportView && activeReport && (
              <button
                onClick={() => onOpenReportView(activeReport)}
                className="button secondary compact"
                style={{ fontSize: "12px" }}
              >
                Standard Report View
              </button>
            )}
          </div>
        </div>

        {/* Bottom Row: Integrated Segmented Tabs & Contextual Selectors */}
        <div className="workspace-header-bottom-row">
          {/* Segmented Control Tabs */}
          <div className="workspace-segmented-control" role="tablist">
            {[
              {
                name: "Overview" as const,
                icon: Layers,
                count: deps?.totalResolved || 0,
              },
              {
                name: "Vulnerabilities" as const,
                icon: ShieldAlert,
                count: breakdown?.advisories || 0,
              },
              {
                name: "Behavioral Flows" as const,
                icon: FileCode2,
                count: breakdown?.dataFlows || 0,
              },
              {
                name: "Remediation History" as const,
                icon: Wrench,
                count: undefined,
              },
              {
                name: "Security Timeline" as const,
                icon: Clock,
                count: projectScans.length,
              },
            ].map(({ name, icon: Icon, count }) => (
              <button
                key={name}
                role="tab"
                aria-selected={activeTab === name}
                className={`workspace-segmented-tab ${activeTab === name ? "active" : ""}`}
                onClick={() => setActiveTab(name as WorkspaceTab)}
              >
                <Icon size={14} />
                <span>{name}</span>
                {count !== undefined && count > 0 && (
                  <span className="workspace-tab-badge">{count}</span>
                )}
              </button>
            ))}
          </div>

          {/* Contextual Selectors */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              flexWrap: "wrap",
            }}
          >
            {/* Project Switcher */}
            {uniqueProjects.length > 1 && (
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                  Project:
                </span>
                <select
                  value={selectedProjectId}
                  onChange={(e) => setSelectedProjectId(e.target.value)}
                  style={{
                    padding: "4px 8px",
                    borderRadius: "6px",
                    background: "var(--surface)",
                    border: "1px solid var(--line)",
                    color: "var(--text)",
                    fontSize: "12px",
                  }}
                >
                  {uniqueProjects.map((p) => {
                    const duplicates = uniqueProjects.filter(
                      (x) => x.name === p.name,
                    );
                    const label =
                      duplicates.length > 1
                        ? `${p.name} (${p.id.slice(0, 8)})`
                        : p.name;
                    return (
                      <option key={p.id} value={p.id}>
                        {label}
                      </option>
                    );
                  })}
                </select>
              </div>
            )}

            {/* Historical Scan Version Switcher */}
            {projectScans.length > 1 && (
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                  Scan:
                </span>
                <select
                  value={activeReportId}
                  onChange={(e) => setActiveReportId(e.target.value)}
                  style={{
                    padding: "4px 8px",
                    borderRadius: "6px",
                    background: "var(--surface)",
                    border: "1px solid var(--line)",
                    color: "var(--text)",
                    fontSize: "12px",
                  }}
                >
                  {projectScans.map((s, idx) => (
                    <option key={s.id} value={s.id}>
                      #{projectScans.length - idx}: {s.source_metadata?.branch ? `[${s.source_metadata.branch}] ` : ""}v{s.version} (
                      {new Date(s.created_at).toLocaleDateString()})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Rescan Success notification */}
      {rescanSuccess && (
        <div
          style={{
            padding: "12px 16px",
            borderRadius: "8px",
            background: "rgba(16, 185, 129, 0.12)",
            border: "1px solid rgba(16, 185, 129, 0.3)",
            color: "var(--foreground, #10b981)",
            fontSize: "13px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <CheckCircle2 size={16} color="#10b981" />
            <span>{rescanSuccess}</span>
          </div>
          <button
            onClick={() => setRescanSuccess(null)}
            style={{
              background: "none",
              border: "none",
              color: "var(--muted)",
              cursor: "pointer",
            }}
          >
            <X size={15} />
          </button>
        </div>
      )}

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

      {/* TAB 1: OVERVIEW & LIVE DEPENDENCY GRAPH */}
      {activeTab === "Overview" && activeReport && breakdown && deps && (
        <div style={{ display: "flex", flexDirection: "column", gap: "18px" }}>
          {/* Quick Metrics Grid */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: "14px",
            }}
          >
            <div className="card" style={{ padding: "16px" }}>
              <span
                style={{
                  fontSize: "11px",
                  color: "var(--muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  fontWeight: 600,
                }}
              >
                TOTAL DEPENDENCIES
              </span>
              <strong
                style={{ display: "block", fontSize: "22px", marginTop: "4px" }}
              >
                {deps.totalResolved}
              </strong>
              <small style={{ color: "var(--muted)", fontSize: "11px" }}>
                {deps.declaredDirect} direct declared &bull; {deps.transitive}{" "}
                transitive
              </small>
            </div>

            <div className="card" style={{ padding: "16px" }}>
              <span
                style={{
                  fontSize: "11px",
                  color: "var(--muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  fontWeight: 600,
                }}
              >
                ACTIONABLE FINDINGS
              </span>
              <strong
                style={{
                  display: "block",
                  fontSize: "22px",
                  marginTop: "4px",
                  color:
                    breakdown.actionable > 0
                      ? "var(--danger, #ffaca1)"
                      : "var(--accent, #c5f467)",
                }}
              >
                {breakdown.actionable}
              </strong>
              <small style={{ color: "var(--muted)", fontSize: "11px" }}>
                {breakdown.informational} informational observations excluded
              </small>
            </div>

            <div className="card" style={{ padding: "16px" }}>
              <span
                style={{
                  fontSize: "11px",
                  color: "var(--muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  fontWeight: 600,
                }}
              >
                KNOWN VULNERABILITIES
              </span>
              <strong
                style={{
                  display: "block",
                  fontSize: "22px",
                  marginTop: "4px",
                  color:
                    breakdown.advisories > 0
                      ? "var(--danger, #ffaca1)"
                      : "var(--accent, #c5f467)",
                }}
              >
                {breakdown.advisories}
              </strong>
              <small style={{ color: "var(--muted)", fontSize: "11px" }}>
                {breakdown.criticalAdvisories} critical &bull;{" "}
                {breakdown.highAdvisories} high
              </small>
            </div>

            <div className="card" style={{ padding: "16px" }}>
              <span
                style={{
                  fontSize: "11px",
                  color: "var(--muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  fontWeight: 600,
                }}
              >
                SOURCE INSPECTION
              </span>
              <strong
                style={{ display: "block", fontSize: "22px", marginTop: "4px" }}
              >
                {deps.inspected} / {deps.totalResolved}
              </strong>
              <small style={{ color: "var(--muted)", fontSize: "11px" }}>
                {deps.skipped} skipped &bull; {deps.unavailable} unavailable
              </small>
            </div>
          </div>

          {/* Integrated Live Dependency Graph */}
          <DependencyGraph
            report={activeReport}
            selectedPackageName={graphFocusPackage}
            onSelectFinding={(fid) => {
              if (onOpenReportView) onOpenReportView(activeReport);
            }}
            onAskIntelligence={(fid) => openIntelligenceForFinding(fid)}
            onRemediate={(fid) => openRemediationForFinding(fid)}
          />
        </div>
      )}

      {/* TAB 3: VULNERABILITIES */}
      {activeTab === "Vulnerabilities" && activeReport && (
        <VulnerabilitiesExplorer
          report={activeReport}
          onSelectGraphPackage={handleNavigateToGraph}
          onAskIntelligence={openIntelligenceForFinding}
          onRemediateFinding={openRemediationForFinding}
          onHandoffFinding={(fid) => openHandoff(fid)}
          onHandoffScan={() => openHandoff()}
          onHandoffSelected={(fids) => openHandoffSelected(fids)}
          onViewFindingEvidence={(fid) => {
            if (onOpenReportView) onOpenReportView(activeReport);
          }}
        />
      )}

      {/* TAB 4: BEHAVIORAL FLOWS */}
      {activeTab === "Behavioral Flows" && activeReport && (
        <BehavioralFlowExplorer
          report={activeReport}
          onSelectFinding={(fid) => {
            if (onOpenReportView) onOpenReportView(activeReport);
          }}
          onAskIntelligence={openIntelligenceForFinding}
        />
      )}

      {/* TAB 5: REMEDIATION HISTORY */}
      {activeTab === "Remediation History" && activeReport && (
        <RemediationHistory
          report={activeReport}
          onOpenPlan={(planId) => openRemediationForFinding()}
        />
      )}

      {/* TAB 6: SECURITY TIMELINE */}
      {activeTab === "Security Timeline" && (
        <SecurityTimeline
          projectScans={projectScans}
          currentReportId={activeReportId}
          onSelectScan={(sid) => setActiveReportId(sid)}
        />
      )}

      {/* Guardian Autopilot Remediation Modal */}
      {remediationOpen && activeReport && (
        <RemediationPanel
          report={activeReport}
          directoryHandle={projectData?.directoryHandle}
          targetFindingId={targetFindingId}
          onClose={() => setRemediationOpen(false)}
          onDirectoryHandleChange={(h) => {
            if (onDirectoryHandleChange) onDirectoryHandleChange(h);
          }}
          onFindingClick={(fid) => {
            setRemediationOpen(false);
            if (onOpenReportView) onOpenReportView(activeReport);
          }}
          onRescanRequested={handleRescan}
        />
      )}

      {/* Guardian Intelligence Advisor Drawer */}
      {intelligenceOpen && activeReport && (
        <IntelligencePanel
          report={activeReport}
          isOpen={intelligenceOpen}
          onClose={() => setIntelligenceOpen(false)}
          selectedFinding={
            activeReport.findings.find((f) => f.id === intelligenceFindingId) ||
            null
          }
          onClearSelectedFinding={() => setIntelligenceFindingId(null)}
          onFocusFinding={(fid: string) => {
            if (onOpenReportView) onOpenReportView(activeReport);
          }}
        />
      )}

      {/* Guardian Handoff 1.0 Modal */}
      {handoffOpen && activeReport && (
        <HandoffModal
          report={activeReport}
          isOpen={handoffOpen}
          initialFindingId={handoffFindingId}
          initialFindingIds={handoffFindingIds}
          onClose={() => setHandoffOpen(false)}
        />
      )}
    </div>
  );
}
