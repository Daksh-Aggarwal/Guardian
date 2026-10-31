"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { motion, AnimatePresence, useReducedMotion } from "framer-motion";
import {
  LayoutDashboard,
  History,
  BookOpen,
  ShieldCheck,
  Sun,
  Moon,
  Plus,
  ArrowUpRight,
  ArrowRight,
  Package,
  ChevronRight,
  Activity,
  FlaskConical,
  Loader2,
  Search,
  X,
  AlertCircle,
  FolderOpen,
  Wrench,
  AlertTriangle,
  FileCode2,
  Network,
  Clock,
  Layers,
  Sparkles,
  Menu,
  CheckCircle2,
} from "lucide-react";
import { api, Report, ScanJob, Finding } from "@/lib/types";
import { getDependencyAccounting, getFindingBreakdown } from "@/lib/accounting";
import {
  Brand,
  Eyebrow,
  Empty,
  Note,
  MetricCard,
  SecurityDimensionCard,
  RecommendedActionCard,
  Badge,
  StatusChip,
  ClassificationBadge,
} from "@/components/ui";
import ScanPanel from "@/components/scan-panel";
import ReportView from "@/components/report";
import ProjectWorkspace from "@/components/project-workspace";
import RemediationPanel from "@/components/remediation-panel";

export default function Home() {
  const reducedMotion = useReducedMotion();
  const [reports, setReports] = useState<Report[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [page, setPage] = useState<
    "Overview" | "Project workspace" | "Scan history" | "How it works"
  >("Overview");
  const [dark, setDark] = useState(true);
  const [themeReady, setThemeReady] = useState(false);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [datasetFilter, setDatasetFilter] = useState<"all" | "real" | "demo">(
    "all",
  );
  const [workspaceProjectName, setWorkspaceProjectName] = useState<
    string | null
  >(null);
  const [workspaceProjectId, setWorkspaceProjectId] = useState<string | null>(
    null,
  );
  const [workspaceInitialReport, setWorkspaceInitialReport] =
    useState<Report | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [remediationOpen, setRemediationOpen] = useState(false);
  const [remediationFinding, setRemediationFinding] = useState<string | null>(
    null,
  );
  const [connectedDirectoryHandle, setConnectedDirectoryHandle] =
    useState<FileSystemDirectoryHandle | null>(null);

  const busy =
    job?.status === "running" ||
    job?.status === "queued" ||
    job?.status === "cancelling";

  const refresh = useCallback(async () => {
    try {
      const data = await api<Report[]>("/scans");
      setReports(data);
      setConnected(true);
    } catch (e) {
      setError((e as Error).message);
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const storedTheme = localStorage.getItem("guardian-theme");
    const isDark =
      storedTheme === "dark" ||
      !storedTheme;
    setDark(isDark);
    setThemeReady(true);

    const storedFilter = sessionStorage.getItem("guardian-dataset-filter") as
      "all" | "real" | "demo" | null;
    if (storedFilter && ["all", "real", "demo"].includes(storedFilter)) {
      setDatasetFilter(storedFilter);
    }

    const id = new URLSearchParams(window.location.search).get("scan");
    if (id) {
      api<Report>(`/scans/${id}`)
        .then(setReport)
        .catch((e) => setError(e.message));
    }

    const urlParams = new URLSearchParams(window.location.search);
    const gh = urlParams.get("github");
    const installationId = urlParams.get("installation_id");

    if (installationId) {
      const setupAction = urlParams.get("setup_action");
      api(`/github/callback?installation_id=${installationId}&setup_action=${setupAction || ""}`)
        .then(() => {
          setNotice("GitHub App successfully connected. You can now browse and inspect repositories.");
          window.history.replaceState(null, "", window.location.pathname);
        })
        .catch((e) => {
          console.error("GitHub callback error:", e);
          window.history.replaceState(null, "", window.location.pathname);
        });
    } else if (gh === "connected") {
      setNotice("GitHub App successfully connected. You can now browse and inspect repositories.");
      window.history.replaceState(null, "", window.location.pathname);
    } else if (gh === "error") {
      setError("Failed to connect GitHub App. Please check your GitHub App configuration and permissions.");
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, [refresh]);

  useEffect(() => {
    sessionStorage.setItem("guardian-dataset-filter", datasetFilter);
  }, [datasetFilter]);

  useEffect(() => {
    if (!themeReady) return;
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("guardian-theme", dark ? "dark" : "light");
  }, [dark, themeReady]);

  const openReport = useCallback((r: Report) => {
    setReport(r);
    window.history.replaceState(null, "", `?scan=${r.id}`);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  // Job Polling
  useEffect(() => {
    if (!busy || !job) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    const poll = async () => {
      try {
        const state = await api<ScanJob>(`/jobs/${job.id}`);
        if (cancelled) return;
        setJob(state);
        if (state.status === "complete") {
          const finishedReport = await api<Report>(`/scans/${job.id}`);
          openReport(finishedReport);
          refresh();
        } else if (state.status === "failed") {
          setError(state.error || "Scan failed.");
          setJob(null);
        } else if (state.status === "cancelled") {
          setError(state.stage || "Scan was cancelled.");
          setJob(null);
        } else {
          timer = setTimeout(poll, 650);
        }
      } catch (e) {
        if (!cancelled) {
          setError((e as Error).message);
          setJob(null);
        }
      }
    };

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [job?.id, busy, openReport, refresh]);

  function navigate(
    p: "Overview" | "Project workspace" | "Scan history" | "How it works",
  ) {
    setPage(p);
    setReport(null);
    window.history.replaceState(null, "", "/");
    setSearch("");
    setMobileMenuOpen(false);
  }

  function startScan(id: string) {
    setError("");
    navigate("Overview");
    setJob({ id, status: "queued", stage: "Queued" });
    document
      .getElementById("new-scan")
      ?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  async function runExample(id: string) {
    try {
      const res = await api<{ id: string }>(`/scans/example/${id}`, {
        method: "POST",
      });
      startScan(res.id);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  // Filter reports according to active dataset filter
  const filteredReports = useMemo(() => {
    return reports.filter((r) => {
      const classification =
        r.classification ||
        (r.source === "synthetic fixture" ? "demo" : "real");
      if (datasetFilter === "real") return classification === "real";
      if (datasetFilter === "demo") return classification === "demo";
      return true;
    });
  }, [reports, datasetFilter]);

  // Reconcile workspace and active report selections when dataset filter changes
  useEffect(() => {
    if (workspaceInitialReport) {
      const cls =
        workspaceInitialReport.classification ||
        (workspaceInitialReport.source === "synthetic fixture"
          ? "demo"
          : "real");
      if (datasetFilter !== "all" && cls !== datasetFilter) {
        setWorkspaceInitialReport(null);
        setWorkspaceProjectName(null);
        setWorkspaceProjectId(null);
      }
    }
    if (report && datasetFilter !== "all") {
      const cls =
        report.classification ||
        (report.source === "synthetic fixture" ? "demo" : "real");
      if (cls !== datasetFilter) {
        setReport(null);
      }
    }
  }, [datasetFilter, workspaceInitialReport, report]);

  const realReportsCount = useMemo(
    () =>
      reports.filter(
        (r) =>
          (r.classification ||
            (r.source === "synthetic fixture" ? "demo" : "real")) === "real",
      ).length,
    [reports],
  );

  const demoReportsCount = useMemo(
    () =>
      reports.filter(
        (r) =>
          (r.classification ||
            (r.source === "synthetic fixture" ? "demo" : "real")) === "demo",
      ).length,
    [reports],
  );

  // Group latest scan per project for deduplicated project metrics
  const latestProjectScans = useMemo(() => {
    const map = new Map<string, Report>();
    for (const r of filteredReports) {
      if (!map.has(r.name)) {
        map.set(r.name, r);
      }
    }
    return Array.from(map.values());
  }, [filteredReports]);

  // Meaningful Calculated Metrics from Actual History (Reconciled & Deduplicated)
  const metrics = useMemo(() => {
    const uniqueProjectsCount = latestProjectScans.length;
    const totalScansCount = filteredReports.length;

    const elevatedProjectsCount = latestProjectScans.filter((r) => {
      const bd = getFindingBreakdown(r.findings);
      return bd.actionable > 0;
    }).length;

    const totalActionableFindings = latestProjectScans.reduce((sum, r) => {
      return sum + getFindingBreakdown(r.findings).actionable;
    }, 0);

    const uniqueDependencyNamesCount = new Set(
      filteredReports.flatMap((r) =>
        r.inspections?.length
          ? r.inspections.map((n) => n.name)
          : r.dependencies.map((d) => d.name),
      ),
    ).size;

    const dependencyVersionsCount = new Set(
      filteredReports.flatMap((r) =>
        r.inspections?.length
          ? r.inspections.map((n) => `${n.name}@${n.version}`)
          : r.dependencies.map((d) => `${d.name}@${d.version}`),
      ),
    ).size;

    const criticalAdvisoriesCount = latestProjectScans.reduce((sum, r) => {
      return sum + getFindingBreakdown(r.findings).criticalAdvisories;
    }, 0);

    return {
      uniqueProjectsCount,
      totalScansCount,
      elevatedProjectsCount,
      totalActionableFindings,
      uniqueDependencyNamesCount,
      dependencyVersionsCount,
      criticalAdvisoriesCount,
    };
  }, [latestProjectScans, filteredReports]);

  // Evidence-grounded Recommended Next Steps derived from active filtered reports
  const recommendedActions = useMemo(() => {
    const actions: {
      id: string;
      priority: "critical" | "high" | "medium" | "low" | "info";
      project: string;
      title: string;
      reason: string;
      report: Report;
      findingId?: string;
    }[] = [];

    for (const r of latestProjectScans) {
      // 1. Critical OSV vulnerability
      const critOsv = r.findings.find(
        (f) => f.severity === "critical" && (f.rule === "OSV" || !!f.advisory),
      );
      if (critOsv && actions.length < 3) {
        actions.push({
          id: `act-${r.id}-${critOsv.id}`,
          priority: "critical",
          project: `${r.name} (${r.version})`,
          title: critOsv.advisory?.summary || critOsv.title,
          reason: `Affects resolved version ${r.version}. Review published advisory and upgrade path.`,
          report: r,
          findingId: critOsv.id,
        });
      }

      // 2. High behavioral signal
      const highBehavior = r.findings.find(
        (f) =>
          f.severity === "high" &&
          (!f.domain || f.domain === "behavior") &&
          f.rule !== "OSV",
      );
      if (highBehavior && actions.length < 3) {
        actions.push({
          id: `act-${r.id}-${highBehavior.id}`,
          priority: "high",
          project: `${r.name} (${r.version})`,
          title: highBehavior.title,
          reason:
            highBehavior.recommendation ||
            "Suspicious runtime behavior identified in source.",
          report: r,
          findingId: highBehavior.id,
        });
      }

      // 3. Incomplete coverage notice
      if (
        r.coverage.some(
          (c) => c.includes("skipped") || c.includes("manifest_only"),
        ) &&
        actions.length < 3
      ) {
        actions.push({
          id: `act-cov-${r.id}`,
          priority: "medium",
          project: `${r.name} (${r.version})`,
          title: "Incomplete Source Inspection Coverage",
          reason:
            "Certain dependencies or source files were skipped. Consider re-scanning with deep budget.",
          report: r,
        });
      }
    }

    return actions;
  }, [latestProjectScans]);

  return (
    <div className="app-shell">
      {/* Mobile Menu Backdrop */}
      {mobileMenuOpen && (
        <div
          className="sidebar-backdrop"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar Navigation */}
      <aside className={`sidebar ${mobileMenuOpen ? "mobile-open" : ""}`}>
        <div className="sidebar-brand-row">
          <Brand />
          <button
            type="button"
            className="mobile-close-btn"
            onClick={() => setMobileMenuOpen(false)}
            aria-label="Close menu"
          >
            <X size={18} />
          </button>
        </div>

        <div className="workspace-label">
          <span className="workspace-icon">G</span>
          <div>
            <span className="workspace-name">Personal Workspace</span>
            <small>LOCAL EDITION · v3.0</small>
          </div>
          <ChevronRight size={14} className="workspace-chevron" />
        </div>

        <div className="nav-label">COMMAND CENTRE</div>
        <nav>
          {[
            { name: "Overview", icon: LayoutDashboard },
            { name: "Project workspace", icon: FolderOpen },
            { name: "Scan history", icon: History },
            { name: "How it works", icon: BookOpen },
          ].map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={page === name && !report ? "active" : ""}
              onClick={() => navigate(name as any)}
            >
              <Icon size={18} />
              <span>
                {name}
                {name === "Scan history" && (
                  <span
                    className={`nav-attention-dot ${reports.length > 0 ? "has-reports" : ""}`}
                    title={
                      reports.length > 0
                        ? `${reports.length} scan${reports.length === 1 ? "" : "s"} in history`
                        : "Scan history attention prompt"
                    }
                  />
                )}
              </span>
            </button>
          ))}
        </nav>

        {/* Sidebar trust banner */}
        <div className="sidebar-note">
          <div className="tiny-shield">
            <ShieldCheck size={20} />
          </div>
          <h4>Evidence Over Assumptions</h4>
          <p>
            Static AST inspection. Transparent coverage boundaries. Grounded AI
            explanations.
          </p>
          <button
            type="button"
            onClick={() => navigate("How it works")}
            className="sidebar-note-link"
          >
            <span>Methodology</span>
            <ArrowUpRight size={13} />
          </button>
        </div>

        {/* Sidebar footer */}
        <div className="sidebar-bottom">
          <span className="avatar">Y</span>
          <div>
            <strong className="sidebar-user-name">Local User</strong>
            <small>Isolated memory · No cloud leakage</small>
          </div>
          <span
            className="local-dot"
            title="Running in local loopback environment"
          />
        </div>
      </aside>

      {/* Main Shell */}
      <div className="main-shell">
        {/* Topbar */}
        <header className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="mobile-menu-btn"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Toggle navigation menu"
            >
              <Menu size={20} />
            </button>

            <div className="breadcrumb">
              <span>Workspace</span>
              <ChevronRight size={13} />
              <strong>{report ? `Report: ${report.name}` : page}</strong>
            </div>
          </div>

          <div className="top-actions">
            <span className={`service-status ${connected ? "online" : ""}`}>
              <i className="status-indicator-dot" />
              <span>{connected ? "Scanner connected" : "Scanner offline"}</span>
            </span>

            <button
              aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
              className="icon-button theme-toggle"
              onClick={() => setDark(!dark)}
              title={dark ? "Use light theme" : "Use dark theme"}
            >
              {dark ? <Sun size={17} /> : <Moon size={17} />}
            </button>

            <button
              type="button"
              className="btn-new-scan-top"
              onClick={() => {
                navigate("Overview");
                setTimeout(
                  () =>
                    document
                      .getElementById("new-scan")
                      ?.scrollIntoView({ behavior: "smooth", block: "center" }),
                  50,
                );
              }}
            >
              <Plus size={15} />
              <span>New scan</span>
            </button>

            <span className="header-avatar" title="Local session">
              Y
            </span>
          </div>
        </header>

        {/* Main Content Viewport */}
        <main>
          {error && (
            <div className="global-error" role="alert">
              <AlertCircle size={18} />
              <span>{error}</span>
              <button
                type="button"
                className="btn-error-retry"
                onClick={() => {
                  setError("");
                  refresh();
                }}
              >
                Retry
              </button>
              <button
                type="button"
                aria-label="Dismiss error"
                onClick={() => setError("")}
                className="btn-error-dismiss"
              >
                <X size={15} />
              </button>
            </div>
          )}

          {notice && (
            <div
              style={{
                background: "rgba(16, 185, 129, 0.15)",
                border: "1px solid rgba(16, 185, 129, 0.3)",
                color: "#10b981",
                padding: "10px 16px",
                borderRadius: "8px",
                marginBottom: "16px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontSize: "13px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <CheckCircle2 size={16} />
                <span>{notice}</span>
              </div>
              <button
                type="button"
                onClick={() => setNotice("")}
                style={{
                  background: "none",
                  border: "none",
                  color: "#10b981",
                  cursor: "pointer",
                  padding: "4px",
                }}
              >
                <X size={14} />
              </button>
            </div>
          )}

          {/* VIEW 1: ACTIVE REPORT VIEW */}
          {report ? (
            <>
              <ReportView
                key={report.id}
                report={report}
                onBack={() => navigate("Scan history")}
                onPrepareFix={(f) => {
                  setRemediationFinding(f.id);
                  setRemediationOpen(true);
                }}
                onInvestigateProject={(r) => {
                  setWorkspaceProjectName(r.name);
                  setWorkspaceProjectId(r.project_id || r.name);
                  setWorkspaceInitialReport(r);
                  navigate("Project workspace");
                }}
              />

              {remediationOpen && (
                <RemediationPanel
                  report={report}
                  directoryHandle={connectedDirectoryHandle}
                  targetFindingId={remediationFinding}
                  onClose={() => setRemediationOpen(false)}
                  onDirectoryHandleChange={setConnectedDirectoryHandle}
                  onFindingClick={(fid) => {
                    setRemediationOpen(false);
                    setTimeout(() => {
                      document
                        .getElementById("finding-" + fid)
                        ?.scrollIntoView({
                          behavior: "smooth",
                          block: "center",
                        });
                    }, 100);
                  }}
                />
              )}
            </>
          ) : page === "Project workspace" ? (
            /* VIEW 2: PROJECT WORKSPACE */
            <ProjectWorkspace
              onBack={() => navigate("Overview")}
              onReportGenerated={(r) => {
                setReport(r);
                refresh();
              }}
              onDirectoryHandleChange={setConnectedDirectoryHandle}
              initialReport={workspaceInitialReport}
              initialProjectName={workspaceProjectName}
              initialProjectId={workspaceProjectId || workspaceInitialReport?.project_id || undefined}
              allReports={filteredReports}
              onOpenReportView={(r) => openReport(r)}
            />
          ) : page === "How it works" ? (
            /* VIEW 3: METHODOLOGY */
            <Methodology />
          ) : (
            /* VIEW 4: COMMAND CENTRE (Overview or Scan History) */
            <motion.div
              initial={false}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: reducedMotion ? 0 : 0.32 }}
            >
              {/* Command Centre Page Header */}
              <div className="page-heading">
                <div>
                  <Eyebrow>SUPPLY-CHAIN SECURITY COMMAND CENTRE</Eyebrow>
                  <h1 className="heading-title">
                    {page === "Overview"
                      ? "Security Command Centre"
                      : "Inspection History"}
                  </h1>
                  <p className="heading-subtitle">
                    {page === "Overview"
                      ? "Evidence-grounded supply chain security, AST behavioral inspection, and verified advisory tracking."
                      : "Complete repository of past inspections with full evidence trails preserved."}
                  </p>
                </div>

                <div className="page-heading-actions">
                  <div
                    className="dataset-filter-control"
                    role="group"
                    aria-label="Dataset Filter"
                  >
                    <button
                      type="button"
                      className={`dataset-filter-btn ${datasetFilter === "all" ? "active" : ""}`}
                      onClick={() => setDatasetFilter("all")}
                      title="Show all projects and demo data"
                    >
                      All{" "}
                      <span className="dataset-count-pill">
                        {reports.length}
                      </span>
                    </button>
                    <button
                      type="button"
                      className={`dataset-filter-btn ${datasetFilter === "real" ? "active" : ""}`}
                      onClick={() => setDatasetFilter("real")}
                      title="Show only real projects and registry lookups"
                    >
                      Real Projects{" "}
                      <span className="dataset-count-pill">
                        {realReportsCount}
                      </span>
                    </button>
                    <button
                      type="button"
                      className={`dataset-filter-btn ${datasetFilter === "demo" ? "active" : ""}`}
                      onClick={() => setDatasetFilter("demo")}
                      title="Show only synthetic fixtures and demo data"
                    >
                      Demo Data{" "}
                      <span className="dataset-count-pill">
                        {demoReportsCount}
                      </span>
                    </button>
                  </div>

                  <button
                    className="button secondary"
                    onClick={() => navigate("Project workspace")}
                  >
                    <FolderOpen size={16} />
                    <span>Project workspace</span>
                  </button>
                  <button
                    className="button primary"
                    onClick={() => {
                      navigate("Overview");
                      setTimeout(
                        () =>
                          document.getElementById("new-scan")?.scrollIntoView({
                            behavior: "smooth",
                            block: "center",
                          }),
                        50,
                      );
                    }}
                  >
                    <Plus size={16} />
                    <span>New scan</span>
                  </button>
                </div>
              </div>

              {page === "Overview" && (
                <>
                  {/* Meaningful Security Overview Metrics */}
                  <div className="metrics-grid">
                    <MetricCard
                      label="Projects Inspected"
                      value={metrics.uniqueProjectsCount}
                      icon={<Package size={18} />}
                      detail={`${metrics.totalScansCount} total ${metrics.totalScansCount === 1 ? "scan" : "scans"} recorded`}
                      status="neutral"
                    />
                    <MetricCard
                      label="Requiring Attention"
                      value={metrics.elevatedProjectsCount}
                      icon={<AlertTriangle size={18} />}
                      detail={`${metrics.totalActionableFindings} actionable ${metrics.totalActionableFindings === 1 ? "signal" : "signals"} to review`}
                      status={
                        metrics.elevatedProjectsCount > 0
                          ? "warning"
                          : "success"
                      }
                    />
                    <MetricCard
                      label="Dependencies Inventoried"
                      value={metrics.uniqueDependencyNamesCount}
                      icon={<ShieldCheck size={18} />}
                      detail={`${metrics.dependencyVersionsCount} resolved versions mapped`}
                      status="neutral"
                    />
                    <MetricCard
                      label="Critical Advisories"
                      value={metrics.criticalAdvisoriesCount}
                      icon={<Activity size={18} />}
                      detail="Upstream OSV vulnerability matches"
                      status={
                        metrics.criticalAdvisoriesCount > 0
                          ? "danger"
                          : "success"
                      }
                    />
                  </div>

                  {/* Security Assessment Overview: 4 Independent Assessment Domains */}
                  <section className="command-domains-section">
                    <div className="section-title-row">
                      <div>
                        <Eyebrow>INDEPENDENT ASSESSMENT DOMAINS</Eyebrow>
                        <h2>Four-Dimensional Security Posture</h2>
                        <p>
                          Guardian keeps detection domains decoupled. No
                          arbitrary combined score.
                        </p>
                      </div>
                    </div>

                    <div className="dimension-grid">
                      <SecurityDimensionCard
                        title="Behavioral Assessment"
                        domain="RUNTIME SIGNALS"
                        status="Static AST Heuristics"
                        statusTone="info"
                        headline="Exfiltration & Execution"
                        description="Inspects AST call chains for child_process spawning, sensitive environment token access, and outbound network sinks without executing code."
                        metric={`${reports.filter((r) => r.findings.some((f) => (!f.domain || f.domain === "behavior") && f.rule !== "OSV" && f.severity !== "info")).length} scans with signals`}
                        metricLabel="across history"
                        icon={<FileCode2 size={18} />}
                      />

                      <SecurityDimensionCard
                        title="Known Vulnerabilities"
                        domain="INTELLIGENCE"
                        status="OSV Upstream Database"
                        statusTone="warning"
                        headline="Exact Version Queries"
                        description="Cross-references lockfile and manifest versions directly with the Open Source Vulnerabilities database for published CVEs and GHSAs."
                        metric={`${metrics.criticalAdvisoriesCount} critical matches`}
                        metricLabel="recorded in history"
                        icon={<Network size={18} />}
                      />

                      <SecurityDimensionCard
                        title="Package Integrity"
                        domain="PROVENANCE"
                        status="Digest Verification"
                        statusTone="success"
                        headline="Checksum Validation"
                        description="Calculates SHA-512 and SHA-256 digests on retrieved tarballs against official registry metadata to detect tampered distribution archives."
                        metric="Active"
                        metricLabel="verification engine"
                        icon={<ShieldCheck size={18} />}
                      />

                      <SecurityDimensionCard
                        title="Inspection Coverage"
                        domain="TRANSPARENCY"
                        status="Decoupled Semantics"
                        statusTone="purple"
                        headline="Coverage Boundaries"
                        description="Explicitly reports skipped packages, recursion limits, and unparsed files. 'No elevated signals' is never presented as an absolute guarantee of safety."
                        metric="Bounded Depth"
                        metricLabel="maximum recursion 8"
                        icon={<Layers size={18} />}
                      />
                    </div>
                  </section>

                  {/* Evidence-Grounded Recommended Actions */}
                  {recommendedActions.length > 0 && (
                    <section className="recommended-actions-section">
                      <div className="section-title-row">
                        <div>
                          <Eyebrow>PRIORITIZED NEXT STEPS</Eyebrow>
                          <h2>Recommended Actions</h2>
                          <p>
                            Grounded in actual findings from your recent
                            security scans.
                          </p>
                        </div>
                      </div>

                      <div className="actions-grid">
                        {recommendedActions.map((act) => (
                          <RecommendedActionCard
                            key={act.id}
                            priority={act.priority}
                            project={act.project}
                            title={act.title}
                            reason={act.reason}
                            onClick={() => {
                              openReport(act.report);
                              if (act.findingId) {
                                setTimeout(() => {
                                  document
                                    .getElementById("finding-" + act.findingId)
                                    ?.scrollIntoView({
                                      behavior: "smooth",
                                      block: "center",
                                    });
                                }, 250);
                              }
                            }}
                          />
                        ))}
                      </div>
                    </section>
                  )}

                  {/* Scan Launchpad & Informational Guide */}
                  <div className="home-grid">
                    <ScanPanel
                      onStart={startScan}
                      busy={!!busy}
                      job={job}
                      onConnectFolder={() => navigate("Project workspace")}
                    />

                    {/* Security Philosophy Card */}
                    <section className="guide-card">
                      <div className="guide-visual" aria-hidden="true">
                        <div className="orbit orbit-one" />
                        <div className="orbit orbit-two" />
                        <span className="orbit-node node-one">
                          <Package size={17} />
                        </span>
                        <span className="orbit-node node-two">
                          <FileCode2 size={16} />
                        </span>
                        <span className="orbit-node node-three">
                          <ShieldCheck size={17} />
                        </span>
                        <span className="central-shield">
                          <ShieldCheck size={42} strokeWidth={1.5} />
                        </span>
                      </div>
                      <Eyebrow>EXPLAINABLE SECURITY ARCHITECTURE</Eyebrow>
                      <h2>
                        More than a verdict.
                        <br />
                        The evidence behind it.
                      </h2>
                      <p>
                        Guardian connects suspicious code patterns directly to
                        syntax evidence, explains them without jargon, and
                        surfaces contextual AI guidance.
                      </p>
                      <button
                        type="button"
                        className="text-link inline-learn-link"
                        onClick={() => navigate("How it works")}
                      >
                        <span>Explore methodology</span>
                        <ArrowRight size={14} />
                      </button>
                      <div className="guide-tags">
                        <span>Local Static AST</span>
                        <span>OSV Intelligence</span>
                        <span>Zero Execution</span>
                      </div>
                    </section>
                  </div>

                  {/* Synthetic Demonstrations Strip */}
                  <section className="examples-strip">
                    <div className="examples-left">
                      <div className="flask-icon-wrap">
                        <FlaskConical size={20} />
                      </div>
                      <div>
                        <h3>Synthetic Demonstration Benchmarks</h3>
                        <p>
                          Execute real scans on safe, inert synthetic test
                          packages.
                        </p>
                      </div>
                    </div>
                    <div className="example-actions">
                      <button
                        type="button"
                        disabled={!!busy}
                        onClick={() => runExample("benign")}
                        title="Scan everyday clean npm package with dependencies"
                      >
                        <span>Everyday package</span>
                        <ArrowUpRight size={14} />
                      </button>
                      <button
                        type="button"
                        disabled={!!busy}
                        onClick={() => runExample("exfiltration")}
                        title="Scan AST exfiltration payload tracking sensitive tokens to outbound request"
                      >
                        <span>Sensitive data flow</span>
                        <ArrowUpRight size={14} />
                      </button>
                      <button
                        type="button"
                        disabled={!!busy}
                        onClick={() => runExample("correlated")}
                        title="Scan suspicious lifecycle script downloading remote executable"
                      >
                        <span>Suspicious installer</span>
                        <ArrowUpRight size={14} />
                      </button>
                      <button
                        type="button"
                        disabled={!!busy}
                        onClick={() => runExample("pypi-demo")}
                        title="Scan Python PyPI project with requirements.txt, pyproject.toml, and Python AST data-flow"
                      >
                        <span>PyPI Python</span>
                        <ArrowUpRight size={14} />
                      </button>
                      <button
                        type="button"
                        disabled={!!busy}
                        onClick={() => runExample("pnpm-demo")}
                        title="Scan project with pnpm-lock.yaml manifest and dependency resolution"
                      >
                        <span>pnpm project</span>
                        <ArrowUpRight size={14} />
                      </button>
                      <button
                        type="button"
                        disabled={!!busy}
                        onClick={() => runExample("yarn-demo")}
                        title="Scan project with modern Yarn Berry yarn.lock manifest"
                      >
                        <span>Yarn project</span>
                        <ArrowUpRight size={14} />
                      </button>
                    </div>
                  </section>
                </>
              )}

              {/* Recent Scans Explorer / All Scans Table */}
              <section className="recent-section">
                <div className="section-heading">
                  <div>
                    <h2>
                      {page === "Overview"
                        ? "Recent Security Scans"
                        : "All Inspections"}
                    </h2>
                    <p>
                      Evidence trails and report history across all analyzed
                      packages.
                    </p>
                  </div>

                  {page === "Overview" ? (
                    <button
                      type="button"
                      className="text-link"
                      onClick={() => navigate("Scan history")}
                    >
                      <span>View complete history</span>
                      <ArrowRight size={14} />
                    </button>
                  ) : (
                    <div className="history-search">
                      <Search size={15} />
                      <input
                        aria-label="Search scans"
                        placeholder="Search by package name or version…"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                      />
                    </div>
                  )}
                </div>

                <div className="card scan-table">
                  {loading ? (
                    <div className="empty-loading-state">
                      <Loader2 className="spin" size={24} />
                      <span>Connecting to scanner engine…</span>
                    </div>
                  ) : !reports.length ? (
                    <Empty
                      title="No scans in your evidence trail yet"
                      action={
                        <button
                          type="button"
                          className="button primary"
                          onClick={() => {
                            document
                              .getElementById("new-scan")
                              ?.scrollIntoView({ behavior: "smooth" });
                          }}
                        >
                          <Plus size={16} />
                          <span>Run your first scan</span>
                        </button>
                      }
                    >
                      Upload a project archive or look up an npm package. Every
                      assessment produces a permanent evidence report.
                    </Empty>
                  ) : (
                    <>
                      <div className="table-header">
                        <span>PACKAGE / PROJECT</span>
                        <span>BEHAVIORAL ASSESSMENT</span>
                        <span>FINDINGS</span>
                        <span>SCANNED AT</span>
                        <span>ACTION</span>
                      </div>

                      {filteredReports
                        .filter((r) => {
                          const q = search.toLowerCase();
                          return (
                            r.name.toLowerCase().includes(q) ||
                            r.version.toLowerCase().includes(q) ||
                            r.source.toLowerCase().includes(q)
                          );
                        })
                        .slice(0, page === "Overview" ? 6 : 50)
                        .map((r) => {
                          const hasElevated = r.findings.some((f) =>
                            ["critical", "high"].includes(f.severity),
                          );
                          const hasMedium = r.findings.some(
                            (f) => f.severity === "medium",
                          );
                          const bd = getFindingBreakdown(r.findings);

                          return (
                            <div
                              key={r.id}
                              className="table-row"
                              style={{ cursor: "pointer" }}
                              onClick={() => openReport(r)}
                            >
                              <span className="package-cell">
                                <span className="package-symbol">
                                  <Package size={18} />
                                </span>
                                <span className="package-titles">
                                  <div
                                    style={{
                                      display: "flex",
                                      alignItems: "center",
                                      gap: "6px",
                                    }}
                                  >
                                    <strong>{r.name}</strong>
                                    <ClassificationBadge
                                      classification={
                                        r.classification ||
                                        (r.source === "synthetic fixture"
                                          ? "demo"
                                          : "real")
                                      }
                                      size="sm"
                                    />
                                  </div>
                                  <small>
                                    v{r.version} · {r.source} ·{" "}
                                    {r.files_analyzed} files
                                  </small>
                                </span>
                              </span>

                              <span>
                                <span
                                  className={`risk-pill ${hasElevated ? "high" : hasMedium ? "medium" : "clear"}`}
                                >
                                  <i />
                                  {r.risk}
                                </span>
                              </span>

                              <span className="findings-cell">
                                <strong>{bd.actionable}</strong>
                                <small>
                                  {" "}
                                  {bd.actionable === 1
                                    ? "signal"
                                    : "signals"}{" "}
                                  to review
                                </small>
                                {bd.informational > 0 && (
                                  <small
                                    style={{
                                      color: "var(--muted)",
                                      fontSize: "10px",
                                      display: "block",
                                    }}
                                  >
                                    +{bd.informational} observations
                                  </small>
                                )}
                              </span>

                              <span className="date-cell">
                                <strong>
                                  {new Date(r.created_at).toLocaleDateString(
                                    undefined,
                                    {
                                      month: "short",
                                      day: "numeric",
                                    },
                                  )}
                                </strong>
                                <small>
                                  {new Date(r.created_at).toLocaleTimeString(
                                    undefined,
                                    {
                                      hour: "2-digit",
                                      minute: "2-digit",
                                    },
                                  )}
                                </small>
                              </span>

                              <span
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "8px",
                                  justifyContent: "flex-end",
                                }}
                              >
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setWorkspaceProjectName(r.name);
                                    setWorkspaceProjectId(r.project_id || r.name);
                                    setWorkspaceInitialReport(r);
                                    navigate("Project workspace");
                                  }}
                                  style={{
                                    background: "rgba(99, 102, 241, 0.12)",
                                    border: "1px solid rgba(99, 102, 241, 0.3)",
                                    color: "var(--accent)",
                                    borderRadius: "4px",
                                    padding: "3px 8px",
                                    fontSize: "11px",
                                    cursor: "pointer",
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: "4px",
                                    fontWeight: 500,
                                  }}
                                  title="Open in Project Investigation Workspace"
                                >
                                  <span>Investigate</span>
                                  <ChevronRight size={12} />
                                </button>
                              </span>
                            </div>
                          );
                        })}
                    </>
                  )}
                </div>
              </section>
            </motion.div>
          )}

          {/* Footer */}
          <footer>
            <span>
              <ShieldCheck size={14} />
              Guardian 3.0 · Software Supply-Chain Intelligence
            </span>
            <span>
              Static inspection. Transparent coverage. Grounded AI reasoning.
            </span>
          </footer>
        </main>
      </div>
    </div>
  );
}

function Methodology() {
  return (
    <div className="methodology-page">
      <div className="page-heading">
        <div>
          <Eyebrow>TRANSPARENCY BY DESIGN</Eyebrow>
          <h1 className="heading-title">Evidence Before Assumptions.</h1>
          <p className="heading-subtitle">
            A security assessment should empower your judgment, not decide in a
            black box.
          </p>
        </div>
      </div>

      <div className="method-grid">
        {[
          {
            n: "01",
            title: "Inspect. Never execute.",
            text: "Guardian unpacks ZIP files and npm tarballs strictly in bounded virtual memory with recursive size and symlink checks. Uploaded lifecycle scripts and untrusted executables are never run.",
          },
          {
            n: "02",
            title: "Syntax AST data-flow tracking.",
            text: "A Babel AST parser inspects JavaScript syntax trees. File-local data tracking traces sensitive sources (e.g. process.env credentials) to outbound network sinks with line and column citations.",
          },
          {
            n: "03",
            title: "Decoupled 4D assessment.",
            text: "Behavioral signals, OSV vulnerability intelligence, package integrity checksums, and source inspection coverage remain distinct dimensions. We never fabricate an artificial overall safety score.",
          },
          {
            n: "04",
            title: "Make uncertainty visible.",
            text: "Skipped dependency depths, unparsed files, and unavailable intelligence are prominent in coverage. 'No elevated signals' is never presented as proof of absolute safety.",
          },
        ].map((x) => (
          <section className="card method-card" key={x.n}>
            <span className="method-num">{x.n}</span>
            <h2>{x.title}</h2>
            <p>{x.text}</p>
          </section>
        ))}
      </div>

      <Note>
        Guardian is a local supply-chain defense engine. It performs bounded AST
        static analysis and exact OSV database cross-referencing. Explanation
        responses are evidence-grounded in stored scan findings.
      </Note>
    </div>
  );
}
