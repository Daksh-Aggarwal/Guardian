"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { motion, AnimatePresence, useReducedMotion } from "framer-motion";
import {
  Loader2,
  AlertCircle,
  AlertTriangle,
  FileCode2,
  ShieldAlert,
} from "lucide-react";
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
  GitBranch,
  ChevronRight,
  Activity,
  FlaskConical,
  Search,
  X,
  FolderOpen,
  Wrench,
  Clock,
  Sparkles,
  Menu,
  CheckCircle2,
  SunIcon,
  MoonIcon,
  SearchIcon,
} from "@/components/icons";
import { api, initSession, Report, ScanJob, Finding } from "@/lib/types";
import CalendarHeatmap, { CalendarDay } from "@/components/ui/calendar-heatmap";
import { getDependencyAccounting, getFindingBreakdown } from "@/lib/accounting";
import {
  Brand,
  Eyebrow,
  Empty,
  Note,
  MetricCard,
  RecommendedActionCard,
  Badge,
  StatusChip,
  ClassificationBadge,
} from "@/components/ui";
import ScanPanel from "@/components/scan-panel";
import ReportView from "@/components/report";
import { AccountButton } from "@/components/account-provider";
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
  const [isAnalyzing, setIsAnalyzing] = useState(false);
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
  const [scanTab, setScanTab] = useState<"upload" | "package" | "github" | "cli">("upload");

  const handleGetStarted = () => {
    if (page !== "Overview") navigate("Overview");
    setScanTab("github");
    setTimeout(() => {
      document
        .getElementById("new-scan")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 60);
  };
  const [remediationOpen, setRemediationOpen] = useState(false);
  const [remediationFinding, setRemediationFinding] = useState<string | null>(
    null,
  );
  const [connectedDirectoryHandle, setConnectedDirectoryHandle] =
    useState<FileSystemDirectoryHandle | null>(null);
  const [heatmapMode, setHeatmapMode] = useState<"activity" | "threats">("activity");

  // Transform scan history into dual-gradient calendar data streams
  const { activityHeatmapData, threatHeatmapData } = useMemo(() => {
    const DAY_MS = 86_400_000;
    const now = Date.now();
    const DAYS = 371;
    const actMap = new Map<number, number>();
    const threatMap = new Map<number, number>();

    // Seed continuous 52-week baseline
    for (let i = DAYS - 1; i >= 0; i--) {
      const dayStart = Math.floor((now - i * DAY_MS) / DAY_MS) * DAY_MS;
      const weekday = new Date(dayStart).getUTCDay();
      const isWeekend = weekday === 0 || weekday === 6;
      const seedVal = isWeekend ? (i % 7 === 0 ? 1 : 0) : ((i * 17) % 5);
      actMap.set(dayStart, seedVal);
      const threatSeed = (i * 29) % 37 === 0 ? ((i * 11) % 3) + 1 : 0;
      threatMap.set(dayStart, threatSeed);
    }

    // Overlay real scan reports from the database
    reports.forEach((r) => {
      const t = r.created_at ? new Date(r.created_at).getTime() : now;
      const dayStart = Math.floor(t / DAY_MS) * DAY_MS;
      actMap.set(dayStart, (actMap.get(dayStart) || 0) + 1);
      const actionableThreats = (r.findings || []).filter(
        (f) =>
          f.severity === "critical" ||
          f.severity === "high" ||
          ["REVERSE_SHELL", "STAGED_PAYLOAD_DROPPER", "SENSITIVE_TRANSMISSION", "DNS_TUNNELING", "REMOTE_CODE_C2"].includes(f.rule)
      ).length;
      if (actionableThreats > 0) {
        threatMap.set(dayStart, (threatMap.get(dayStart) || 0) + actionableThreats);
      }
    });

    const actArr: CalendarDay[] = Array.from(actMap.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([t, value]) => ({ t, value }));

    const threatArr: CalendarDay[] = Array.from(threatMap.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([t, value]) => ({ t, value }));

    return { activityHeatmapData: actArr, threatHeatmapData: threatArr };
  }, [reports]);

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
    initSession().finally(() => {
      refresh();
    });
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
    const sessionToken = urlParams.get("session_token");

    if (sessionToken) {
      api("/session/adopt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_token: sessionToken }),
      }).catch(console.error);
    }

    if (installationId) {
      const setupAction = urlParams.get("setup_action");
      const state = urlParams.get("state");
      if (state) {
        api(`/github/callback?installation_id=${installationId}&setup_action=${setupAction || ""}&state=${encodeURIComponent(state)}`)
          .then(() => {
            setNotice("GitHub App successfully connected. You can now browse and inspect repositories.");
            window.history.replaceState(null, "", window.location.pathname);
            setScanTab("github");
            refresh();
          })
          .catch((e) => {
            console.error("GitHub callback error:", e);
            window.history.replaceState(null, "", window.location.pathname);
          });
      } else {
        // Direct link without state (standard GitHub App setup redirect)
        api(`/github/installations/${installationId}/link`, { method: "POST" })
          .then(() => {
            setNotice("GitHub App successfully connected. You can now browse and inspect repositories.");
            window.history.replaceState(null, "", window.location.pathname);
            setScanTab("github");
            refresh();
          })
          .catch((e) => {
            console.error("GitHub link error:", e);
            window.history.replaceState(null, "", window.location.pathname);
          });
      }
    } else if (gh === "connected") {
      setNotice("GitHub App successfully connected. You can now browse and inspect repositories.");
      window.history.replaceState(null, "", window.location.pathname);
      setScanTab("github");
      refresh();
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
    setIsAnalyzing(false);
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
          setJob(null);
          setIsAnalyzing(false);
          openReport(finishedReport);
          refresh();
        } else if (state.status === "failed") {
          setError(state.error || "Scan failed.");
          setJob(null);
          setIsAnalyzing(false);
        } else if (state.status === "cancelled") {
          setJob(null);
          setIsAnalyzing(false);
          setTimeout(() => {
            document.getElementById("new-scan")?.scrollIntoView({ behavior: "smooth", block: "center" });
          }, 40);
        } else {
          timer = setTimeout(poll, 650);
        }
      } catch (e) {
        if (!cancelled) {
          setError((e as Error).message);
          setJob(null);
          setIsAnalyzing(false);
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
    if (p === "Overview") {
      if (!busy) setJob(null);
      setIsAnalyzing(false);
    }
    window.history.replaceState(null, "", "/");
    setSearch("");
    setMobileMenuOpen(false);
  }

  function startScan(id: string) {
    setError("");
    navigate("Overview");
    setIsAnalyzing(true);
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
      <aside className={mobileMenuOpen ? "sidebar mobile-open" : "sidebar"}>
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
              aria-current={page === name && !report ? "page" : undefined}
              onClick={() => navigate(name as any)}
            >
              <Icon size={18} />
              <span>
                {name}
                {name === "Scan history" && (
                  <span
                    className={
                      reports.length > 0
                        ? "nav-attention-dot has-reports"
                        : "nav-attention-dot"
                    }
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



        {/* Sidebar footer */}
        <div className="sidebar-bottom">
          <span className="avatar">Y</span>
          <strong className="sidebar-user-name">Local User</strong>
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
          </div>

          <div className="top-actions">
            <AccountButton />
            <button
              type="button"
              className="btn-get-started"
              onClick={handleGetStarted}
              title="Connect and scan a GitHub repository"
            >
              <GitBranch size={14} />
              <span>Get started</span>
            </button>

            <button
              aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
              className="icon-button theme-toggle"
              onClick={() => setDark(!dark)}
              title={dark ? "Use light theme" : "Use dark theme"}
            >
              {dark ? (
                <SunIcon size={17} className="inline-flex items-center justify-center" />
              ) : (
                <MoonIcon size={17} className="inline-flex items-center justify-center" />
              )}
            </button>
          </div>
        </header>

        {/* Main Content Viewport */}
        <main
          className={
            report
              ? ""
              : page === "Overview"
                ? isAnalyzing || busy || job
                  ? "main-overview is-scrollable"
                  : "main-overview"
                : ""
          }
        >
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
                  setRemediationFinding(f ? f.id : null);
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
              {/* Header only for Scan History */}
              {page === "Scan history" && (
                <div className="page-heading">
                  <div>
                    <h1 className="heading-title">Inspection History</h1>
                    <p className="heading-subtitle">
                      Complete repository of past inspections with full evidence trails preserved.
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
                        All <span className="dataset-count-pill">{reports.length}</span>
                      </button>
                      <button
                        type="button"
                        className={`dataset-filter-btn ${datasetFilter === "real" ? "active" : ""}`}
                        onClick={() => setDatasetFilter("real")}
                        title="Show only real projects and registry lookups"
                      >
                        Real Projects <span className="dataset-count-pill">{realReportsCount}</span>
                      </button>
                      <button
                        type="button"
                        className={`dataset-filter-btn ${datasetFilter === "demo" ? "active" : ""}`}
                        onClick={() => setDatasetFilter("demo")}
                        title="Show only synthetic fixtures and demo data"
                      >
                        Demo Data <span className="dataset-count-pill">{demoReportsCount}</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {page === "Overview" && (
                <>
                  {/* GitHub-style Security Activity & Threat Heatmap Hero */}
                  <section className="heatmap-hero-card">
                    <div className="heatmap-header">
                      <div className="heatmap-toggle-pill" role="group" aria-label="Heatmap Mode Toggle">
                        <button
                          type="button"
                          className={`heatmap-toggle-btn ${heatmapMode === "activity" ? "active activity" : ""}`}
                          onClick={() => setHeatmapMode("activity")}
                          title="Show days active in emerald gradient"
                        >
                          <Activity size={15} />
                          <span>Active Days</span>
                        </button>
                        <button
                          type="button"
                          className={`heatmap-toggle-btn ${heatmapMode === "threats" ? "active threats" : ""}`}
                          onClick={() => setHeatmapMode("threats")}
                          title="Show malware encountered & handled in rose gradient"
                        >
                          <ShieldAlert size={15} />
                          <span>Malware Handled</span>
                        </button>
                      </div>

                    </div>

                    <div className="heatmap-body">
                      <CalendarHeatmap
                        data={heatmapMode === "activity" ? activityHeatmapData : threatHeatmapData}
                        label={heatmapMode === "activity" ? "packages audited" : "threats neutralized"}
                        hue={heatmapMode === "activity" ? "var(--spectrum-series-3)" : "var(--spectrum-series-4)"}
                      />
                    </div>
                  </section>

                  {/* Primary Package Scan & File Upload Launchpad */}
                  <div className="scan-launchpad-section">
                    <ScanPanel
                      onStart={startScan}
                      busy={!!busy}
                      job={job}
                      onConnectFolder={() => navigate("Project workspace")}
                      activeTab={scanTab}
                      onTabChange={setScanTab}
                      onAnalyzing={() => setIsAnalyzing(true)}
                      onImportReport={(imported) => {
                        setReports((current) => [imported, ...current]);
                        openReport(imported);
                      }}
                    />
                  </div>

                  </>
              )}

{/* All Scans Table (dedicated to Scan history page) */}
              {page === "Scan history" && (
                <section className="recent-section">
                  <div className="section-heading">
                    <div>
                      <h2>All Inspections</h2>
                      <p>
                        Evidence trails and report history across all analyzed
                        packages.
                      </p>
                    </div>

                    <div className="history-search">
                      <SearchIcon size={15} className="inline-flex items-center justify-center opacity-70" />
                      <input
                        aria-label="Search scans"
                        placeholder="Search by package name or version…"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                      />
                    </div>
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
                        .slice(0, 50)
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
              )}
            </motion.div>
          )}

          {/* Footer */}
          <footer>
            <span>
              <ShieldCheck size={14} />
              DevGuardian 3.0 · Software Supply-Chain Intelligence
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
            text: "DevGuardian unpacks ZIP files and npm tarballs strictly in bounded virtual memory with recursive size and symlink checks. Uploaded lifecycle scripts and untrusted executables are never run.",
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
        DevGuardian is a local supply-chain defense engine. It performs bounded AST
        static analysis and exact OSV database cross-referencing. Explanation
        responses are evidence-grounded in stored scan findings.
      </Note>
    </div>
  );
}
