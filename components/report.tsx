"use client";

import React, { useState, useMemo, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ArrowDownToLine,
  AlertTriangle,
  FileCode2,
  Info,
  Network,
  Filter,
  ShieldAlert,
  Share2,
} from "lucide-react";
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  Check,
  Package,
  Wrench,
  Search,
  Sparkles,
  Layers,
  GitBranch,
  HelpCircle,
  Clock,
  FileText,
  ExternalLink,
  SlidersHorizontal,
  FolderOpen,
} from "@/components/icons";
import {
  Report,
  Finding,
  Severity,
  Evidence,
  DataFlow,
  Advisory,
} from "@/lib/types";
import {
  Badge,
  Eyebrow,
  Note,
  External,
  Empty,
  StatusChip,
  SecurityDimensionCard,
  SectionHeader,
  ClassificationBadge,
} from "./ui";
import { getDependencyAccounting, getFindingBreakdown } from "@/lib/accounting";
import IntelligencePanel from "./intelligence-panel";
import HandoffModal from "./handoff-modal";
import {
  IntelligenceOverview,
  DependencyInspection,
  FlowEvidence,
  AdvisoryDetails,
  IntegrityDetails,
} from "./intelligence";

export default function ReportView({
  report,
  onBack,
  onPrepareFix,
  onInvestigateProject,
  onHandoffFinding,
  onHandoffScan,
}: {
  report: Report;
  onBack: () => void;
  onPrepareFix?: (finding: Finding) => void;
  onInvestigateProject?: (report: Report) => void;
  onHandoffFinding?: (findingId: string) => void;
  onHandoffScan?: () => void;
}) {
  const [advanced, setAdvanced] = useState(false);
  const tabsRef = useRef<HTMLDivElement>(null);

  const navigateToTab = (
    targetTab: "Findings" | "Dependencies" | "Coverage" | "Evidence",
    options?: { domain?: string; severity?: string },
  ) => {
    setTab(targetTab);
    if (options?.domain !== undefined) {
      setFilterDomain(options.domain);
    }
    if (options?.severity !== undefined) {
      setFilterSeverity(options.severity);
    }
    setTimeout(() => {
      if (tabsRef.current) {
        tabsRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 60);
  };
  const [tab, setTab] = useState<
    "Findings" | "Dependencies" | "Coverage" | "Evidence"
  >("Findings");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    report.findings.find((f) => f.severity !== "info")?.id ||
      report.findings[0]?.id ||
      null,
  );
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterDomain, setFilterDomain] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [groupByPackage, setGroupByPackage] = useState(true);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [copilotFindingId, setCopilotFindingId] = useState<string | null>(null);
  const [handoffOpen, setHandoffOpen] = useState(false);
  const [handoffFindingId, setHandoffFindingId] = useState<string | null>(null);

  const handleOpenHandoff = (fid?: string) => {
    setHandoffFindingId(fid || null);
    setHandoffOpen(true);
    if (fid && onHandoffFinding) {
      onHandoffFinding(fid);
    } else if (!fid && onHandoffScan) {
      onHandoffScan();
    }
  };

  // Exact dependency & finding accounting reconciliation
  const deps = useMemo(() => getDependencyAccounting(report), [report]);
  const breakdown = useMemo(
    () => getFindingBreakdown(report.findings),
    [report.findings],
  );

  // Findings breakdown
  const elevatedFindings = report.findings.filter((f) => f.severity !== "info");
  const criticalFindings = report.findings.filter(
    (f) => f.severity === "critical",
  );
  const highFindings = report.findings.filter((f) => f.severity === "high");
  const behavioralFindings = report.findings.filter(
    (f) => (!f.domain || f.domain === "behavior") && f.rule !== "OSV",
  );
  const elevatedBehavioral = behavioralFindings.filter(
    (f) => f.severity !== "info",
  );
  const osvFindings = report.findings.filter(
    (f) => f.rule === "OSV" || f.domain === "vulnerability" || !!f.advisory,
  );
  const integrityFindings = report.findings.filter(
    (f) => f.domain === "integrity",
  );
  const dataFlowFindings = report.findings.filter(
    (f) => f.data_flows && f.data_flows.length > 0,
  );

  // Adaptive Summary Logic (Evidence-grounded)
  const summaryMode = useMemo(() => {
    if (
      osvFindings.some((f) => ["critical", "high"].includes(f.severity)) &&
      elevatedBehavioral.length === 0
    ) {
      return "vulnerabilities_primary";
    }
    if (elevatedBehavioral.length > 0) {
      return "behavioral_primary";
    }
    if (
      report.files_analyzed === 0 ||
      report.assessments?.behavior?.coverage_status === "manifest_only"
    ) {
      return "manifest_only";
    }
    if (
      report.coverage.some(
        (c) => c.includes("skipped") || c.includes("incomplete"),
      )
    ) {
      return "coverage_limited";
    }
    if (elevatedFindings.length > 0) {
      return "mixed_elevated";
    }
    return "clean";
  }, [osvFindings, elevatedBehavioral, report]);

  // Selected finding object
  const activeFinding = useMemo(
    () => report.findings.find((f) => f.id === selectedFindingId) || null,
    [report.findings, selectedFindingId],
  );

  const copilotActiveFinding = useMemo(
    () => report.findings.find((f) => f.id === copilotFindingId) || null,
    [report.findings, copilotFindingId],
  );

  // Filtered findings
  const visibleFindings = useMemo(() => {
    return report.findings.filter((f) => {
      if (filterSeverity !== "all" && f.severity !== filterSeverity)
        return false;
      if (
        filterDomain === "behavioral" &&
        (f.rule === "OSV" || f.domain === "integrity")
      )
        return false;
      if (filterDomain === "vulnerabilities" && f.rule !== "OSV" && !f.advisory)
        return false;
      if (filterDomain === "integrity" && f.domain !== "integrity")
        return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const displayTitle = f.advisory?.summary || f.title;
        const matchTitle = displayTitle.toLowerCase().includes(q);
        const matchRule = f.rule.toLowerCase().includes(q);
        const matchPkg = (f.package || "").toLowerCase().includes(q);
        const matchAdv = (f.advisory?.id || "").toLowerCase().includes(q);
        const matchExp = f.explanation.toLowerCase().includes(q);
        if (!matchTitle && !matchRule && !matchPkg && !matchAdv && !matchExp)
          return false;
      }
      return true;
    });
  }, [report.findings, filterSeverity, filterDomain, searchQuery]);

  // Group findings by package
  const groupedFindings = useMemo(() => {
    const groups: Record<string, Finding[]> = {};
    for (const f of visibleFindings) {
      const pkgKey =
        f.package ||
        (f.rule === "OSV" && f.advisory
          ? "Dependencies (OSV)"
          : "Root Project Source");
      if (!groups[pkgKey]) groups[pkgKey] = [];
      groups[pkgKey].push(f);
    }
    return groups;
  }, [visibleFindings]);

  function focusFinding(id: string) {
    setTab("Findings");
    setSelectedFindingId(id);
    setTimeout(() => {
      document.getElementById("finding-" + id)?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    }, 100);
  }

  function openCopilotForFinding(finding: Finding) {
    setSelectedFindingId(finding.id);
    setCopilotFindingId(finding.id);
    setCopilotOpen(true);
  }

  function downloadReport() {
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `guardian-${report.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="report-view-container"
    >
      {report.cli && (
        <section
          className="card"
          style={{ padding: "1.25rem", marginBottom: "1rem" }}
          aria-label="CLI installation decision"
        >
          <strong>
            Guardian CLI · {report.cli.ecosystem} ·{" "}
            {report.cli.decision?.decision || "Decision unavailable"}
          </strong>
          <p>
            Installation: {report.cli.installation?.status || "not attempted"}.
            Lifecycle scripts: {report.cli.lifecycle_scripts || "disabled"}.
          </p>
          {report.cli.imported && (
            <p>
              Imported local evidence. Findings, artifact hashes and
              installation claims were not reverified by this website.
            </p>
          )}
          {!!report.cli.decision?.reasons?.length && (
            <ul>
              {report.cli.decision.reasons.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>
          )}
        </section>
      )}
      {/* Top action bar */}
      <div className="report-action-bar">
        <div className="report-action-left">
          <button
            type="button"
            className="btn-secondary-subtle"
            onClick={onBack}
          >
            <ArrowLeft size={15} />
            <span>All scans</span>
          </button>
          <span className="breadcrumb-divider">/</span>
          <span className="report-package-tag">{report.name}</span>
          <span className="report-version-badge">v{report.version}</span>
        </div>

        <div className="report-action-right">
          <button
            type="button"
            className="btn-secondary-subtle"
            onClick={() => handleOpenHandoff()}
            title="Export AI-agnostic remediation instructions for coding agents"
          >
            <Share2 size={14} color="var(--accent)" />
            <span>Get AI Fix Instructions</span>
          </button>

          {onInvestigateProject && (
            <button
              type="button"
              className="btn-secondary-subtle"
              onClick={() => onInvestigateProject(report)}
              title="Open project in Investigation Workspace"
            >
              <GitBranch size={14} />
              <span>Investigate Project</span>
            </button>
          )}

          <button
            type="button"
            className="copilot-toggle-btn"
            onClick={() => {
              setCopilotFindingId(selectedFindingId);
              setCopilotOpen((prev) => !prev);
            }}
          >
            <Sparkles size={15} className="copilot-spark" />
            <span>Guardian Intelligence</span>
            <span className="ai-status-pulse" />
          </button>

          <button
            type="button"
            className="btn-secondary-subtle"
            onClick={downloadReport}
            title="Export raw JSON report"
          >
            <ArrowDownToLine size={14} />
            <span>Export JSON</span>
          </button>

          {/* Simple vs Advanced mode selector */}
          <div
            className="mode-toggle-pill"
            role="group"
            aria-label="Report detail level"
          >
            <button
              type="button"
              className={!advanced ? "active" : ""}
              onClick={() => setAdvanced(false)}
            >
              Simple
            </button>
            <button
              type="button"
              className={advanced ? "active" : ""}
              onClick={() => setAdvanced(true)}
            >
              Advanced
            </button>
          </div>
        </div>
      </div>

      {/* Main Report Header */}
      <header className="report-main-header">
        <div className="report-title-area">
          <div className="report-title-top-row">
            <Eyebrow>SECURITY ASSESSMENT REPORT</Eyebrow>
            <ClassificationBadge
              classification={
                report.classification ||
                (report.source === "synthetic fixture" ? "demo" : "real")
              }
            />
          </div>
          <h1 className="report-title">
            {report.name}
            <span className="version-chip">{report.version}</span>
          </h1>
          <div className="report-meta-strip">
            <span className="meta-item">
              <Clock size={13} />
              {new Date(report.created_at).toLocaleString()}
            </span>
            <span className="meta-separator">·</span>
            <span className="meta-item">
              <Package size={13} />
              {report.source}
            </span>
            <span className="meta-separator">·</span>
            <span className="meta-item">
              <FileCode2 size={13} />
              {report.files_analyzed} source{" "}
              {report.files_analyzed === 1 ? "file" : "files"}
            </span>
            <span className="meta-separator">·</span>
            <span className="meta-item">
              <Network size={13} />
              {deps.totalResolved}{" "}
              {deps.totalResolved === 1 ? "dependency" : "dependencies"}
              <span style={{ opacity: 0.75, marginLeft: 4 }}>
                ({deps.declaredDirect} direct, {deps.transitive} transitive)
              </span>
            </span>
            <span className="meta-separator">·</span>
            <span className="meta-item duration">
              {(report.duration_ms / 1000).toFixed(1)}s elapsed
            </span>
          </div>
        </div>
      </header>

      {/* Adaptive Assessment Summary Banner */}
      <section className={`adaptive-summary-banner banner-${summaryMode}`}>
        <div className="summary-symbol-wrap">
          {summaryMode === "clean" ? (
            <ShieldCheck size={32} strokeWidth={1.75} />
          ) : summaryMode === "manifest_only" ? (
            <Info size={32} strokeWidth={1.75} />
          ) : (
            <AlertTriangle size={32} strokeWidth={1.75} />
          )}
        </div>

        <div className="summary-content">
          <span className="summary-kicker">
            {summaryMode === "vulnerabilities_primary"
              ? "ADVISORY MATCHES IN DEPENDENCIES"
              : summaryMode === "behavioral_primary"
                ? "BEHAVIORAL SIGNALS DETECTED"
                : summaryMode === "manifest_only"
                  ? "MANIFEST INSPECTION ONLY"
                  : summaryMode === "coverage_limited"
                    ? "INSPECTION BOUNDARIES IDENTIFIED"
                    : "VERIFIED SCAN ASSESSMENT"}
          </span>

          <h2 className="summary-headline">
            {summaryMode === "vulnerabilities_primary"
              ? `${osvFindings.length} Known ${osvFindings.length === 1 ? "Vulnerability" : "Vulnerabilities"} in Resolved Dependencies`
              : summaryMode === "behavioral_primary"
                ? report.risk ||
                  "Elevated Behavioral Signals Require Investigation"
                : summaryMode === "manifest_only"
                  ? "Package Source Uninspected · Manifest & OSV Intelligence Checked"
                  : summaryMode === "coverage_limited"
                    ? "Partial Source Coverage · Review Inspection Limitations"
                    : "No Elevated Signals Identified in Inspected Content"}
          </h2>

          <p className="summary-rationale">
            {summaryMode === "vulnerabilities_primary"
              ? `Guardian cross-referenced declared packages against the OSV vulnerability database. ${criticalFindings.length > 0 ? `${criticalFindings.length} critical and ` : ""}${highFindings.length > 0 ? `${highFindings.length} high priority ` : ""}advisories apply to resolved versions. Inspected source code showed no separate behavioral exfiltration patterns.`
              : summaryMode === "behavioral_primary"
                ? report.rationale ||
                  "Static syntax inspection observed code patterns that warrant review before this package is executed or deployed in production."
                : summaryMode === "manifest_only"
                  ? "No source code files were included or analyzed in this input. Manifest dependencies were inventoried and checked against OSV intelligence, but internal runtime behavior cannot be assessed."
                  : summaryMode === "coverage_limited"
                    ? report.rationale ||
                      "Certain dependencies or source files were skipped or could not be retrieved. Review the coverage section to understand what was inspected versus uninspected."
                    : "Guardian inspected all included files and dependency manifests with bounded AST static analysis. No known malicious exfiltration signatures, suspicious child processes, or advisory matches were identified."}
          </p>

          <div className="summary-disclaimer">
            <Info size={13} />
            <span>
              {summaryMode === "clean"
                ? "Static analysis assesses available evidence; no automated security tool can certify software as absolutely safe."
                : "Findings reflect static observations and advisory records. Inspect the evidence trail before deciding to install or deploy."}
            </span>
          </div>
        </div>

        <div className="summary-stats-box">
          <div className="summary-stat-count">
            <strong>{elevatedFindings.length}</strong>
            <span>
              {elevatedFindings.length === 1
                ? "Finding to review"
                : "Findings to review"}
            </span>
          </div>
          {elevatedFindings.length > 0 && (
            <button
              type="button"
              className="summary-jump-btn"
              onClick={() => {
                navigateToTab("Findings", { severity: "all" });
              }}
            >
              <span>View findings</span>
              <ChevronRight size={13} />
            </button>
          )}
        </div>
      </section>

      {/* 4 Independent Assessment Dimension Cards */}
      <section className="dimensions-section">
        <div className="dimension-grid">
          {/* 1. Behavioral Assessment */}
          <SecurityDimensionCard
            title="Behavioral Assessment"
            domain="CODE BEHAVIOR"
            status={
              elevatedBehavioral.length > 0
                ? "Signals detected"
                : report.files_analyzed === 0
                  ? "Unavailable"
                  : "Clean"
            }
            statusTone={
              elevatedBehavioral.some((f) =>
                ["critical", "high"].includes(f.severity),
              )
                ? "danger"
                : elevatedBehavioral.length > 0
                  ? "warning"
                  : report.files_analyzed === 0
                    ? "purple"
                    : "success"
            }
            headline={
              elevatedBehavioral.length > 0
                ? `${elevatedBehavioral.length} behavioral ${elevatedBehavioral.length === 1 ? "signal" : "signals"}`
                : report.files_analyzed === 0
                  ? "Source code uninspected"
                  : "No suspicious behaviors"
            }
            description={
              report.files_analyzed === 0
                ? "Manifest-only scan: no source code syntax trees analyzed."
                : advanced
                  ? `Analyzed ${report.files_analyzed} files under AST analysis for process execution, network sinks, and credential reads.`
                  : elevatedBehavioral.length > 0
                    ? "Suspicious runtime patterns like sensitive data access or shell commands detected."
                    : "Direct AST inspection found no credential exfiltration, shell spawning, or dynamic code execution."
            }
            metric={elevatedBehavioral.length}
            metricLabel="behavioral findings"
            icon={<FileCode2 size={18} />}
            onClick={() => {
              navigateToTab("Findings", { domain: "behavioral" });
            }}
          />

          {/* 2. Known Vulnerabilities (OSV) */}
          <SecurityDimensionCard
            title="Known Vulnerabilities"
            domain="OSV DATABASE"
            status={
              osvFindings.length > 0
                ? "Advisories present"
                : report.intelligence === "checked"
                  ? "Checked"
                  : report.intelligence
            }
            statusTone={
              osvFindings.some((f) => ["critical", "high"].includes(f.severity))
                ? "danger"
                : osvFindings.length > 0
                  ? "warning"
                  : "success"
            }
            headline={
              osvFindings.length > 0
                ? `${osvFindings.length} advisory ${osvFindings.length === 1 ? "match" : "matches"}`
                : "No known vulnerabilities"
            }
            description={
              osvFindings.length > 0
                ? `${osvFindings.filter((f) => f.severity === "critical").length} critical, ${osvFindings.filter((f) => f.severity === "high").length} high priority vulnerabilities found in resolved dependency versions.`
                : `Queried the OSV advisory database against ${deps.totalResolved} resolved dependency ${deps.totalResolved === 1 ? "version" : "versions"}.`
            }
            metric={osvFindings.length}
            metricLabel="upstream advisories"
            icon={<Network size={18} />}
            onClick={() => {
              navigateToTab("Findings", { domain: "vulnerabilities" });
            }}
          />

          {/* 3. Package Integrity */}
          <SecurityDimensionCard
            title="Package Integrity"
            domain="CHECKSUM VERIFICATION"
            status={
              integrityFindings.length > 0
                ? "Integrity concern"
                : report.root_integrity?.status === "verified"
                  ? "Verified"
                  : report.root_integrity?.status || "Not applicable"
            }
            statusTone={
              integrityFindings.length > 0
                ? "danger"
                : report.root_integrity?.status === "verified"
                  ? "success"
                  : "neutral"
            }
            headline={
              integrityFindings.length > 0
                ? `${integrityFindings.length} checksum mismatches`
                : report.root_integrity?.status === "verified"
                  ? "Registry checksum verified"
                  : "Integrity verified or local"
            }
            description={
              report.root_integrity
                ? `Published SHA-512 / SHA-256 digest matches registry metadata. (Notice: Checksums establish byte consistency, never software safety.)`
                : "No remote npm tarballs downloaded; project files evaluated in bounded local memory."
            }
            metric={report.root_integrity?.status || "Local"}
            metricLabel="registry digest status"
            icon={<ShieldCheck size={18} />}
            onClick={() => navigateToTab("Dependencies")}
          />

          {/* 4. Source Inspection Coverage */}
          <SecurityDimensionCard
            title="Inspection Coverage"
            domain="ANALYSIS BOUNDARIES"
            status={
              report.assessments?.inspection?.status ||
              (report.files_analyzed > 0 ? "Complete" : "Manifest only")
            }
            statusTone={
              report.assessments?.inspection?.status === "incomplete" ||
              report.coverage.some((c) => c.includes("skipped"))
                ? "warning"
                : report.files_analyzed === 0
                  ? "purple"
                  : "success"
            }
            headline={
              report.inspection_summary
                ? `${deps.inspected} / ${deps.totalResolved} dependencies inspected`
                : `${report.files_analyzed} source files inspected`
            }
            description={
              report.inspection_summary
                ? `${deps.skipped} skipped by budget profile, ${deps.unavailable + deps.unresolved} unavailable or unretrieved.`
                : "Deep syntax analysis executed under bounded recursion without executing untrusted code."
            }
            metric={
              report.inspection_summary
                ? `${deps.inspected}/${deps.totalResolved}`
                : `${report.files_analyzed}`
            }
            metricLabel={
              report.inspection_summary
                ? "inspected dependencies"
                : "files analyzed"
            }
            icon={<Package size={18} />}
            onClick={() => navigateToTab("Coverage")}
          />
        </div>
      </section>

      {/* Main Content Area: Tabs + Aside */}
      <div className="report-body-layout">
        <div className="report-main-col">
          {/* Navigation Tabs */}
          <div ref={tabsRef} className="report-tab-nav" role="tablist" id="report-tabs">
            <button
              type="button"
              role="tab"
              aria-selected={tab === "Findings"}
              className={`report-tab-btn ${tab === "Findings" ? "active" : ""}`}
              onClick={() => setTab("Findings")}
            >
              <span>Findings</span>
              <span className="tab-badge">{report.findings.length}</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={tab === "Dependencies"}
              className={`report-tab-btn ${tab === "Dependencies" ? "active" : ""}`}
              onClick={() => setTab("Dependencies")}
            >
              <span>Dependencies</span>
              <span className="tab-badge">{deps.totalResolved}</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={tab === "Coverage"}
              className={`report-tab-btn ${tab === "Coverage" ? "active" : ""}`}
              onClick={() => setTab("Coverage")}
            >
              <span>Inspection Coverage</span>
              <span className="tab-badge">{report.coverage.length}</span>
            </button>

            {dataFlowFindings.length > 0 && (
              <button
                type="button"
                role="tab"
                aria-selected={tab === "Evidence"}
                className={`report-tab-btn ${tab === "Evidence" ? "active" : ""}`}
                onClick={() => setTab("Evidence")}
              >
                <span>Evidence & Data Flows</span>
                <span className="tab-badge special">
                  {dataFlowFindings.length}
                </span>
              </button>
            )}
          </div>

          {/* TAB 1: FINDINGS */}
          {tab === "Findings" && (
            <div className="tab-findings-content">
              {/* Filter and search bar */}
              <div className="findings-toolbar">
                <div className="findings-search-wrap">
                  <Search size={14} className="search-icon" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter by title, package, advisory ID, or rule…"
                    aria-label="Filter findings"
                    className="findings-search-input"
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      onClick={() => setSearchQuery("")}
                      className="search-clear-btn"
                    >
                      Clear
                    </button>
                  )}
                </div>

                <div className="findings-filter-controls">
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    aria-label="Filter by severity"
                    className="filter-select"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Observations</option>
                  </select>

                  <select
                    value={filterDomain}
                    onChange={(e) => setFilterDomain(e.target.value)}
                    aria-label="Filter by domain"
                    className="filter-select"
                  >
                    <option value="all">All Categories</option>
                    <option value="behavioral">Behavioral Signals</option>
                    <option value="vulnerabilities">
                      Known Advisories (OSV)
                    </option>
                    <option value="integrity">Package Integrity</option>
                  </select>

                  <button
                    type="button"
                    className={`group-toggle-btn ${groupByPackage ? "active" : ""}`}
                    onClick={() => setGroupByPackage((prev) => !prev)}
                    title="Group related findings by package"
                  >
                    <Layers size={14} />
                    <span>Group by package</span>
                  </button>
                </div>
              </div>

              {/* Findings Count Summary */}
              <div className="findings-results-meta">
                <span>
                  Showing <strong>{visibleFindings.length}</strong> of{" "}
                  <strong>{report.findings.length}</strong> recorded findings
                </span>
                {(filterSeverity !== "all" ||
                  filterDomain !== "all" ||
                  searchQuery) && (
                  <button
                    type="button"
                    className="reset-filters-btn"
                    onClick={() => {
                      setFilterSeverity("all");
                      setFilterDomain("all");
                      setSearchQuery("");
                    }}
                  >
                    Reset filters
                  </button>
                )}
              </div>

              {visibleFindings.length === 0 ? (
                <Empty title="No matching findings in this view">
                  Try adjusting the severity or category filter, or check scan
                  coverage.
                </Empty>
              ) : groupByPackage ? (
                /* Grouped by Package View */
                <div className="findings-grouped-container">
                  {Object.entries(groupedFindings).map(
                    ([pkgName, pkgFindings]) => (
                      <PackageFindingsGroup
                        key={pkgName}
                        packageName={pkgName}
                        findings={pkgFindings}
                        selectedId={selectedFindingId}
                        onSelectFinding={setSelectedFindingId}
                        onAskCopilot={openCopilotForFinding}
                        onPrepareFix={onPrepareFix}
                        onHandoffFinding={handleOpenHandoff}
                        advanced={advanced}
                      />
                    ),
                  )}
                </div>
              ) : (
                /* Flat List View */
                <div className="findings-flat-list">
                  {visibleFindings.map((f) => (
                    <FindingItemCard
                      key={f.id}
                      finding={f}
                      isOpen={selectedFindingId === f.id}
                      onToggle={() =>
                        setSelectedFindingId(
                          selectedFindingId === f.id ? null : f.id,
                        )
                      }
                      onAskCopilot={() => openCopilotForFinding(f)}
                      onPrepareFix={onPrepareFix}
                      onHandoffFinding={handleOpenHandoff}
                      advanced={advanced}
                    />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: DEPENDENCIES */}
          {tab === "Dependencies" && (
            <div className="tab-dependencies-content">
              {report.engine_version === "2" ? (
                <DependencyInspection report={report} advanced={advanced} />
              ) : (
                <div className="card dependency-card">
                  <SectionHeader
                    title="Dependency Inventory"
                    description="Declared ranges and resolved versions from included manifests."
                  />
                  {!report.dependencies.length ? (
                    <Empty title="No dependencies found">
                      This input does not declare external dependency versions.
                    </Empty>
                  ) : (
                    <div className="dependency-table">
                      {report.dependencies.map((d, i) => (
                        <div
                          key={d.name + d.version + i}
                          className="dependency-row"
                        >
                          <Package size={16} />
                          <strong>{d.name}</strong>
                          <code>{d.version}</code>
                          <span className="status-chip neutral">
                            {d.direct ? "Direct" : "Transitive / lockfile"}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  <Note>
                    Dependency source is not fetched recursively.
                    Known-vulnerability checks require exact versions.
                  </Note>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: COVERAGE */}
          {tab === "Coverage" && (
            <div className="tab-coverage-content">
              <div className="card coverage-main-card">
                <SectionHeader
                  eyebrow="TRANSPARENCY BY DESIGN"
                  title="What This Scan Can & Cannot Prove"
                  description="Explicit inspection boundaries and coverage guarantees are integral to the assessment, never hidden fine print."
                />

                <div className="coverage-dimensions-stack">
                  <div className="coverage-box">
                    <div className="coverage-box-header">
                      <div className="coverage-box-title">
                        <FileCode2 size={16} />
                        <strong>Source & Behavioral Inspection</strong>
                      </div>
                      <StatusChip
                        status={
                          report.assessments?.behavior?.coverage_status ||
                          "complete"
                        }
                      />
                    </div>
                    <p>
                      {advanced
                        ? `${report.files_analyzed} source files inspected via Node.js Babel AST with maximum call depth 8 and module limit 100. Status: ${report.assessments?.behavior?.coverage_status || "complete"}.`
                        : report.files_analyzed > 0
                          ? `Guardian directly parsed ${report.files_analyzed} source files for behavioral indicators like private token access, child process execution, and outbound network sinks.`
                          : "Manifest-only scan: no package source code was analyzed."}
                    </p>
                  </div>

                  <div className="coverage-box">
                    <div className="coverage-box-header">
                      <div className="coverage-box-title">
                        <Package size={16} />
                        <strong>
                          Dependency Resolution & Source Retrieval
                        </strong>
                      </div>
                      <StatusChip
                        status={
                          report.assessments?.inspection?.status || "complete"
                        }
                      />
                    </div>
                    <p>
                      {advanced
                        ? `${report.inspection_summary?.inspected || 0}/${report.inspection_summary?.total || 0} packages inspected (${report.inspection_summary?.skipped || 0} skipped, ${report.inspection_summary?.unavailable || 0} unavailable, ${report.inspection_summary?.unresolved || 0} unresolved, ${report.inspection_summary?.integrity_failed || 0} integrity failed).`
                        : report.inspection_summary &&
                            report.inspection_summary.total > 0
                          ? `${report.inspection_summary.inspected} of ${report.inspection_summary.total} dependency locations inspected under the ${report.inspection_summary.profile || "fast"} budget profile.`
                          : "No external dependencies declared or attempted."}
                    </p>
                  </div>

                  <div className="coverage-box">
                    <div className="coverage-box-header">
                      <div className="coverage-box-title">
                        <Network size={16} />
                        <strong>Vulnerability Intelligence (OSV)</strong>
                      </div>
                      <StatusChip
                        status={
                          report.assessments?.vulnerabilities?.status ||
                          report.intelligence
                        }
                      />
                    </div>
                    <p>
                      {advanced
                        ? `Exact-version queries evaluated against OSV database. Intelligence status: ${report.assessments?.vulnerabilities?.status || report.intelligence}. Matches: ${report.assessments?.vulnerabilities?.count ?? osvFindings.length}.`
                        : (report.assessments?.vulnerabilities?.status ||
                              report.intelligence) === "checked"
                          ? "OSV vulnerability database was queried successfully for all declared exact package versions."
                          : "Vulnerability intelligence was unavailable or partially evaluated during this scan."}
                    </p>
                  </div>
                </div>

                <div className="coverage-notices-area">
                  <Eyebrow>SPECIFIC SCAN NOTICES & LIMITATIONS</Eyebrow>
                  {report.coverage.map((c, i) => (
                    <div className="coverage-notice-item" key={i}>
                      <Info size={15} />
                      <p>{c}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: EVIDENCE & DATA FLOWS */}
          {tab === "Evidence" && (
            <div className="tab-evidence-content">
              <div className="card evidence-overview-card">
                <SectionHeader
                  eyebrow="STATIC DATA-FLOW TRACING"
                  title="Observed Information Propagation Paths"
                  description="Traces sensitive information from source (e.g. process.env API keys) to sink (e.g. outbound network requests) across syntax trees."
                />

                <div className="data-flows-list">
                  {dataFlowFindings.map((f) => (
                    <div key={f.id} className="finding-flow-block">
                      <div className="flow-block-header">
                        <div>
                          <Badge severity={f.severity} size="sm" />
                          <strong className="flow-finding-title">
                            {f.title}
                          </strong>
                        </div>
                        <button
                          type="button"
                          className="btn-secondary-subtle compact"
                          onClick={() => focusFinding(f.id)}
                        >
                          View in findings
                        </button>
                      </div>
                      <FlowEvidence finding={f} advanced={advanced} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar: Recommended Next Steps & Finding Breakdown */}
        <aside className="report-sidebar-col">
          <div className="card report-next-steps-card">
            <Eyebrow>RECOMMENDED NEXT STEPS</Eyebrow>
            <h3>Make an informed decision</h3>

            <div className="next-steps-list">
              {(elevatedFindings.length > 0
                ? elevatedFindings.slice(0, 3)
                : report.findings.slice(0, 2)
              ).map((f, i) => (
                <button
                  key={f.id}
                  type="button"
                  className="next-step-btn"
                  onClick={() => focusFinding(f.id)}
                >
                  <span className="step-num">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <div className="step-text">
                    <strong>{f.advisory?.summary || f.title}</strong>
                    <p>{f.recommendation}</p>
                  </div>
                  <ChevronRight size={14} className="step-chevron" />
                </button>
              ))}

              {!report.findings.length && (
                <p className="no-findings-hint">
                  Verify the package publisher and review scan coverage limits
                  before use.
                </p>
              )}
            </div>
          </div>

          {/* Copilot Quick Launch Banner */}
          <div className="card copilot-callout-card">
            <div className="copilot-callout-top">
              <Sparkles size={18} className="copilot-icon" />
              <h4>Have questions about this report?</h4>
            </div>
            <p>
              Guardian Intelligence can explain finding severity, attack
              mechanisms, and verify if vulnerabilities affect your environment.
            </p>
            <button
              type="button"
              className="copilot-callout-btn"
              onClick={() => {
                setCopilotFindingId(selectedFindingId);
                setCopilotOpen(true);
              }}
            >
              <span>Ask Guardian Intelligence</span>
              <ChevronRight size={14} />
            </button>
          </div>

          {/* Finding Breakdown by Severity */}
          <div className="card severity-breakdown-card">
            <Eyebrow>FINDING BREAKDOWN</Eyebrow>
            <div className="severity-rows-list">
              {(
                ["critical", "high", "medium", "low", "info"] as Severity[]
              ).map((s) => {
                const count = report.findings.filter(
                  (f) => f.severity === s,
                ).length;
                return (
                  <button
                    key={s}
                    type="button"
                    className={`severity-breakdown-row ${filterSeverity === s ? "active" : ""}`}
                    onClick={() => {
                      setTab("Findings");
                      setFilterSeverity(filterSeverity === s ? "all" : s);
                    }}
                  >
                    <Badge severity={s} size="sm" />
                    <span className="severity-count">{count}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </aside>
      </div>

      {/* Persistent Collapsible Right-Side Guardian Intelligence Panel */}
      <IntelligencePanel
        report={report}
        isOpen={copilotOpen}
        onClose={() => setCopilotOpen(false)}
        selectedFinding={copilotActiveFinding}
        onClearSelectedFinding={() => setCopilotFindingId(null)}
        onFocusFinding={(fid) => {
          focusFinding(fid);
          setCopilotFindingId(fid);
        }}
        advanced={advanced}
      />

      {/* Guardian Handoff 1.0 Modal */}
      {handoffOpen && (
        <HandoffModal
          report={report}
          isOpen={handoffOpen}
          initialFindingId={handoffFindingId}
          onClose={() => setHandoffOpen(false)}
        />
      )}
    </motion.div>
  );
}

// Grouped Package Card Component
function PackageFindingsGroup({
  packageName,
  findings,
  selectedId,
  onSelectFinding,
  onAskCopilot,
  onPrepareFix,
  onHandoffFinding,
  advanced,
}: {
  packageName: string;
  findings: Finding[];
  selectedId: string | null;
  onSelectFinding: (id: string) => void;
  onAskCopilot: (f: Finding) => void;
  onPrepareFix?: (f: Finding) => void;
  onHandoffFinding?: (findingId: string) => void;
  advanced: boolean;
}) {
  const [collapsed, setCollapsed] = useState(false);

  const highestSeverity = useMemo(() => {
    const severities: Severity[] = [
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ];
    for (const s of severities) {
      if (findings.some((f) => f.severity === s)) return s;
    }
    return "info";
  }, [findings]);

  return (
    <div className={`package-group-card ${collapsed ? "collapsed" : ""}`}>
      <button
        type="button"
        className="package-group-header"
        onClick={() => setCollapsed((p) => !p)}
        aria-expanded={!collapsed}
      >
        <div className="pkg-header-left">
          <Package size={17} className="pkg-icon" />
          <div className="pkg-info">
            <strong className="pkg-name">{packageName}</strong>
            <span className="pkg-count">
              {findings.length}{" "}
              {findings.length === 1 ? "recorded finding" : "recorded findings"}
            </span>
          </div>
        </div>

        <div className="pkg-header-right">
          <Badge severity={highestSeverity} size="sm" />
          <ChevronDown
            size={16}
            className={`pkg-chevron ${collapsed ? "rotate-up" : ""}`}
          />
        </div>
      </button>

      {!collapsed && (
        <div className="package-group-findings-list">
          {findings.map((f) => (
            <FindingItemCard
              key={f.id}
              finding={f}
              isOpen={selectedId === f.id}
              onToggle={() => onSelectFinding(selectedId === f.id ? "" : f.id)}
              onAskCopilot={() => onAskCopilot(f)}
              onPrepareFix={onPrepareFix}
              onHandoffFinding={onHandoffFinding}
              advanced={advanced}
              isGrouped
            />
          ))}
        </div>
      )}
    </div>
  );
}

// Individual Finding Item Card
function FindingItemCard({
  finding: f,
  isOpen,
  onToggle,
  onAskCopilot,
  onPrepareFix,
  onHandoffFinding,
  advanced,
  isGrouped = false,
}: {
  finding: Finding;
  isOpen: boolean;
  onToggle: () => void;
  onAskCopilot: () => void;
  onPrepareFix?: (f: Finding) => void;
  onHandoffFinding?: (findingId: string) => void;
  advanced: boolean;
  isGrouped?: boolean;
}) {
  // Meaningful Title Logic
  const displayTitle = useMemo(() => {
    if (f.advisory?.summary) return f.advisory.summary;
    if (f.rule === "OSV" && f.advisory?.id) {
      return `${f.package || "Dependency"}: ${f.advisory.id}`;
    }
    return f.title;
  }, [f]);

  return (
    <article
      id={"finding-" + f.id}
      className={`finding-card ${isOpen ? "expanded" : ""} ${isGrouped ? "grouped-item" : ""}`}
    >
      <button
        type="button"
        className="finding-card-header"
        onClick={onToggle}
        aria-expanded={isOpen}
      >
        <span className={`finding-severity-icon ${f.severity}`}>
          {f.severity === "info" ? (
            <Info size={16} />
          ) : f.severity === "critical" || f.severity === "high" ? (
            <AlertTriangle size={16} />
          ) : (
            <AlertTriangle size={16} />
          )}
        </span>

        <div className="finding-header-content">
          <strong className="finding-main-title">{displayTitle}</strong>
          <div className="finding-subtext">
            {f.advisory?.id && (
              <span className="advisory-id-tag">{f.advisory.id}</span>
            )}
            <span className="finding-category">{f.category}</span>
            <span className="bullet-sep">·</span>
            <span className="finding-confidence">
              {f.confidence} confidence
            </span>
            {f.package && (
              <span className="finding-pkg-tag">pkg: {f.package}</span>
            )}
          </div>
        </div>

        <div className="finding-header-badges">
          {f.advisory?.fixed_versions &&
            f.advisory.fixed_versions.length > 0 && (
              <span
                className="fixed-version-pill"
                title={`Fixed in: ${f.advisory.fixed_versions.join(", ")}`}
              >
                Fixed: {f.advisory.fixed_versions[0]}
              </span>
            )}
          <Badge severity={f.severity} size="sm" />
          <ChevronDown
            size={16}
            className={`finding-chevron ${isOpen ? "rotate" : ""}`}
          />
        </div>
      </button>

      {isOpen && (
        <motion.div
          initial={false}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.15 }}
          className="finding-card-body"
        >
          <ol className="evidence-trail" aria-label="Finding evidence trail">
            <li><span className="evidence-index">01</span><div>
              <h4>What Guardian found</h4>
              <p>{advanced ? f.observed : f.explanation}</p>
              <code>{f.id}</code>
            </div></li>
            <li><span className="evidence-index">02</span><div>
              <h4>Why it matters</h4><p>{f.implication}</p>
            </div></li>
            <li><span className="evidence-index">03</span><div>
              <h4>What you can do</h4><p>{f.recommendation}</p>
            </div></li>
          </ol>

          {/* Interactive Data Flows */}
          {f.data_flows && f.data_flows.length > 0 && (
            <FlowEvidence finding={f} advanced={advanced} />
          )}

          {/* Advisory Details */}
          {f.advisory && <AdvisoryDetails finding={f} advanced={advanced} />}

          {/* Source Evidence */}
          <div className="evidence-section">
            <div className="evidence-section-header">
              <h4>
                {advanced
                  ? "Source Evidence & Syntax AST"
                  : "Evidence Location"}
              </h4>
              {advanced && <code className="rule-badge">{f.rule}</code>}
            </div>

            {f.evidence.map((e, idx) => (
              <div className="evidence-code-block" key={idx}>
                <div className="evidence-file-line">
                  <FileCode2 size={13} />
                  <span>
                    {e.file}:{e.line}
                    {advanced ? `:${e.column}` : ""}
                  </span>
                </div>

                {advanced ? (
                  <pre className="evidence-snippet">
                    <code>{e.snippet}</code>
                  </pre>
                ) : (
                  <p className="evidence-detail">{e.detail}</p>
                )}
              </div>
            ))}
          </div>

          {/* Recommendation */}
          <div className="recommendation-callout">
            <Check size={16} className="recommendation-icon" />
            <div className="recommendation-text">
              <h4>Recommended Action</h4>
              <p>{f.recommendation}</p>
            </div>
          </div>

          {/* Action Footer: Ask Copilot & Prepare Fix */}
          <div className="finding-action-footer">
            <div className="finding-action-left">
              {f.references.map((r) => {
                let label = "Read Advisory";
                try {
                  const host = new URL(r).hostname.replace(/^www\./, "");
                  label = `Advisory (${host})`;
                } catch {}
                return (
                  <External href={r} key={r}>
                    {label}
                  </External>
                );
              })}
            </div>

            <div className="finding-action-right">
              <button
                type="button"
                className="btn-copilot-ask"
                onClick={(e) => {
                  e.stopPropagation();
                  onAskCopilot();
                }}
              >
                <Sparkles size={13} />
                <span>Ask Guardian Intelligence</span>
              </button>

              {onPrepareFix && (
                <button
                  type="button"
                  className="btn-prepare-fix"
                  onClick={(e) => {
                    e.stopPropagation();
                    onPrepareFix(f);
                  }}
                >
                  <Wrench size={13} />
                  <span>Prepare fix with Guardian Autopilot</span>
                </button>
              )}

              {onHandoffFinding && (
                <button
                  type="button"
                  className="btn-prepare-fix"
                  onClick={(e) => {
                    e.stopPropagation();
                    onHandoffFinding(f.id);
                  }}
                  title="Export AI fix instructions for this finding"
                >
                  <Share2 size={13} color="var(--accent)" />
                  <span>Get AI Fix Instructions</span>
                </button>
              )}
            </div>
          </div>

          {/* Limitations */}
          {!!f.limitations?.length && (
            <div className="finding-uncertainties">
              <h4>What Remains Uncertain</h4>
              {f.limitations.map((text, i) => (
                <p key={i}>{text}</p>
              ))}
            </div>
          )}
        </motion.div>
      )}
    </article>
  );
}
