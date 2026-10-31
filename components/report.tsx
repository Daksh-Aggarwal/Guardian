"use client";
import { useState } from "react";
import { motion } from "framer-motion";
import {
  ArrowLeft,
  ArrowDownToLine,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
  Check,
  FileCode2,
  Package,
  Info,
  Network,
} from "lucide-react";
import { Report, Finding, Severity } from "@/lib/types";
import { Badge, Eyebrow, Note, External, Empty } from "./ui";
import Explainer from "./explainer";
import {
  IntelligenceOverview,
  DependencyInspection,
  FlowEvidence,
  AdvisoryDetails,
} from "./intelligence";
export default function ReportView({
  report,
  onBack,
}: {
  report: Report;
  onBack: () => void;
}) {
  const [advanced, setAdvanced] = useState(false),
    [tab, setTab] = useState("Findings"),
    [selected, setSelected] = useState<string | null>(
      report.findings.find((f) => f.severity !== "info")?.id || null,
    ),
    [filter, setFilter] = useState("all");
  const elevated = report.findings.filter((f) => f.severity !== "info"),
    behavioralElevated = report.findings.filter(
      (f) =>
        (!f.domain || f.domain === "behavior") &&
        f.rule !== "OSV" &&
        f.severity !== "info",
    ),
    isV2 = report.engine_version === "2",
    displayElevated = isV2 ? behavioralElevated : elevated,
    high = report.findings
      .filter((f) => (!f.domain || f.domain === "behavior") && f.rule !== "OSV")
      .some((f) => ["high", "critical"].includes(f.severity));
  const visible = report.findings.filter(
    (f) => filter === "all" || f.severity === filter,
  );
  function focus(id: string) {
    setTab("Findings");
    setSelected(id);
    setFilter("all");
    setTimeout(
      () =>
        document
          .getElementById("finding-" + id)
          ?.scrollIntoView({ behavior: "smooth", block: "center" }),
      100,
    );
  }
  function download() {
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
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
      <div className="report-top">
        <button className="back-button" onClick={onBack}>
          <ArrowLeft size={15} />
          All scans
        </button>
        <button className="button secondary compact" onClick={download}>
          <ArrowDownToLine size={15} />
          Export JSON
        </button>
      </div>
      <div className="page-heading">
        <div>
          <Eyebrow>PACKAGE INTELLIGENCE / SCAN REPORT</Eyebrow>
          <h1>
            {report.name}
            <span className="version">{report.version}</span>
          </h1>
          <p>
            {new Date(report.created_at).toLocaleString()}
            <span className="separator">/</span>
            {report.source}
            <span className="separator">/</span>
            {(report.duration_ms / 1000).toFixed(1)}s
          </p>
        </div>
        <div className="mode-switch" aria-label="Report mode">
          <button
            aria-pressed={!advanced}
            className={!advanced ? "active" : ""}
            onClick={() => setAdvanced(false)}
          >
            Simple
          </button>
          <button
            aria-pressed={advanced}
            className={advanced ? "active" : ""}
            onClick={() => setAdvanced(true)}
          >
            Advanced
          </button>
        </div>
      </div>
      <section
        className={`verdict ${high ? "concern" : displayElevated.length ? "review" : "calm"}`}
      >
        <div className="verdict-symbol">
          {displayElevated.length ? (
            <AlertTriangle size={29} />
          ) : (
            <ShieldCheck size={29} />
          )}
        </div>
        <div>
          <Eyebrow>
            {isV2 ? "BEHAVIORAL ASSESSMENT" : "OVERALL ASSESSMENT"}
          </Eyebrow>
          <h2>{report.risk}</h2>
          <p>{report.rationale}</p>
        </div>
        <div className="verdict-count">
          <strong>{displayElevated.length}</strong>
          <span>
            {isV2
              ? displayElevated.length === 1
                ? "behavioral signal"
                : "behavioral signals"
              : displayElevated.length === 1
                ? "signal to review"
                : "signals to review"}
          </span>
        </div>
      </section>
      <IntelligenceOverview report={report} />
      <div className="report-stats">
        <div>
          <FileCode2 size={19} />
          <span>
            <strong>{report.files_analyzed}</strong> source files inspected
          </span>
        </div>
        <div>
          <Package size={19} />
          <span>
            <strong>{report.dependencies.length}</strong> dependency versions
          </span>
        </div>
        <div>
          <Network size={19} />
          <span>
            OSV intelligence <strong>{report.intelligence}</strong>
          </span>
        </div>
      </div>
      <div className="report-layout">
        <div>
          <div className="report-tabs">
            {["Findings", "Dependencies", "Coverage"].map((t) => (
              <button
                className={tab === t ? "active" : ""}
                key={t}
                onClick={() => setTab(t)}
              >
                {t}
                <span>
                  {t === "Findings"
                    ? report.findings.length
                    : t === "Dependencies"
                      ? report.dependencies.length
                      : report.coverage.length}
                </span>
              </button>
            ))}
          </div>
          {tab === "Findings" && (
            <>
              <div className="filter-row">
                <span>
                  {advanced
                    ? "Technical evidence & detection rules"
                    : "What Guardian found"}
                </span>
                <select
                  aria-label="Filter by severity"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                >
                  <option value="all">All severities</option>
                  {["critical", "high", "medium", "low", "info"].map((s) => (
                    <option key={s} value={s}>
                      {s === "info" ? "Observations" : s}
                    </option>
                  ))}
                </select>
              </div>
              {!visible.length ? (
                <Empty title="No findings in this view">
                  Review scan coverage before making a trust decision.
                </Empty>
              ) : (
                <div className="finding-list">
                  {visible.map((f) => (
                    <FindingRow
                      key={f.id}
                      finding={f}
                      advanced={advanced}
                      open={selected === f.id}
                      onToggle={() =>
                        setSelected(selected === f.id ? null : f.id)
                      }
                    />
                  ))}
                </div>
              )}
            </>
          )}
          {tab === "Dependencies" && report.engine_version === "2" && (
            <DependencyInspection report={report} advanced={advanced} />
          )}
          {tab === "Dependencies" && report.engine_version !== "2" && (
            <div className="card dependency-card">
              <h3>Dependency inventory</h3>
              <p>
                Declared ranges and resolved versions from included manifests.
              </p>
              {!report.dependencies.length ? (
                <Empty title="No dependencies found">
                  This input does not declare dependency versions.
                </Empty>
              ) : (
                <div className="dependency-table">
                  {report.dependencies.map((d, i) => (
                    <div key={d.name + d.version + i}>
                      <Package size={16} />
                      <strong>{d.name}</strong>
                      <code>{d.version}</code>
                      <span>
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
          {tab === "Coverage" && (
            <div className="card coverage-card">
              <Eyebrow>TRANSPARENCY BY DESIGN</Eyebrow>
              <h2>What this scan can tell you.</h2>
              <p>
                These boundaries are part of the assessment, not fine print.
              </p>

              <div
                className="coverage-dimensions"
                style={{
                  marginTop: "20px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "14px",
                }}
              >
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
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: "8px",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <FileCode2 size={16} />
                      <strong style={{ fontSize: "12px" }}>
                        Source & Behavioral Inspection
                      </strong>
                    </div>
                    <span className="status-chip">
                      {report.assessments?.behavior?.coverage_status ||
                        "complete"}
                    </span>
                  </div>
                  <p
                    style={{
                      fontSize: "11px",
                      color: "var(--muted)",
                      margin: "0",
                      lineHeight: "1.6",
                    }}
                  >
                    {advanced
                      ? `${report.files_analyzed} source files analyzed under Node.js Babel AST inspection with bounded call depth (8) and module limit (100). Status: ${report.assessments?.behavior?.coverage_status || "complete"}.`
                      : report.files_analyzed > 0
                        ? `Guardian inspected ${report.files_analyzed} source files directly for behavioral signals like credential access and sensitive data flow.`
                        : "Manifest-only scan: no package source code was analyzed."}
                  </p>
                </div>

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
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: "8px",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <Package size={16} />
                      <strong style={{ fontSize: "12px" }}>
                        Dependency Graph Resolution
                      </strong>
                    </div>
                    <span className="status-chip">
                      {report.assessments?.inspection?.status || "complete"}
                    </span>
                  </div>
                  <p
                    style={{
                      fontSize: "11px",
                      color: "var(--muted)",
                      margin: "0",
                      lineHeight: "1.6",
                    }}
                  >
                    {advanced
                      ? `${report.inspection_summary?.inspected || 0}/${report.inspection_summary?.total || 0} packages inspected (${report.inspection_summary?.skipped || 0} skipped, ${report.inspection_summary?.unavailable || 0} unavailable, ${report.inspection_summary?.unresolved || 0} unresolved, ${report.inspection_summary?.integrity_failed || 0} integrity failed, ${report.inspection_summary?.not_attempted || 0} not attempted).`
                      : report.inspection_summary &&
                          report.inspection_summary.total > 0
                        ? `${report.inspection_summary.inspected} of ${report.inspection_summary.total} dependency locations inspected under the ${report.inspection_summary.profile || "fast"} budget profile.`
                        : "No external dependencies declared."}
                  </p>
                </div>

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
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: "8px",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <Network size={16} />
                      <strong style={{ fontSize: "12px" }}>
                        Vulnerability Intelligence (OSV)
                      </strong>
                    </div>
                    <span className="status-chip">
                      {report.assessments?.vulnerabilities?.status ||
                        report.intelligence}
                    </span>
                  </div>
                  <p
                    style={{
                      fontSize: "11px",
                      color: "var(--muted)",
                      margin: "0",
                      lineHeight: "1.6",
                    }}
                  >
                    {advanced
                      ? `Exact-version queries evaluated against OSV database. Intelligence status: ${report.assessments?.vulnerabilities?.status || report.intelligence}. Matches: ${report.assessments?.vulnerabilities?.count ?? report.findings.filter((f) => f.rule === "OSV").length}.`
                      : (report.assessments?.vulnerabilities?.status ||
                            report.intelligence) === "checked"
                        ? "OSV vulnerability database was queried for exact package versions."
                        : (report.assessments?.vulnerabilities?.status ||
                              report.intelligence) === "partial"
                          ? "Vulnerability intelligence is partial; some dependencies or advisories could not be completely resolved."
                          : "Vulnerability intelligence was unavailable during this scan."}
                  </p>
                </div>
              </div>

              <div style={{ marginTop: "24px" }}>
                <Eyebrow>ANALYSIS LIMITATIONS & NOTICES</Eyebrow>
                {report.coverage.map((c, i) => (
                  <div className="coverage-item" key={i}>
                    <Info size={17} />
                    <p>{c}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
          <Explainer key={report.id} report={report} onFinding={focus} />
        </div>
        <aside className="report-aside">
          <div className="card">
            <Eyebrow>YOUR NEXT STEPS</Eyebrow>
            <h3>Make an informed decision.</h3>
            {(elevated.length
              ? elevated.slice(0, 3)
              : report.findings.slice(0, 2)
            ).map((f, i) => (
              <button
                className="next-step"
                key={f.id}
                onClick={() => focus(f.id)}
              >
                <span>{String(i + 1).padStart(2, "0")}</span>
                <p>{f.recommendation}</p>
                <ChevronRight size={14} />
              </button>
            ))}
            {!report.findings.length && (
              <p>
                Verify the package publisher and review the scan’s coverage
                limits before use.
              </p>
            )}
          </div>
          <div className="trust-note">
            <ShieldCheck size={20} />
            <h4>Evidence, not a black box.</h4>
            <p>
              Severity describes potential impact. Confidence describes the
              strength of the detection. Neither proves malicious intent.
            </p>
            <button className="text-link" onClick={() => setTab("Coverage")}>
              Understand scan coverage
              <ChevronRight size={14} />
            </button>
          </div>
          <div className="severity-summary">
            <Eyebrow>FINDING BREAKDOWN</Eyebrow>
            {(["critical", "high", "medium", "low", "info"] as Severity[]).map(
              (s) => (
                <div key={s}>
                  <Badge severity={s} />
                  <span>
                    {report.findings.filter((f) => f.severity === s).length}
                  </span>
                </div>
              ),
            )}
          </div>
        </aside>
      </div>
    </motion.div>
  );
}
function FindingRow({
  finding: f,
  advanced,
  open,
  onToggle,
}: {
  finding: Finding;
  advanced: boolean;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <article
      id={"finding-" + f.id}
      className={`finding ${open ? "expanded" : ""}`}
    >
      <button
        className="finding-heading"
        onClick={onToggle}
        aria-expanded={open}
      >
        <span className={`finding-icon ${f.severity}`}>
          {f.severity === "info" ? (
            <Info size={18} />
          ) : (
            <AlertTriangle size={18} />
          )}
        </span>
        <span className="finding-title">
          <strong>{f.title}</strong>
          <span>
            {f.category}
            <i /> {f.confidence} confidence
          </span>
        </span>
        <Badge severity={f.severity} />
        <ChevronDown size={16} className={open ? "rotate" : ""} />
      </button>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="finding-body"
        >
          <div className="explanation-block">
            <h4>{advanced ? "Observed behavior" : "What was found"}</h4>
            <p>{advanced ? f.observed : f.explanation}</p>
          </div>
          <div className="explanation-block">
            <h4>Why it matters</h4>
            <p>{f.implication}</p>
          </div>
          <FlowEvidence finding={f} advanced={advanced} />
          <AdvisoryDetails finding={f} advanced={advanced} />
          {f.package && (
            <p className="package-attribution">Package: {f.package}</p>
          )}
          <div className="evidence-heading">
            <h4>{advanced ? "Source evidence" : "Where we found it"}</h4>
            {advanced && <code>{f.rule}</code>}
          </div>
          {f.evidence.map((e, i) => (
            <div className="source-evidence" key={i}>
              <div>
                <FileCode2 size={14} />
                <span>
                  {e.file}:{e.line}
                  {advanced ? `:${e.column}` : ""}
                </span>
              </div>
              {advanced ? (
                <pre>
                  <code>{e.snippet}</code>
                </pre>
              ) : (
                <p>{e.detail}</p>
              )}
            </div>
          ))}
          <div className="recommendation">
            <Check size={17} />
            <div>
              <h4>Recommended action</h4>
              <p>{f.recommendation}</p>
            </div>
          </div>
          {!!f.limitations?.length && (
            <div className="finding-limitations">
              <h4>What remains uncertain</h4>
              {f.limitations.map((text, i) => (
                <p key={i}>{text}</p>
              ))}
            </div>
          )}
          {f.references.map((r) => {
            let label = "Read vulnerability advisory";
            try {
              const host = new URL(r).hostname.replace(/^www\./, "");
              label = `Advisory reference (${host})`;
            } catch {}
            return (
              <External href={r} key={r}>
                {label}
              </External>
            );
          })}
        </motion.div>
      )}
    </article>
  );
}
