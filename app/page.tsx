"use client";
import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
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
} from "lucide-react";
import { api, Report, ScanJob } from "@/lib/types";
import { Brand, Eyebrow, Empty, Note } from "@/components/ui";
import ScanPanel from "@/components/scan-panel";
import ReportView from "@/components/report";
export default function Home() {
  const [reports, setReports] = useState<Report[]>([]),
    [report, setReport] = useState<Report | null>(null),
    [page, setPage] = useState("Overview"),
    [dark, setDark] = useState(false),
    [job, setJob] = useState<ScanJob | null>(null),
    [error, setError] = useState(""),
    [connected, setConnected] = useState(false),
    [loading, setLoading] = useState(true),
    [search, setSearch] = useState("");
  const busy = job?.status === "running";
  const refresh = useCallback(async () => {
    try {
      setReports(await api<Report[]>("/scans"));
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
    setDark(localStorage.getItem("guardian-theme") === "dark");
    const id = new URLSearchParams(window.location.search).get("scan");
    if (id)
      api<Report>(`/scans/${id}`)
        .then(setReport)
        .catch((e) => setError(e.message));
  }, [refresh]);
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("guardian-theme", dark ? "dark" : "light");
  }, [dark]);
  const open = useCallback((r: Report) => {
    setReport(r);
    window.history.replaceState(null, "", `?scan=${r.id}`);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);
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
          open(await api<Report>(`/scans/${job.id}`));
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
  }, [job?.id, busy, open, refresh]);
  function navigate(p: string) {
    setPage(p);
    setReport(null);
    window.history.replaceState(null, "", "/");
    setSearch("");
  }
  function start(id: string) {
    setError("");
    navigate("Overview");
    setJob({ id, status: "running", stage: "Queued" });
    document
      .getElementById("new-scan")
      ?.scrollIntoView({ behavior: "smooth", block: "center" });
  }
  async function example(id: string) {
    try {
      start(
        (await api<{ id: string }>(`/scans/example/${id}`, { method: "POST" }))
          .id,
      );
    } catch (e) {
      setError((e as Error).message);
    }
  }
  const elevated = reports.filter((r) =>
      r.findings.some((f) => f.severity !== "info"),
    ).length,
    dependencies = new Set(
      reports.flatMap((r) => r.dependencies.map((d) => d.name)),
    ).size;
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <div className="workspace-label">
          <span>G</span>
          <div>
            Personal workspace<small>LOCAL EDITION</small>
          </div>
          <ChevronRight size={15} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {[
            { name: "Overview", icon: LayoutDashboard },
            { name: "Scan history", icon: History },
            { name: "How it works", icon: BookOpen },
          ].map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={page === name && !report ? "active" : ""}
              onClick={() => navigate(name)}
            >
              <Icon size={18} />
              {name}
              {name === "Scan history" && <span>{reports.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-note">
          <div className="tiny-shield">
            <ShieldCheck size={20} />
          </div>
          <h4>Trust is built on evidence.</h4>
          <p>See what your software does. Understand why it matters.</p>
          <button onClick={() => navigate("How it works")}>
            Meet Guardian
            <ArrowUpRight size={14} />
          </button>
        </div>
        <div className="sidebar-bottom">
          <span className="avatar">Y</span>
          <div>
            Your workspace<small>No account required</small>
          </div>
          <span className="local-dot" />
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace
            <ChevronRight size={13} />
            <strong>{report ? "Scan report" : page}</strong>
          </div>
          <div className="top-actions">
            <span className={`service-status ${connected ? "online" : ""}`}>
              <i />
              {connected ? "Scanner connected" : "Scanner offline"}
            </span>
            <button
              aria-label={dark ? "Use light mode" : "Use dark mode"}
              className="icon-button"
              onClick={() => setDark(!dark)}
            >
              {dark ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <span className="header-avatar">Y</span>
          </div>
        </header>
        <main>
          {error && (
            <div className="global-error" role="alert">
              <AlertCircle size={18} />
              <span>{error}</span>
              <button
                onClick={() => {
                  setError("");
                  refresh();
                }}
              >
                Retry
              </button>
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {report ? (
            <ReportView
              key={report.id}
              report={report}
              onBack={() => navigate("Scan history")}
            />
          ) : page === "How it works" ? (
            <Methodology />
          ) : (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <div className="page-heading">
                <div>
                  <Eyebrow>YOUR SOFTWARE. A CLEARER PICTURE.</Eyebrow>
                  <h1>
                    {page === "Overview"
                      ? "Know what you trust."
                      : "Your scan history."}
                  </h1>
                  <p>
                    {page === "Overview"
                      ? "A closer look at your dependencies. Confidence in your next decision."
                      : "Every inspection, with its evidence intact."}
                  </p>
                </div>
                <button
                  className="button primary"
                  onClick={() => {
                    navigate("Overview");
                    setTimeout(
                      () =>
                        document
                          .getElementById("new-scan")
                          ?.scrollIntoView({ behavior: "smooth" }),
                      50,
                    );
                  }}
                >
                  <Plus size={17} />
                  New scan
                </button>
              </div>
              {page === "Overview" && (
                <>
                  <div className="overview-stats">
                    <Stat
                      label="Projects inspected"
                      value={reports.length}
                      icon={<Package size={19} />}
                      detail="Across your recent scans"
                    />
                    <Stat
                      label="Scans to review"
                      value={elevated}
                      icon={<Activity size={19} />}
                      detail="With elevated security signals"
                    />
                    <Stat
                      label="Dependencies discovered"
                      value={dependencies}
                      icon={<ShieldCheck size={19} />}
                      detail="Unique names in your manifests"
                    />
                  </div>
                  <div className="home-grid">
                    <ScanPanel onStart={start} busy={!!busy} job={job} />
                    <section className="guide-card">
                      <div className="guide-visual" aria-hidden="true">
                        <div className="orbit orbit-one" />
                        <div className="orbit orbit-two" />
                        <span className="orbit-node node-one">
                          <Package size={17} />
                        </span>
                        <span className="orbit-node node-two">
                          <FileSymbol />
                        </span>
                        <span className="orbit-node node-three">
                          <CheckSymbol />
                        </span>
                        <span className="central-shield">
                          <ShieldCheck size={41} strokeWidth={1.4} />
                        </span>
                      </div>
                      <Eyebrow>SECURITY, WITHOUT THE GUESSWORK</Eyebrow>
                      <h2>
                        More than a red flag.
                        <br />
                        The reason behind it.
                      </h2>
                      <p>
                        Guardian connects suspicious behavior to real evidence,
                        then explains it in language that makes sense.
                      </p>
                      <button
                        className="text-link"
                        onClick={() => navigate("How it works")}
                      >
                        See how we analyze
                        <ArrowRight size={15} />
                      </button>
                      <div className="guide-tags">
                        <span>Static analysis</span>
                        <span>Explainable findings</span>
                      </div>
                    </section>
                  </div>
                  <section className="examples-strip">
                    <div>
                      <FlaskConical size={20} />
                      <div>
                        <h3>Take a closer look.</h3>
                        <p>Run a real scan on a safe, synthetic example.</p>
                      </div>
                    </div>
                    <div className="example-actions">
                      <button
                        disabled={!!busy}
                        onClick={() => example("benign")}
                      >
                        Everyday package
                        <ArrowUpRight size={14} />
                      </button>
                      <button
                        disabled={!!busy}
                        onClick={() => example("exfiltration")}
                      >
                        Sensitive data flow
                        <ArrowUpRight size={14} />
                      </button>
                      <button
                        disabled={!!busy}
                        onClick={() => example("correlated")}
                      >
                        Suspicious installer
                        <ArrowUpRight size={14} />
                      </button>
                    </div>
                  </section>
                </>
              )}
              <section className="recent-section">
                <div className="section-heading">
                  <div>
                    <h2>
                      {page === "Overview" ? "Recent scans" : "All scans"}
                    </h2>
                    <p>Your evidence trail, always within reach.</p>
                  </div>
                  {page === "Overview" ? (
                    <button
                      className="text-link"
                      onClick={() => navigate("Scan history")}
                    >
                      View history
                      <ArrowRight size={15} />
                    </button>
                  ) : (
                    <div className="history-search">
                      <Search size={16} />
                      <input
                        aria-label="Search scans"
                        placeholder="Find a package…"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                      />
                    </div>
                  )}
                </div>
                <div className="card scan-table">
                  {loading ? (
                    <div className="empty">
                      <Loader2 className="spin" />
                      Connecting to scanner…
                    </div>
                  ) : !reports.length ? (
                    <Empty title="Your first insight starts here.">
                      Upload a project or try an example. Every report here
                      comes from a real scan.
                    </Empty>
                  ) : (
                    <>
                      <div className="table-header">
                        <span>PACKAGE / PROJECT</span>
                        <span>ASSESSMENT</span>
                        <span>FINDINGS</span>
                        <span>SCANNED</span>
                        <span />
                      </div>
                      {reports
                        .filter((r) =>
                          r.name.toLowerCase().includes(search.toLowerCase()),
                        )
                        .slice(0, page === "Overview" ? 5 : 50)
                        .map((r) => (
                          <button
                            className="table-row"
                            key={r.id}
                            onClick={() => open(r)}
                          >
                            <span className="package-cell">
                              <span className="package-symbol">
                                <Package size={20} />
                              </span>
                              <span>
                                <strong>{r.name}</strong>
                                <small>
                                  {r.version} <i>·</i> {r.source}
                                </small>
                              </span>
                            </span>
                            <span>
                              <span
                                className={`risk-pill ${r.findings.some((f) => ["high", "critical"].includes(f.severity)) ? "high" : r.findings.some((f) => f.severity !== "info") ? "medium" : "clear"}`}
                              >
                                <i />
                                {r.risk}
                              </span>
                            </span>
                            <span className="findings-cell">
                              {
                                r.findings.filter((f) => f.severity !== "info")
                                  .length
                              }
                              <small> to review</small>
                            </span>
                            <span className="date-cell">
                              {new Date(r.created_at).toLocaleDateString(
                                undefined,
                                { month: "short", day: "numeric" },
                              )}
                              <small>
                                {new Date(r.created_at).toLocaleTimeString(
                                  undefined,
                                  { hour: "2-digit", minute: "2-digit" },
                                )}
                              </small>
                            </span>
                            <ChevronRight size={16} />
                          </button>
                        ))}
                    </>
                  )}
                </div>
              </section>
            </motion.div>
          )}
          <footer>
            <span>
              <ShieldCheck size={14} />
              Guardian · Know what you trust.
            </span>
            <span>Static inspection. Human judgment.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
function Stat({
  label,
  value,
  icon,
  detail,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  detail: string;
}) {
  return (
    <div className="stat">
      <div>
        <span>{label}</span>
        {icon}
      </div>
      <strong>{String(value).padStart(2, "0")}</strong>
      <p>{detail}</p>
    </div>
  );
}
function FileSymbol() {
  return <span style={{ fontFamily: "monospace", fontSize: 16 }}>{"{ }"}</span>;
}
function CheckSymbol() {
  return <ShieldCheck size={17} />;
}
function Methodology() {
  return (
    <div>
      <div className="page-heading">
        <div>
          <Eyebrow>BUILT TO BE UNDERSTOOD</Eyebrow>
          <h1>Evidence before assumptions.</h1>
          <p>
            A security assessment should help you decide, not decide for you.
          </p>
        </div>
      </div>
      <div className="method-grid">
        {[
          {
            n: "01",
            title: "Inspect. Never execute.",
            text: "Guardian reads your manifests and source files. ZIP and npm tarballs are unpacked in bounded memory, with path, size and link checks. Uploaded scripts are never run.",
          },
          {
            n: "02",
            title: "Connect the signals.",
            text: "A JavaScript syntax tree identifies behavior. File-local data tracking connects sensitive information to outbound requests. Individual network or environment accesses remain observations.",
          },
          {
            n: "03",
            title: "Show the reasoning.",
            text: "Every finding has source evidence, confidence, potential consequences and a next step. Simple and Advanced modes are two views of the same report.",
          },
          {
            n: "04",
            title: "Make uncertainty visible.",
            text: "Unparsed files, missing source and unavailable vulnerability intelligence are shown in coverage. No elevated signals is not a guarantee of safety.",
          },
        ].map((x) => (
          <section className="card method-card" key={x.n}>
            <span>{x.n}</span>
            <h2>{x.title}</h2>
            <p>{x.text}</p>
          </section>
        ))}
      </div>
      <Note>
        Guardian is a local npm-focused prototype. It does not execute code,
        certify packages, or perform complete cross-file data-flow analysis.
        Explanation responses are deterministic and grounded in stored findings.
      </Note>
    </div>
  );
}
