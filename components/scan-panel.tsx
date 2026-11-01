"use client";

import { useRef, useState } from "react";
import {
  UploadCloud,
  FileArchive,
  Loader2,
  FileCode2,
} from "lucide-react";
import {
  ArrowRight,
  Package,
  Check,
  ShieldCheck,
  FolderOpen,
  X,
  Sliders,
  Sparkles,
  GitBranch,
} from "@/components/icons";
import { motion, AnimatePresence } from "framer-motion";
import { api, ScanJob, Report } from "@/lib/types";
import { Note } from "./ui";
import GitHubConnectPanel from "./github-connect-panel";
import { MagneticDropZone } from "./ui/magnetic-drop-zone";

export type { ScanJob };

export default function ScanPanel({
  onStart,
  busy,
  job,
  onConnectFolder,
  activeTab,
  onTabChange,
  onAnalyzing,
  onImportReport,
}: {
  onStart: (id: string) => void;
  busy: boolean;
  job: ScanJob | null;
  onConnectFolder?: () => void;
  activeTab?: "upload" | "package" | "github" | "cli";
  onTabChange?: (tab: "upload" | "package" | "github" | "cli") => void;
  onAnalyzing?: () => void;
  onImportReport?: (report: Report) => void;
}) {
  const [internalTab, setInternalTab] = useState<"upload" | "package" | "github" | "cli">("upload");
  const tab = activeTab ?? internalTab;
  const setTab = (nextTab: "upload" | "package" | "github" | "cli") => {
    setInternalTab(nextTab);
    onTabChange?.(nextTab);
  };
  const [ecosystem, setEcosystem] = useState<"npm" | "pypi">("npm");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("latest");
  const [profile, setProfile] = useState<"fast" | "deep">("fast");
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  // CLI Import state
  const [cliFile, setCliFile] = useState<File | null>(null);
  const [cliConsent, setCliConsent] = useState(false);
  const [cliImporting, setCliImporting] = useState(false);

  const disabled = busy || sending;

  async function submit() {
    setError("");
    setSending(true);
    onAnalyzing?.();
    try {
      let result: { id: string };
      if (tab === "upload") {
        if (!files.length) {
          throw new Error(
            "Choose a project ZIP or manifest (package.json, requirements.txt, pyproject.toml, poetry.lock, package-lock.json, pnpm-lock.yaml, yarn.lock) to inspect.",
          );
        }
        const data = new FormData();
        data.append("profile", profile);
        files.forEach((f) => data.append("files", f));
        result = await api("/scans/upload", { method: "POST", body: data });
      } else {
        if (!name.trim()) throw new Error(`Enter ${ecosystem === "pypi" ? "a PyPI" : "an npm"} package name.`);
        result = await api("/scans/package", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: name.trim(),
            version: version.trim() || "latest",
            profile,
            ecosystem,
          }),
        });
      }
      onStart(result.id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSending(false);
    }
  }

  async function handleImportCli() {
    if (!cliFile || !cliConsent) return;
    setCliImporting(true);
    setError("");
    try {
      if (cliFile.size > 8 * 1024 * 1024)
        throw new Error("Reports must be at most 8 MB.");
      const reportData: unknown = JSON.parse(await cliFile.text());
      const imported = await api<Report>("/cli/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report: reportData, consent: true }),
      });
      setCliFile(null);
      setCliConsent(false);
      onImportReport?.(imported);
    } catch (problem) {
      setError(
        problem instanceof Error
          ? problem.message
          : "Could not import this report.",
      );
    } finally {
      setCliImporting(false);
    }
  }

  function chooseFiles(selected: File[]) {
    const totalSize = selected.reduce((n, f) => n + f.size, 0);
    if (totalSize > 10 * 1024 * 1024) {
      setError("Combined files exceed 10 MB limit.");
      return;
    }
    setFiles(selected);
    setError("");
  }

  return (
    <section className="card scan-launchpad-card" id="new-scan">
      <div className="launchpad-header">
        <h2 className="launchpad-title">Begin Investigation</h2>
      </div>

      {/* Mode Tabs */}
      <div className="launchpad-tabs" role="tablist" aria-label="Investigation source options">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "upload"}
          className={`launchpad-tab-btn ${tab === "upload" ? "active" : ""}`}
          onClick={() => setTab("upload")}
        >
          <UploadCloud size={16} />
          <span>Upload Project</span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={tab === "package"}
          className={`launchpad-tab-btn ${tab === "package" ? "active" : ""}`}
          onClick={() => setTab("package")}
        >
          <Package size={16} />
          <span>Look Up Package</span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={tab === "github"}
          className={`launchpad-tab-btn ${tab === "github" ? "active" : ""}`}
          onClick={() => setTab("github")}
        >
          <GitBranch size={16} />
          <span>GitHub Repository</span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={tab === "cli"}
          className={`launchpad-tab-btn ${tab === "cli" ? "active" : ""}`}
          onClick={() => setTab("cli")}
        >
          <FileCode2 size={16} />
          <span>Import CLI Report</span>
        </button>
      </div>

      {tab === "upload" ? (
        <div className="launchpad-upload-area">
          <MagneticDropZone
            accept=".zip,.json,.yaml,.yml,.lock,requirements.txt,pyproject.toml,poetry.lock"
            multiple
            maxSize={10 * 1024 * 1024}
            files={files}
            onFilesChange={chooseFiles}
            disabled={disabled}
            title="Drop project archive or browse files"
            subtitle="Supports project .ZIP, package.json, package-lock.json, pnpm-lock.yaml, or yarn.lock"
            className="mb-3 min-h-[220px]"
          />
          {onConnectFolder && (
            <div className="connect-folder-hint">
              <button
                type="button"
                className="text-link inline-folder-link"
                onClick={onConnectFolder}
              >
                <FolderOpen size={14} />
                <span>
                  Or connect local folder with Autopilot (supports direct code
                  fixes) →
                </span>
              </button>
            </div>
          )}
        </div>
      ) : tab === "package" ? (
        <div className="launchpad-package-area">
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px", flexWrap: "wrap" }}>
            <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.05em", textTransform: "uppercase", color: "var(--muted)" }}>
              Target Ecosystem:
            </span>
            <button
              type="button"
              className={`quick-pkg-chip ${ecosystem === "npm" ? "active" : ""}`}
              style={{
                cursor: "pointer",
                padding: "4px 12px",
                borderRadius: "14px",
                border: "1px solid " + (ecosystem === "npm" ? "var(--accent-border)" : "var(--line)"),
                background: ecosystem === "npm" ? "var(--accent)" : "var(--surface)",
                color: ecosystem === "npm" ? "var(--on-accent)" : "var(--text)",
                fontWeight: ecosystem === "npm" ? 600 : 400,
                fontSize: "12px",
              }}
              onClick={() => {
                setEcosystem("npm");
                setName("");
              }}
            >
              npm
            </button>
            <button
              type="button"
              className={`quick-pkg-chip ${ecosystem === "pypi" ? "active" : ""}`}
              style={{
                cursor: "pointer",
                padding: "4px 12px",
                borderRadius: "14px",
                border: "1px solid " + (ecosystem === "pypi" ? "var(--accent-border)" : "var(--line)"),
                background: ecosystem === "pypi" ? "var(--accent)" : "var(--surface)",
                color: ecosystem === "pypi" ? "var(--on-accent)" : "var(--text)",
                fontWeight: ecosystem === "pypi" ? 600 : 400,
                fontSize: "12px",
              }}
              onClick={() => {
                setEcosystem("pypi");
                setName("");
              }}
            >
              PyPI (Python)
            </button>
          </div>

          <div className="package-input-grid">
            <div className="package-name-field">
              <label htmlFor="pkg-name-input">
                Package Name
                <span className="label-sub">(from {ecosystem === "pypi" ? "PyPI" : "npm"} registry)</span>
              </label>
              <div className="input-with-icon">
                <Package size={17} className="input-prefix-icon" />
                <input
                  id="pkg-name-input"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={ecosystem === "pypi" ? "e.g. requests, urllib3, flask, django" : "e.g. express, lodash, @babel/core"}
                  disabled={disabled}
                />
              </div>
            </div>

            <div className="package-version-field">
              <label htmlFor="pkg-version-input">Version / Tag</label>
              <input
                id="pkg-version-input"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder="latest or 1.0.0"
                disabled={disabled}
              />
            </div>
          </div>

          <div className="quick-suggestions-row">
            <span className="suggestions-label">Try:</span>
            {(ecosystem === "pypi" ? ["requests", "urllib3", "flask", "django"] : ["express", "lodash", "axios", "cors"]).map((pkg) => (
              <button
                key={pkg}
                type="button"
                className="quick-pkg-chip"
                disabled={disabled}
                onClick={() => {
                  setName(pkg);
                  setVersion("latest");
                }}
              >
                {pkg}
              </button>
            ))}
          </div>

          <Note>
            Guardian fetches and extracts the official published distribution
            directly from {ecosystem === "pypi" ? "pypi.org / files.pythonhosted.org" : "registry.npmjs.org"} into bounded memory. No lifecycle or setup
            scripts are run.
          </Note>
        </div>
      ) : tab === "github" ? (
        <GitHubConnectPanel
          onStartScan={onStart}
          disabled={disabled}
          profile={profile}
          onProfileChange={setProfile}
        />
      ) : (
        /* tab === "cli" */
        <div className="launchpad-upload-area">
          <MagneticDropZone
            accept=".json,application/json"
            multiple={false}
            maxSize={8 * 1024 * 1024}
            files={cliFile ? [cliFile] : []}
            onFilesChange={(selected) => {
              setCliFile(selected[0] || null);
              setCliConsent(false);
              setError("");
            }}
            disabled={cliImporting || disabled}
            title="Drop Guardian CLI JSON report or browse"
            subtitle="Exported with 'guardian report --output report.json' (up to 8 MB)"
            className="mb-3 min-h-[200px]"
          />
          <label
            className="cli-import-consent"
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "8px",
              fontSize: "12.5px",
              color: "var(--text-secondary)",
              cursor: "pointer",
              margin: "8px 0 16px",
            }}
          >
            <input
              type="checkbox"
              checked={cliConsent}
              onChange={(e) => setCliConsent(e.target.checked)}
              disabled={cliImporting || disabled}
              style={{ marginTop: "3px", accentColor: "var(--accent)" }}
            />
            <span>I consent to saving this report and its evidence in this local website.</span>
          </label>
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button
              type="button"
              className="btn-primary-large"
              disabled={!cliFile || !cliConsent || cliImporting || disabled}
              onClick={handleImportCli}
            >
              {cliImporting ? (
                <>
                  <Loader2 size={16} className="spin" />
                  <span>Importing report…</span>
                </>
              ) : (
                <>
                  <span>Import and view report</span>
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {error && (
        <div role="alert" className="launchpad-error">
          <span>{error}</span>
        </div>
      )}

      {/* Progress or Submit Action */}
      {busy && job ? (
        <div className="scan-active-progress" aria-live="polite">
          <div className="progress-top-row">
            <div className="progress-status-indicator">
              <Loader2 size={16} className="spin text-accent" />
              <strong>{job.stage}</strong>
            </div>
            <button
              type="button"
              className="cancel-scan-btn"
              disabled={cancelling || job.status === "cancelling"}
              onClick={async () => {
                setCancelling(true);
                try {
                  await api(`/jobs/${job.id}/cancel`, { method: "POST" });
                } catch (e) {
                  setError((e as Error).message);
                  setCancelling(false);
                }
              }}
            >
              {cancelling || job.status === "cancelling"
                ? "Cancelling…"
                : "Cancel scan"}
            </button>
          </div>

          <div className="progress-bar-track">
            <motion.div
              className="progress-bar-fill"
              initial={{ width: "10%" }}
              animate={{ width: "95%" }}
              transition={{ duration: 12, ease: "linear" }}
            />
          </div>

          <div className="stages-timeline">
            {[
              "Inspecting input",
              "Analyzing source & dependencies",
              "Inspecting dependency sources",
              "Checking vulnerability intelligence",
              "Building evidence-backed report",
            ].map((s, i) => {
              const stagesOrder = [
                "Queued",
                "Inspecting input",
                "Analyzing source & dependencies",
                "Inspecting dependency sources",
                "Checking vulnerability intelligence",
                "Building evidence-backed report",
              ];
              const activeIndex = stagesOrder.indexOf(job.stage);
              const isPast = i < activeIndex;
              const isCurrent = i === activeIndex - 1;

              return (
                <div
                  key={s}
                  className={`stage-step ${isPast ? "done" : ""} ${isCurrent ? "active" : ""}`}
                >
                  <span className="step-circle">
                    {isPast ? <Check size={11} /> : i + 1}
                  </span>
                  <span className="step-label">
                    {
                      [
                        "Ingest",
                        "Syntax AST",
                        "Dependencies",
                        "OSV Intel",
                        "Report",
                      ][i]
                    }
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      ) : tab !== "github" && tab !== "cli" ? (
        <div className="launchpad-footer">
          <label
            className="deeper-analysis-toggle"
            title="Toggle deep dependency analysis (up to 20 packages / 4 levels)"
          >
            <input
              type="checkbox"
              checked={profile === "deep"}
              onChange={(e) => setProfile(e.target.checked ? "deep" : "fast")}
              disabled={disabled}
            />
            <span className="toggle-switch">
              <span className="toggle-thumb" />
            </span>
            <span className="toggle-label">Deeper analysis</span>
          </label>

          <button
            type="button"
            disabled={disabled}
            className="btn-primary-large"
            onClick={submit}
          >
            {sending ? (
              <Loader2 size={17} className="spin" />
            ) : (
              <>
                <span>Analyze {tab === "upload" ? "project" : "package"}</span>
                <ArrowRight size={16} />
              </>
            )}
          </button>
        </div>
      ) : null}
    </section>
  );
}
