"use client";

import { useRef, useState } from "react";
import {
  UploadCloud,
  ArrowRight,
  Package,
  FileArchive,
  Loader2,
  Check,
  ShieldCheck,
  FolderOpen,
  X,
  FileCode2,
  Sliders,
  Sparkles,
  GitBranch,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { api, ScanJob } from "@/lib/types";
import { Note, Eyebrow } from "./ui";
import GitHubConnectPanel from "./github-connect-panel";

export type { ScanJob };

export default function ScanPanel({
  onStart,
  busy,
  job,
  onConnectFolder,
}: {
  onStart: (id: string) => void;
  busy: boolean;
  job: ScanJob | null;
  onConnectFolder?: () => void;
}) {
  const [tab, setTab] = useState<"upload" | "package" | "github">("upload");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("latest");
  const [profile, setProfile] = useState<"fast" | "deep">("fast");
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [drag, setDrag] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const disabled = busy || sending;

  async function submit() {
    setError("");
    setSending(true);
    try {
      let result: { id: string };
      if (tab === "upload") {
        if (!files.length) {
          throw new Error(
            "Choose a project ZIP or npm manifest (package.json / package-lock.json) to inspect.",
          );
        }
        const data = new FormData();
        data.append("profile", profile);
        files.forEach((f) => data.append("files", f));
        result = await api("/scans/upload", { method: "POST", body: data });
      } else {
        if (!name.trim()) throw new Error("Enter an npm package name.");
        result = await api("/scans/package", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: name.trim(),
            version: version.trim() || "latest",
            profile,
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

  function chooseFiles(selected: File[]) {
    const totalSize = selected.reduce((n, f) => n + f.size, 0);
    if (totalSize > 10 * 1024 * 1024) {
      setError("Combined files exceed 10 MB limit.");
      return;
    }
    setFiles(selected);
    setError("");
  }

  function removeFile(index: number) {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  }

  return (
    <section className="card scan-launchpad-card" id="new-scan">
      <div className="launchpad-header">
        <div>
          <Eyebrow>SECURITY LAUNCHPAD</Eyebrow>
          <h2 className="launchpad-title">Inspect before you trust.</h2>
          <p className="launchpad-subtitle">
            Static inspection of manifests, tarballs, and source code. Zero code
            execution.
          </p>
        </div>
        <span className="launchpad-tag">NPM ECOSYSTEM</span>
      </div>

      {/* Mode Tabs */}
      <div className="launchpad-tabs" role="tablist">
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
      </div>

      {tab === "upload" ? (
        <div className="launchpad-upload-area">
          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept=".zip,.json"
            aria-label="Upload project files"
            className="visually-hidden"
            onChange={(e) => chooseFiles(Array.from(e.target.files || []))}
          />

          <div
            className={`dropzone-box ${drag ? "dragging" : ""} ${files.length > 0 ? "has-files" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDrag(true);
            }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDrag(false);
              if (!disabled) chooseFiles(Array.from(e.dataTransfer.files));
            }}
            onClick={() => {
              if (!files.length) fileInputRef.current?.click();
            }}
          >
            {files.length === 0 ? (
              <div className="dropzone-empty">
                <motion.div
                  className="dropzone-icon-wrap"
                  whileHover={{ scale: 1.08 }}
                  transition={{ type: "spring", stiffness: 300, damping: 15 }}
                >
                  <UploadCloud size={28} />
                </motion.div>
                <strong>Drop project archive or browse files</strong>
                <span>
                  Supports project .ZIP, package.json, or package-lock.json
                </span>
                <small>
                  Bounded local memory inspection · Up to 10 MB · Code is never
                  executed
                </small>
              </div>
            ) : (
              <div className="dropzone-selected-files">
                <div className="selected-files-header">
                  <span>Selected files ({files.length}):</span>
                  <button
                    type="button"
                    className="add-more-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      fileInputRef.current?.click();
                    }}
                  >
                    Change files
                  </button>
                </div>
                <div className="selected-files-list">
                  {files.map((file, i) => (
                    <div key={i} className="selected-file-chip">
                      <FileArchive size={15} />
                      <span className="file-chip-name">{file.name}</span>
                      <span className="file-chip-size">
                        {(file.size / 1024).toFixed(1)} KB
                      </span>
                      <button
                        type="button"
                        className="file-remove-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          removeFile(i);
                        }}
                        aria-label={`Remove ${file.name}`}
                      >
                        <X size={13} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

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
          <div className="package-input-grid">
            <div className="package-name-field">
              <label htmlFor="pkg-name-input">
                Package Name
                <span className="label-sub">(from npm registry)</span>
              </label>
              <div className="input-with-icon">
                <Package size={17} />
                <input
                  id="pkg-name-input"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. express, lodash, @babel/core"
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
            {["express", "lodash", "axios", "cors"].map((pkg) => (
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
            Guardian fetches and extracts the official published tarball
            directly from registry.npmjs.org into bounded memory. No lifecycle
            scripts are run.
          </Note>
        </div>
      ) : (
        <GitHubConnectPanel
          onStartScan={onStart}
          disabled={disabled}
          profile={profile}
          onProfileChange={setProfile}
        />
      )}

      {/* Budget Selector (for Upload and Package tabs) */}
      {tab !== "github" && (
        <div className="budget-selection-bar">
          <div className="budget-label-row">
            <label htmlFor="budget-select" className="budget-label">
              <Sliders size={14} />
              <span>Dependency Inspection Depth</span>
            </label>
            <select
              id="budget-select"
              value={profile}
              onChange={(e) => setProfile(e.target.value as "fast" | "deep")}
              disabled={disabled}
              className="budget-select"
            >
              <option value="fast">Fast · Up to 6 packages / 2 levels</option>
              <option value="deep">Deep · Up to 20 packages / 4 levels</option>
            </select>
          </div>
          <small className="budget-hint">
            Inspects resolved exact dependencies under recursive bounded depth.
            Limits are transparently reported in coverage.
          </small>
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
      ) : (
        <div className="launchpad-footer">
          <div className="guarantee-text">
            <ShieldCheck size={16} className="guarantee-icon" />
            <span>
              Deterministic static inspection · Evidence before assumptions
            </span>
          </div>

          {tab !== "github" && (
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
          )}
        </div>
      )}
    </section>
  );
}
