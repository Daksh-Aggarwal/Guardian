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
} from "lucide-react";
import { api, ScanJob } from "@/lib/types";
import { Note } from "./ui";
export type { ScanJob };
export default function ScanPanel({
  onStart,
  busy,
  job,
}: {
  onStart: (id: string) => void;
  busy: boolean;
  job: ScanJob | null;
}) {
  const [tab, setTab] = useState<"upload" | "package">("upload"),
    [name, setName] = useState(""),
    [version, setVersion] = useState("latest"),
    [profile, setProfile] = useState("fast"),
    [files, setFiles] = useState<File[]>([]),
    [error, setError] = useState(""),
    [sending, setSending] = useState(false),
    [cancelling, setCancelling] = useState(false),
    [drag, setDrag] = useState(false);
  const ref = useRef<HTMLInputElement>(null);
  const disabled = busy || sending;
  async function submit() {
    setError("");
    setSending(true);
    try {
      let result: { id: string };
      if (tab === "upload") {
        if (!files.length)
          throw new Error("Choose a ZIP or npm manifest to inspect.");
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
  function choose(selected: File[]) {
    if (selected.reduce((n, f) => n + f.size, 0) > 10 * 1024 * 1024) {
      setError("Choose files totaling 10 MB or less.");
      return;
    }
    setFiles(selected);
    setError("");
  }
  return (
    <section className="card scan-card" id="new-scan">
      <div className="section-heading">
        <div>
          <h2>Start with a second opinion.</h2>
          <p>Understand what’s inside before you install.</p>
        </div>
        <span className="small-label">NPM ECOSYSTEM</span>
      </div>
      <div className="tabs">
        <button
          className={tab === "upload" ? "active" : ""}
          onClick={() => setTab("upload")}
        >
          <UploadCloud size={16} />
          Upload a project
        </button>
        <button
          className={tab === "package" ? "active" : ""}
          onClick={() => setTab("package")}
        >
          <Package size={16} />
          Look up a package
        </button>
      </div>
      {tab === "upload" ? (
        <>
          <input
            ref={ref}
            type="file"
            multiple
            accept=".zip,.json"
            aria-label="Project files"
            className="visually-hidden"
            onChange={(e) => choose(Array.from(e.target.files || []))}
          />
          <button
            disabled={disabled}
            className={`dropzone ${drag ? "dragging" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDrag(true);
            }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDrag(false);
              if (!disabled) choose(Array.from(e.dataTransfer.files));
            }}
            onClick={() => ref.current?.click()}
          >
            <span className="upload-icon">
              {files.length ? (
                <FileArchive size={25} />
              ) : (
                <UploadCloud size={25} />
              )}
            </span>
            <strong>
              {files.length
                ? files.map((f) => f.name).join(" + ")
                : "Drop your project here, or browse files"}
            </strong>
            <span>Project ZIP, package.json, or package-lock.json</span>
            <small>Up to 10 MB · No code is executed</small>
          </button>
        </>
      ) : (
        <div className="package-input">
          <label>
            Package name
            <div className="input-icon">
              <Package size={18} />
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. express or @scope/package"
                disabled={disabled}
              />
            </div>
          </label>
          <label>
            Version or tag
            <input
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="latest"
              disabled={disabled}
            />
          </label>
          <Note>
            Inspects the published tarball from the npm registry. No
            installation required.
          </Note>
        </div>
      )}
      <div className="budget-choice">
        <label>
          Dependency inspection
          <select
            aria-label="Dependency inspection budget"
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            disabled={disabled}
          >
            <option value="fast">Fast · up to 6 packages / 2 levels</option>
            <option value="deep">Deeper · up to 20 packages / 4 levels</option>
          </select>
        </label>
        <small>
          Uses exact lockfile versions. Limits and incomplete coverage are
          reported. Operator settings may override these defaults.
        </small>
      </div>
      {error && (
        <div role="alert" className="error">
          {error}
        </div>
      )}
      {busy && job ? (
        <div className="scan-progress" aria-live="polite">
          <div>
            <Loader2 size={17} className="spin" />
            <strong>{job.stage}</strong>
          </div>
          <button
            className="text-link"
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
          <div className="progress-track">
            <span />
          </div>
          <div className="stage-list">
            {[
              "Inspecting input",
              "Analyzing source & dependencies",
              "Inspecting dependency sources",
              "Checking vulnerability intelligence",
              "Building evidence-backed report",
            ].map((s, i) => {
              const active = [
                "Queued",
                "Inspecting input",
                "Analyzing source & dependencies",
                "Inspecting dependency sources",
                "Checking vulnerability intelligence",
                "Building evidence-backed report",
              ].indexOf(job.stage);
              return (
                <span className={i < active ? "done" : ""} key={s}>
                  {i < active - 1 ? <Check size={12} /> : <i />}
                  {
                    [
                      "Ingest",
                      "Analyze",
                      "Dependencies",
                      "Intelligence",
                      "Report",
                    ][i]
                  }
                </span>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="scan-footer">
          <span>
            <ShieldCheck size={15} />
            Private analysis. Clear evidence.
          </span>
          <button
            disabled={disabled}
            className="button primary"
            onClick={submit}
          >
            {sending ? (
              <Loader2 size={16} className="spin" />
            ) : (
              <>
                Analyze {tab === "upload" ? "project" : "package"}
                <ArrowRight size={16} />
              </>
            )}
          </button>
        </div>
      )}
    </section>
  );
}
