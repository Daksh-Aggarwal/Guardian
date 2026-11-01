"use client";

import { useState } from "react";
import { FileCode2, ChevronRight, Loader2 } from "lucide-react";
import { api, Report } from "@/lib/types";

export default function CliReportImport({
  onImport,
}: {
  onImport: (report: Report) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function importReport() {
    if (!file || !consent) return;
    setBusy(true);
    setError("");
    try {
      if (file.size > 8 * 1024 * 1024)
        throw new Error("Reports must be at most 8 MB.");
      const report: unknown = JSON.parse(await file.text());
      const imported = await api<Report>("/cli/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report, consent: true }),
      });
      setFile(null);
      setConsent(false);
      onImport(imported);
    } catch (problem) {
      setError(
        problem instanceof Error
          ? problem.message
          : "Could not import this report.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="cli-import-card">
      <summary className="cli-import-summary">
        <FileCode2 size={16} style={{ color: "var(--accent)" }} />
        <span>Open a Guardian CLI report</span>
        <ChevronRight size={14} className="cli-import-chevron" />
      </summary>
      <div className="cli-import-content">
        <p className="cli-import-desc">
          Export JSON with <code>guardian report --output report.json</code>,
          then choose it here. This saves report evidence in this local website.
          Source archives are never uploaded. Imported results are labeled and
          are not reverified scans. Account sync is unavailable.
        </p>
        <div className="cli-import-file-row">
          <input
            id="cli-file-input"
            aria-label="Guardian CLI JSON report file input"
            type="file"
            accept=".json,application/json"
            disabled={busy}
            onChange={(event) => {
              setFile(event.target.files?.[0] || null);
              setConsent(false);
              setError("");
            }}
          />
        </div>
        <label className="cli-import-consent">
          <input
            type="checkbox"
            checked={consent}
            onChange={(event) => setConsent(event.target.checked)}
            disabled={busy}
            aria-label="Consent to save report locally"
          />
          <span>
            I consent to saving this report and its evidence in this local
            website.
          </span>
        </label>
        <div>
          <button
            className="button primary"
            type="button"
            disabled={!file || !consent || busy}
            onClick={importReport}
          >
            {busy ? (
              <>
                <Loader2 size={14} className="animate-spin inline mr-1" />
                <span>Importing…</span>
              </>
            ) : (
              <span>Import report</span>
            )}
          </button>
        </div>
        {error && (
          <p role="alert" className="cli-import-error">
            {error}
          </p>
        )}
      </div>
    </details>
  );
}
