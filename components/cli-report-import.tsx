"use client";

import { useState } from "react";
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
    <details className="card" style={{ padding: "1.25rem", marginTop: "1rem" }}>
      <summary style={{ cursor: "pointer", fontWeight: 600 }}>
        Open a Guardian CLI report
      </summary>
      <p style={{ margin: "0.75rem 0", color: "var(--text-secondary)" }}>
        Export JSON with <code>guardian report --output report.json</code>, then
        choose it here. This saves report evidence in this local website. Source
        archives are never uploaded. Imported results are labeled and are not
        reverified scans. Account sync is unavailable.
      </p>
      <input
        aria-label="Guardian CLI JSON report"
        type="file"
        accept=".json,application/json"
        disabled={busy}
        onChange={(event) => {
          setFile(event.target.files?.[0] || null);
          setConsent(false);
          setError("");
        }}
      />
      <label
        style={{
          display: "flex",
          gap: "0.5rem",
          margin: "1rem 0",
          alignItems: "start",
        }}
      >
        <input
          type="checkbox"
          checked={consent}
          onChange={(event) => setConsent(event.target.checked)}
          disabled={busy}
        />
        I consent to saving this report and its evidence in this local website.
      </label>
      <button
        className="btn-secondary"
        type="button"
        disabled={!file || !consent || busy}
        onClick={importReport}
      >
        {busy ? "Importing…" : "Import report"}
      </button>
      {error && (
        <p role="alert" style={{ marginTop: "0.75rem" }}>
          {error}
        </p>
      )}
    </details>
  );
}
