"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useAccount } from "./account-provider";
import { accountRequest } from "@/lib/account-request";
import { getSupabase } from "@/lib/supabase";
import type { Report } from "@/lib/types";
import ReportView from "./report";

type Device = {
  id: string;
  device_name: string;
  operating_system: string;
  cli_version: string;
  last_seen_at: string;
  revoked_at: string | null;
};
type Scan = {
  id: string;
  project_name: string;
  ecosystem: string;
  decision: string;
  scanned_at: string;
  severity_summary: Record<string, number>;
  device_name: string;
};
type Overview = {
  total_scans: number;
  connected_devices: number;
  decisions: Record<string, number>;
};

export default function AccountDashboard() {
  const {
    session,
    loading,
    configured,
    error: authError,
    signIn,
    signOut,
  } = useAccount();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const identity = useRef<string | undefined>(undefined);
  identity.current = session?.user.id;
  const request = useCallback(
    <T,>(path: string, options?: RequestInit) =>
      accountRequest<T>(getSupabase()?.auth || null, path, options),
    [],
  );
  const refresh = useCallback(async () => {
    const owner = identity.current;
    if (!owner) return;
    setBusy(true);
    setError("");
    try {
      const [nextOverview, nextScans, nextDevices] = await Promise.all([
        request<Overview>("/overview"),
        request<Scan[]>("/scans"),
        request<Device[]>("/devices"),
      ]);
      if (identity.current !== owner) return;
      setOverview(nextOverview);
      setScans(nextScans);
      setDevices(nextDevices);
    } catch (problem) {
      if (identity.current === owner)
        setError(
          problem instanceof Error
            ? problem.message
            : "Account data unavailable.",
        );
    } finally {
      if (identity.current === owner) setBusy(false);
    }
  }, [request]);
  useEffect(() => {
    setOverview(null);
    setScans([]);
    setDevices([]);
    setReport(null);
    setError("");
    if (session?.user.id) void refresh();
  }, [session?.user.id, refresh]);
  useEffect(() => {
    const theme = localStorage.getItem("guardian-theme") || "dark";
    document.documentElement.dataset.theme = theme;
  }, []);
  async function openReport(id: string) {
    const owner = identity.current;
    setError("");
    try {
      const next = await request<Report>(`/scans/${encodeURIComponent(id)}`);
      if (identity.current === owner) setReport(next);
    } catch (problem) {
      if (identity.current === owner)
        setError(
          problem instanceof Error ? problem.message : "Report unavailable.",
        );
    }
  }
  async function revoke(id: string) {
    if (
      !window.confirm(
        "Revoke this device? It will need a new guardian login before it can synchronize again.",
      )
    )
      return;
    setError("");
    try {
      await request(`/devices/${encodeURIComponent(id)}/revoke`, {
        method: "POST",
      });
      await refresh();
    } catch (problem) {
      setError(
        problem instanceof Error
          ? problem.message
          : "Device could not be revoked.",
      );
    }
  }

  return (
    <main className="account-shell">
      <header className="account-header">
        <a href="/" className="account-brand">
          Guardian <span>/ Account</span>
        </a>
        <div className="account-actions">
          {session && (
            <>
              <span>
                {session.user.user_metadata?.user_name ||
                  session.user.email ||
                  "Signed in"}
              </span>
              <button className="btn-secondary" onClick={() => void signOut()}>
                Sign out
              </button>
            </>
          )}
          {process.env.NEXT_PUBLIC_GUARDIAN_CLOUD_MODE !== "true" && (
            <a href="/" className="btn-secondary">
              Scanner
            </a>
          )}
        </div>
      </header>
      {(error || authError) && (
        <div className="account-error" role="alert">
          {error || authError}
        </div>
      )}
      {loading ? (
        <p role="status">Restoring your account session…</p>
      ) : !session ? (
        <section className="account-card account-welcome">
          <p className="account-eyebrow">LOCAL ANALYSIS. YOUR ACCOUNT.</p>
          <h1>Your scans, together.</h1>
          <p>
            Connect the Guardian CLI, keep package analysis on your computer,
            and bring the reports you choose into one account.
          </p>
          <button
            className="btn-primary"
            onClick={() => void signIn()}
            disabled={!configured}
          >
            Sign in with GitHub
          </button>
          {!configured && (
            <p className="account-muted">
              Account login is not configured. Add the public Supabase settings
              to .env and restart the frontend. Local scanning remains
              available.
            </p>
          )}
          <p className="account-muted">
            Account sign-in is separate from installing the Guardian GitHub App.
            It grants no repository access.
          </p>
        </section>
      ) : report ? (
        <section className="account-report">
          <p className="account-muted">
            Synchronized local evidence · source snippets withheld · no cloud
            rescan. Use local Guardian for source investigation and remediation.
          </p>
          <ReportView
            report={report}
            onBack={() => setReport(null)}
            cloudMode
            handoffRequest={request}
          />
        </section>
      ) : (
        <>
          <section className="account-intro">
            <div>
              <p className="account-eyebrow">ACCOUNT OVERVIEW</p>
              <h1>Security history, connected.</h1>
              <p className="account-muted">
                Reports you explicitly synchronized from your devices. Local
                scans never upload automatically.
              </p>
            </div>
            <button
              className="btn-secondary"
              disabled={busy}
              onClick={() => void refresh()}
            >
              {busy ? "Refreshing…" : "Refresh"}
            </button>
          </section>
          <section
            className="account-metrics"
            aria-label="Account scan metrics"
          >
            <article className="account-card">
              <span>Total scans</span>
              <strong>{overview?.total_scans ?? "—"}</strong>
            </article>
            {["ALLOW", "WARN", "BLOCK", "REVIEW"].map((decision) => (
              <article className="account-card" key={decision}>
                <span>{decision}</span>
                <strong>{overview ? overview.decisions[decision] : "—"}</strong>
              </article>
            ))}
            <article className="account-card">
              <span>Authorized devices</span>
              <strong>{overview?.connected_devices ?? "—"}</strong>
            </article>
          </section>
          <section className="account-card">
            <div className="account-section-title">
              <h2>Recent scans</h2>
              <span className="account-muted">Latest 100</span>
            </div>
            {!scans.length ? (
              <div className="account-empty">
                <h3>No scans yet.</h3>
                <p>
                  Run <code>guardian login</code>, then{" "}
                  <code>guardian check --ecosystem npm lodash@4.17.21</code> and{" "}
                  <code>guardian report --sync</code> to see your first scan
                  here.
                </p>
                <p>
                  A REVIEW decision is preserved when coverage is incomplete.
                </p>
              </div>
            ) : (
              <div className="account-table-wrap">
                <table className="account-table">
                  <thead>
                    <tr>
                      <th>Project / package</th>
                      <th>Decision</th>
                      <th>Severity</th>
                      <th>Device</th>
                      <th>Scanned</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((scan) => (
                      <tr key={scan.id}>
                        <td>
                          <button
                            className="account-report-link"
                            onClick={() => void openReport(scan.id)}
                          >
                            {scan.project_name}
                          </button>
                          <small>{scan.ecosystem}</small>
                        </td>
                        <td>
                          <span
                            className={`account-decision decision-${scan.decision.toLowerCase()}`}
                          >
                            {scan.decision}
                          </span>
                        </td>
                        <td>
                          {Object.entries(scan.severity_summary)
                            .map(([severity, count]) => `${count} ${severity}`)
                            .join(" · ")}
                        </td>
                        <td>{scan.device_name}</td>
                        <td>{new Date(scan.scanned_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <section className="account-card">
            <div className="account-section-title">
              <h2>Devices</h2>
              <code>guardian devices</code>
            </div>
            {!devices.length ? (
              <div className="account-empty">
                <h3>Connect your first terminal.</h3>
                <p>
                  Run <code>guardian login</code> to register a device. Your
                  operating system credential manager keeps its session private.
                </p>
              </div>
            ) : (
              <ul className="account-devices">
                {devices.map((device) => (
                  <li key={device.id}>
                    <div>
                      <strong>{device.device_name}</strong>
                      <p>
                        {device.operating_system} · CLI {device.cli_version}
                      </p>
                      <small>
                        Last seen{" "}
                        {new Date(device.last_seen_at).toLocaleString()}
                      </small>
                    </div>
                    <div className="account-actions">
                      <span>
                        {device.revoked_at ? "Revoked" : "Authorized"}
                      </span>
                      {!device.revoked_at && (
                        <button
                          className="btn-secondary"
                          onClick={() => void revoke(device.id)}
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </main>
  );
}
