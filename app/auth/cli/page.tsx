"use client";

import { useEffect, useState } from "react";

export default function CLIAuthPage() {
  const [request, setRequest] = useState<{
    device_name: string;
    operating_system: string;
    authorize_url: string;
  } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const identifier =
      new URL(window.location.href).searchParams.get("request_id") || "";
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(identifier)) {
      setError("Start this connection with guardian login in your terminal.");
      return;
    }
    const controller = new AbortController();
    fetch(`/api/account/cli/requests/${identifier}`, {
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok)
          throw new Error(
            "This connection request expired. Run guardian login again.",
          );
        return response.json();
      })
      .then(setRequest)
      .catch((problem) => {
        if (!controller.signal.aborted)
          setError(problem.message || "Connection unavailable.");
      });
    return () => controller.abort();
  }, []);
  return (
    <main className="account-shell account-connect">
      <a href="/account" className="account-brand">
        Guardian / Account
      </a>
      <section className="account-card">
        <p className="account-eyebrow">CONNECT YOUR TERMINAL</p>
        <h1>Authorize Guardian CLI</h1>
        <p>
          Connect this device to the same Guardian account you use on the
          website. Reports stay local until you explicitly synchronize them.
        </p>
        {error ? (
          <p role="alert" className="account-error">
            {error}
          </p>
        ) : request ? (
          <>
            <dl>
              <dt>Device</dt>
              <dd>{request.device_name}</dd>
              <dt>Operating system</dt>
              <dd>{request.operating_system}</dd>
            </dl>
            <p>
              Continue only if you just ran <code>guardian login</code> on this
              device. GitHub will confirm your identity through Supabase.
            </p>
            <a className="btn-primary" href={request.authorize_url}>
              Continue with GitHub
            </a>
          </>
        ) : (
          <p role="status">Loading the connection request…</p>
        )}
        <p className="account-muted">
          This account connection does not grant GitHub repository permissions
          or install the DevGuardian GitHub App.
        </p>
      </section>
    </main>
  );
}
