"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Globe,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import {
  GitBranch,
  Search,
  Lock,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  ArrowRight,
  Sliders,
  Sparkles,
  RefreshCw,
  LogOut,
  FolderGit2,
} from "@/components/icons";
import { motion, AnimatePresence } from "framer-motion";
import {
  api,
  initSession,
  GitHubStatus,
  GitHubInstallation,
  GitHubRepository,
  GitHubBranch,
} from "@/lib/types";
import { Eyebrow, Badge } from "./ui";

export default function GitHubConnectPanel({
  onStartScan,
  disabled = false,
  profile,
  onProfileChange,
}: {
  onStartScan: (jobId: string) => void;
  disabled?: boolean;
  profile: "fast" | "deep";
  onProfileChange: (p: "fast" | "deep") => void;
}) {
  const [sessionReady, setSessionReady] = useState(false);
  const [status, setStatus] = useState<GitHubStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [repos, setRepos] = useState<GitHubRepository[]>([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [search, setSearch] = useState("");
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepository | null>(null);
  const [branches, setBranches] = useState<GitHubBranch[]>([]);
  const [loadingBranches, setLoadingBranches] = useState(false);
  const [selectedBranch, setSelectedBranch] = useState<string>("");
  const [activeCommitSha, setActiveCommitSha] = useState<string | null>(null);
  const [startingScan, setStartingScan] = useState(false);
  const [linkingId, setLinkingId] = useState<number | null>(null);

  // Fetch connection status
  const fetchStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api<GitHubStatus>("/github/status");
      setStatus(res);
      if (res.connected) {
        fetchRepos();
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleLinkInstallation = async (instId: number) => {
    setLinkingId(instId);
    setError(null);
    try {
      await api(`/github/installations/${instId}/link`, { method: "POST" });
      setSelectedRepo(null);
      setRepos([]);
      setBranches([]);
      setSelectedBranch("");
      setActiveCommitSha(null);
      await fetchStatus();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLinkingId(null);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    setError(null);
    try {
      const res = await api<GitHubStatus>("/github/sync", { method: "POST" });
      setStatus(res);
      if (res.connected) {
        fetchRepos();
      } else if (!res.available_installations || res.available_installations.length === 0) {
        setError(res.reason || "No GitHub App installation found on your GitHub account. Ensure the app is installed at GitHub.");
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSyncing(false);
    }
  };

  useEffect(() => {
    let active = true;
    async function init() {
      await initSession();
      if (!active) return;
      setSessionReady(true);
      await fetchStatus();
    }
    init();
    return () => {
      active = false;
    };
  }, []);

  // Fetch repositories
  const fetchRepos = async (query?: string) => {
    setLoadingRepos(true);
    try {
      const url = query ? `/github/repositories?q=${encodeURIComponent(query)}` : "/github/repositories";
      const list = await api<GitHubRepository[]>(url);
      setRepos(list);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingRepos(false);
    }
  };

  // When a repository is selected, load its branches
  useEffect(() => {
    if (!selectedRepo) {
      setBranches([]);
      setSelectedBranch("");
      setActiveCommitSha(null);
      return;
    }

    let cancelled = false;
    setLoadingBranches(true);
    api<GitHubBranch[]>(`/github/repositories/${selectedRepo.id}/branches`)
      .then((bList) => {
        if (cancelled) return;
        setBranches(bList);
        const def = bList.find((b) => b.is_default) || bList[0];
        if (def) {
          setSelectedBranch(def.name);
          setActiveCommitSha(def.commit_sha);
        }
      })
      .catch((err) => {
        if (!cancelled) setError((err as Error).message);
      })
      .finally(() => {
        if (!cancelled) setLoadingBranches(false);
      });

    return () => {
      cancelled = true;
    };
  }, [selectedRepo]);

  // Connect GitHub App
  const handleConnect = async () => {
    setError(null);
    try {
      const flow = await api<{ install_url: string; state: string }>("/github/connect", {
        method: "POST",
      });
      window.location.href = flow.install_url;
    } catch (err) {
      setError((err as Error).message);
    }
  };

  // Explicit installation selection
  const handleSelectInstallation = async (instId: number) => {
    setLoading(true);
    setError(null);
    try {
      await api<GitHubInstallation>(`/github/installations/${instId}/select`, { method: "POST" });
      setSelectedRepo(null);
      setRepos([]);
      setBranches([]);
      setSelectedBranch("");
      setActiveCommitSha(null);
      await fetchStatus();
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
    }
  };

  // Disconnect GitHub
  const handleDisconnect = async (instId?: number) => {
    setError(null);
    try {
      const targetId = instId || status?.installation?.id;
      if (targetId) {
        await api(`/github/installations/${targetId}/disconnect`, { method: "POST" });
      } else {
        await api("/github/disconnect", { method: "POST" });
      }
      setSelectedRepo(null);
      setRepos([]);
      setBranches([]);
      setSelectedBranch("");
      setActiveCommitSha(null);
      await fetchStatus();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  // Filter repos by search
  const filteredRepos = useMemo(() => {
    if (!search.trim()) return repos;
    const term = search.toLowerCase();
    return repos.filter(
      (r) => r.name.toLowerCase().includes(term) || r.full_name.toLowerCase().includes(term)
    );
  }, [repos, search]);

  // Start GitHub Scan
  const handleStartScan = async () => {
    if (!selectedRepo) return;
    setStartingScan(true);
    setError(null);
    try {
      const result = await api<{ id: string }>("/scans/github", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repository_id: selectedRepo.id,
          branch: selectedBranch || undefined,
          profile,
        }),
      });
      onStartScan(result.id);
    } catch (err) {
      setError((err as Error).message);
      setStartingScan(false);
    }
  };

  if (!sessionReady || loading) {
    return (
      <div style={{ padding: "40px", textAlign: "center", color: "var(--muted)" }}>
        <Loader2 size={20} className="animate-spin" style={{ margin: "0 auto 8px" }} />
        <p style={{ fontSize: "13px" }}>Checking GitHub connection status...</p>
      </div>
    );
  }

  // Not configured on server
  if (status && !status.configured) {
    return (
      <div
        className="card"
        style={{
          padding: "24px",
          background: "var(--surface-muted)",
          border: "1px dashed var(--line)",
          borderRadius: "8px",
        }}
      >
        <div style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
          <FolderGit2 size={24} style={{ color: "var(--accent)", marginTop: "2px" }} />
          <div>
            <h3 style={{ margin: "0 0 6px", fontSize: "15px", fontWeight: 600 }}>
              GitHub App Configuration Required
            </h3>
            <p style={{ margin: "0 0 12px", fontSize: "13px", color: "var(--muted)", lineHeight: 1.5 }}>
              To connect Guardian to GitHub, configure your GitHub App credentials in the server environment (.env).
            </p>
            <div
              style={{
                background: "rgba(0,0,0,0.25)",
                padding: "10px 14px",
                borderRadius: "6px",
                fontFamily: "monospace",
                fontSize: "12px",
                color: "var(--text)",
                lineHeight: 1.6,
                marginBottom: "12px",
              }}
            >
              GITHUB_APP_ID=your_app_id<br />
              GITHUB_APP_CLIENT_ID=your_client_id<br />
              GITHUB_APP_CLIENT_SECRET=your_client_secret<br />
              GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..."
            </div>
            <p style={{ margin: 0, fontSize: "12px", color: "var(--muted)" }}>
              Permissions required: <code>Contents (read & write)</code>, <code>Pull Requests (read & write)</code>, <code>Metadata (read)</code>.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Configured but Not Connected
  if (status && !status.connected) {
    return (
      <div
        className="card"
        style={{
          padding: "32px 24px",
          textAlign: "center",
          background: "var(--surface-muted)",
          borderRadius: "8px",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: "14px",
        }}
      >
        <div
          style={{
            width: "48px",
            height: "48px",
            borderRadius: "50%",
            background: "rgba(99, 102, 241, 0.15)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--accent)",
          }}
        >
          <GitBranch size={24} />
        </div>
        <div>
          <h3 style={{ margin: "0 0 6px", fontSize: "16px", fontWeight: 600 }}>
            Connect Your GitHub Account
          </h3>
          <p style={{ margin: "0 auto", maxWidth: "440px", fontSize: "13px", color: "var(--muted)", lineHeight: 1.5 }}>
            Authorize the Guardian GitHub App to discover accessible repositories, inspect actual code without execution, and open automated Autopilot remediation pull requests.
          </p>
        </div>

        {error && (
          <div style={{ color: "#ef4444", fontSize: "12px", background: "rgba(239, 68, 68, 0.1)", padding: "6px 12px", borderRadius: "4px" }}>
            {error}
          </div>
        )}

        {status.available_installations && status.available_installations.length > 0 && (
          <div
            style={{
              width: "100%",
              maxWidth: "480px",
              background: "var(--surface)",
              border: "1px solid var(--line)",
              borderRadius: "8px",
              padding: "16px",
              textAlign: "left",
              display: "flex",
              flexDirection: "column",
              gap: "10px",
              marginTop: "4px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <CheckCircle2 size={16} style={{ color: "var(--accent)" }} />
              <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--text)" }}>
                Detected GitHub App Installations
              </span>
            </div>
            <p style={{ margin: 0, fontSize: "12px", color: "var(--muted)", lineHeight: 1.4 }}>
              The Guardian GitHub App is already installed on the following account(s). Choose your account to connect this session:
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "4px" }}>
              {status.available_installations.map((inst) => (
                <div
                  key={inst.id}
                  className="github-installation-row"
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
                    {inst.avatar_url ? (
                      <img
                        src={inst.avatar_url}
                        alt={inst.account_login}
                        style={{ width: "24px", height: "24px", borderRadius: "50%", flexShrink: 0 }}
                      />
                    ) : (
                      <GitBranch size={16} style={{ color: "var(--accent)", flexShrink: 0 }} />
                    )}
                    <div style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>
                      <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {inst.account_login}
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--muted)" }}>
                        {inst.account_type} &bull; #{inst.id}
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => handleLinkInstallation(inst.id)}
                    disabled={linkingId === inst.id}
                    className="button primary"
                    style={{
                      fontSize: "12px",
                      padding: "6px 14px",
                      flexShrink: 0,
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    {linkingId === inst.id ? (
                      <>
                        <Loader2 size={12} className="animate-spin" />
                        <span>Connecting...</span>
                      </>
                    ) : (
                      <span>Connect as {inst.account_login}</span>
                    )}
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", justifyContent: "center", marginTop: "4px" }}>
          <button
            onClick={handleConnect}
            className="button primary"
            style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}
          >
            <GitBranch size={16} />
            <span>Install / Connect GitHub App</span>
          </button>

          <button
            onClick={handleSync}
            disabled={syncing}
            className="button secondary"
            style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}
          >
            <RefreshCw size={14} className={syncing ? "animate-spin" : ""} />
            <span>{syncing ? "Checking GitHub..." : "Check Existing Installation"}</span>
          </button>
        </div>
      </div>
    );
  }

  // Connected State
  const installation = status?.installation;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      {/* Account Status Header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "10px",
          padding: "10px 14px",
          background: "var(--surface-muted)",
          borderRadius: "8px",
          border: "1px solid var(--line)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          {installation?.avatar_url ? (
            <img
              src={installation.avatar_url}
              alt={installation.account_login}
              style={{ width: "24px", height: "24px", borderRadius: "50%" }}
            />
          ) : (
            <GitBranch size={16} style={{ color: "var(--accent)" }} />
          )}
          <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--text)" }}>
            {installation?.account_login}
          </span>
          <span
            style={{
              fontSize: "11px",
              padding: "2px 6px",
              borderRadius: "4px",
              background: "rgba(16, 185, 129, 0.15)",
              color: "#10b981",
              fontWeight: 600,
            }}
          >
            Connected
          </span>
          <span style={{ fontSize: "11px", color: "var(--muted)" }}>
            ({installation?.account_type})
          </span>

          {status?.installations && status.installations.length > 1 && (
            <div style={{ display: "inline-flex", alignItems: "center", gap: "6px", marginLeft: "8px" }}>
              <label style={{ fontSize: "11px", color: "var(--muted)" }}>Switch Account:</label>
              <select
                value={installation?.id}
                onChange={(e) => handleSelectInstallation(Number(e.target.value))}
                style={{
                  fontSize: "12px",
                  padding: "3px 8px",
                  borderRadius: "4px",
                  border: "1px solid var(--line)",
                  background: "var(--surface)",
                  color: "var(--text)",
                  cursor: "pointer",
                }}
              >
                {status.installations.map((inst) => (
                  <option key={inst.id} value={inst.id}>
                    {inst.account_login} ({inst.account_type})
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <button
            onClick={handleConnect}
            className="button secondary compact"
            title="Connect another GitHub account or organization"
            style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "11px" }}
          >
            <GitBranch size={12} />
            <span>+ Add Account</span>
          </button>
          <button
            onClick={() => fetchRepos(search)}
            disabled={loadingRepos}
            className="button secondary compact"
            title="Refresh repository list"
            style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "11px" }}
          >
            <RefreshCw size={12} className={loadingRepos ? "animate-spin" : ""} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => handleDisconnect()}
            className="button secondary compact"
            title="Disconnect current GitHub account"
            style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "11px", color: "#f87171" }}
          >
            <LogOut size={12} />
            <span>Disconnect</span>
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            color: "#ef4444",
            fontSize: "12px",
            background: "rgba(239, 68, 68, 0.1)",
            padding: "8px 12px",
            borderRadius: "6px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <AlertTriangle size={14} />
          <span>{error}</span>
        </div>
      )}

      {/* Repository Selection */}
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <label style={{ fontSize: "12px", fontWeight: 600, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Select Repository to Inspect ({filteredRepos.length})
          </label>
        </div>

        {/* Search Input */}
        <div style={{ position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: "12px", top: "10px", color: "var(--muted)" }} />
          <input
            type="text"
            placeholder="Search repositories by name..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: "100%",
              padding: "8px 12px 8px 34px",
              borderRadius: "6px",
              background: "var(--surface)",
              border: "1px solid var(--line)",
              color: "var(--text)",
              fontSize: "13px",
            }}
          />
        </div>

        {/* Repositories Scrollable List */}
        <div
          style={{
            maxHeight: "180px",
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
            gap: "4px",
            borderRadius: "6px",
            border: "1px solid var(--line)",
            background: "var(--surface)",
            padding: "4px",
          }}
        >
          {loadingRepos ? (
            <div style={{ padding: "24px", textAlign: "center", color: "var(--muted)" }}>
              <Loader2 size={16} className="animate-spin" style={{ margin: "0 auto 6px" }} />
              <span style={{ fontSize: "12px" }}>Loading accessible repositories...</span>
            </div>
          ) : filteredRepos.length === 0 ? (
            <div style={{ padding: "24px", textAlign: "center", color: "var(--muted)", fontSize: "12px" }}>
              No matching repositories found. Ensure the Guardian GitHub App has access granted.
            </div>
          ) : (
            filteredRepos.map((r) => {
              const isSelected = selectedRepo?.id === r.id;
              return (
                <div
                  key={r.id}
                  onClick={() => setSelectedRepo(r)}
                  style={{
                    padding: "8px 12px",
                    borderRadius: "5px",
                    cursor: "pointer",
                    background: isSelected ? "var(--accent-soft, rgba(99, 102, 241, 0.15))" : "transparent",
                    border: isSelected ? "1px solid var(--accent, #6366f1)" : "1px solid transparent",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    transition: "all 0.12s ease",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", minWidth: 0 }}>
                    {r.private ? (
                      <Lock size={13} style={{ color: "#f59e0b", flexShrink: 0 }} />
                    ) : (
                      <Globe size={13} style={{ color: "var(--muted)", flexShrink: 0 }} />
                    )}
                    <span
                      style={{
                        fontSize: "13px",
                        fontWeight: isSelected ? 600 : 500,
                        color: isSelected ? "var(--accent, #6366f1)" : "var(--text)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {r.full_name}
                    </span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "6px", flexShrink: 0 }}>
                    <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                      {r.default_branch}
                    </span>
                    {isSelected && <CheckCircle2 size={14} style={{ color: "var(--accent)" }} />}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Selected Repository Configuration & Branch Selector */}
      {selectedRepo && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          style={{
            padding: "16px",
            background: "var(--surface-muted)",
            borderRadius: "8px",
            border: "1px solid var(--line)",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px" }}>
            <div>
              <strong style={{ fontSize: "14px", color: "var(--text)" }}>{selectedRepo.full_name}</strong>
              <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "2px" }}>
                Targeting commit SHA for immutable, verifiable security scanning
              </div>
            </div>

            <a
              href={selectedRepo.html_url}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                fontSize: "12px",
                color: "var(--accent)",
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
                textDecoration: "none",
              }}
            >
              <span>GitHub</span>
              <ExternalLink size={12} />
            </a>
          </div>

          {/* Branch Picker */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "10px" }}>
            <div>
              <label style={{ display: "block", fontSize: "11px", color: "var(--muted)", marginBottom: "4px" }}>
                Select Branch
              </label>
              {loadingBranches ? (
                <div style={{ padding: "6px 10px", fontSize: "12px", color: "var(--muted)" }}>
                  <Loader2 size={12} className="animate-spin inline mr-1" /> Loading branches...
                </div>
              ) : (
                <select
                  value={selectedBranch}
                  onChange={(e) => {
                    const branchName = e.target.value;
                    setSelectedBranch(branchName);
                    const b = branches.find((x) => x.name === branchName);
                    if (b) setActiveCommitSha(b.commit_sha);
                  }}
                  style={{
                    width: "100%",
                    padding: "7px 10px",
                    borderRadius: "6px",
                    background: "var(--surface)",
                    border: "1px solid var(--line)",
                    color: "var(--text)",
                    fontSize: "12px",
                  }}
                >
                  {branches.map((b) => (
                    <option key={b.name} value={b.name}>
                      {b.name} {b.is_default ? "(Default)" : ""}
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div>
              <label style={{ display: "block", fontSize: "11px", color: "var(--muted)", marginBottom: "4px" }}>
                Resolved Commit SHA
              </label>
              <div
                style={{
                  padding: "7px 10px",
                  borderRadius: "6px",
                  background: "var(--surface)",
                  border: "1px solid var(--line)",
                  fontFamily: "monospace",
                  fontSize: "12px",
                  color: "var(--text)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <span>{activeCommitSha ? activeCommitSha.slice(0, 10) : "Resolving..."}</span>
                <span
                  style={{
                    fontSize: "10px",
                    padding: "1px 5px",
                    borderRadius: "3px",
                    background: "rgba(99, 102, 241, 0.15)",
                    color: "var(--accent)",
                  }}
                >
                  Immutable
                </span>
              </div>
            </div>
          </div>

          {/* Profile Selector */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              paddingTop: "6px",
              borderTop: "1px solid var(--line)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <Sliders size={13} style={{ color: "var(--muted)" }} />
              <span style={{ fontSize: "12px", color: "var(--muted)" }}>Inspection Profile:</span>
            </div>

            <div style={{ display: "flex", gap: "4px" }}>
              <button
                type="button"
                onClick={() => onProfileChange("fast")}
                style={{
                  padding: "4px 8px",
                  borderRadius: "4px",
                  fontSize: "11px",
                  cursor: "pointer",
                  background: profile === "fast" ? "var(--accent-soft)" : "transparent",
                  color: profile === "fast" ? "var(--accent)" : "var(--muted)",
                  border: profile === "fast" ? "1px solid var(--accent)" : "1px solid transparent",
                }}
              >
                Fast (Direct)
              </button>
              <button
                type="button"
                onClick={() => onProfileChange("deep")}
                style={{
                  padding: "4px 8px",
                  borderRadius: "4px",
                  fontSize: "11px",
                  cursor: "pointer",
                  background: profile === "deep" ? "var(--accent-soft)" : "transparent",
                  color: profile === "deep" ? "var(--accent)" : "var(--muted)",
                  border: profile === "deep" ? "1px solid var(--accent)" : "1px solid transparent",
                }}
              >
                Deep (Transitive)
              </button>
            </div>
          </div>

          {/* Launch Scan Button */}
          <button
            onClick={handleStartScan}
            disabled={disabled || startingScan || !selectedRepo || !activeCommitSha}
            className="button primary"
            style={{
              width: "100%",
              padding: "10px",
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              gap: "8px",
              marginTop: "4px",
            }}
          >
            {startingScan ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Ingesting GitHub Repository...</span>
              </>
            ) : (
              <>
                <Sparkles size={16} />
                <span>Inspect Repository with Guardian</span>
              </>
            )}
          </button>
        </motion.div>
      )}
    </div>
  );
}
