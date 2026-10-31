"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Wrench,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Loader2,
  RotateCcw,
  Sparkles,
  ShieldCheck,
  GitBranch,
  ArrowRight,
  RefreshCw,
  X,
  FileCode,
  Terminal,
  FolderOpen,
} from "lucide-react";
import {
  api,
  Report,
  Finding,
  RemediationPlan,
  VerificationResult,
} from "@/lib/types";
import { Eyebrow } from "./ui";
import RemediationPlanView from "./remediation-plan";
import {
  applyPlanToFileSystem,
  undoPlanFromFileSystem,
  downloadPatchFile,
  isFileSystemAccessSupported,
} from "@/lib/fs-access";

export default function RemediationPanel({
  report,
  directoryHandle: initialDirectoryHandle,
  targetFindingId,
  onClose,
  onFindingClick,
  onRescanRequested,
  onDirectoryHandleChange,
}: {
  report: Report;
  directoryHandle?: FileSystemDirectoryHandle | null;
  targetFindingId?: string | null;
  onClose: () => void;
  onFindingClick?: (findingId: string) => void;
  onRescanRequested?: () => Promise<Report | void>;
  onDirectoryHandleChange?: (handle: FileSystemDirectoryHandle | null) => void;
}) {
  const [directoryHandle, setDirectoryHandle] =
    useState<FileSystemDirectoryHandle | null>(initialDirectoryHandle || null);
  const [consent, setConsent] = useState(false);
  const [showConsentModal, setShowConsentModal] = useState(false);
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>(
    targetFindingId ? [targetFindingId] : [],
  );
  const [verification, setVerification] = useState<VerificationResult | null>(
    null,
  );
  const [canUndo, setCanUndo] = useState(false);
  const [confirmApply, setConfirmApply] = useState(false);

  useEffect(() => {
    if (initialDirectoryHandle) {
      setDirectoryHandle(initialDirectoryHandle);
    }
  }, [initialDirectoryHandle]);

  async function connectFolder(): Promise<FileSystemDirectoryHandle | null> {
    if (!isFileSystemAccessSupported()) {
      setError(
        "Direct disk access requires the File System Access API (available in Chrome, Edge, and Chromium-based browsers). In Firefox/Safari, use the downloaded .patch file.",
      );
      return null;
    }
    try {
      setStage("Select your project folder on disk to grant access...");
      const handle = await (window as any).showDirectoryPicker({
        mode: "read",
      });
      setDirectoryHandle(handle);
      if (onDirectoryHandleChange) onDirectoryHandleChange(handle);
      setActionSuccess(
        `Connected folder '${handle.name}'. You can now apply changes directly.`,
      );
      return handle;
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError(`Could not select folder: ${(err as Error).message}`);
      }
      return null;
    } finally {
      setStage("");
    }
  }

  // Initialize consent from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem("guardian_remediation_consent");
      if (stored === "true") {
        setConsent(true);
      }
    } catch {}
  }, []);

  function handleConsentChange(value: boolean) {
    setConsent(value);
    try {
      localStorage.setItem(
        "guardian_remediation_consent",
        value ? "true" : "false",
      );
    } catch {}
  }

  // Generate remediation plan
  async function generatePlan() {
    setLoading(true);
    setError(null);
    setActionSuccess(null);
    setVerification(null);
    setStage("Building minimized context & inspecting findings...");

    try {
      setStage("Generating structured patch with Guardian...");
      const res = await api<RemediationPlan>(
        `/scans/${report.id}/remediation/plan`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            finding_ids:
              selectedFindingIds.length > 0 ? selectedFindingIds : null,
            consent: consent,
          }),
        },
      );

      setPlan(res);
      setConfirmApply(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setStage("");
    }
  }

  // Reject plan
  async function rejectPlan() {
    if (!plan) return;
    try {
      const res = await api<RemediationPlan>(
        `/remediation/plans/${plan.plan_id}/reject`,
        { method: "POST" },
      );
      setPlan(res);
      setActionSuccess("Plan rejected. No local files were modified.");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  // Approve and Apply changes through browser File System Access API
  async function applyPlan() {
    if (!plan) return;

    let handle = directoryHandle;

    // If no directory handle is currently active, prompt the user to pick their project folder on disk
    if (!handle) {
      if (isFileSystemAccessSupported()) {
        try {
          setLoading(true);
          setStage(
            "Please select your project folder on disk to grant access...",
          );
          handle = await (window as any).showDirectoryPicker({ mode: "read" });
          setDirectoryHandle(handle);
          if (onDirectoryHandleChange) onDirectoryHandleChange(handle);
        } catch (err) {
          setLoading(false);
          setStage("");
          if ((err as Error).name === "AbortError") {
            return;
          }
          downloadPatchFile(plan);
          setActionSuccess(
            "Could not connect local folder handle. A unified .patch file has been downloaded for manual application.",
          );
          return;
        }
      } else {
        downloadPatchFile(plan);
        setActionSuccess(
          "Direct disk access is not supported in this browser (Firefox/Safari). A unified .patch file has been downloaded for manual application.",
        );
        return;
      }
    }

    setLoading(true);
    setError(null);
    setActionSuccess(null);
    setStage("Verifying target file hashes on disk...");

    try {
      // 1. Mark status 'approved' in backend
      await api<RemediationPlan>(`/remediation/plans/${plan.plan_id}/approve`, {
        method: "POST",
      });

      if (!handle) {
        throw new Error("No folder handle available for file application.");
      }

      // 2. Apply changes through browser handles with pre-check and IndexedDB backup
      setStage("Applying approved modifications & updating local files...");
      const result = await applyPlanToFileSystem(handle, plan);

      // 3. Record applied in backend
      const updatedPlan = await api<RemediationPlan>(
        `/remediation/plans/${plan.plan_id}/applied`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            applied_at: new Date().toISOString(),
            modified_files: result.modifiedFiles,
            success: true,
          }),
        },
      );

      setPlan(updatedPlan);
      setCanUndo(true);
      setConfirmApply(false);
      setActionSuccess(
        `Successfully applied changes to ${result.modifiedFiles.length} file(s). Automatic rollback backup saved in browser IndexedDB.`,
      );
    } catch (err) {
      setError((err as Error).message);
      if (plan) {
        await api<RemediationPlan>(
          `/remediation/plans/${plan.plan_id}/applied`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              applied_at: new Date().toISOString(),
              modified_files: [],
              success: false,
              error: (err as Error).message,
            }),
          },
        ).catch(() => {});
      }
    } finally {
      setLoading(false);
      setStage("");
    }
  }

  // Revert changes from IndexedDB backup
  async function undoChanges() {
    if (!plan) return;
    let handle = directoryHandle;
    if (!handle) {
      handle = await connectFolder();
      if (!handle) return;
    }
    setLoading(true);
    setError(null);
    setActionSuccess(null);
    setStage("Restoring original files from IndexedDB backup...");

    try {
      const result = await undoPlanFromFileSystem(handle, plan);
      setCanUndo(false);
      setActionSuccess(
        `Successfully restored ${result.restoredFiles.length} file(s) to original state.`,
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setStage("");
    }
  }

  // Rescan and verify outcomes
  async function rescanAndVerify() {
    if (!plan || !onRescanRequested) return;
    setLoading(true);
    setError(null);
    setActionSuccess(null);
    setStage("Rescanning modified project...");

    try {
      const rescannedReport = await onRescanRequested();
      if (!rescannedReport) {
        throw new Error("Rescan did not return a valid report.");
      }

      setStage(
        "Comparing pre-remediation and post-remediation security findings...",
      );
      const result = await api<VerificationResult>(
        `/remediation/plans/${plan.plan_id}/verification`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            rescanned_scan_id: rescannedReport.id,
          }),
        },
      );

      setVerification(result);
      setActionSuccess(
        "Verification complete. Results compared against baseline scan.",
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setStage("");
    }
  }

  const eligibleFindings = report.findings.filter(
    (f) =>
      f.severity !== "info" ||
      f.rule === "OSV" ||
      f.rule.startsWith("INSTALL_"),
  );

  return (
    <div
      className="remediation-panel-overlay"
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(0, 0, 0, 0.75)",
        backdropFilter: "blur(4px)",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        zIndex: 1000,
        padding: "20px",
      }}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.96 }}
        className="card"
        style={{
          width: "100%",
          maxWidth: "960px",
          maxHeight: "90vh",
          display: "flex",
          flexDirection: "column",
          padding: 0,
          overflow: "hidden",
          border: "1px solid var(--border)",
          boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5)",
        }}
      >
        {/* Panel Header */}
        <div
          style={{
            padding: "16px 20px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "var(--surface)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div
              style={{
                width: "32px",
                height: "32px",
                borderRadius: "8px",
                background: "rgba(59, 130, 246, 0.15)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "var(--accent-blue, #3b82f6)",
              }}
            >
              <Wrench size={18} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: "16px" }}>
                Guardian Autopilot Remediation
              </h3>
              <p
                style={{
                  margin: "2px 0 0",
                  fontSize: "11px",
                  color: "var(--muted)",
                }}
              >
                AI-assisted software remediation with deterministic verification
                and local rollback protection.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="icon-button"
            style={{ width: "32px", height: "32px" }}
            aria-label="Close remediation panel"
          >
            <X size={18} />
          </button>
        </div>

        {/* Panel Body */}
        <div
          style={{
            flex: 1,
            overflowY: "auto",
            padding: "20px",
            display: "flex",
            flexDirection: "column",
            gap: "18px",
          }}
        >
          {/* Alerts / Error messages */}
          {error && (
            <div
              style={{
                padding: "12px 16px",
                borderRadius: "8px",
                background: "rgba(239, 68, 68, 0.12)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                color: "#ef4444",
                fontSize: "13px",
                display: "flex",
                alignItems: "flex-start",
                gap: "10px",
              }}
            >
              <AlertTriangle
                size={18}
                style={{ flexShrink: 0, marginTop: "2px" }}
              />
              <div style={{ flex: 1 }}>{error}</div>
              <button
                onClick={() => setError(null)}
                style={{
                  background: "none",
                  border: "none",
                  color: "#ef4444",
                  cursor: "pointer",
                }}
              >
                <X size={15} />
              </button>
            </div>
          )}

          {actionSuccess && (
            <div
              style={{
                padding: "12px 16px",
                borderRadius: "8px",
                background: "rgba(16, 185, 129, 0.12)",
                border: "1px solid rgba(16, 185, 129, 0.3)",
                color: "#10b981",
                fontSize: "13px",
                display: "flex",
                alignItems: "flex-start",
                gap: "10px",
              }}
            >
              <CheckCircle2
                size={18}
                style={{ flexShrink: 0, marginTop: "2px" }}
              />
              <div style={{ flex: 1 }}>{actionSuccess}</div>
              <button
                onClick={() => setActionSuccess(null)}
                style={{
                  background: "none",
                  border: "none",
                  color: "#10b981",
                  cursor: "pointer",
                }}
              >
                <X size={15} />
              </button>
            </div>
          )}

          {/* Folder Connection Status Banner */}
          {!directoryHandle ? (
            <div
              style={{
                padding: "12px 16px",
                background: "rgba(59, 130, 246, 0.08)",
                borderRadius: "8px",
                border: "1px solid rgba(59, 130, 246, 0.25)",
                fontSize: "12px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "12px",
                flexWrap: "wrap",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "10px",
                }}
              >
                <FolderOpen
                  size={18}
                  color="var(--accent-blue, #3b82f6)"
                  style={{ flexShrink: 0, marginTop: "2px" }}
                />
                <div>
                  <strong style={{ color: "var(--foreground)" }}>
                    Direct Disk Modification Available
                  </strong>
                  <p
                    style={{
                      margin: "2px 0 0",
                      color: "var(--muted)",
                      lineHeight: "1.5",
                    }}
                  >
                    Standard browser uploads provide an in-memory copy only. To
                    apply approved fixes directly to your local files, link your
                    folder on disk.
                  </p>
                </div>
              </div>
              <button
                onClick={connectFolder}
                className="button primary compact"
                style={{
                  fontSize: "11px",
                  whiteSpace: "nowrap",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <FolderOpen size={13} />
                Connect local folder
              </button>
            </div>
          ) : (
            <div
              style={{
                padding: "10px 14px",
                background: "rgba(16, 185, 129, 0.06)",
                borderRadius: "8px",
                border: "1px solid rgba(16, 185, 129, 0.2)",
                fontSize: "12px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "10px",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: "8px" }}
              >
                <FolderOpen size={16} color="var(--accent-green, #10b981)" />
                <span>
                  <strong>Connected Folder:</strong> {directoryHandle.name}{" "}
                  (Direct in-place application enabled)
                </span>
              </div>
              <button
                onClick={connectFolder}
                className="button secondary compact"
                style={{ fontSize: "10px", padding: "2px 8px" }}
              >
                Change folder
              </button>
            </div>
          )}

          {/* Dedicated Project-Code Consent Section */}
          <div
            style={{
              padding: "12px 16px",
              background: consent
                ? "rgba(16, 185, 129, 0.05)"
                : "rgba(255, 255, 255, 0.02)",
              borderRadius: "8px",
              border: `1px solid ${consent ? "rgba(16, 185, 129, 0.2)" : "var(--border)"}`,
              fontSize: "12px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "10px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Sparkles
                size={16}
                color={
                  consent ? "var(--accent-green, #10b981)" : "var(--muted)"
                }
              />
              <div>
                <strong>Gemini Cognitive Remediation Planning:</strong>{" "}
                <span style={{ color: "var(--muted)" }}>
                  {consent
                    ? "Opted-in. Selected redacted project context is shared for structured reasoning."
                    : "Running locally (deterministic). Project code remains strictly local."}
                </span>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <button
                onClick={() => setShowConsentModal(true)}
                className="button secondary compact"
                style={{ fontSize: "11px" }}
              >
                Privacy settings & details
              </button>
              <label
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  cursor: "pointer",
                  fontSize: "12px",
                }}
              >
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(e) => handleConsentChange(e.target.checked)}
                />
                Enable AI inference
              </label>
            </div>
          </div>

          {/* If no plan generated yet, show findings selection and generate button */}
          {!plan && (
            <div
              style={{ display: "flex", flexDirection: "column", gap: "14px" }}
            >
              <div>
                <Eyebrow>SELECT FINDINGS TO ADDRESS</Eyebrow>
                <p
                  style={{
                    fontSize: "12px",
                    color: "var(--muted)",
                    margin: "4px 0 10px",
                  }}
                >
                  Select one or more findings for Guardian to formulate a
                  targeted remediation patch:
                </p>

                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                    maxHeight: "240px",
                    overflowY: "auto",
                  }}
                >
                  {eligibleFindings.length === 0 ? (
                    <p
                      style={{
                        fontSize: "12px",
                        color: "var(--muted)",
                        fontStyle: "italic",
                      }}
                    >
                      No elevated or actionable findings detected in this scan.
                    </p>
                  ) : (
                    eligibleFindings.map((f) => {
                      const isSelected = selectedFindingIds.includes(f.id);
                      return (
                        <div
                          key={f.id}
                          onClick={() => {
                            setSelectedFindingIds((prev) =>
                              prev.includes(f.id)
                                ? prev.filter((id) => id !== f.id)
                                : [...prev, f.id],
                            );
                          }}
                          style={{
                            padding: "10px 14px",
                            borderRadius: "6px",
                            background: isSelected
                              ? "rgba(59, 130, 246, 0.1)"
                              : "var(--surface)",
                            border: `1px solid ${isSelected ? "rgba(59, 130, 246, 0.4)" : "var(--border)"}`,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            cursor: "pointer",
                            gap: "10px",
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: "10px",
                            }}
                          >
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => {}}
                              style={{ cursor: "pointer" }}
                            />
                            <div>
                              <strong style={{ fontSize: "13px" }}>
                                {f.title}
                              </strong>
                              <span
                                style={{
                                  fontSize: "11px",
                                  color: "var(--muted)",
                                  marginLeft: "8px",
                                }}
                              >
                                {f.rule} {f.package ? `(${f.package})` : ""}
                              </span>
                            </div>
                          </div>
                          <span
                            style={{
                              fontSize: "10px",
                              fontWeight: 600,
                              textTransform: "uppercase",
                              padding: "2px 6px",
                              borderRadius: "4px",
                              background: "rgba(255,255,255,0.06)",
                            }}
                          >
                            {f.severity}
                          </span>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  justifyContent: "flex-end",
                  marginTop: "10px",
                }}
              >
                <button
                  onClick={generatePlan}
                  disabled={loading}
                  className="button primary"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  {loading ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    <Wrench size={16} />
                  )}
                  {loading ? "Generating plan..." : "Generate remediation plan"}
                </button>
              </div>
            </div>
          )}

          {/* Loading indicator with stage message */}
          {loading && (
            <div
              style={{
                padding: "24px",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                gap: "12px",
              }}
            >
              <Loader2
                size={24}
                className="animate-spin"
                color="var(--accent-blue, #3b82f6)"
              />
              <span style={{ fontSize: "13px", color: "var(--muted)" }}>
                {stage}
              </span>
            </div>
          )}

          {/* Plan View if plan exists */}
          {plan && !loading && (
            <div
              style={{ display: "flex", flexDirection: "column", gap: "20px" }}
            >
              <RemediationPlanView
                plan={plan}
                onFindingClick={onFindingClick}
              />

              {/* Verification Results Banner if verified */}
              {verification && (
                <div
                  className="card"
                  style={{
                    padding: "16px",
                    background: "rgba(16, 185, 129, 0.05)",
                    border: "1px solid rgba(16, 185, 129, 0.3)",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      marginBottom: "8px",
                    }}
                  >
                    <ShieldCheck
                      size={18}
                      color="var(--accent-green, #10b981)"
                    />
                    <strong
                      style={{
                        fontSize: "14px",
                        color: "var(--accent-green, #10b981)",
                      }}
                    >
                      Verification Outcome
                    </strong>
                  </div>
                  <p
                    style={{
                      margin: "0 0 10px",
                      fontSize: "12px",
                      color: "var(--foreground)",
                    }}
                  >
                    {verification.summary}
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: "10px",
                      fontSize: "12px",
                    }}
                  >
                    <div>
                      <strong style={{ color: "var(--accent-green, #10b981)" }}>
                        Resolved ({verification.resolved_findings.length}):
                      </strong>
                      <ul
                        style={{
                          margin: "4px 0",
                          paddingLeft: "16px",
                          color: "var(--muted)",
                        }}
                      >
                        {verification.resolved_findings.map((f, i) => (
                          <li key={i}>{f}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <strong
                        style={{ color: "var(--accent-orange, #f97316)" }}
                      >
                        Persistent / Remaining (
                        {verification.persistent_findings.length}):
                      </strong>
                      <ul
                        style={{
                          margin: "4px 0",
                          paddingLeft: "16px",
                          color: "var(--muted)",
                        }}
                      >
                        {verification.persistent_findings.map((f, i) => (
                          <li key={i}>{f}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* Git Branch & Backup Warning before Approval */}
              {confirmApply && (
                <div
                  style={{
                    padding: "14px 18px",
                    background: "rgba(249, 115, 22, 0.1)",
                    border: "1px solid rgba(249, 115, 22, 0.3)",
                    borderRadius: "8px",
                    fontSize: "12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                    }}
                  >
                    <GitBranch
                      size={16}
                      color="var(--accent-orange, #f97316)"
                    />
                    <strong style={{ color: "var(--accent-orange, #f97316)" }}>
                      Pre-application advisory:
                    </strong>
                  </div>
                  <p style={{ margin: 0, lineHeight: "1.5" }}>
                    Guardian will write exact file modifications to your local
                    project. It is strongly recommended to work on a dedicated
                    Git branch and ensure untracked files are committed. A local
                    IndexedDB recovery backup will be captured automatically
                    before modification.
                  </p>
                  <div
                    style={{ display: "flex", gap: "10px", marginTop: "4px" }}
                  >
                    <button
                      onClick={applyPlan}
                      className="button primary compact"
                      style={{
                        background: "var(--accent-green, #10b981)",
                        borderColor: "var(--accent-green, #10b981)",
                      }}
                    >
                      Confirm and apply modifications
                    </button>
                    <button
                      onClick={() => setConfirmApply(false)}
                      className="button secondary compact"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Panel Footer Controls */}
        <div
          style={{
            padding: "14px 20px",
            borderTop: "1px solid var(--border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "var(--surface)",
            gap: "10px",
            flexWrap: "wrap",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            {plan && plan.status === "proposed" && !confirmApply && (
              <>
                <button
                  onClick={rejectPlan}
                  disabled={loading}
                  className="button secondary compact"
                  style={{ color: "var(--accent-red, #ef4444)" }}
                >
                  <XCircle size={14} />
                  Reject plan
                </button>
                <button
                  onClick={generatePlan}
                  disabled={loading}
                  className="button secondary compact"
                >
                  <RefreshCw size={14} />
                  Regenerate
                </button>
              </>
            )}
            {canUndo && directoryHandle && (
              <button
                onClick={undoChanges}
                disabled={loading}
                className="button secondary compact"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <RotateCcw size={14} />
                Undo latest changes
              </button>
            )}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            {plan && plan.status === "proposed" && !confirmApply && (
              <button
                onClick={() => setConfirmApply(true)}
                disabled={loading}
                className="button primary"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <CheckCircle2 size={16} />
                Approve and apply
              </button>
            )}

            {plan &&
              (plan.status === "applied" || plan.status === "verified") &&
              onRescanRequested && (
                <button
                  onClick={rescanAndVerify}
                  disabled={loading}
                  className="button primary"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <RefreshCw
                    size={16}
                    className={loading ? "animate-spin" : ""}
                  />
                  Rescan & verify outcome
                </button>
              )}

            <button onClick={onClose} className="button secondary">
              Close
            </button>
          </div>
        </div>
      </motion.div>

      {/* Consent Details Modal */}
      {showConsentModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.8)",
            zIndex: 1100,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "20px",
          }}
        >
          <div
            className="card"
            style={{
              maxWidth: "520px",
              padding: "20px",
              display: "flex",
              flexDirection: "column",
              gap: "14px",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: "8px" }}
              >
                <ShieldCheck size={18} color="var(--accent-blue, #3b82f6)" />
                <h4 style={{ margin: 0 }}>Project Code Privacy & Consent</h4>
              </div>
              <button
                onClick={() => setShowConsentModal(false)}
                className="icon-button"
              >
                <X size={16} />
              </button>
            </div>

            <p
              style={{
                margin: 0,
                fontSize: "12px",
                color: "var(--foreground)",
                opacity: 0.85,
                lineHeight: "1.6",
              }}
            >
              Guardian takes a privacy-first approach to software remediation:
            </p>

            <ul
              style={{
                margin: 0,
                paddingLeft: "18px",
                fontSize: "12px",
                color: "var(--muted)",
                lineHeight: "1.6",
              }}
            >
              <li>
                <strong>Targeted Context Only:</strong> Full project directories
                are NEVER uploaded. Only files directly related to targeted
                findings (e.g. manifests or snippets) are shared.
              </li>
              <li>
                <strong>Automated Secret Redaction:</strong> All credentials,
                API tokens, passwords, private keys, and auth headers are
                automatically stripped before external transmission.
              </li>
              <li>
                <strong>Deterministic Fallback:</strong> If consent is declined
                or Gemini is disabled, Guardian formulates remediation plans
                using its local deterministic engine.
              </li>
              <li>
                <strong>No Code Execution:</strong> Gemini is an advisor only
                and cannot execute terminal commands or write files directly.
              </li>
            </ul>

            <label
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "10px",
                padding: "10px",
                background: "var(--surface-muted, rgba(255,255,255,0.02))",
                borderRadius: "6px",
                fontSize: "12px",
                cursor: "pointer",
              }}
            >
              <input
                type="checkbox"
                checked={consent}
                onChange={(e) => handleConsentChange(e.target.checked)}
                style={{ marginTop: "3px" }}
              />
              <span>
                I consent to sending selected, secret-redacted project files to
                Google Gemini API for remediation planning.
              </span>
            </label>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button
                onClick={() => setShowConsentModal(false)}
                className="button primary compact"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
