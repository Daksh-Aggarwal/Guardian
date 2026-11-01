"use client";

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  XCircle,
  Loader2,
  FileCode,
  ShieldAlert,
} from "lucide-react";
import {
  Wrench,
  CheckCircle2,
  RotateCcw,
  Sparkles,
  ShieldCheck,
  GitBranch,
  ArrowRight,
  RefreshCw,
  X,
  Terminal,
  FolderOpen,
  GitPullRequest,
  ExternalLink,
} from "@/components/icons";
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
  validatePlanFilesForReapplication,
  downloadPatchFile,
  isFileSystemAccessSupported,
} from "@/lib/fs-access";
import { getRemediationBackup } from "@/lib/indexeddb-backup";

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
  onRescanRequested?: (profile?: "fast" | "deep") => Promise<Report | void>;
  onDirectoryHandleChange?: (handle: FileSystemDirectoryHandle | null) => void;
}) {
  const [directoryHandle, setDirectoryHandle] =
    useState<FileSystemDirectoryHandle | null>(initialDirectoryHandle || null);
  const [consent, setConsent] = useState(false);
  const [showConsentModal, setShowConsentModal] = useState(false);
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState("");
  const [rescanProfile, setRescanProfile] = useState<"fast" | "deep">("fast");
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>(
    targetFindingId ? [targetFindingId] : [],
  );

  useEffect(() => {
    if (targetFindingId) {
      setSelectedFindingIds((prev) =>
        prev.includes(targetFindingId) ? prev : [...prev, targetFindingId],
      );
    }
  }, [targetFindingId]);
  const [verification, setVerification] = useState<VerificationResult | null>(
    null,
  );
  const [canUndo, setCanUndo] = useState(false);
  const [confirmApply, setConfirmApply] = useState(false);

  useEffect(() => {
    if (plan && plan.status === "applied") {
      getRemediationBackup(plan.plan_id)
        .then((b) => {
          if (b && b.files && b.files.length > 0) {
            setCanUndo(true);
          }
        })
        .catch(() => {});
    } else {
      setCanUndo(false);
    }
  }, [plan]);

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
  // Lock background scroll and pause Lenis when drawer is open
  useEffect(() => {
    const prevBodyOverflow = document.body.style.overflow;
    const prevHtmlOverflow = document.documentElement.style.overflow;
    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";

    const lenis = (window as any).__lenis;
    if (lenis && typeof lenis.stop === "function") {
      lenis.stop();
    }

    return () => {
      document.body.style.overflow = prevBodyOverflow;
      document.documentElement.style.overflow = prevHtmlOverflow;
      if (lenis && typeof lenis.start === "function") {
        lenis.start();
      }
    };
  }, []);

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
      const job = await api<{ id: string }>(
        `/scans/${report.id}/remediation/jobs`,
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

      for (;;) {
        const state = await api<{
          status: "queued" | "running" | "complete" | "failed";
          stage: string;
          plan?: RemediationPlan;
          error?: string;
        }>(`/remediation/jobs/${job.id}`);
        setStage(state.stage);
        if (state.status === "failed") {
          throw new Error(state.error || "Remediation generation failed.");
        }
        if (state.status === "complete") {
          if (!state.plan) throw new Error("Completed remediation job returned no plan.");
          setPlan(state.plan);
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 750));
      }
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

    if (plan.validation_status && plan.validation_status !== "VERIFIED") {
      setError(
        `Cannot apply remediation plan: validation status is '${plan.validation_status}'. ` +
          (plan.validation_reasons?.join("; ") || ""),
      );
      return;
    }

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
    setStage("Verifying write permission and target file hashes on disk...");

    const previousStatus = plan.status;

    try {
      if (!handle) {
        throw new Error("No folder handle available for file application.");
      }

      // Check / request write permission first
      if (typeof (handle as any).requestPermission === "function") {
        const permStatus = await (handle as any).requestPermission({
          mode: "readwrite",
        });
        if (permStatus !== "granted") {
          throw new Error(
            "Write permission was denied by the user. Proposed changes were not written to disk.",
          );
        }
      }

      // 1. Mark status 'approved' in backend
      await api<RemediationPlan>(`/remediation/plans/${plan.plan_id}/approve`, {
        method: "POST",
      });

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
      setConfirmApply(false);
      if (plan && previousStatus === "reverted") {
        // Ensure plan is safely returned to reverted state on reapplication failure
        try {
          const revertedPlan = await api<RemediationPlan>(
            `/remediation/plans/${plan.plan_id}/revert`,
            { method: "POST" },
          );
          setPlan(revertedPlan);
        } catch (revertErr) {
          console.error("Failed to reset plan status to reverted:", revertErr);
        }
      } else if (plan) {
        try {
          const failedPlan = await api<RemediationPlan>(
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
          );
          setPlan(failedPlan);
        } catch (failErr) {
          console.error("Failed to record plan failure:", failErr);
        }
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
      // ONLY after successful undo on filesystem, update backend plan status
      const updatedPlan = await api<RemediationPlan>(
        `/remediation/plans/${plan.plan_id}/revert`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            reverted_at: new Date().toISOString(),
            restored_files: result.restoredFiles,
          }),
        },
      );
      setPlan(updatedPlan);
      setCanUndo(false);
      setConfirmApply(false);
      setActionSuccess(
        `Successfully restored ${result.restoredFiles.length} file(s) to original state. You can reapply this plan at any time.`,
      );
    } catch (err) {
      // Failed Undo does not mark the plan as reverted
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setStage("");
    }
  }

  // Revalidate target files and initiate reapplication flow
  async function initiateReapply() {
    if (!plan) return;
    let handle = directoryHandle;
    if (!handle) {
      handle = await connectFolder();
      if (!handle) return;
    }

    setLoading(true);
    setError(null);
    setActionSuccess(null);
    setStage("Revalidating target files against pre-remediation hashes...");

    try {
      // 1. Revalidate all affected files against the original pre-remediation SHA256 hashes
      await validatePlanFilesForReapplication(handle, plan);

      // 2. Validation passed! Present the existing diff for review and require explicit approval again
      setConfirmApply(true);
      setActionSuccess(
        "Target files validated on disk. Please review the diff and confirm reapplication.",
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setStage("");
    }
  }

  const isGitHubTarget = Boolean(
    report.source_metadata?.source_type === "github" || plan?.repository_id,
  );

  async function applyGitHubPR() {
    if (!plan) return;

    if (plan.validation_status && plan.validation_status !== "VERIFIED") {
      setError(
        `Cannot apply remediation plan on GitHub: validation status is '${plan.validation_status}'. ` +
          (plan.validation_reasons?.join("; ") || ""),
      );
      return;
    }

    setLoading(true);
    setError(null);
    setActionSuccess(null);
    setStage("Verifying target branch commit & creating Git objects...");

    try {
      const res = await api<{
        plan_id: string;
        pr_number: number;
        pr_url: string;
        remediation_branch: string;
        commit_sha: string;
        status: string;
      }>(`/remediation/plans/${plan.plan_id}/apply-github`, {
        method: "POST",
      });

      setPlan((prev) =>
        prev
          ? {
              ...prev,
              status: "applied",
              pr_number: res.pr_number,
              pr_url: res.pr_url,
              remediation_branch: res.remediation_branch,
              remediation_commit_sha: res.commit_sha,
              pr_state: "open",
            }
          : null,
      );
      setConfirmApply(false);
      setActionSuccess(
        `Successfully created Pull Request #${res.pr_number} on GitHub!`,
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setStage("");
    }
  }

  async function closeGitHubPR() {
    if (!plan || !plan.pr_number) return;
    setLoading(true);
    setError(null);
    setActionSuccess(null);
    setStage("Closing Pull Request on GitHub...");

    try {
      const res = await api<{
        status: RemediationPlan["status"];
        pr_state: string;
        message?: string;
      }>(`/remediation/plans/${plan.plan_id}/close-github-pr`, {
        method: "POST",
      });
      setPlan((prev) =>
        prev
          ? {
              ...prev,
              status:
                res.status ||
                (res.pr_state === "merged" ? "applied" : "pr_closed"),
              pr_state: res.pr_state || "closed",
            }
          : null,
      );
      setActionSuccess(
        res.message ||
          (res.pr_state === "merged"
            ? `Pull Request #${plan.pr_number} was already merged. Merged changes cannot be undone by closing the PR; a separate Git revert is required.`
            : `Pull Request #${plan.pr_number} closed without merge. Remediation branch changes were not merged into target branch.`),
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
    setStage(`Rescanning modified project (${rescanProfile} profile)...`);

    try {
      const rescannedReport = await onRescanRequested(rescanProfile);
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
        `Verification complete: ${result.resolved_findings.length} findings resolved, ${result.persistent_findings.length} persistent (${rescanProfile} profile).`,
      );
      setTimeout(() => {
        document
          .getElementById("remediation-verification-outcome")
          ?.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 100);
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

  const selectAllRef = useRef<HTMLInputElement>(null);

  const allEligibleSelected =
    eligibleFindings.length > 0 &&
    eligibleFindings.every((f) => selectedFindingIds.includes(f.id));

  const selectedEligibleCount = eligibleFindings.filter((f) =>
    selectedFindingIds.includes(f.id),
  ).length;

  const someEligibleSelected =
    selectedEligibleCount > 0 && !allEligibleSelected;

  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = someEligibleSelected;
    }
  }, [someEligibleSelected]);

  const handleToggleSelectAll = () => {
    if (allEligibleSelected) {
      const eligibleIds = new Set(eligibleFindings.map((f) => f.id));
      setSelectedFindingIds((prev) =>
        prev.filter((id) => !eligibleIds.has(id)),
      );
    } else {
      const eligibleIds = eligibleFindings.map((f) => f.id);
      setSelectedFindingIds((prev) =>
        Array.from(new Set([...prev, ...eligibleIds])),
      );
    }
  };

  const handleSelectAll = () => {
    const eligibleIds = eligibleFindings.map((f) => f.id);
    setSelectedFindingIds((prev) =>
      Array.from(new Set([...prev, ...eligibleIds])),
    );
  };

  const handleClearAll = () => {
    const eligibleIds = new Set(eligibleFindings.map((f) => f.id));
    setSelectedFindingIds((prev) => prev.filter((id) => !eligibleIds.has(id)));
  };

  return (
    <div
      className="remediation-panel-overlay"
      data-lenis-prevent="true"
      onWheel={(e) => e.stopPropagation()}
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
          maxWidth: "1000px",
          maxHeight: "92vh",
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
                width: "34px",
                height: "34px",
                borderRadius: "8px",
                background: "rgba(59, 130, 246, 0.15)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "var(--accent-blue, #3b82f6)",
                flexShrink: 0,
              }}
            >
              <Wrench size={18} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: "16px", fontWeight: 600 }}>
                Guardian Autopilot Remediation
              </h3>
              <p
                style={{
                  margin: "2px 0 0",
                  fontSize: "12px",
                  color: "var(--muted)",
                }}
              >
                {plan
                  ? "Deterministic solution generated with verified safety checks and rollback protection."
                  : "AI-assisted software remediation with deterministic verification and local rollback protection."}
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
            padding: "18px 20px",
            display: "flex",
            flexDirection: "column",
            gap: "14px",
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

          {/* If no plan generated yet, show pre-flight controls and findings list */}
          {!plan && (
            <div
              style={{ display: "flex", flexDirection: "column", gap: "14px" }}
            >
              {/* Compact Pre-flight Configuration Ribbon */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "10px 14px",
                  background: "var(--surface)",
                  border: "1px solid var(--border)",
                  borderRadius: "8px",
                  gap: "12px",
                  flexWrap: "wrap",
                }}
              >
                {/* Left: Folder connection status */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    fontSize: "12px",
                  }}
                >
                  <FolderOpen
                    size={16}
                    color={
                      directoryHandle
                        ? "var(--accent-green, #10b981)"
                        : "var(--accent-blue, #3b82f6)"
                    }
                  />
                  <span>
                    {directoryHandle ? (
                      <>
                        <strong>Linked Folder:</strong> {directoryHandle.name}{" "}
                        <span style={{ color: "var(--muted)" }}>
                          (Direct disk modification enabled)
                        </span>
                      </>
                    ) : (
                      <span style={{ color: "var(--muted)" }}>
                        Memory session · Direct disk apply requires linking local folder
                      </span>
                    )}
                  </span>
                  <button
                    type="button"
                    onClick={connectFolder}
                    className="button secondary compact"
                    style={{ fontSize: "11px", padding: "2px 8px" }}
                  >
                    {directoryHandle ? "Change folder" : "Link folder"}
                  </button>
                </div>

                {/* Right: AI Consent toggle */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    fontSize: "12px",
                  }}
                >
                  <label
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "6px",
                      cursor: "pointer",
                      userSelect: "none",
                    }}
                  >
                    <Sparkles
                      size={14}
                      color={
                        consent
                          ? "var(--accent-green, #10b981)"
                          : "var(--muted)"
                      }
                    />
                    <span style={{ fontWeight: 500 }}>AI Inference</span>
                    <input
                      type="checkbox"
                      checked={consent}
                      onChange={(e) => handleConsentChange(e.target.checked)}
                      style={{
                        cursor: "pointer",
                        accentColor: "var(--accent-blue, #3b82f6)",
                      }}
                    />
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowConsentModal(true)}
                    className="button secondary compact"
                    style={{
                      fontSize: "11px",
                      padding: "2px 8px",
                      color: "var(--muted)",
                    }}
                    title="View privacy boundaries"
                  >
                    Privacy info
                  </button>
                </div>
              </div>

              <div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: "8px",
                  }}
                >
                  <Eyebrow>SELECT FINDINGS TO ADDRESS</Eyebrow>
                  {eligibleFindings.length > 0 && (
                    <span
                      style={{
                        fontSize: "11px",
                        color:
                          selectedEligibleCount > 0
                            ? "var(--accent-blue, #3b82f6)"
                            : "var(--muted)",
                        fontWeight: selectedEligibleCount > 0 ? 600 : 400,
                      }}
                    >
                      {selectedEligibleCount} of {eligibleFindings.length}{" "}
                      selected
                    </span>
                  )}
                </div>

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

                {eligibleFindings.length > 0 && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "8px 12px",
                      background: "rgba(255, 255, 255, 0.02)",
                      border: "1px solid var(--border)",
                      borderRadius: "6px",
                      marginBottom: "10px",
                      gap: "10px",
                    }}
                  >
                    <label
                      htmlFor="autopilot-select-all-issues"
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "8px",
                        cursor: "pointer",
                        fontSize: "12px",
                        fontWeight: 500,
                        userSelect: "none",
                      }}
                    >
                      <input
                        id="autopilot-select-all-issues"
                        ref={selectAllRef}
                        type="checkbox"
                        checked={allEligibleSelected}
                        onChange={handleToggleSelectAll}
                        style={{
                          cursor: "pointer",
                          accentColor: "var(--accent-blue, #3b82f6)",
                          width: "15px",
                          height: "15px",
                        }}
                        aria-label="Select all issues"
                      />
                      <span>Select all issues ({eligibleFindings.length})</span>
                    </label>

                    <div
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                      }}
                    >
                      {!allEligibleSelected ? (
                        <button
                          type="button"
                          onClick={handleSelectAll}
                          className="button secondary compact"
                          style={{
                            fontSize: "11px",
                            padding: "3px 8px",
                            height: "24px",
                            lineHeight: "20px",
                          }}
                        >
                          Select all
                        </button>
                      ) : null}
                      {selectedEligibleCount > 0 && (
                        <button
                          type="button"
                          onClick={handleClearAll}
                          className="button secondary compact"
                          style={{
                            fontSize: "11px",
                            padding: "3px 8px",
                            height: "24px",
                            lineHeight: "20px",
                          }}
                        >
                          Deselect all
                        </button>
                      )}
                    </div>
                  </div>
                )}

                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                    maxHeight: "260px",
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
                            transition:
                              "background 0.15s ease, border-color 0.15s ease",
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
                              onClick={(e) => e.stopPropagation()}
                              onChange={() => {
                                setSelectedFindingIds((prev) =>
                                  prev.includes(f.id)
                                    ? prev.filter((id) => id !== f.id)
                                    : [...prev, f.id],
                                );
                              }}
                              style={{
                                cursor: "pointer",
                                accentColor: "var(--accent-blue, #3b82f6)",
                                width: "15px",
                                height: "15px",
                              }}
                              aria-label={`Select issue ${f.title}`}
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
                  marginTop: "6px",
                }}
              >
                <button
                  onClick={generatePlan}
                  disabled={loading || eligibleFindings.length === 0}
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
                  {loading
                    ? "Generating plan..."
                    : selectedEligibleCount > 0
                      ? `Generate remediation plan (${selectedEligibleCount} ${selectedEligibleCount === 1 ? "issue" : "issues"})`
                      : "Generate remediation plan (all actionable)"}
                </button>
              </div>
            </div>
          )}

          {/* Loading indicator with stage message */}
          {loading && (
            <div
              style={{
                padding: "36px 20px",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                gap: "12px",
              }}
            >
              <Loader2
                size={28}
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
              style={{ display: "flex", flexDirection: "column", gap: "14px" }}
            >
              {/* Compact Plan Metadata Strip */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "8px 14px",
                  background: "var(--surface)",
                  border: "1px solid var(--border)",
                  borderRadius: "8px",
                  fontSize: "12px",
                  flexWrap: "wrap",
                  gap: "8px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    flexWrap: "wrap",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    <FolderOpen
                      size={14}
                      color={
                        directoryHandle
                          ? "var(--accent-green, #10b981)"
                          : "var(--accent-blue, #3b82f6)"
                      }
                    />
                    <span>
                      {directoryHandle ? (
                        <>
                          <strong>Target Folder:</strong> {directoryHandle.name}
                        </>
                      ) : (
                        <span style={{ color: "var(--muted)" }}>
                          Memory-only session · Local folder unlinked
                        </span>
                      )}
                    </span>
                    {!directoryHandle && (
                      <button
                        type="button"
                        onClick={connectFolder}
                        className="button secondary compact"
                        style={{ fontSize: "10px", padding: "1px 6px" }}
                      >
                        Link folder
                      </button>
                    )}
                  </div>

                  <span style={{ color: "var(--border)" }}>•</span>

                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    <Sparkles
                      size={14}
                      color={
                        consent
                          ? "var(--accent-green, #10b981)"
                          : "var(--muted)"
                      }
                    />
                    <span style={{ color: "var(--muted)" }}>
                      {consent
                        ? "Gemini AI-assisted plan"
                        : "Deterministic local engine"}
                    </span>
                    <button
                      type="button"
                      onClick={() => setShowConsentModal(true)}
                      style={{
                        background: "none",
                        border: "none",
                        color: "var(--muted)",
                        cursor: "pointer",
                        padding: 0,
                        fontSize: "11px",
                        textDecoration: "underline",
                      }}
                    >
                      Privacy
                    </button>
                  </div>
                </div>

                {isGitHubTarget && report.source_metadata?.branch && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      color: "var(--muted)",
                      fontSize: "11px",
                    }}
                  >
                    <GitBranch size={13} />
                    <span>
                      Target: <code>{report.source_metadata.branch}</code>
                    </span>
                  </div>
                )}
              </div>

              {/* GitHub Pull Request Link Banner if applied */}
              {plan.pr_url && (
                <div
                  style={{
                    padding: "10px 14px",
                    background: "rgba(16, 185, 129, 0.1)",
                    border: "1px solid rgba(16, 185, 129, 0.3)",
                    borderRadius: "8px",
                    fontSize: "12px",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: "10px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                    }}
                  >
                    <GitPullRequest size={16} style={{ color: "#10b981" }} />
                    <strong style={{ color: "#10b981" }}>
                      Pull Request #{plan.pr_number} ({plan.pr_state || "open"}
                      ):
                    </strong>
                    <span style={{ color: "var(--text)" }}>
                      Remediation branch <code>{plan.remediation_branch}</code>
                    </span>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                    }}
                  >
                    <a
                      href={plan.pr_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="button primary compact"
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                        textDecoration: "none",
                        fontSize: "12px",
                      }}
                    >
                      <span>View on GitHub</span>
                      <ExternalLink size={12} />
                    </a>
                    {plan.pr_state !== "closed" && (
                      <button
                        onClick={closeGitHubPR}
                        disabled={loading}
                        className="button secondary compact"
                        style={{ fontSize: "12px", color: "#f87171" }}
                      >
                        Close PR
                      </button>
                    )}
                  </div>
                </div>
              )}

              {/* The Enhanced Remediation Plan View with Segmented Tabs */}
              <RemediationPlanView
                plan={plan}
                findings={report.findings}
                verification={verification}
                onFindingClick={onFindingClick}
              />
            </div>
          )}
        </div>

        {/* Pinned Pre-Application Confirmation Sheet (Docked right above footer) */}
        <AnimatePresence>
          {confirmApply && plan && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              style={{
                borderTop: isGitHubTarget
                  ? "1px solid rgba(99, 102, 241, 0.4)"
                  : "1px solid rgba(249, 115, 22, 0.4)",
                background: isGitHubTarget
                  ? "rgba(99, 102, 241, 0.08)"
                  : "rgba(249, 115, 22, 0.08)",
                padding: "12px 20px",
                display: "flex",
                flexDirection: "column",
                gap: "8px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "10px",
                  flexWrap: "wrap",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  {isGitHubTarget ? (
                    <GitPullRequest
                      size={16}
                      color="var(--accent, #6366f1)"
                    />
                  ) : (
                    <GitBranch
                      size={16}
                      color="var(--accent-orange, #f97316)"
                    />
                  )}
                  <strong
                    style={{
                      fontSize: "13px",
                      color: isGitHubTarget
                        ? "var(--accent, #6366f1)"
                        : "var(--accent-orange, #f97316)",
                    }}
                  >
                    {isGitHubTarget
                      ? "Confirm GitHub Pull Request Creation"
                      : "Pre-Application Advisory: Confirm Local Disk Write"}
                  </strong>
                </div>

                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    onClick={isGitHubTarget ? applyGitHubPR : applyPlan}
                    disabled={
                      loading ||
                      (plan.validation_status &&
                        plan.validation_status !== "VERIFIED")
                    }
                    className="button primary compact"
                    style={{
                      background: isGitHubTarget
                        ? "var(--accent, #6366f1)"
                        : "var(--accent-green, #10b981)",
                      borderColor: isGitHubTarget
                        ? "var(--accent, #6366f1)"
                        : "var(--accent-green, #10b981)",
                      opacity:
                        plan.validation_status &&
                        plan.validation_status !== "VERIFIED"
                          ? 0.6
                          : 1,
                      cursor:
                        plan.validation_status &&
                        plan.validation_status !== "VERIFIED"
                          ? "not-allowed"
                          : "pointer",
                      fontSize: "12px",
                      padding: "4px 12px",
                    }}
                  >
                    {isGitHubTarget
                      ? "Confirm & Create Pull Request"
                      : plan.status === "reverted"
                        ? "Confirm & Reapply modifications"
                        : "Confirm & Apply modifications"}
                  </button>
                  <button
                    onClick={() => setConfirmApply(false)}
                    className="button secondary compact"
                    style={{ fontSize: "12px", padding: "4px 10px" }}
                  >
                    Cancel
                  </button>
                </div>
              </div>

              <p
                style={{
                  margin: 0,
                  fontSize: "11px",
                  lineHeight: "1.5",
                  color: "var(--foreground)",
                  opacity: 0.9,
                }}
              >
                {isGitHubTarget ? (
                  <>
                    Guardian Autopilot will create a dedicated remediation branch (
                    <code>
                      guardian/remediation/{plan.plan_id.slice(0, 8)}
                    </code>
                    ) from commit{" "}
                    <code>
                      {(
                        report.source_metadata?.commit_sha ||
                        plan.commit_sha ||
                        ""
                      ).slice(0, 7)}
                    </code>
                    , apply atomic Git modifications, and open a Pull Request
                    against{" "}
                    <code>
                      {report.source_metadata?.branch ||
                        plan.branch ||
                        "main"}
                    </code>
                    . Guardian will never directly push to your default branch or
                    automatically merge.
                  </>
                ) : (
                  <>
                    Guardian will write exact file modifications directly to
                    your local project on disk. A local IndexedDB rollback
                    snapshot will be captured automatically before modification,
                    allowing safe 1-click undo. It is strongly recommended to
                    work on a clean Git branch with untracked files committed.
                  </>
                )}
              </p>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Panel Footer Controls */}
        <div
          style={{
            padding: "12px 20px",
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
                  <RefreshCw
                    size={14}
                    className="inline-flex items-center justify-center"
                  />
                  Regenerate
                </button>
              </>
            )}
            {plan && plan.status === "reverted" && !confirmApply && (
              <button
                onClick={generatePlan}
                disabled={loading}
                className="button secondary compact"
              >
                <RefreshCw
                  size={14}
                  className="inline-flex items-center justify-center"
                />
                Regenerate fresh plan
              </button>
            )}
            {canUndo &&
              directoryHandle &&
              plan &&
              plan.status === "applied" && (
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
                disabled={
                  loading ||
                  (plan.validation_status &&
                    plan.validation_status !== "VERIFIED")
                }
                className="button primary"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  opacity:
                    plan.validation_status &&
                    plan.validation_status !== "VERIFIED"
                      ? 0.6
                      : 1,
                  cursor:
                    plan.validation_status &&
                    plan.validation_status !== "VERIFIED"
                      ? "not-allowed"
                      : "pointer",
                }}
                title={
                  plan.validation_status &&
                  plan.validation_status !== "VERIFIED"
                    ? `Approval blocked: Plan validation is ${plan.validation_status}`
                    : undefined
                }
              >
                {plan.validation_status &&
                plan.validation_status !== "VERIFIED" ? (
                  <>
                    <ShieldAlert size={16} />
                    {plan.validation_status === "UNVERIFIED"
                      ? "Unverified (Application Blocked)"
                      : "Validation Failed (Blocked)"}
                  </>
                ) : isGitHubTarget ? (
                  <>
                    <GitPullRequest size={16} />
                    Approve and Create Pull Request
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={16} />
                    Approve and apply
                  </>
                )}
              </button>
            )}

            {plan &&
              plan.status === "applied" &&
              isGitHubTarget &&
              plan.pr_url && (
                <a
                  href={plan.pr_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="button secondary compact"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "6px",
                    textDecoration: "none",
                  }}
                >
                  <ExternalLink size={14} />
                  Open PR #{plan.pr_number}
                </a>
              )}

            {plan && plan.status === "reverted" && !confirmApply && (
              <button
                onClick={initiateReapply}
                disabled={loading}
                className="button primary"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <CheckCircle2 size={16} />
                Reapply existing plan
              </button>
            )}

            {verification && !loading && (
              <span
                style={{
                  fontSize: "12px",
                  color: "var(--accent-green, #10b981)",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "4px",
                  fontWeight: 500,
                  marginRight: "4px",
                }}
              >
                <CheckCircle2 size={14} />
                Verified: {verification.resolved_findings.length} resolved
              </span>
            )}

            {plan &&
              (plan.status === "applied" || plan.status === "verified") &&
              onRescanRequested && (
                <div
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  {/* Rescan Profile Selector (Fast vs Deep) */}
                  <div
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      background: "var(--surface-2, rgba(255, 255, 255, 0.05))",
                      border:
                        "1px solid var(--border, rgba(255, 255, 255, 0.12))",
                      borderRadius: "6px",
                      padding: "2px",
                      gap: "2px",
                    }}
                    title={
                      rescanProfile === "fast"
                        ? "Fast Profile: Direct dependencies and top-level packages (faster budget)"
                        : "Deep Profile: Up to 20 packages and 4 levels deep (thorough inspection)"
                    }
                  >
                    <button
                      type="button"
                      onClick={() => setRescanProfile("fast")}
                      disabled={loading}
                      aria-label="Set fast rescan profile"
                      style={{
                        padding: "3px 8px",
                        fontSize: "11px",
                        fontWeight: rescanProfile === "fast" ? 600 : 400,
                        borderRadius: "4px",
                        border: "none",
                        cursor: loading ? "not-allowed" : "pointer",
                        background:
                          rescanProfile === "fast"
                            ? "var(--accent, #c5f467)"
                            : "transparent",
                        color:
                          rescanProfile === "fast"
                            ? "var(--on-accent, #111c08)"
                            : "var(--muted, #94a3b8)",
                        transition: "all 0.15s ease",
                      }}
                    >
                      Fast
                    </button>
                    <button
                      type="button"
                      onClick={() => setRescanProfile("deep")}
                      disabled={loading}
                      aria-label="Set deep rescan profile"
                      style={{
                        padding: "3px 8px",
                        fontSize: "11px",
                        fontWeight: rescanProfile === "deep" ? 600 : 400,
                        borderRadius: "4px",
                        border: "none",
                        cursor: loading ? "not-allowed" : "pointer",
                        background:
                          rescanProfile === "deep"
                            ? "var(--accent, #c5f467)"
                            : "transparent",
                        color:
                          rescanProfile === "deep"
                            ? "var(--on-accent, #111c08)"
                            : "var(--muted, #94a3b8)",
                        transition: "all 0.15s ease",
                      }}
                    >
                      Deep
                    </button>
                  </div>

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
                    {loading ? (
                      <>
                        <RefreshCw size={16} className="animate-spin" />
                        <span>Rescanning...</span>
                      </>
                    ) : verification ? (
                      <>
                        <CheckCircle2 size={16} />
                        <span>Rescan & re-verify</span>
                      </>
                    ) : (
                      <>
                        <RefreshCw size={16} />
                        <span>Rescan & verify outcome</span>
                      </>
                    )}
                  </button>
                </div>
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
