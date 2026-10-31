/**
 * Browser File System Access API utilities with safe permission lifecycle,
 * SHA-256 pre-write validation, partial-write rollback, and local undo.
 */

import type { RemediationPlan, ProposedFileChange } from "./types";
import {
  saveRemediationBackup,
  getRemediationBackup,
  type BackupFileEntry,
} from "./indexeddb-backup";

export const MAX_PROJECT_FILES = 250;
export const MAX_FILE_SIZE = 1_048_576; // 1 MB
export const MAX_AGGREGATE_SIZE = 10_485_760; // 10 MB

const EXCLUDED_DIRS = new Set([
  ".git",
  "node_modules",
  ".venv",
  "venv",
  ".next",
  "dist",
  "build",
  "coverage",
  ".cache",
  ".turbo",
  ".vscode",
  ".idea",
  "vendor",
]);

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".svg",
  ".webp",
  ".bmp",
  ".tiff",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".tgz",
  ".rar",
  ".7z",
  ".wasm",
  ".pyc",
  ".exe",
  ".bin",
  ".dll",
  ".so",
  ".dylib",
  ".ttf",
  ".woff",
  ".woff2",
  ".eot",
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".webm",
  ".sqlite",
  ".sqlite3",
  ".db",
]);

const SECRET_PATTERNS = [
  /^\.env(\..+)?$/i,
  /.*\.(pem|key|pfx|p12|pkcs12|crt|cert)$/i,
  /^(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\..+)?$/i,
  /^(credentials|secrets|service-account|serviceAccountKey)\.json$/i,
];

export function isFileSystemAccessSupported(): boolean {
  return typeof window !== "undefined" && "showDirectoryPicker" in window;
}

export async function computeBrowserSHA256(text: string): Promise<string> {
  const enc = new TextEncoder();
  const buffer = await crypto.subtle.digest("SHA-256", enc.encode(text));
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export type ExcludedFileEntry = {
  path: string;
  reason: string;
};

export type ProjectScanStats = {
  totalDiscovered: number;
  eligible: number;
  excluded: number;
  excludedList: ExcludedFileEntry[];
  totalBytes: number;
  projectName: string;
};

export type ProjectDirectoryResult = {
  directoryHandle: FileSystemDirectoryHandle;
  projectName: string;
  files: Record<string, string>; // relativePath -> text content
  fileHandles: Map<string, FileSystemFileHandle>;
  stats: ProjectScanStats;
};

function isSecretFilename(name: string): boolean {
  return SECRET_PATTERNS.some((p) => p.test(name));
}

function hasBinaryExtension(name: string): boolean {
  const dotIdx = name.lastIndexOf(".");
  if (dotIdx === -1) return false;
  return BINARY_EXTENSIONS.has(name.substring(dotIdx).toLowerCase());
}

/**
 * Traverses a local project directory using window.showDirectoryPicker in 'read' mode.
 * Must be triggered by direct user interaction.
 */
export async function openProjectDirectory(): Promise<ProjectDirectoryResult> {
  if (!isFileSystemAccessSupported()) {
    throw new Error(
      "The File System Access API is not supported in this browser. Please use Google Chrome, Microsoft Edge, or a Chromium-based browser, or use archive inspection.",
    );
  }

  // Request directory picker in READ mode only!
  const directoryHandle = await (window as any).showDirectoryPicker({
    mode: "read",
  });

  const projectName = directoryHandle.name || "local-project";
  const files: Record<string, string> = {};
  const fileHandles = new Map<string, FileSystemFileHandle>();
  const excludedList: ExcludedFileEntry[] = [];
  let totalDiscovered = 0;
  let totalBytes = 0;

  async function traverse(
    dirHandle: FileSystemDirectoryHandle,
    currentPath: string,
  ) {
    for await (const entry of (dirHandle as any).values()) {
      totalDiscovered++;
      const relativePath = currentPath
        ? `${currentPath}/${entry.name}`
        : entry.name;

      if (entry.kind === "directory") {
        if (EXCLUDED_DIRS.has(entry.name)) {
          excludedList.push({
            path: relativePath,
            reason: `Excluded standard directory (${entry.name})`,
          });
          continue;
        }
        await traverse(entry as FileSystemDirectoryHandle, relativePath);
      } else if (entry.kind === "file") {
        const fileHandle = entry as FileSystemFileHandle;

        if (isSecretFilename(entry.name)) {
          excludedList.push({
            path: relativePath,
            reason: "Excluded secret or credential file",
          });
          continue;
        }

        if (hasBinaryExtension(entry.name)) {
          excludedList.push({
            path: relativePath,
            reason: "Binary or media asset",
          });
          continue;
        }

        if (Object.keys(files).length >= MAX_PROJECT_FILES) {
          excludedList.push({
            path: relativePath,
            reason: `Exceeded project file ceiling (${MAX_PROJECT_FILES} files)`,
          });
          continue;
        }

        try {
          const file = await fileHandle.getFile();
          if (file.size > MAX_FILE_SIZE) {
            excludedList.push({
              path: relativePath,
              reason: `File size exceeds 1 MB limit (${(file.size / 1024).toFixed(1)} KB)`,
            });
            continue;
          }

          if (totalBytes + file.size > MAX_AGGREGATE_SIZE) {
            excludedList.push({
              path: relativePath,
              reason: "Aggregate project snapshot exceeds 10 MB limit",
            });
            continue;
          }

          const text = await file.text();
          files[relativePath] = text;
          fileHandles.set(relativePath, fileHandle);
          totalBytes += file.size;
        } catch (err) {
          excludedList.push({
            path: relativePath,
            reason: `Could not read as UTF-8 text (${(err as Error).message})`,
          });
        }
      }
    }
  }

  await traverse(directoryHandle, "");

  return {
    directoryHandle,
    projectName,
    files,
    fileHandles,
    stats: {
      totalDiscovered,
      eligible: Object.keys(files).length,
      excluded: excludedList.length,
      excludedList,
      totalBytes,
      projectName,
    },
  };
}

/**
 * Resolves a nested file handle inside a directory handle, creating parent directories if needed.
 */
async function resolveFileHandle(
  root: FileSystemDirectoryHandle,
  relativePath: string,
  create: boolean = false,
): Promise<FileSystemFileHandle> {
  const parts = relativePath.split("/").filter(Boolean);
  const fileName = parts.pop()!;
  let currentDir = root;

  for (const part of parts) {
    currentDir = await currentDir.getDirectoryHandle(part, { create });
  }

  return currentDir.getFileHandle(fileName, { create });
}

/**
 * Applies approved remediation changes sequentially with SHA-256 pre-check and rollback protection.
 */
export async function applyPlanToFileSystem(
  directoryHandle: FileSystemDirectoryHandle,
  plan: RemediationPlan,
): Promise<{ success: boolean; modifiedFiles: string[] }> {
  // 1. Request 'readwrite' permission explicitly
  const permissionStatus = await (directoryHandle as any).requestPermission({
    mode: "readwrite",
  });
  if (permissionStatus !== "granted") {
    throw new Error(
      "Write permission was denied by the user. Proposed changes were not written to disk.",
    );
  }

  // 2. Pre-flight verification: re-read every target file and verify hashes match plan
  const backupEntries: BackupFileEntry[] = [];
  for (const change of plan.proposed_changes) {
    if (change.operation === "update") {
      let handle: FileSystemFileHandle;
      try {
        handle = await resolveFileHandle(
          directoryHandle,
          change.file_path,
          false,
        );
      } catch {
        throw new Error(
          `Target file '${change.file_path}' could not be located on disk. Application aborted.`,
        );
      }

      const file = await handle.getFile();
      const currentText = await file.text();
      const currentHash = await computeBrowserSHA256(currentText);

      if (currentHash !== change.original_sha256) {
        throw new Error(
          `File '${change.file_path}' has changed on disk since the plan was created. ` +
            `Expected SHA-256 ${change.original_sha256.substring(0, 10)}... but found ${currentHash.substring(0, 10)}... ` +
            `Application aborted to protect local edits. Please generate a fresh plan.`,
        );
      }

      backupEntries.push({
        path: change.file_path,
        content: currentText,
        sha256: currentHash,
      });
    }
  }

  // 3. Save backup snapshot in browser IndexedDB before touching disk
  await saveRemediationBackup({
    plan_id: plan.plan_id,
    timestamp: new Date().toISOString(),
    files: backupEntries,
  });

  // 4. Sequentially write modified and created files
  const modifiedFiles: string[] = [];
  try {
    for (const change of plan.proposed_changes) {
      if (change.operation === "update") {
        const handle = await resolveFileHandle(
          directoryHandle,
          change.file_path,
          false,
        );
        const originalText = backupEntries.find(
          (b) => b.path === change.file_path,
        )!.content;

        // Apply edits sequentially
        let updatedText = originalText;
        for (const edit of change.edits) {
          if (!updatedText.includes(edit.old_text)) {
            throw new Error(
              `Anchor text not found during replacement in '${change.file_path}'.`,
            );
          }
          updatedText = updatedText.replace(edit.old_text, edit.new_text);
        }

        // Write to file
        const writable = await (handle as any).createWritable();
        await writable.write(updatedText);
        await writable.close();

        // Verify written hash
        const writtenFile = await handle.getFile();
        const writtenText = await writtenFile.text();
        const writtenHash = await computeBrowserSHA256(writtenText);

        if (writtenHash !== change.proposed_sha256) {
          throw new Error(
            `Hash verification failed after writing '${change.file_path}'. Expected ${change.proposed_sha256.substring(0, 8)}, got ${writtenHash.substring(0, 8)}.`,
          );
        }

        modifiedFiles.push(change.file_path);
      } else if (change.operation === "create") {
        const handle = await resolveFileHandle(
          directoryHandle,
          change.file_path,
          true,
        );
        const content = change.created_content || "";

        const writable = await (handle as any).createWritable();
        await writable.write(content);
        await writable.close();

        const writtenFile = await handle.getFile();
        const writtenText = await writtenFile.text();
        const writtenHash = await computeBrowserSHA256(writtenText);

        if (writtenHash !== change.proposed_sha256) {
          throw new Error(
            `Hash verification failed after creating '${change.file_path}'.`,
          );
        }

        modifiedFiles.push(change.file_path);
      }
    }

    return { success: true, modifiedFiles };
  } catch (err) {
    // 5. Rollback on failure: restore modified files from backup
    let rollbackSuccess = true;
    for (const entry of backupEntries) {
      if (modifiedFiles.includes(entry.path)) {
        try {
          const handle = await resolveFileHandle(
            directoryHandle,
            entry.path,
            false,
          );
          const writable = await (handle as any).createWritable();
          await writable.write(entry.content);
          await writable.close();
        } catch {
          rollbackSuccess = false;
        }
      }
    }

    const rollbackMsg = rollbackSuccess
      ? "All modified files were successfully restored to their original state."
      : "CRITICAL: Some files could not be restored automatically. Review local backups in IndexedDB.";

    throw new Error(
      `Application failed midway (${(err as Error).message}). ${rollbackMsg}`,
    );
  }
}

/**
 * Reverts the latest applied remediation plan using the IndexedDB backup.
 */
export async function undoPlanFromFileSystem(
  directoryHandle: FileSystemDirectoryHandle,
  plan: RemediationPlan,
): Promise<{ success: boolean; restoredFiles: string[] }> {
  const perm = await (directoryHandle as any).requestPermission({
    mode: "readwrite",
  });
  if (perm !== "granted") {
    throw new Error(
      "Write permission is required to undo applied modifications.",
    );
  }

  const backup = await getRemediationBackup(plan.plan_id);
  if (!backup) {
    throw new Error(
      "No local backup snapshot found in IndexedDB for this remediation plan.",
    );
  }

  // Pre-check: verify files still match the post-application state
  for (const change of plan.proposed_changes) {
    if (change.operation === "update") {
      const handle = await resolveFileHandle(
        directoryHandle,
        change.file_path,
        false,
      );
      const file = await handle.getFile();
      const text = await file.text();
      const currentHash = await computeBrowserSHA256(text);

      if (currentHash !== change.proposed_sha256) {
        throw new Error(
          `Cannot safely undo: '${change.file_path}' has been modified since Guardian applied changes. ` +
            `Aborting undo to prevent overwriting your latest manual edits.`,
        );
      }
    }
  }

  // Restore originals
  const restoredFiles: string[] = [];
  for (const entry of backup.files) {
    const handle = await resolveFileHandle(directoryHandle, entry.path, false);
    const writable = await (handle as any).createWritable();
    await writable.write(entry.content);
    await writable.close();

    const file = await handle.getFile();
    const text = await file.text();
    const restoredHash = await computeBrowserSHA256(text);
    if (restoredHash !== entry.sha256) {
      throw new Error(`Restoration verification failed for '${entry.path}'.`);
    }

    restoredFiles.push(entry.path);
  }

  return { success: true, restoredFiles };
}

/**
 * Revalidates all target files against their pre-remediation SHA-256 hashes before reapplication.
 * Throws a descriptive error explaining which files are stale if any have changed or cannot be read.
 */
export async function validatePlanFilesForReapplication(
  directoryHandle: FileSystemDirectoryHandle,
  plan: RemediationPlan,
): Promise<{ valid: boolean; staleFiles: string[] }> {
  const staleFiles: string[] = [];

  for (const change of plan.proposed_changes) {
    if (change.operation === "update") {
      let handle: FileSystemFileHandle;
      try {
        handle = await resolveFileHandle(
          directoryHandle,
          change.file_path,
          false,
        );
      } catch {
        staleFiles.push(
          `'${change.file_path}' (target file not found on disk)`,
        );
        continue;
      }

      try {
        const file = await handle.getFile();
        const currentText = await file.text();
        const currentHash = await computeBrowserSHA256(currentText);

        if (currentHash !== change.original_sha256) {
          staleFiles.push(
            `'${change.file_path}' (expected original SHA-256 ${change.original_sha256.substring(0, 10)}..., found ${currentHash.substring(0, 10)}...)`,
          );
        }
      } catch (err) {
        staleFiles.push(
          `'${change.file_path}' (could not read file: ${(err as Error).message})`,
        );
      }
    } else if (change.operation === "create") {
      try {
        await resolveFileHandle(directoryHandle, change.file_path, false);
        staleFiles.push(
          `'${change.file_path}' (file already exists on disk for create operation)`,
        );
      } catch {
        // Expected: file does not exist
      }
    }
  }

  if (staleFiles.length > 0) {
    throw new Error(
      `Reapplication refused: ${staleFiles.length} file(s) have changed on disk since the plan was undone:\n` +
        staleFiles.map((f) => `• ${f}`).join("\n") +
        `\nAborting reapplication to protect local edits. Please generate a fresh plan.`,
    );
  }

  return { valid: true, staleFiles: [] };
}

/**
 * Generates combined unified diff text for export as a standard .patch file.
 */
export function generatePatchFile(plan: RemediationPlan): string {
  const header = [
    `# Guardian Remediation Patch - Plan ${plan.plan_id}`,
    `# Title: ${plan.title}`,
    `# Date: ${plan.created_at}`,
    `# Findings Addressed: ${plan.findings_addressed.join(", ")}`,
    "",
  ].join("\n");

  const diffs = plan.proposed_changes.map((c) => c.diff).join("\n\n");
  return `${header}\n${diffs}\n`;
}

/**
 * Triggers a browser download of the remediation patch file.
 */
export function downloadPatchFile(plan: RemediationPlan): void {
  const patchContent = generatePatchFile(plan);
  const blob = new Blob([patchContent], { type: "text/x-diff;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `guardian-remediation-${plan.plan_id}.patch`;
  a.click();
  URL.revokeObjectURL(url);
}
