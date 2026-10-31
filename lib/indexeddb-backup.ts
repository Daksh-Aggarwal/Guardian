/**
 * Local IndexedDB backup storage for rollback protection and safe undo.
 * Backups remain strictly local in browser storage and are never uploaded.
 */

const DB_NAME = "guardian_remediation_backups";
const DB_VERSION = 1;
const STORE_NAME = "backups";

export type BackupFileEntry = {
  path: string;
  content: string;
  sha256: string;
};

export type RemediationBackup = {
  plan_id: string;
  timestamp: string;
  files: BackupFileEntry[];
};

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof window === "undefined" || !window.indexedDB) {
      reject(
        new Error("IndexedDB is not supported in this browser environment."),
      );
      return;
    }

    const request = window.indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "plan_id" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error || new Error("Failed to open IndexedDB"));
  });
}

export async function saveRemediationBackup(
  backup: RemediationBackup,
): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const req = store.put(backup);

    req.onsuccess = () => resolve();
    req.onerror = () =>
      reject(
        req.error || new Error("Failed to save backup snapshot in IndexedDB."),
      );
  });
}

export async function getRemediationBackup(
  planId: string,
): Promise<RemediationBackup | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(planId);

    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () =>
      reject(
        req.error ||
          new Error("Failed to retrieve backup snapshot from IndexedDB."),
      );
  });
}

export async function deleteRemediationBackup(planId: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const req = store.delete(planId);

    req.onsuccess = () => resolve();
    req.onerror = () =>
      reject(
        req.error ||
          new Error("Failed to delete backup snapshot from IndexedDB."),
      );
  });
}
