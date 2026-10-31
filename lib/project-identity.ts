/**
 * Persistent project identity management for local filesystem directories.
 * Eliminates folder-name collisions by leveraging FileSystemDirectoryHandle.isSameEntry()
 * stored in IndexedDB to verify directory entry identity rather than relying on folder display names.
 */

const REGISTRY_DB_NAME = "guardian_project_registry";
const REGISTRY_DB_VERSION = 1;
const REGISTRY_STORE = "directory_handles";

export interface RegisteredProjectHandle {
  id: string;
  name: string;
  handle?: FileSystemDirectoryHandle;
  registeredAt: string;
  lastOpenedAt: string;
}

function openRegistryDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof window === "undefined" || !window.indexedDB) {
      reject(new Error("IndexedDB is not supported in this environment."));
      return;
    }
    const req = window.indexedDB.open(REGISTRY_DB_NAME, REGISTRY_DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(REGISTRY_STORE)) {
        db.createObjectStore(REGISTRY_STORE, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("Failed to open project registry DB."));
  });
}

/**
 * Resolves a stable, collision-free project ID for a local directory handle.
 * 1. Checks existing registered directory handles using handle.isSameEntry().
 * 2. If an exact match is found, returns the directory's persistent ID.
 * 3. If no match is found, assigns a new unique ID and registers the directory handle.
 * 4. Fallback: If isSameEntry() is unavailable, assigns an independent ID per session
 *    to prevent merging distinct directories with identical folder names.
 */
export async function resolveProjectDirectoryId(
  directoryHandle: FileSystemDirectoryHandle,
  projectName: string,
  existingProjectId?: string | null
): Promise<string> {
  // If a known valid project ID was already associated with this scan session, preserve it
  if (existingProjectId) {
    return existingProjectId;
  }

  const sanitized = projectName.replace(/[^a-zA-Z0-9_-]/g, "_").toLowerCase() || "dir";

  try {
    const db = await openRegistryDB();
    const entries: RegisteredProjectHandle[] = await new Promise((resolve, reject) => {
      const tx = db.transaction(REGISTRY_STORE, "readonly");
      const store = tx.objectStore(REGISTRY_STORE);
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });

    // Check if any registered handle matches the current directory handle
    for (const entry of entries) {
      if (entry.handle && typeof (entry.handle as any).isSameEntry === "function") {
        try {
          const isSame = await (directoryHandle as any).isSameEntry(entry.handle);
          if (isSame) {
            // Reopening the same directory: refresh lastOpened timestamp and update handle reference
            const updated: RegisteredProjectHandle = {
              ...entry,
              name: projectName,
              handle: directoryHandle,
              lastOpenedAt: new Date().toISOString(),
            };
            const writeTx = db.transaction(REGISTRY_STORE, "readwrite");
            writeTx.objectStore(REGISTRY_STORE).put(updated);
            return entry.id;
          }
        } catch {
          // If isSameEntry throws (e.g. permission check), continue checking remaining entries
        }
      }
    }

    // No existing handle matched: generate a new unique, collision-proof project ID
    const randomSuffix = Math.random().toString(36).substring(2, 10);
    const newId = `proj_loc_${sanitized}_${randomSuffix}`;

    const newRecord: RegisteredProjectHandle = {
      id: newId,
      name: projectName,
      handle: directoryHandle,
      registeredAt: new Date().toISOString(),
      lastOpenedAt: new Date().toISOString(),
    };

    const writeTx = db.transaction(REGISTRY_STORE, "readwrite");
    writeTx.objectStore(REGISTRY_STORE).put(newRecord);

    return newId;
  } catch (err) {
    // Safe fallback when IndexedDB is unavailable: generate a unique random ID
    // (Never reuse a name-based ID to ensure folders with identical names do not collide)
    const randomSuffix = Math.random().toString(36).substring(2, 10);
    return `proj_loc_${sanitized}_${randomSuffix}`;
  }
}
