import assert from "node:assert/strict";
import test from "node:test";
import { register } from "node:module";

// Custom loader to resolve extensionless imports in Node
const loaderDataUrl = `data:text/javascript,
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (err) {
    if (specifier.startsWith('.') && !specifier.endsWith('.ts')) {
      return await nextResolve(specifier + '.ts', context);
    }
    throw err;
  }
}
`;
register(loaderDataUrl);

// In-memory IndexedDB mock
const backupStore = new Map();
globalThis.window = {
  indexedDB: {
    open: () => {
      const req = {
        result: {
          objectStoreNames: { contains: () => true },
          transaction: () => ({
            objectStore: () => ({
              getAll: () => {
                const r = { result: Array.from(backupStore.values()) };
                queueMicrotask(() => r.onsuccess?.());
                return r;
              },
              put: (item) => {
                const key = item.id || item.plan_id;
                backupStore.set(key, item);
                const r = {};
                queueMicrotask(() => r.onsuccess?.());
                return r;
              },
              get: (id) => {
                const r = { result: backupStore.get(id) || null };
                queueMicrotask(() => r.onsuccess?.());
                return r;
              },
              delete: (id) => {
                backupStore.delete(id);
                const r = {};
                queueMicrotask(() => r.onsuccess?.());
                return r;
              },
            }),
          }),
        },
      };
      queueMicrotask(() => req.onsuccess?.());
      return req;
    },
  },
};

// Import fs-access utilities and package-utils
const {
  validatePlanFilesForReapplication,
  applyPlanToFileSystem,
  undoPlanFromFileSystem,
  cleanEmptyCreatedDirectories,
  computeBrowserSHA256,
} = await import("../lib/fs-access.ts");

const {
  parsePackageSpecifier,
  extractPackageFromPath,
  normalizeFindingPackage,
  normalizePackageName,
  getFindingSignature,
  compareSemver,
  isValidSemver,
  comparePep440,
  isValidPep440,
  compareVersions,
  compareVersionsSafe,
} = await import("../lib/package-utils.ts");

const { resolveProjectDirectoryId } = await import("../lib/project-identity.ts");

// Mock FileSystemFileHandle & FileSystemDirectoryHandle
class MockFileHandle {
  constructor(name, content, shouldFailWrite = false) {
    this.name = name;
    this.content = content;
    this.shouldFailWrite = shouldFailWrite;
    this.kind = "file";
  }

  async getFile() {
    return {
      name: this.name,
      size: Buffer.byteLength(this.content),
      text: async () => this.content,
    };
  }

  async createWritable() {
    if (this.shouldFailWrite) {
      throw new Error(`Disk write I/O error on '${this.name}'`);
    }
    let buffer = "";
    return {
      write: async (chunk) => {
        buffer += chunk;
      },
      close: async () => {
        this.content = buffer;
      },
    };
  }
}

class MockDirectoryHandle {
  constructor(name = "test-project") {
    this.name = name;
    this.kind = "directory";
    this.files = new Map();
    this.permission = "granted";
  }

  async isSameEntry(other) {
    return this === other;
  }

  async requestPermission({ mode } = {}) {
    return this.permission;
  }

  async getFileHandle(name, { create } = {}) {
    if (this.files.has(name)) {
      return this.files.get(name);
    }
    if (create) {
      const handle = new MockFileHandle(name, "");
      this.files.set(name, handle);
      return handle;
    }
    throw new Error(`File '${name}' not found`);
  }

  async getDirectoryHandle(name, { create } = {}) {
    if (this.files.has(name)) {
      const entry = this.files.get(name);
      return entry;
    }
    if (create) {
      const dir = new MockDirectoryHandle(name);
      this.files.set(name, dir);
      return dir;
    }
    const err = new Error(`Directory '${name}' not found`);
    err.name = "NotFoundError";
    throw err;
  }

  values() {
    const list = Array.from(this.files.values());
    let idx = 0;
    return {
      next: async () => {
        if (idx < list.length) {
          return { value: list[idx++], done: false };
        }
        return { value: undefined, done: true };
      },
    };
  }

  async removeEntry(name, options = {}) {
    if (this.files.has(name)) {
      this.files.delete(name);
      return;
    }
    const err = new Error(`File '${name}' not found`);
    err.name = "NotFoundError";
    throw err;
  }
}

test("1. Reapplication refuses when an affected file's hash has changed", async () => {
  const originalText = '{\n  "dependencies": {\n    "express": "^4.18.2"\n  }\n}';
  const originalHash = await computeBrowserSHA256(originalText);
  const proposedText = '{\n  "dependencies": {\n    "express": "^4.19.2"\n  }\n}';
  const proposedHash = await computeBrowserSHA256(proposedText);

  const plan = {
    plan_id: "plan_test_hash_change",
    scan_id: "scan_1",
    title: "Update express",
    summary: "Update",
    priority: "medium",
    expected_outcome: "Fixed",
    findings_addressed: ["f1"],
    proposed_changes: [
      {
        file_path: "package.json",
        operation: "update",
        original_sha256: originalHash,
        proposed_sha256: proposedHash,
        edits: [{ old_text: "^4.18.2", new_text: "^4.19.2" }],
        diff: "diff",
        rationale: "Upgrade",
        finding_ids: ["f1"],
        expected_result: "Upgraded",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "reverted",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  // Simulate user modifying package.json after undo
  dirHandle.files.set("package.json", new MockFileHandle("package.json", '{\n  "dependencies": {\n    "express": "user-modified"\n  }\n}'));

  await assert.rejects(
    async () => {
      await validatePlanFilesForReapplication(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Reapplication refused/);
      assert.match(err.message, /package\.json/);
      assert.match(err.message, /have changed on disk since the plan was undone/);
      return true;
    }
  );
});

test("2. Reapplication succeeds when affected files match original pre-remediation hashes", async () => {
  const originalText = '{\n  "dependencies": {\n    "express": "^4.18.2"\n  }\n}';
  const originalHash = await computeBrowserSHA256(originalText);
  const proposedText = '{\n  "dependencies": {\n    "express": "^4.19.2"\n  }\n}';
  const proposedHash = await computeBrowserSHA256(proposedText);

  const plan = {
    plan_id: "plan_test_valid",
    scan_id: "scan_1",
    title: "Update express",
    summary: "Update",
    priority: "medium",
    expected_outcome: "Fixed",
    findings_addressed: ["f1"],
    proposed_changes: [
      {
        file_path: "package.json",
        operation: "update",
        original_sha256: originalHash,
        proposed_sha256: proposedHash,
        edits: [{ old_text: "^4.18.2", new_text: "^4.19.2" }],
        diff: "diff",
        rationale: "Upgrade",
        finding_ids: ["f1"],
        expected_result: "Upgraded",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "reverted",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  dirHandle.files.set("package.json", new MockFileHandle("package.json", originalText));

  const result = await validatePlanFilesForReapplication(dirHandle, plan);
  assert.equal(result.valid, true);
  assert.equal(result.staleFiles.length, 0);
});

test("3. Reapplication handles denied filesystem write permission", async () => {
  const originalText = 'console.log("hello");';
  const originalHash = await computeBrowserSHA256(originalText);
  const proposedText = 'console.log("hello world");';
  const proposedHash = await computeBrowserSHA256(proposedText);

  const plan = {
    plan_id: "plan_perm_denied",
    scan_id: "scan_1",
    title: "Hello world",
    summary: "Hello",
    priority: "low",
    expected_outcome: "Better",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "index.js",
        operation: "update",
        original_sha256: originalHash,
        proposed_sha256: proposedHash,
        edits: [{ old_text: '"hello"', new_text: '"hello world"' }],
        diff: "diff",
        rationale: "Change greeting",
        finding_ids: [],
        expected_result: "Changed",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "reverted",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  dirHandle.files.set("index.js", new MockFileHandle("index.js", originalText));
  dirHandle.permission = "denied"; // Permission denied by user

  await assert.rejects(
    async () => {
      await applyPlanToFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Write permission was denied by the user/);
      return true;
    }
  );

  // File on disk was untouched
  const fileHandle = dirHandle.files.get("index.js");
  assert.equal(fileHandle.content, originalText);
});

test("4. Undo refuses when post-application files have changed", async () => {
  const originalText = "foo = 1;";
  const originalHash = await computeBrowserSHA256(originalText);
  const appliedText = "foo = 2;";
  const appliedHash = await computeBrowserSHA256(appliedText);

  const plan = {
    plan_id: "plan_undo_refused",
    scan_id: "scan_1",
    title: "Change foo",
    summary: "Change",
    priority: "low",
    expected_outcome: "Done",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "app.js",
        operation: "update",
        original_sha256: originalHash,
        proposed_sha256: appliedHash,
        edits: [{ old_text: "foo = 1;", new_text: "foo = 2;" }],
        diff: "diff",
        rationale: "Update",
        finding_ids: [],
        expected_result: "Done",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "applied",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  // Simulate user making manual edits after Guardian applied changes
  const userEditedText = "foo = 999; // user manual edit";
  dirHandle.files.set("app.js", new MockFileHandle("app.js", userEditedText));

  // Store backup entry as would be saved during application
  backupStore.set("plan_undo_refused", {
    plan_id: "plan_undo_refused",
    timestamp: new Date().toISOString(),
    files: [{ path: "app.js", content: originalText, sha256: originalHash }],
  });

  await assert.rejects(
    async () => {
      await undoPlanFromFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Cannot safely undo/);
      assert.match(err.message, /has been modified since Guardian applied changes/);
      return true;
    }
  );

  // User's manual edit was preserved intact!
  assert.equal(dirHandle.files.get("app.js").content, userEditedText);
});

test("5. Successful undo restores original files and verifies hashes", async () => {
  const originalText = "export const x = 10;";
  const originalHash = await computeBrowserSHA256(originalText);
  const appliedText = "export const x = 20;";
  const appliedHash = await computeBrowserSHA256(appliedText);

  const plan = {
    plan_id: "plan_undo_success",
    scan_id: "scan_1",
    title: "Update x",
    summary: "Update",
    priority: "low",
    expected_outcome: "Done",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "config.ts",
        operation: "update",
        original_sha256: originalHash,
        proposed_sha256: appliedHash,
        edits: [{ old_text: "10", new_text: "20" }],
        diff: "diff",
        rationale: "Update",
        finding_ids: [],
        expected_result: "Done",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "applied",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  // File currently has applied content
  dirHandle.files.set("config.ts", new MockFileHandle("config.ts", appliedText));

  // Save backup
  backupStore.set("plan_undo_success", {
    plan_id: "plan_undo_success",
    timestamp: new Date().toISOString(),
    files: [{ path: "config.ts", content: originalText, sha256: originalHash }],
  });

  const undoResult = await undoPlanFromFileSystem(dirHandle, plan);
  assert.equal(undoResult.success, true);
  assert.deepEqual(undoResult.restoredFiles, ["config.ts"]);

  // File on disk was restored to original
  assert.equal(dirHandle.files.get("config.ts").content, originalText);
});

test("6. Failed reapplication rolls back safely and does not leave files in partial state", async () => {
  const origFile1 = "file 1 original";
  const origHash1 = await computeBrowserSHA256(origFile1);
  const propFile1 = "file 1 modified";
  const propHash1 = await computeBrowserSHA256(propFile1);

  const origFile2 = "file 2 original";
  const origHash2 = await computeBrowserSHA256(origFile2);
  const propFile2 = "file 2 modified";
  const propHash2 = await computeBrowserSHA256(propFile2);

  const plan = {
    plan_id: "plan_rollback_test",
    scan_id: "scan_1",
    title: "Multi file plan",
    summary: "Multi",
    priority: "high",
    expected_outcome: "Both updated",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "f1.txt",
        operation: "update",
        original_sha256: origHash1,
        proposed_sha256: propHash1,
        edits: [{ old_text: "original", new_text: "modified" }],
        diff: "diff1",
        rationale: "Update 1",
        finding_ids: [],
        expected_result: "Modified 1",
      },
      {
        file_path: "f2.txt",
        operation: "update",
        original_sha256: origHash2,
        proposed_sha256: propHash2,
        edits: [{ old_text: "original", new_text: "modified" }],
        diff: "diff2",
        rationale: "Update 2",
        finding_ids: [],
        expected_result: "Modified 2",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "reverted",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  dirHandle.files.set("f1.txt", new MockFileHandle("f1.txt", origFile1));
  // f2 will fail during createWritable / write
  dirHandle.files.set("f2.txt", new MockFileHandle("f2.txt", origFile2, true));

  await assert.rejects(
    async () => {
      await applyPlanToFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Application failed midway/);
      assert.match(err.message, /restored to their original state/);
      return true;
    }
  );

  // File 1 was rolled back to original content
  assert.equal(dirHandle.files.get("f1.txt").content, origFile1);
  // File 2 is also at original content
  assert.equal(dirHandle.files.get("f2.txt").content, origFile2);
});

test("7. Undo removes newly created files from disk while restoring updated files", async () => {
  const origUpdated = 'console.log("existing");';
  const propUpdated = 'console.log("existing safe");';
  const origHashUpdated = await computeBrowserSHA256(origUpdated);
  const propHashUpdated = await computeBrowserSHA256(propUpdated);

  const createdContent = 'export const helper = () => true;\n';
  const createdHash = await computeBrowserSHA256(createdContent);

  const plan = {
    plan_id: "plan_test_create_and_undo",
    scan_id: "scan_create_undo",
    title: "Create helper and update existing",
    summary: "Create and update",
    priority: "medium",
    expected_outcome: "Fixed",
    findings_addressed: ["f1", "f2"],
    proposed_changes: [
      {
        file_path: "existing.js",
        operation: "update",
        original_sha256: origHashUpdated,
        proposed_sha256: propHashUpdated,
        edits: [{ old_text: '"existing"', new_text: '"existing safe"' }],
        diff: "diff-existing",
        rationale: "Sanitize existing",
        finding_ids: ["f1"],
        expected_result: "Sanitized",
      },
      {
        file_path: "new_helper.js",
        operation: "create",
        original_sha256: "",
        proposed_sha256: createdHash,
        edits: [],
        diff: "diff-new-helper",
        rationale: "Add helper module",
        finding_ids: ["f2"],
        expected_result: "Created helper module",
        created_content: createdContent,
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "approved",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  dirHandle.files.set("existing.js", new MockFileHandle("existing.js", origUpdated));

  // Ensure new_helper.js does not exist initially
  assert.equal(dirHandle.files.has("new_helper.js"), false);

  // 1. Apply plan
  const applyRes = await applyPlanToFileSystem(dirHandle, plan);
  assert.equal(applyRes.success, true);
  assert.equal(applyRes.modifiedFiles.length, 2);
  assert.equal(dirHandle.files.get("existing.js").content, propUpdated);
  assert.equal(dirHandle.files.has("new_helper.js"), true);
  assert.equal(dirHandle.files.get("new_helper.js").content, createdContent);

  // 2. Undo plan
  const undoRes = await undoPlanFromFileSystem(dirHandle, plan);
  assert.equal(undoRes.success, true);
  assert.equal(undoRes.restoredFiles.length, 2);
  assert.ok(undoRes.restoredFiles.includes("existing.js"));
  assert.ok(undoRes.restoredFiles.includes("new_helper.js"));

  // Check filesystem: existing.js restored, new_helper.js removed!
  assert.equal(dirHandle.files.get("existing.js").content, origUpdated);
  assert.equal(dirHandle.files.has("new_helper.js"), false);
});

test("8. Undo refuses if a newly created file was modified after application", async () => {
  const createdContent = 'export const safeConfig = { secure: true };\n';
  const createdHash = await computeBrowserSHA256(createdContent);

  const plan = {
    plan_id: "plan_test_create_modified_undo",
    scan_id: "scan_create_mod",
    title: "Create safe config",
    summary: "Create config",
    priority: "high",
    expected_outcome: "Created",
    findings_addressed: ["f1"],
    proposed_changes: [
      {
        file_path: "safe-config.js",
        operation: "create",
        original_sha256: "",
        proposed_sha256: createdHash,
        edits: [],
        diff: "diff",
        rationale: "Add safe config",
        finding_ids: ["f1"],
        expected_result: "Created",
        created_content: createdContent,
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "approved",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();

  // Apply plan
  await applyPlanToFileSystem(dirHandle, plan);
  assert.equal(dirHandle.files.has("safe-config.js"), true);

  // User manually edits safe-config.js after Guardian created it
  dirHandle.files.get("safe-config.js").content = '// User manual comment\n' + createdContent;

  // Undo must refuse
  await assert.rejects(
    async () => {
      await undoPlanFromFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Cannot safely undo/);
      assert.match(err.message, /Created file 'safe-config.js' has been modified/);
      return true;
    }
  );

  // File was NOT removed because undo was aborted to protect user's manual edits
  assert.equal(dirHandle.files.has("safe-config.js"), true);
});

test("9. Failed application rolls back newly created files written midway", async () => {
  const createdContent = 'const helper = "temp";';
  const createdHash = await computeBrowserSHA256(createdContent);

  const origFile2 = "hello world";
  const origHash2 = await computeBrowserSHA256(origFile2);
  const propHash2 = await computeBrowserSHA256("hello modified");

  const plan = {
    plan_id: "plan_test_create_midway_rollback",
    scan_id: "scan_midway",
    title: "Create file then fail on next update",
    summary: "Rollback test",
    priority: "high",
    expected_outcome: "Clean rollback",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "created_temp.js",
        operation: "create",
        original_sha256: "",
        proposed_sha256: createdHash,
        edits: [],
        diff: "diff",
        rationale: "Create helper",
        finding_ids: [],
        expected_result: "Created",
        created_content: createdContent,
      },
      {
        file_path: "f2.txt",
        operation: "update",
        original_sha256: origHash2,
        proposed_sha256: propHash2,
        edits: [{ old_text: "world", new_text: "modified" }],
        diff: "diff2",
        rationale: "Update",
        finding_ids: [],
        expected_result: "Updated",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "approved",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  // f2 will fail during write
  dirHandle.files.set("f2.txt", new MockFileHandle("f2.txt", origFile2, true));

  await assert.rejects(
    async () => {
      await applyPlanToFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Application failed midway/);
      return true;
    }
  );

  // created_temp.js was written before f2 threw, but rollback removed it!
  assert.equal(dirHandle.files.has("created_temp.js"), false);
  // f2 remains untouched
  assert.equal(dirHandle.files.get("f2.txt").content, origFile2);
});

test("10. Reapplication succeeds after undoing a plan containing newly created files", async () => {
  const createdContent = 'module.exports = { secure: true };';
  const createdHash = await computeBrowserSHA256(createdContent);

  const plan = {
    plan_id: "plan_test_create_reapply",
    scan_id: "scan_create_reapply",
    title: "Create security module",
    summary: "Reapplication test with create",
    priority: "medium",
    expected_outcome: "Created and reapplied",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "security.js",
        operation: "create",
        original_sha256: "",
        proposed_sha256: createdHash,
        edits: [],
        diff: "diff",
        rationale: "Add security module",
        finding_ids: [],
        expected_result: "Security module present",
        created_content: createdContent,
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "reverted",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();

  // 1. Initial apply
  await applyPlanToFileSystem(dirHandle, plan);
  assert.equal(dirHandle.files.has("security.js"), true);

  // 2. Undo
  await undoPlanFromFileSystem(dirHandle, plan);
  assert.equal(dirHandle.files.has("security.js"), false);

  // 3. Reapplication pre-check validation passes because created file was cleaned up on undo
  const validation = await validatePlanFilesForReapplication(dirHandle, plan);
  assert.equal(validation.valid, true);
  assert.equal(validation.staleFiles.length, 0);

  // 4. Reapplication succeeds
  const reapplyRes = await applyPlanToFileSystem(dirHandle, plan);
  assert.equal(reapplyRes.success, true);
  assert.equal(dirHandle.files.has("security.js"), true);
  assert.equal(dirHandle.files.get("security.js").content, createdContent);
});

test("11. Write succeeds but verification fails: touched file is rolled back and hash verified", async () => {
  const origText = 'const x = 1;';
  const origHash = await computeBrowserSHA256(origText);
  // Intentional fake proposed hash to trigger post-write hash verification failure
  const fakePropHash = "0000000000000000000000000000000000000000000000000000000000000000";

  const plan = {
    plan_id: "plan_test_verify_fail",
    scan_id: "scan_verify_fail",
    title: "Verify fail test",
    summary: "Verification failure",
    priority: "medium",
    expected_outcome: "Rolled back",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "index.js",
        operation: "update",
        original_sha256: origHash,
        proposed_sha256: fakePropHash,
        edits: [{ old_text: "const x = 1;", new_text: "const x = 2;" }],
        diff: "diff",
        rationale: "Update",
        finding_ids: [],
        expected_result: "Updated",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "approved",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  dirHandle.files.set("index.js", new MockFileHandle("index.js", origText));

  await assert.rejects(
    async () => {
      await applyPlanToFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Hash verification failed/);
      assert.match(err.message, /All modified and created files were successfully restored/);
      return true;
    }
  );

  // File was written with 'const x = 2;', but verification threw and rollback restored 'const x = 1;'!
  assert.equal(dirHandle.files.get("index.js").content, origText);
  const currentHash = await computeBrowserSHA256(dirHandle.files.get("index.js").content);
  assert.equal(currentHash, origHash);
});

test("12. Multi-file partial write failure restores all touched files and removes created files", async () => {
  const orig1 = 'console.log("file1");';
  const orig2 = 'console.log("file2");';
  const origHash1 = await computeBrowserSHA256(orig1);
  const origHash2 = await computeBrowserSHA256(orig2);
  const prop1 = 'console.log("file1_mod");';
  const propHash1 = await computeBrowserSHA256(prop1);
  const createdContent = 'console.log("new_helper");';
  const createdHash = await computeBrowserSHA256(createdContent);

  const plan = {
    plan_id: "plan_multi_fail",
    scan_id: "scan_multi_fail",
    title: "Multi file apply with middle failure",
    summary: "Multi-file failure test",
    priority: "high",
    expected_outcome: "Full rollback",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "file1.js",
        operation: "update",
        original_sha256: origHash1,
        proposed_sha256: propHash1,
        edits: [{ old_text: 'console.log("file1");', new_text: 'console.log("file1_mod");' }],
        diff: "diff1",
        rationale: "Update 1",
        finding_ids: [],
        expected_result: "Updated 1",
      },
      {
        file_path: "helper.js",
        operation: "create",
        original_sha256: "",
        proposed_sha256: createdHash,
        edits: [],
        diff: "diff_create",
        rationale: "Create helper",
        finding_ids: [],
        expected_result: "Created",
        created_content: createdContent,
      },
      {
        file_path: "file2.js",
        operation: "update",
        original_sha256: origHash2,
        proposed_sha256: "some_hash",
        edits: [{ old_text: 'console.log("file2");', new_text: 'console.log("file2_mod");' }],
        diff: "diff2",
        rationale: "Update 2",
        finding_ids: [],
        expected_result: "Updated 2",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "approved",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  dirHandle.files.set("file1.js", new MockFileHandle("file1.js", orig1));
  // file2 will fail on write
  dirHandle.files.set("file2.js", new MockFileHandle("file2.js", orig2, true));

  await assert.rejects(
    async () => {
      await applyPlanToFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Disk write I\/O error on 'file2.js'/);
      assert.match(err.message, /All modified and created files were successfully restored/);
      return true;
    }
  );

  // file1.js was restored to original content
  assert.equal(dirHandle.files.get("file1.js").content, orig1);
  assert.equal(await computeBrowserSHA256(dirHandle.files.get("file1.js").content), origHash1);
  // helper.js was removed from directory
  assert.equal(dirHandle.files.has("helper.js"), false);
  // file2.js is untouched
  assert.equal(dirHandle.files.get("file2.js").content, orig2);
});

test("13. Rollback encountering write failure reports incomplete rollback with actionable message", async () => {
  const origText = 'console.log("safe");';
  const origHash = await computeBrowserSHA256(origText);
  const propText = 'console.log("updated");';
  const propHash = await computeBrowserSHA256(propText);
  const f2Text = 'console.log("f2");';
  const f2Hash = await computeBrowserSHA256(f2Text);
  const f2PropText = 'console.log("f2_mod");';
  const f2PropHash = await computeBrowserSHA256(f2PropText);

  const plan = {
    plan_id: "plan_rollback_fail",
    scan_id: "scan_rollback_fail",
    title: "Rollback fail test",
    summary: "Simulate failure during rollback write",
    priority: "critical",
    expected_outcome: "Reports critical rollback failure",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "f1.js",
        operation: "update",
        original_sha256: origHash,
        proposed_sha256: propHash,
        edits: [{ old_text: 'console.log("safe");', new_text: 'console.log("updated");' }],
        diff: "diff1",
        rationale: "Update",
        finding_ids: [],
        expected_result: "Updated",
      },
      {
        file_path: "f2.js",
        operation: "update",
        original_sha256: f2Hash,
        proposed_sha256: f2PropHash,
        edits: [{ old_text: 'console.log("f2");', new_text: 'console.log("f2_mod");' }],
        diff: "diff2",
        rationale: "Update",
        finding_ids: [],
        expected_result: "Updated",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "approved",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  const f1Handle = new MockFileHandle("f1.js", origText);
  dirHandle.files.set("f1.js", f1Handle);
  // f2 triggers failure during apply
  dirHandle.files.set("f2.js", new MockFileHandle("f2.js", f2Text, true));

  // Now make f1 fail during subsequent rollback write
  const originalCreateWritable = f1Handle.createWritable.bind(f1Handle);
  let callCount = 0;
  f1Handle.createWritable = async function () {
    callCount++;
    if (callCount === 2) {
      // Second call is during rollback!
      throw new Error("Disk hardware failure during rollback restoration");
    }
    return originalCreateWritable();
  };

  await assert.rejects(
    async () => {
      await applyPlanToFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /CRITICAL: Some files could not be restored automatically/);
      assert.match(err.message, /f1\.js/);
      return true;
    }
  );

  // Backup snapshot in IndexedDB is still preserved for user recovery!
  assert.equal(backupStore.has("plan_rollback_fail"), true);
});

test("14. Failure during multi-file undo reports partial undo and preserves backup", async () => {
  const orig1 = "orig 1";
  const orig2 = "orig 2";
  const prop1 = "prop 1";
  const prop2 = "prop 2";
  const propHash1 = await computeBrowserSHA256(prop1);
  const propHash2 = await computeBrowserSHA256(prop2);
  const origHash1 = await computeBrowserSHA256(orig1);
  const origHash2 = await computeBrowserSHA256(orig2);

  const plan = {
    plan_id: "plan_undo_fail",
    scan_id: "scan_undo_fail",
    title: "Undo fail test",
    summary: "Undo partial write failure",
    priority: "medium",
    expected_outcome: "Handles undo failure",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "u1.txt",
        operation: "update",
        original_sha256: origHash1,
        proposed_sha256: propHash1,
        edits: [{ old_text: orig1, new_text: prop1 }],
        diff: "d1",
        rationale: "U1",
        finding_ids: [],
        expected_result: "P1",
      },
      {
        file_path: "u2.txt",
        operation: "update",
        original_sha256: origHash2,
        proposed_sha256: propHash2,
        edits: [{ old_text: orig2, new_text: prop2 }],
        diff: "d2",
        rationale: "U2",
        finding_ids: [],
        expected_result: "P2",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "applied",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  dirHandle.files.set("u1.txt", new MockFileHandle("u1.txt", prop1));
  // u2 will fail when written during undo
  dirHandle.files.set("u2.txt", new MockFileHandle("u2.txt", prop2, true));

  // Seed backup in IndexedDB
  backupStore.set("plan_undo_fail", {
    plan_id: "plan_undo_fail",
    timestamp: new Date().toISOString(),
    files: [
      { path: "u1.txt", content: orig1, sha256: origHash1 },
      { path: "u2.txt", content: orig2, sha256: origHash2 },
    ],
    createdFiles: [],
  });

  await assert.rejects(
    async () => {
      await undoPlanFromFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Undo failed for files/);
      assert.match(err.message, /u2\.txt/);
      assert.match(err.message, /Partial undo restored: \[u1\.txt\]/);
      return true;
    }
  );

  // u1 was restored
  assert.equal(dirHandle.files.get("u1.txt").content, orig1);
});

test("15. Scoped npm package normalization handles all variants", () => {
  // Scoped with version
  const p1 = parsePackageSpecifier("@babel/core@7.26.0");
  assert.equal(p1.name, "@babel/core");
  assert.equal(p1.version, "7.26.0");

  // Scoped without version
  const p2 = parsePackageSpecifier("@types/node");
  assert.equal(p2.name, "@types/node");
  assert.equal(p2.version, null);

  // Scoped with multiple '@' in version/tag
  const p3 = parsePackageSpecifier("@tanstack/react-query@5.0.0-beta@2");
  assert.equal(p3.name, "@tanstack/react-query");
  assert.equal(p3.version, "5.0.0-beta@2");

  // Unscoped with version
  const p4 = parsePackageSpecifier("lodash@4.17.21");
  assert.equal(p4.name, "lodash");
  assert.equal(p4.version, "4.17.21");

  // Unscoped bare name
  const p5 = parsePackageSpecifier("express");
  assert.equal(p5.name, "express");
  assert.equal(p5.version, null);

  // Path extraction: scoped package in node_modules
  const fromPath1 = extractPackageFromPath("node_modules/@babel/core/lib/index.js");
  assert.equal(fromPath1, "@babel/core");

  // Path extraction: nested node_modules
  const fromPath2 = extractPackageFromPath("node_modules/parent/node_modules/@scope/child/index.js");
  assert.equal(fromPath2, "@scope/child");

  // Path extraction: unscoped package in nested node_modules
  const fromPath3 = extractPackageFromPath("a/node_modules/b/node_modules/express/lib/view.js");
  assert.equal(fromPath3, "express");

  // Finding normalization
  const fScoped = { package: "@babel/core@7.26.0" };
  assert.equal(normalizeFindingPackage(fScoped), "@babel/core");

  const fEvidence = { evidence: [{ file: "node_modules/@tanstack/react-query/build/index.js" }] };
  assert.equal(normalizeFindingPackage(fEvidence), "@tanstack/react-query");
});

test("16. Security timeline finding signatures and dependency comparison", () => {
  // Vulnerability finding signature prioritizes advisory ID and package
  const fVuln = {
    id: "f_1",
    rule: "OSV",
    title: "Arbitrary code execution",
    package: "@babel/core@7.26.0",
    advisory: { id: "GHSA-67hx-6x53-jw92", summary: "Title" },
    evidence: [],
    references: [],
    severity: "high",
    category: "Vulnerability",
    confidence: "high",
    observed: "",
    explanation: "",
    implication: "",
    recommendation: "",
  };
  const sigVuln = getFindingSignature(fVuln);
  assert.equal(sigVuln, "vuln:GHSA-67hx-6x53-jw92:@babel/core");

  // Behavioral finding signature uses rule + package + evidence file
  const fBehav = {
    id: "f_2",
    rule: "PROCESS_EXEC",
    title: "Spawn child process",
    package: "my-package",
    evidence: [{ file: "src/installer.js", line: 12, snippet: "" }],
    references: [],
    severity: "critical",
    category: "Behavior",
    confidence: "high",
    observed: "",
    explanation: "",
    implication: "",
    recommendation: "",
  };
  const sigBehav = getFindingSignature(fBehav);
  assert.equal(sigBehav, "behavior:PROCESS_EXEC:my-package:src/installer.js");

  // Version comparison
  assert.equal(compareSemver("4.17.21", "4.17.20"), 1); // upgraded
  assert.equal(compareSemver("4.17.19", "4.17.20"), -1); // downgraded
  assert.equal(compareSemver("1.0.0", "1.0.0"), 0); // unchanged
  assert.equal(compareSemver("2.0.0-beta.2", "2.0.0-beta.1"), 1);
});

test("17. SemVer 2.0.0 prerelease ordering according to official specification", () => {
  // Numeric prerelease comparisons: 10 vs 2 must compare numerically, not lexically
  assert.equal(compareSemver("2.0.0-alpha.10", "2.0.0-alpha.2"), 1);
  assert.equal(compareSemver("2.0.0-alpha.2", "2.0.0-alpha.10"), -1);

  // Normal version vs prerelease: normal version has higher precedence
  assert.equal(compareSemver("2.0.0", "2.0.0-rc.1"), 1);
  assert.equal(compareSemver("2.0.0-rc.1", "2.0.0"), -1);

  // Differing number of prerelease fields: larger set has higher precedence
  assert.equal(compareSemver("1.0.0-beta.1", "1.0.0-beta"), 1);
  assert.equal(compareSemver("1.0.0-beta", "1.0.0-beta.1"), -1);

  // Numeric identifier has lower precedence than non-numeric identifier
  assert.equal(compareSemver("1.0.0-alpha.1", "1.0.0-alpha.beta"), -1);
  assert.equal(compareSemver("1.0.0-alpha.beta", "1.0.0-alpha.1"), 1);

  // Build metadata is stripped and ignored for precedence
  assert.equal(compareSemver("1.0.0+001", "1.0.0+20130313144700"), 0);
  assert.equal(compareSemver("1.0.0-beta+exp.sha.5114f85", "1.0.0-beta"), 0);

  // Invalid / partial version handling
  assert.equal(compareSemver(null, "1.0.0"), -1);
  assert.equal(compareSemver("1.0.0", null), 1);
  assert.equal(compareSemver(null, null), 0);
});

test("18. Ecosystem-aware package normalization", () => {
  // npm: preserves scoped prefixes and internal dashes/underscores
  assert.equal(normalizePackageName("@babel/core", "npm"), "@babel/core");
  assert.equal(normalizePackageName("@Types/Node", "npm"), "@types/Node");
  assert.equal(normalizePackageName("lodash_core", "npm"), "lodash_core");

  // PyPI: follows PEP 503 normalization (lowercase, replaces runs of [-_.]+ with single -)
  assert.equal(normalizePackageName("Flask_RESTful", "pypi"), "flask-restful");
  assert.equal(normalizePackageName("oslo.config", "pypi"), "oslo-config");
  assert.equal(normalizePackageName("ruamel.yaml--clib", "pypi"), "ruamel-yaml-clib");
});

test("19. Rollback and cleanup of empty newly-created directories", async () => {
  // Create a mock hierarchy: root -> src -> components
  const createdDirs = ["src/components", "src"];
  const subDir = new MockDirectoryHandle("components");
  const parentDir = new MockDirectoryHandle("src");
  parentDir.files.set("components", subDir);

  const rootDir = new MockDirectoryHandle("root");
  rootDir.files.set("src", parentDir);

  // Directory is currently empty (subDir has no files)
  const cleaned = await cleanEmptyCreatedDirectories(rootDir, createdDirs);
  assert.ok(cleaned.includes("src/components"));
});

test("20. Undo error classification rejects permission errors rather than assuming file absence", async () => {
  const plan = {
    plan_id: "plan_perm_test",
    scan_id: "scan_perm",
    title: "Permission test",
    summary: "Test",
    priority: "low",
    expected_outcome: "Done",
    findings_addressed: [],
    proposed_changes: [
      {
        file_path: "secret.js",
        operation: "create",
        original_sha256: "",
        proposed_sha256: "somehash",
        edits: [],
        diff: "",
        rationale: "",
        finding_ids: [],
        expected_result: "",
      },
    ],
    tradeoffs: [],
    potential_risks: [],
    assumptions: [],
    manual_steps: [],
    recommended_verification: [],
    limitations: [],
    status: "applied",
    created_at: new Date().toISOString(),
  };

  const dirHandle = new MockDirectoryHandle();
  // Override getFileHandle to simulate a permission / security denial
  dirHandle.getFileHandle = async () => {
    const err = new Error("The request is not allowed by the user agent or the platform in the current context.");
    err.name = "NotAllowedError";
    throw err;
  };

  backupStore.set("plan_perm_test", {
    plan_id: "plan_perm_test",
    timestamp: new Date().toISOString(),
    files: [],
    createdFiles: ["secret.js"],
  });

  await assert.rejects(
    async () => {
      await undoPlanFromFileSystem(dirHandle, plan);
    },
    (err) => {
      assert.match(err.message, /Cannot safely undo/);
      assert.match(err.message, /NotAllowedError/);
      return true;
    }
  );
});

test("21. Strict SemVer 2.0.0 validation and comparison", () => {
  // Prerelease ordering
  assert.equal(compareSemver("1.0.0-alpha.2", "1.0.0-alpha.10"), -1);
  assert.equal(compareSemver("1.0.0-beta", "1.0.0-beta.1"), -1);
  assert.equal(compareSemver("1.0.0-rc.1", "1.0.0"), -1);
  assert.equal(compareSemver("1.0.0", "1.0.0-rc.1"), 1);

  // Build metadata equality (stripped and ignored)
  assert.equal(compareSemver("1.0.0+build1", "1.0.0+build2"), 0);

  // Rejection of range operators
  assert.throws(() => compareSemver("^1.2.3", "1.2.3"), TypeError);
  assert.throws(() => compareSemver("~1.2.3", "1.2.3"), TypeError);
  assert.throws(() => compareSemver(">=1.2.3", "1.2.3"), TypeError);

  // Leading 'v' rejected by default unless allowLeadingV is set
  assert.throws(() => compareSemver("v1.2.3", "1.2.3"), TypeError);
  assert.equal(compareSemver("v1.2.3", "1.2.3", { allowLeadingV: true }), 0);
});

test("22. PEP 440 PyPI parsing, normalization, and ordering", () => {
  // Trailing zero normalization in release segment (1.0.0 == 1.0)
  assert.equal(comparePep440("1.0.0", "1.0"), 0);
  assert.equal(comparePep440("2.1.0", "2.1"), 0);
  assert.equal(comparePep440("2.1.1", "2.1"), 1);

  // Epoch comparison
  assert.equal(comparePep440("1!1.0", "2.0"), 1);

  // Pre-release tag ordering: a < b < rc < final
  assert.equal(comparePep440("1.0a1", "1.0b1"), -1);
  assert.equal(comparePep440("1.0b1", "1.0rc1"), -1);
  assert.equal(comparePep440("1.0rc1", "1.0"), -1);

  // Post release > final
  assert.equal(comparePep440("1.0.post1", "1.0"), 1);

  // Dev release < final
  assert.equal(comparePep440("1.0.dev1", "1.0"), -1);

  // Local version
  assert.equal(comparePep440("1.0+local1", "1.0"), 1);

  // Rejection of invalid / range specifiers
  assert.throws(() => comparePep440("==1.0", "1.0"), TypeError);
  assert.throws(() => comparePep440(">=1.0", "1.0"), TypeError);
  assert.throws(() => comparePep440("^1.0", "1.0"), TypeError);
});

test("23. Ecosystem-aware version comparison & safety", () => {
  // npm ecosystem uses SemVer
  assert.equal(compareVersions("1.0.0-rc.1", "1.0.0", "npm"), -1);
  // PyPI ecosystem uses PEP 440
  assert.equal(compareVersions("1.0.0", "1.0", "pypi"), 0);
  assert.equal(compareVersions("1.0a1", "1.0", "pypi"), -1);

  // compareVersionsSafe does not throw on invalid/range versions
  assert.doesNotThrow(() => compareVersionsSafe("^1.2.3", "1.2.3", "npm"));
  assert.doesNotThrow(() => compareVersionsSafe(">=2.0.0", "1.0.0", "pypi"));
});

test("24. Local project identity isolation using FileSystemDirectoryHandle.isSameEntry", async () => {
  // Two distinct directory handles with the same folder name "backend"
  const dirHandleA = new MockDirectoryHandle("backend");
  const dirHandleB = new MockDirectoryHandle("backend");

  const idA = await resolveProjectDirectoryId(dirHandleA, "backend");
  const idB = await resolveProjectDirectoryId(dirHandleB, "backend");

  // Distinct directories MUST receive distinct project IDs
  assert.notEqual(idA, idB);
  assert.match(idA, /^proj_loc_backend_/);
  assert.match(idB, /^proj_loc_backend_/);

  // Reopening the same directory handle reuses the existing persistent project ID
  const idA_reopened = await resolveProjectDirectoryId(dirHandleA, "backend");
  assert.equal(idA_reopened, idA);
});
