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
              put: (backup) => {
                backupStore.set(backup.plan_id, backup);
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

// Import fs-access utilities
const {
  validatePlanFilesForReapplication,
  applyPlanToFileSystem,
  undoPlanFromFileSystem,
  computeBrowserSHA256,
} = await import("../lib/fs-access.ts");

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
    // For single level paths
    return this;
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
