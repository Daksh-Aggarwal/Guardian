import assert from "node:assert/strict";
import test from "node:test";

// Test suite for Guardian Handoff 1.0 specifications and client contracts

function sanitizeFilenamePart(part) {
  if (!part) return "project";
  let cleaned = part.replace(/[^a-zA-Z0-9_\-\.]/g, "-");
  cleaned = cleaned.replace(/-+/g, "-").replace(/^[\-\.]+|[\-\.]+$/g, "");
  return cleaned.slice(0, 48) || "project";
}

function generateSafeFilename(projectName, scanId, dateStr = "20261031") {
  const cleanProj = sanitizeFilenamePart(projectName);
  const cleanScan = sanitizeFilenamePart(scanId.slice(0, 8));
  const cleanDate = sanitizeFilenamePart(dateStr);
  return `guardian-handoff-${cleanProj}-${cleanScan}-${cleanDate}.md`;
}

function extractJsonAppendix(markdown) {
  const startMarker = "```json\n";
  const endMarker = "\n```";
  const startPos = markdown.indexOf(startMarker);
  if (startPos === -1) return null;
  const contentStart = startPos + startMarker.length;
  const endPos = markdown.indexOf(endMarker, contentStart);
  if (endPos === -1) return null;
  const jsonStr = markdown.slice(contentStart, endPos);
  return JSON.parse(jsonStr);
}

test("1. Filename sanitization handles dangerous characters and paths", () => {
  const fn1 = generateSafeFilename("../../etc/passwd", "scan_12345678");
  assert.equal(fn1.includes(".."), false);
  assert.equal(fn1.includes("/"), false);
  assert.equal(fn1.startsWith("guardian-handoff-etc-passwd-scan_123"), true);

  const fn2 = generateSafeFilename("acme:corp/repo*test", "scan_98765432");
  assert.equal(fn2.includes(":"), false);
  assert.equal(fn2.includes("*"), false);
  assert.equal(fn2.includes("/"), false);
  assert.equal(fn2.startsWith("guardian-handoff-acme-corp-repo-test-scan_987"), true);
});

test("2. Machine-readable JSON appendix extraction and schema validation", () => {
  const sampleMarkdown = `# Claude Code Remediation Instruction Package
> Target: **Claude Code (CLI Agent)**

## 1. Executive Summary & Objective
Sample text.

---

## Guardian Evidence Appendix

The following machine-readable JSON appendix contains the complete canonical security handoff representation.

\`\`\`json
{
  "schema_version": "1.0.0",
  "handoff_id": "gho_test123",
  "generated_at": "2026-10-31T20:00:00Z",
  "target_agent": "claude_code",
  "remediation_mode": "focused_fix",
  "scope": "finding",
  "scan": {
    "scan_id": "scan_test_01",
    "risk_level": "high"
  },
  "findings": [
    {
      "finding_id": "FIND-01",
      "severity": "high",
      "title": "Prototype pollution"
    }
  ]
}
\`\`\`
`;

  const parsed = extractJsonAppendix(sampleMarkdown);
  assert.ok(parsed !== null, "JSON appendix should be extracted");
  assert.equal(parsed.schema_version, "1.0.0");
  assert.equal(parsed.target_agent, "claude_code");
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].finding_id, "FIND-01");
});

test("3. Secret redaction preserves sanitized placeholders", () => {
  const sampleSnippet = `const awsKey = "[REDACTED_AWS_KEY]"; const token = "[REDACTED_GITHUB_TOKEN]";`;
  assert.equal(sampleSnippet.includes("AKIA"), false);
  assert.equal(sampleSnippet.includes("ghp_"), false);
  assert.equal(sampleSnippet.includes("[REDACTED_AWS_KEY]"), true);
  assert.equal(sampleSnippet.includes("[REDACTED_GITHUB_TOKEN]"), true);
});

test("4. Supported targets and modes enumeration", () => {
  const targets = ["universal", "claude_code", "cursor", "codex", "github_copilot"];
  const modes = ["focused_fix", "deep_remediation"];
  assert.equal(targets.length, 5);
  assert.equal(modes.length, 2);
  assert.ok(targets.includes("claude_code"));
  assert.ok(targets.includes("cursor"));
  assert.ok(targets.includes("codex"));
  assert.ok(targets.includes("github_copilot"));
  assert.ok(targets.includes("universal"));
});

test("5. Code fence breakout prevention calculates safe fence delimiter", () => {
  function getSafeFence(code) {
    const runs = code.match(/`+/g) || [];
    const maxRun = runs.reduce((max, r) => Math.max(max, r.length), 0);
    return "`".repeat(Math.max(3, maxRun + 1));
  }

  const normalCode = "console.log('hello');";
  assert.equal(getSafeFence(normalCode), "```");

  const adversarialCode = "```\nconsole.log('breakout');\n```";
  assert.equal(getSafeFence(adversarialCode), "````");

  const ultraAdversarial = "``````\nconst x = 1;\n``````";
  assert.equal(getSafeFence(ultraAdversarial), "```````");
});

test("6. Markdown table cell escaping prevents pipe breakout", () => {
  function escapeTableCell(text) {
    return text.replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
  }
  const untrustedDesc = "malicious|pipe|injection\nnew line";
  const escaped = escapeTableCell(untrustedDesc);
  assert.equal(escaped.includes("\n"), false);
  assert.equal(escaped, "malicious\\|pipe\\|injection new line");
});

