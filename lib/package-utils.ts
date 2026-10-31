import type { Finding } from "./types";

export interface PackageSpecifier {
  name: string;
  version: string | null;
}

/**
 * Normalizes npm package specifiers or finding package strings into { name, version }.
 * Correctly handles:
 * - Scoped packages: '@babel/core@7.26.0', '@types/node', '@tanstack/react-query@5.0.0'
 * - Packages with multiple '@' characters: '@scope/pkg@1.0.0-beta@2'
 * - Unscoped packages: 'lodash@4.17.21', 'express'
 */
export function parsePackageSpecifier(raw?: string | null): PackageSpecifier {
  if (!raw || typeof raw !== "string") {
    return { name: "", version: null };
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    return { name: "", version: null };
  }

  // Scoped package starting with '@'
  if (trimmed.startsWith("@")) {
    const slashIdx = trimmed.indexOf("/");
    if (slashIdx !== -1) {
      // Look for the version delimiter '@' after the scope slash
      const atIdx = trimmed.indexOf("@", slashIdx + 1);
      if (atIdx !== -1) {
        return {
          name: trimmed.slice(0, atIdx),
          version: trimmed.slice(atIdx + 1) || null,
        };
      }
      return { name: trimmed, version: null };
    }
  }

  // Unscoped package: first '@' after position 0
  const atIdx = trimmed.indexOf("@");
  if (atIdx > 0) {
    return {
      name: trimmed.slice(0, atIdx),
      version: trimmed.slice(atIdx + 1) || null,
    };
  }

  return { name: trimmed, version: null };
}

/**
 * Extracts a package name from a relative or absolute file path inside node_modules.
 * Handles nested node_modules, scoped packages, and trailing subpaths.
 */
export function extractPackageFromPath(
  filePath?: string | null,
): string | null {
  if (!filePath || typeof filePath !== "string") return null;
  const nmIdx = filePath.lastIndexOf("node_modules/");
  if (nmIdx === -1) return null;

  const afterNm = filePath.slice(nmIdx + "node_modules/".length);
  const parts = afterNm.split("/").filter(Boolean);
  if (parts.length === 0) return null;

  if (parts[0].startsWith("@")) {
    if (parts.length >= 2) {
      return `${parts[0]}/${parts[1]}`;
    }
    return parts[0];
  }

  return parts[0];
}

/**
 * Normalizes package identity for a finding, prioritizing finding.package metadata
 * and falling back to evidence file paths.
 */
export function normalizeFindingPackage(f: {
  package?: string | null;
  evidence?: Array<{ file: string }>;
}): string | null {
  if (f.package) {
    const { name } = parsePackageSpecifier(f.package);
    if (name) return name;
  }

  if (f.evidence && f.evidence.length > 0) {
    for (const ev of f.evidence) {
      const extracted = extractPackageFromPath(ev.file);
      if (extracted) return extracted;
    }
  }

  return null;
}

/**
 * Robust finding signature prioritizing advisory identifier and package identity
 * for vulnerabilities, package + rule for integrity, and rule + package + evidence
 * for behavioral findings.
 */
export function getFindingSignature(f: Finding): string {
  const rawPkg = normalizeFindingPackage(f) || f.package || "";
  const pkg = rawPkg ? normalizePackageName(rawPkg) : "";
  if (f.advisory?.id || f.rule === "OSV" || f.domain === "vulnerability") {
    const advId = f.advisory?.id || f.title || "";
    return `vuln:${advId}:${pkg}`;
  }
  if (f.domain === "integrity" || f.rule === "PACKAGE_INTEGRITY") {
    return `integrity:${pkg}:${f.rule}`;
  }
  // Behavioral finding: stable rule + package + normalized evidence path (line numbers omitted to preserve stability across edits)
  const evFile = f.evidence && f.evidence[0] ? f.evidence[0].file : "";
  const normalizedFile = evFile.replace(/^\.?\//, "").trim();
  return `behavior:${f.rule}:${pkg}:${normalizedFile}`;
}

/**
 * Ecosystem-aware package name normalization.
 * - npm: preserves scoped packages (@scope/name) and underscores; does not collapse separators.
 * - PyPI: follows PEP 503 (lowercased, all run of `[-_.]+` replaced with single `-`).
 */
export function normalizePackageName(
  name?: string | null,
  ecosystem: "npm" | "pypi" = "npm",
): string {
  if (!name || typeof name !== "string") return "";
  const trimmed = name.trim();
  if (!trimmed) return "";
  if (ecosystem === "pypi") {
    return trimmed.toLowerCase().replace(/[-_.]+/g, "-");
  }
  if (trimmed.startsWith("@")) {
    const slashIdx = trimmed.indexOf("/");
    if (slashIdx !== -1) {
      return `${trimmed.slice(0, slashIdx).toLowerCase()}/${trimmed.slice(slashIdx + 1)}`;
    }
  }
  return trimmed;
}

/**
 * Compares two SemVer 2.0.0 version strings according to the official specification.
 * 1. Build metadata (+...) is stripped and ignored for precedence.
 * 2. Major, minor, and patch are compared numerically.
 * 3. A normal release has higher precedence than any pre-release (e.g. 2.0.0 > 2.0.0-rc.1).
 * 4. Pre-release identifiers separated by dots are compared:
 *    - Numeric identifiers are compared as integers (e.g. alpha.10 > alpha.2).
 *    - Identifiers with letters are compared lexically (ASCII order).
 *    - Numeric identifiers have lower precedence than non-numeric identifiers.
 *    - More pre-release identifiers have higher precedence (e.g. 1.0.0-beta.1 > 1.0.0-beta).
 * Returns 1 if v1 > v2, -1 if v1 < v2, and 0 if equal.
 */
export function compareSemver(v1?: string | null, v2?: string | null): number {
  if (!v1 && !v2) return 0;
  if (!v1) return -1;
  if (!v2) return 1;

  // Clean version strings (strip leading v, ^, ~, >=, <=, etc.)
  const clean1 = v1.replace(/^[v^~>=<]+/, "").trim();
  const clean2 = v2.replace(/^[v^~>=<]+/, "").trim();

  if (clean1 === clean2) return 0;

  // Strip build metadata (+...)
  const noBuild1 = clean1.split("+")[0];
  const noBuild2 = clean2.split("+")[0];

  // Separate core version from prerelease
  const dashIdx1 = noBuild1.indexOf("-");
  const dashIdx2 = noBuild2.indexOf("-");

  const core1 = dashIdx1 === -1 ? noBuild1 : noBuild1.slice(0, dashIdx1);
  const prerelease1 = dashIdx1 === -1 ? null : noBuild1.slice(dashIdx1 + 1);

  const core2 = dashIdx2 === -1 ? noBuild2 : noBuild2.slice(0, dashIdx2);
  const prerelease2 = dashIdx2 === -1 ? null : noBuild2.slice(dashIdx2 + 1);

  const parts1 = core1.split(".").map((n) => parseInt(n, 10) || 0);
  const parts2 = core2.split(".").map((n) => parseInt(n, 10) || 0);

  const maxLen = Math.max(parts1.length, parts2.length);
  for (let i = 0; i < maxLen; i++) {
    const p1 = parts1[i] ?? 0;
    const p2 = parts2[i] ?? 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }

  // Core versions are equal. Check prereleases:
  // A version without a prerelease has higher precedence than one with a prerelease.
  if (!prerelease1 && prerelease2) return 1;
  if (prerelease1 && !prerelease2) return -1;
  if (!prerelease1 && !prerelease2) return 0;

  // Both have prereleases: compare dot-separated identifiers
  const idents1 = (prerelease1 as string).split(".");
  const idents2 = (prerelease2 as string).split(".");

  const idLen = Math.max(idents1.length, idents2.length);
  for (let i = 0; i < idLen; i++) {
    const id1 = idents1[i];
    const id2 = idents2[i];

    // If one ran out of identifiers, the one with more identifiers has higher precedence
    if (id1 === undefined) return -1;
    if (id2 === undefined) return 1;

    if (id1 === id2) continue;

    const isNum1 = /^\d+$/.test(id1);
    const isNum2 = /^\d+$/.test(id2);

    if (isNum1 && isNum2) {
      const n1 = parseInt(id1, 10);
      const n2 = parseInt(id2, 10);
      if (n1 > n2) return 1;
      if (n1 < n2) return -1;
    } else if (isNum1 && !isNum2) {
      // Numeric identifiers have lower precedence than non-numeric
      return -1;
    } else if (!isNum1 && isNum2) {
      return 1;
    } else {
      // Both non-numeric: ASCII lexical order
      return id1.localeCompare(id2);
    }
  }

  return 0;
}
