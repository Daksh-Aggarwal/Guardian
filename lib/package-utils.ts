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
  const pkg = normalizeFindingPackage(f) || f.package || "";
  if (f.advisory?.id || f.rule === "OSV" || f.domain === "vulnerability") {
    const advId = f.advisory?.id || f.title || "";
    return `vuln:${advId}:${pkg}`;
  }
  if (f.domain === "integrity" || f.rule === "PACKAGE_INTEGRITY") {
    return `integrity:${pkg}:${f.rule}`;
  }
  // Behavioral finding
  const evFile = f.evidence && f.evidence[0] ? f.evidence[0].file : "";
  return `behavior:${f.rule}:${pkg}:${evFile}`;
}

/**
 * Compares two semver version strings.
 * Returns 1 if v1 > v2, -1 if v1 < v2, and 0 if equal.
 */
export function compareSemver(v1?: string | null, v2?: string | null): number {
  if (!v1 && !v2) return 0;
  if (!v1) return -1;
  if (!v2) return 1;

  // Clean version strings
  const clean1 = v1.replace(/^[v^~>=<]+/, "").trim();
  const clean2 = v2.replace(/^[v^~>=<]+/, "").trim();

  if (clean1 === clean2) return 0;

  const parts1 = clean1
    .split(/[-+]/)[0]
    .split(".")
    .map((n) => parseInt(n, 10) || 0);
  const parts2 = clean2
    .split(/[-+]/)[0]
    .split(".")
    .map((n) => parseInt(n, 10) || 0);

  const len = Math.max(parts1.length, parts2.length);
  for (let i = 0; i < len; i++) {
    const p1 = parts1[i] ?? 0;
    const p2 = parts2[i] ?? 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }

  // If numeric parts are equal, string comparison for pre-releases
  return clean1.localeCompare(clean2);
}
