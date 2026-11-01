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
 * Official SemVer 2.0.0 specification regex.
 * Strictly checks for major.minor.patch[-prerelease][+buildmetadata].
 * Rejects leading zeros in numeric identifiers and invalid characters.
 */
export const STRICT_SEMVER_REGEX =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

export const FORBIDDEN_SEMVER_CHARS = /[><=~!*^,]/;

export interface SemverOptions {
  allowLeadingV?: boolean;
}

export function isValidSemver(
  version?: string | null,
  options: SemverOptions = {},
): boolean {
  if (!version || typeof version !== "string") return false;
  let clean = version.trim();
  if (FORBIDDEN_SEMVER_CHARS.test(clean)) return false;
  if (
    options.allowLeadingV &&
    (clean.startsWith("v") || clean.startsWith("V"))
  ) {
    clean = clean.slice(1);
  }
  return STRICT_SEMVER_REGEX.test(clean);
}

function compareAscii(s1: string, s2: string): number {
  if (s1 === s2) return 0;
  return s1 < s2 ? -1 : 1;
}

/**
 * Compares two SemVer 2.0.0 version strings strictly according to the official specification.
 * 1. Range operators (^, ~, >=, <=, etc.) are strictly forbidden and throw TypeError.
 * 2. Build metadata (+...) is stripped and ignored for precedence.
 * 3. Major, minor, and patch are compared numerically.
 * 4. A normal release has higher precedence than any pre-release (e.g. 2.0.0 > 2.0.0-rc.1).
 * 5. Pre-release identifiers separated by dots are compared:
 *    - Numeric identifiers are compared as integers (e.g. alpha.10 > alpha.2).
 *    - Identifiers with letters are compared by ASCII lexical order.
 *    - Numeric identifiers have lower precedence than non-numeric identifiers.
 *    - More pre-release identifiers have higher precedence (e.g. 1.0.0-beta.1 > 1.0.0-beta).
 * Returns 1 if v1 > v2, -1 if v1 < v2, and 0 if equal.
 */
export function compareSemver(
  v1?: string | null,
  v2?: string | null,
  options: SemverOptions = {},
): number {
  if (!v1 && !v2) return 0;
  if (!v1) return -1;
  if (!v2) return 1;

  let clean1 = v1.trim();
  let clean2 = v2.trim();

  if (options.allowLeadingV) {
    if (clean1.startsWith("v") || clean1.startsWith("V"))
      clean1 = clean1.slice(1);
    if (clean2.startsWith("v") || clean2.startsWith("V"))
      clean2 = clean2.slice(1);
  }

  if (!isValidSemver(clean1, { allowLeadingV: false })) {
    throw new TypeError(`Invalid SemVer 2.0.0 version string: '${v1}'`);
  }
  if (!isValidSemver(clean2, { allowLeadingV: false })) {
    throw new TypeError(`Invalid SemVer 2.0.0 version string: '${v2}'`);
  }

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

  const parts1 = core1.split(".").map((n) => parseInt(n, 10));
  const parts2 = core2.split(".").map((n) => parseInt(n, 10));

  for (let i = 0; i < 3; i++) {
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
      // Both non-numeric: strictly ASCII lexical order (NOT localeCompare)
      return compareAscii(id1, id2);
    }
  }

  return 0;
}

/**
 * PEP 440 canonical regex and validation.
 */
export const PEP440_REGEX =
  /^([0-9]+!)?([0-9]+(?:\.[0-9]+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?([0-9]+)?)?(?:(?:[-_.]?(?:post|rev|r)[-_.]?([0-9]+)?)|(?:-([0-9]+)))?(?:[-_.]?dev[-_.]?([0-9]+)?)?(?:\+([0-9a-zA-Z]+(?:[-_.][0-9a-zA-Z]+)*))?$/i;

export const FORBIDDEN_PEP440_CHARS = /[><=~*^]|!=/;

export interface ParsedPep440 {
  epoch: number;
  release: number[];
  pre: [string, number] | null;
  post: number | null;
  dev: number | null;
  local: string | null;
}

export function isValidPep440(version?: string | null): boolean {
  if (!version || typeof version !== "string") return false;
  const clean = version.trim();
  if (["unresolved", "latest", "*", ""].includes(clean)) return false;
  if (
    clean.includes("*") ||
    clean.includes("==") ||
    FORBIDDEN_PEP440_CHARS.test(clean)
  )
    return false;
  return PEP440_REGEX.test(clean);
}

export function parsePep440(version: string): ParsedPep440 | null {
  if (!version || typeof version !== "string") return null;
  const clean = version.trim();
  if (["unresolved", "latest", "*", ""].includes(clean)) return null;
  if (
    clean.includes("*") ||
    clean.includes("==") ||
    FORBIDDEN_PEP440_CHARS.test(clean)
  )
    return null;
  const m = clean.match(PEP440_REGEX);
  if (!m) return null;

  const epoch = m[1] ? parseInt(m[1].replace("!", ""), 10) : 0;
  const release = m[2].split(".").map((n) => parseInt(n, 10));

  let pre: [string, number] | null = null;
  if (m[3]) {
    let tag = m[3].toLowerCase();
    if (tag === "alpha") tag = "a";
    else if (tag === "beta") tag = "b";
    else if (tag === "c" || tag === "pre" || tag === "preview") tag = "rc";
    const num = m[4] ? parseInt(m[4], 10) : 0;
    pre = [tag, num];
  }

  let post: number | null = null;
  const rawPost = m[5] || m[6];
  if (rawPost !== undefined) {
    post = parseInt(rawPost, 10);
  } else if (clean.includes(".post") || clean.includes("-post")) {
    post = 0;
  }

  let dev: number | null = null;
  if (m[7] !== undefined) {
    dev = parseInt(m[7], 10);
  } else if (clean.includes(".dev") || clean.includes("-dev")) {
    dev = 0;
  }

  const local = m[8] || null;

  return { epoch, release, pre, post, dev, local };
}

/**
 * Builds the authoritative PEP 440 comparison key tuple matching Python packaging.version._cmpkey.
 * Returns: (epoch, trimmed_release, suffix_tuple, optional_cmp_local)
 */
function getPep440CmpKey(p: ParsedPep440) {
  // Strip trailing zeros from release: 1.0.0 compares equal to 1.0
  const trimmed = [...p.release];
  while (trimmed.length > 0 && trimmed[trimmed.length - 1] === 0) {
    trimmed.pop();
  }

  // pre_rank: dev-only=-1, a=0, b=1, rc=2, no-pre=3
  // Dev-only releases (no pre or post) get -1 so they sort before any alpha/beta/rc.
  let preRank: number;
  let preN: number;
  if (p.pre === null && p.post === null && p.dev !== null) {
    preRank = -1;
    preN = 0;
  } else if (p.pre === null) {
    preRank = 3;
    preN = 0;
  } else {
    const preOrder: Record<string, number> = { a: 0, b: 1, rc: 2 };
    preRank = preOrder[p.pre[0]] ?? 2;
    preN = p.pre[1];
  }

  // post_rank: no-post=0, post=1
  const postRank = p.post === null ? 0 : 1;
  const postN = p.post === null ? 0 : p.post;

  // dev_rank: dev=0, no-dev=1 (Releases without dev segment sort after those with one)
  const devRank = p.dev === null ? 1 : 0;
  const devN = p.dev === null ? 0 : p.dev;

  const suffix = [preRank, preN, postRank, postN, devRank, devN];

  // Local segments: strings sort before ints (-1 vs int), strings compare lexicographically,
  // ints compare numerically. Shorter segment tuple sorts before longer when prefix matches.
  let cmpLocal: Array<[number, string]> | null = null;
  if (p.local !== null) {
    const segments = p.local.split(/[.\-_]/);
    cmpLocal = segments.map((seg) => {
      if (/^\d+$/.test(seg)) {
        return [parseInt(seg, 10), ""];
      }
      return [-1, seg.toLowerCase()];
    });
  }

  return { epoch: p.epoch, release: trimmed, suffix, cmpLocal };
}

/**
 * Compares two PyPI versions according to PEP 440.
 */
export function comparePep440(v1?: string | null, v2?: string | null): number {
  if (!v1 && !v2) return 0;
  if (!v1) return -1;
  if (!v2) return 1;

  const p1 = parsePep440(v1);
  const p2 = parsePep440(v2);

  if (!p1) throw new TypeError(`Invalid PEP 440 version: '${v1}'`);
  if (!p2) throw new TypeError(`Invalid PEP 440 version: '${v2}'`);

  const k1 = getPep440CmpKey(p1);
  const k2 = getPep440CmpKey(p2);

  // 1. Epoch
  if (k1.epoch !== k2.epoch) {
    return k1.epoch > k2.epoch ? 1 : -1;
  }

  // 2. Release segment
  const maxRelLen = Math.max(k1.release.length, k2.release.length);
  for (let i = 0; i < maxRelLen; i++) {
    const n1 = k1.release[i] ?? 0;
    const n2 = k2.release[i] ?? 0;
    if (n1 !== n2) {
      return n1 > n2 ? 1 : -1;
    }
  }

  // 3. Suffix (pre, post, dev)
  for (let i = 0; i < 6; i++) {
    if (k1.suffix[i] !== k2.suffix[i]) {
      return k1.suffix[i] > k2.suffix[i] ? 1 : -1;
    }
  }

  // 4. Local version (versions without local sort before those with local: 3-tuple < 4-tuple)
  if (k1.cmpLocal === null && k2.cmpLocal !== null) return -1;
  if (k1.cmpLocal !== null && k2.cmpLocal === null) return 1;
  if (k1.cmpLocal !== null && k2.cmpLocal !== null) {
    const maxLocLen = Math.max(k1.cmpLocal.length, k2.cmpLocal.length);
    for (let i = 0; i < maxLocLen; i++) {
      if (i >= k1.cmpLocal.length) return -1;
      if (i >= k2.cmpLocal.length) return 1;
      const [t1, s1] = k1.cmpLocal[i];
      const [t2, s2] = k2.cmpLocal[i];
      if (t1 !== t2) {
        return t1 > t2 ? 1 : -1;
      }
      if (t1 === -1 && s1 !== s2) {
        return compareAscii(s1, s2);
      }
    }
  }

  return 0;
}

/**
 * Ecosystem-aware version comparison.
 * - 'npm': uses strict SemVer 2.0.0
 * - 'pypi': uses PEP 440
 */
export function compareVersions(
  v1?: string | null,
  v2?: string | null,
  ecosystem: "npm" | "pypi" = "npm",
  options: SemverOptions = {},
): number {
  if (ecosystem === "pypi") {
    return comparePep440(v1, v2);
  }
  return compareSemver(v1, v2, options);
}

/**
 * Safe version comparator that does not throw on invalid/unresolved inputs,
 * suitable for sorting dependency tables and timeline displays.
 */
export function compareVersionsSafe(
  v1?: string | null,
  v2?: string | null,
  ecosystem: "npm" | "pypi" = "npm",
): number {
  try {
    return compareVersions(v1, v2, ecosystem);
  } catch {
    if (!v1 && !v2) return 0;
    if (!v1) return -1;
    if (!v2) return 1;
    return compareAscii(v1, v2);
  }
}
