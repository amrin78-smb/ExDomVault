import type { VersionRange } from '../types.ts';

/**
 * Version comparison for self-reported software versions (Milestone 11). Pure and deterministic.
 *
 * Semantics:
 * - Only the leading core of a version is compared: dotted numeric segments plus an optional
 *   letter suffix on the last segment (`7.4.3`, `1.1.1f`, `8.2p1`, `2.0rc1`). Everything after the
 *   core is a distribution/build tail and is ignored for comparison (`7.4.3-4ubuntu2.19`,
 *   `1.0.2k-fips`, `1.18.0-6+deb11u3`, `8.2p1 Ubuntu 4ubuntu0.5`); callers keep it in the text.
 * - Numeric segments compare numerically; missing trailing segments are padded with 0
 *   (`2.4` = `2.4.0`, `1.18` < `1.18.1`).
 * - With equal numbers, the suffix decides: pre-release tags (`alpha`, `beta`, `rc`, `pre`, `preview`,
 *   `dev`) sort before no suffix; no suffix sorts before
 *   a post-release letter suffix (`1.1.1` < `1.1.1a` < `1.1.1f` < `1.1.1w`; `8.2` < `8.2p1` <
 *   `8.2p2`). Letter parts compare alphabetically, then their trailing number numerically. A word after a
 *   `-` or `.` separator that is not a pre-release tag is a tail (`2.4.41-ubuntu`), not a suffix.
 * - A string without a numeric core (`abc`, ``) sorts before any version and equals another such
 *   string; callers should not range-match those (see `parseVersion`).
 */

export interface ParsedVersion {
  /** Numeric segments of the core (`[1, 1, 1]` for `1.1.1f`). */
  numbers: number[];
  /** Letters of the suffix, lowercase (`f`, `p`, `rc`), '' if none. */
  suffix: string;
  /** Number after the suffix letters (`1` for `p1`), 0 if none. */
  suffixNumber: number;
  /** True for alpha/beta/rc/pre/dev suffixes (sort before the release). */
  preRelease: boolean;
}

const CORE = /^v?(\d+(?:\.\d+)*)(?:[.-]?([a-z]+)(\d*))?/i;
const PRE_RELEASE = new Set(['alpha', 'beta', 'rc', 'pre', 'preview', 'dev']);

/** The comparable core of a version, or null when it does not start with a number. */
export function parseVersion(version: string): ParsedVersion | null {
  const text = version.trim();
  const m = CORE.exec(text);
  if (!m?.[1]) return null;
  const numbers = m[1].split('.').map((s) => Number.parseInt(s, 10));
  if (numbers.some((n) => !Number.isSafeInteger(n))) return null;
  let suffix = (m[2] ?? '').toLowerCase();
  let suffixNumber = m[3] ? Number.parseInt(m[3], 10) : 0;
  // A separator-led word that is not a known tag is a tail (`-fips`, `-ubuntu`), not a suffix.
  const sep = text.charAt(m[1].length + (/^v/i.test(text) ? 1 : 0));
  if (suffix && (sep === '-' || sep === '.') && !PRE_RELEASE.has(suffix)) {
    suffix = '';
    suffixNumber = 0;
  }
  if (!Number.isSafeInteger(suffixNumber)) suffixNumber = 0;
  return { numbers, suffix, suffixNumber, preRelease: PRE_RELEASE.has(suffix) };
}

function cmp(a: number, b: number): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Suffix rank: pre-release (-1) < none (0) < post-release letter (1). */
function suffixRank(v: ParsedVersion): number {
  if (!v.suffix) return 0;
  return v.preRelease ? -1 : 1;
}

/** -1 / 0 / 1 (see the module comment for the exact semantics). */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return cmp(pa ? 1 : 0, pb ? 1 : 0);
  const len = Math.max(pa.numbers.length, pb.numbers.length);
  for (let i = 0; i < len; i++) {
    const c = cmp(pa.numbers[i] ?? 0, pb.numbers[i] ?? 0);
    if (c !== 0) return c;
  }
  const r = cmp(suffixRank(pa), suffixRank(pb));
  if (r !== 0) return r;
  if (pa.suffix !== pb.suffix) return pa.suffix < pb.suffix ? -1 : 1;
  return cmp(pa.suffixNumber, pb.suffixNumber);
}

/**
 * True when the version satisfies every bound present in the range (NVD semantics: start/end,
 * including/excluding). A range without any bound (NVD's "exact CPE version" case, which this model
 * does not carry) and a version without a numeric core never match: unknown is not "affected".
 */
export function versionInRange(version: string, range: VersionRange): boolean {
  if (!parseVersion(version)) return false;
  const { startIncluding, startExcluding, endIncluding, endExcluding } = range;
  if (!startIncluding && !startExcluding && !endIncluding && !endExcluding) return false;
  if (startIncluding && compareVersions(version, startIncluding) < 0) return false;
  if (startExcluding && compareVersions(version, startExcluding) <= 0) return false;
  if (endIncluding && compareVersions(version, endIncluding) > 0) return false;
  if (endExcluding && compareVersions(version, endExcluding) >= 0) return false;
  return true;
}
