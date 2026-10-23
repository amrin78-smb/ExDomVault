import type { SoftwareIntel } from '../types.ts';
import type { EolStatus } from './contract.ts';
import { parseVersion, versionInRange } from './version.ts';

/**
 * Matching versions against feed data (Milestone 11). Pure: `now` is passed in.
 *
 * End of life: a version belongs to the product's cycle with the most segments whose dotted numeric
 * segments are a prefix of the version's (`7.4.3` → `7.4`, nginx `1.18.0` → `1.18`, Node.js
 * `18.19.0` → `18`, OpenSSL `1.1.1f` → `1.1.1`). Cycles that are not purely numeric (`8.0-lts`) are
 * ignored. A cycle is end-of-life when the feed says `eol: true`, or its EOL date is on or before
 * `now`. Unknown product/cycle → null (unknown, never "supported").
 */
export function eolStatus(
  product: string,
  version: string,
  cycles: SoftwareIntel['eolCycles'],
  now: string,
): EolStatus | null {
  const parsed = parseVersion(version);
  if (!parsed) return null;
  let best: SoftwareIntel['eolCycles'][number] | null = null;
  let bestLen = 0;
  for (const c of cycles) {
    if (c.product !== product || !/^\d+(?:\.\d+)*$/.test(c.cycle)) continue;
    const parts = c.cycle.split('.').map((s) => Number.parseInt(s, 10));
    if (parts.length > parsed.numbers.length) continue;
    if (!parts.every((n, i) => n === parsed.numbers[i])) continue;
    if (parts.length > bestLen || (parts.length === bestLen && best && c.cycle < best.cycle)) {
      best = c;
      bestLen = parts.length;
    }
  }
  if (!best) return null;
  const nowMs = Date.parse(now);
  const eolMs = best.eolDate ? Date.parse(best.eolDate) : Number.NaN;
  const isEol = best.eolBoolean === true || (!Number.isNaN(eolMs) && eolMs <= nowMs);
  return { cycle: best.cycle, eolDate: best.eolDate, isEol, latestInCycle: best.latest };
}

type Advisory = SoftwareIntel['advisories'][number];

/** Advisories of `product` that are known-exploited (KEV) and carry at least one version range. */
export function rangedKevAdvisories(
  product: string,
  advisories: SoftwareIntel['advisories'],
): Advisory[] {
  return advisories
    .filter((a) => a.product === product && a.kev && a.ranges.length > 0)
    .sort((a, b) => (a.cveId < b.cveId ? -1 : a.cveId > b.cveId ? 1 : 0));
}

/**
 * Known-exploited advisories whose ranges include the version: an advisory matches when ANY of its
 * ranges includes it. Advisories without ranges (NVD record not read yet) never match. Sorted by
 * CVE id.
 */
export function matchAdvisories(
  product: string,
  version: string,
  advisories: SoftwareIntel['advisories'],
): Advisory[] {
  return rangedKevAdvisories(product, advisories).filter((a) =>
    a.ranges.some((r) => versionInRange(version, r)),
  );
}
