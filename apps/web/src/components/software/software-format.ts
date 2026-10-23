import type { IntelFeed, SoftwareItem, VersionRange } from '@exdomainvault/shared';

/** Where a product/version was read from. */
export const SOFTWARE_SOURCE_LABELS: Record<SoftwareItem['source'], string> = {
  http_header: 'HTTP header',
  service_identification: 'Service identification',
};

export const INTEL_FEED_LABELS: Record<IntelFeed, string> = {
  endoflife: 'endoflife.date',
  cisa_kev: 'CISA Known Exploited Vulnerabilities',
  nvd: 'NVD (National Vulnerability Database)',
};

export const INTEL_FEED_DESCRIPTIONS: Record<IntelFeed, string> = {
  endoflife: 'Release cycles and upstream end-of-life dates.',
  cisa_kev: 'CVEs known to be exploited in the wild, filtered to catalogue products.',
  nvd: 'Affected version ranges for those known-exploited CVEs.',
};

/** Only well-formed CVE identifiers are ever turned into links. */
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;

export const isCveId = (value: unknown): value is string =>
  typeof value === 'string' && CVE_PATTERN.test(value);

/** The NVD detail page of a CVE (the id is validated before it reaches a URL). */
export const nvdUrl = (cveId: string) =>
  `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;

/** Hostname or address with the port, e.g. `shop.example.com:443`, `[2001:db8::1]:22`. */
export function softwareLocation(item: Pick<SoftwareItem, 'hostname' | 'ipAddress' | 'port'>) {
  const host = item.hostname ?? item.ipAddress;
  if (!host) return item.port !== null ? `port ${item.port}` : '—';
  if (item.port === null) return host;
  return host.includes(':') ? `[${host}]:${item.port}` : `${host}:${item.port}`;
}

const RANGE_KEYS = ['startIncluding', 'startExcluding', 'endIncluding', 'endExcluding'] as const;

/** Whether a value looks like an NVD affected range (only range bounds, all strings). */
export function isVersionRange(value: unknown): value is VersionRange {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const entries = Object.entries(value);
  return (
    entries.length > 0 &&
    entries.every(
      ([k, v]) => (RANGE_KEYS as readonly string[]).includes(k) && typeof v === 'string',
    )
  );
}

/** `{startIncluding: '2.4.0', endExcluding: '2.4.50'}` → "from 2.4.0 up to (not including) 2.4.50". */
export function rangeText(range: VersionRange): string {
  const parts: string[] = [];
  if (range.startIncluding) parts.push(`from ${range.startIncluding}`);
  if (range.startExcluding) parts.push(`after ${range.startExcluding}`);
  if (range.endIncluding) parts.push(`up to and including ${range.endIncluding}`);
  if (range.endExcluding) parts.push(`up to (not including) ${range.endExcluding}`);
  return parts.length > 0 ? parts.join(' ') : 'all versions';
}
