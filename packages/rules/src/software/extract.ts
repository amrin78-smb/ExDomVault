import { SOFTWARE_PRODUCTS } from '@exdomainvault/shared';
import { parseUrl } from '../rules/http.ts';
import type { HttpObservation, ObservationSet, PortObservation } from '../types.ts';
import type { SoftwareSighting } from './contract.ts';

/**
 * Software extraction from banners (Milestone 11). Pure and deterministic.
 *
 * - Products are recognised ONLY through the `SOFTWARE_PRODUCTS` catalogue patterns; unknown tokens
 *   (`cloudflare`, `openresty`, `Express`, `mod_ssl/2.4`) are ignored.
 * - HTTP headers (`Server`, `X-Powered-By`): parenthesised comments are removed, the rest is split on whitespace into `name[/version]` tokens; the name must equal
 *   a catalogue pattern (case-insensitive). `Apache-Coyote/1.1` is Tomcat with an unknown version
 *   (1.1 is the connector's protocol version, not Tomcat's).
 * - Nmap service identification (`evidence.product` + `evidence.version`): the longest catalogue
 *   pattern equal to the product or followed by a space/slash in it (`Apache httpd`, `OpenSSH`,
 *   `PostgreSQL DB`). The version keeps its first word (`8.2p1 Ubuntu 4ubuntu0.5` → `8.2p1`); the
 *   rest only feeds distribution detection. Nmap's `MySQL 5.5.5-10.3.27-MariaDB-…` is MariaDB
 *   10.3.27.
 * - Distribution: a marker in the product's own version tail (`7.4.3-4ubuntu2.19`), else anywhere
 *   in the banner (`(Ubuntu)`, `(Red Hat Enterprise Linux)`, `el8`, `+deb11u3`).
 * - A version must start with a digit, else it is null (recognised but hidden). Version text is kept
 *   as disclosed, including distribution tails (`7.4.3-4ubuntu2.19`), max 64 chars.
 * - Banners are cut to 200 characters before parsing.
 * - Only `success` observations are used (HTTP-005 also reports `partial` responses; inventory and
 *   the software rules use only complete evidence). Port observations must be `open`.
 * - HTTP sightings are located by hostname only (ipAddress/port null): addresses behind CDNs and load
 *   balancers rotate, and the location must stay stable. Service identification: ip + port.
 */

export const MAX_BANNER = 200;
const MAX_VERSION = 64;

interface CatalogPattern {
  key: string;
  pattern: string;
}

const PATTERNS: readonly CatalogPattern[] = SOFTWARE_PRODUCTS.flatMap((p) =>
  p.patterns.map((pattern) => ({ key: p.key, pattern: pattern.toLowerCase() })),
).sort((a, b) => b.pattern.length - a.pattern.length || (a.pattern < b.pattern ? -1 : 1));

/** Distribution markers, in precedence order (a named distribution beats a generic `el8`). */
const DISTRIBUTIONS: readonly { name: string; re: RegExp }[] = [
  { name: 'Ubuntu', re: /ubuntu/i },
  { name: 'Debian', re: /debian|(?:^|[^a-z])deb(?:\d|u\d|$|[^a-z])/i },
  { name: 'CentOS', re: /centos/i },
  { name: 'Fedora', re: /fedora|\.fc\d+/i },
  { name: 'Red Hat', re: /red\s?hat|rhel|(?:^|[^a-z])el[5-9](?:_\d+)?(?:$|[^a-z0-9])/i },
  { name: 'SUSE', re: /suse|sles/i },
  { name: 'Alpine', re: /alpine/i },
  { name: 'Amazon Linux', re: /amzn/i },
];

/** The distribution a banner or version tail names, or null (exported for tests). */
export function detectDistribution(text: string): string | null {
  for (const d of DISTRIBUTIONS) if (d.re.test(text)) return d.name;
  return null;
}

export interface BannerProduct {
  product: string;
  version: string | null;
  backportDistribution: string | null;
}

function cleanVersion(raw: string | undefined): string | null {
  if (!raw) return null;
  const v = raw.trim().slice(0, MAX_VERSION);
  return /^\d[0-9a-z._+~:-]*$/i.test(v) ? v : null;
}

/** Parse an HTTP `Server` / `X-Powered-By` value (exported for tests). */
export function parseHeaderBanner(banner: string): BannerProduct[] {
  const text = banner.slice(0, MAX_BANNER);
  const bannerDistro = detectDistribution(text);
  const out: BannerProduct[] = [];
  const seen = new Set<string>();
  for (const token of text.replace(/\([^)]*\)?/g, ' ').split(/[\s,;]+/)) {
    if (!token) continue;
    const slash = token.indexOf('/');
    const name = (slash < 0 ? token : token.slice(0, slash)).toLowerCase();
    const match = PATTERNS.find((p) => p.pattern === name);
    if (!match || seen.has(match.key)) continue;
    seen.add(match.key);
    const version =
      slash < 0 || name === 'apache-coyote' ? null : cleanVersion(token.slice(slash + 1));
    out.push({
      product: match.key,
      version,
      backportDistribution: (version && detectDistribution(version)) ?? bannerDistro,
    });
  }
  return out;
}

/** Parse Nmap's product + version (exported for tests). */
export function parseServiceBanner(product: string, version: string | null): BannerProduct | null {
  const name = product.slice(0, MAX_BANNER).trim().toLowerCase();
  const match = PATTERNS.find(
    (p) =>
      name === p.pattern || name.startsWith(`${p.pattern} `) || name.startsWith(`${p.pattern}/`),
  );
  if (!match) return null;
  const versionText = (version ?? '').slice(0, MAX_BANNER).trim();
  const distro = detectDistribution(`${product} ${versionText}`);
  let key = match.key;
  let v = cleanVersion(versionText.split(/\s+/)[0]);
  if (key === 'apache_tomcat' && name.includes('coyote')) v = null;
  if (key === 'mysql' && /mariadb/i.test(versionText)) {
    key = 'mariadb';
    const m = /(?:^|-)(\d+\.\d+\.\d+)-mariadb/i.exec(versionText);
    v = m?.[1] ?? null;
  }
  return { product: key, version: v, backportDistribution: distro };
}

// --- extraction from observations ------------------------------------------------------------

function headerValue(o: HttpObservation, key: 'server' | 'xPoweredBy'): string | null {
  const v = o.evidence[key];
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

function evidenceText(o: PortObservation, key: string): string | null {
  const v = o.evidence[key];
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

function fromHttp(o: HttpObservation): SoftwareSighting[] {
  if (o.resultStatus !== 'success') return [];
  const host = parseUrl(o.url)?.host;
  if (!host) return [];
  const out: SoftwareSighting[] = [];
  for (const key of ['server', 'xPoweredBy'] as const) {
    const value = headerValue(o, key);
    if (!value) continue;
    const banner = value.slice(0, MAX_BANNER);
    for (const p of parseHeaderBanner(banner)) {
      out.push({
        source: 'http_header',
        hostname: host,
        ipAddress: null,
        port: null,
        product: p.product,
        version: p.version,
        banner,
        backportDistribution: p.backportDistribution,
        observedAt: o.observedAt,
        scanJobId: o.scanJobId,
      });
    }
  }
  return out;
}

function fromPort(o: PortObservation): SoftwareSighting | null {
  if (o.resultStatus !== 'success' || o.state !== 'open') return null;
  const product = evidenceText(o, 'product');
  if (!product) return null;
  const version = evidenceText(o, 'version');
  const parsed = parseServiceBanner(product, version);
  if (!parsed) return null;
  return {
    source: 'service_identification',
    hostname: null,
    ipAddress: o.ipAddress.trim().toLowerCase(),
    port: o.port,
    product: parsed.product,
    version: parsed.version,
    banner: `${product}${version ? ` ${version}` : ''}`.slice(0, MAX_BANNER),
    backportDistribution: parsed.backportDistribution,
    observedAt: o.observedAt,
    scanJobId: o.scanJobId,
  };
}

/** Location of a sighting: hostname (HTTP) or `ip:port` / `[v6]:port` (service identification). */
export function sightingLocation(s: SoftwareSighting): string {
  if (s.source === 'http_header') return s.hostname ?? '';
  const ip = s.ipAddress ?? '';
  return ip.includes(':') ? `[${ip}]:${s.port}` : `${ip}:${s.port}`;
}

const str = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** Preference among duplicates: version disclosed, then newest, then banner text. */
function better(a: SoftwareSighting, b: SoftwareSighting): boolean {
  if ((a.version === null) !== (b.version === null)) return a.version !== null;
  if (a.observedAt !== b.observedAt) return a.observedAt > b.observedAt;
  return str(`${a.banner}|${a.version ?? ''}`, `${b.banner}|${b.version ?? ''}`) < 0;
}

/**
 * Sightings from SUCCESSFUL observations, one per (source, location, product), sorted by source,
 * location and product.
 */
export function extractSoftware(observations: ObservationSet): SoftwareSighting[] {
  const all = [
    ...observations.http.flatMap(fromHttp),
    ...observations.ports.map(fromPort).filter((s): s is SoftwareSighting => s !== null),
  ];
  const byKey = new Map<string, SoftwareSighting>();
  for (const s of all) {
    const key = `${s.source}|${sightingLocation(s)}|${s.product}`;
    const prev = byKey.get(key);
    if (!prev || better(s, prev)) byKey.set(key, s);
  }
  return [...byKey.entries()].sort(([a], [b]) => str(a, b)).map(([, s]) => s);
}
