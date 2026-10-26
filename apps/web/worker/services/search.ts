import type { Database } from '@exdomainvault/database';
import { matchAdvisories } from '@exdomainvault/rules';
import { normaliseDomain } from '@exdomainvault/shared/hostname';
import {
  SEARCH_GROUP_LIMIT,
  SOFTWARE_PRODUCTS,
  hasPermission,
  softwareProduct,
  type CurrentUser,
  type SearchResponse,
  type Severity,
} from '@exdomainvault/shared';
import { sql, type SQL } from 'drizzle-orm';
import { rowsOf } from '../lib/db.ts';
import {
  assetVisibility,
  findingVisibility,
  softwareGroups,
  softwareVisibility,
} from './dashboard.ts';
import { loadSoftwareIntel } from './software.ts';

/**
 * Global search (Milestone 13): `GET /search?q=`. One bounded statement per group, each a
 * case-insensitive substring match (`ILIKE` with `%`, `_` and `\` escaped, so user input is never a
 * pattern) ordered exact match first, then shortest, then alphabetically, at most
 * SEARCH_GROUP_LIMIT rows. Groups the caller may not read are empty (domains: `domains:read`;
 * assets, IPs, ports: `assets:read`; software, vulnerabilities, findings: `findings:read`), and
 * asset owners only see rows on assets they own.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;

const LIMIT = SEARCH_GROUP_LIMIT;
/** Assets listed per matching IP address. */
const IP_ASSET_LIMIT = 10;
/** CVE ids considered before the "affects a reported version" filter. */
const CVE_CANDIDATE_LIMIT = 200;

export const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

/** `443`, `port:443`, `port 443` → 443 (1-65535); otherwise null. */
export function portQuery(q: string): number | null {
  const m = /^(?:port\s*[:\s]\s*)?(\d{1,5})$/i.exec(q.trim());
  if (!m) return null;
  const n = Number(m[1]);
  return n >= 1 && n <= 65535 ? n : null;
}

/** `CVE-2024-38475`, `cve-2024`, `2024-384` → the upper-cased text to match; otherwise null. */
export function cveQuery(q: string): string | null {
  const t = q.trim().toUpperCase();
  if (/^CVE-?[\d-]*$/.test(t) || /^\d{4}-\d*$/.test(t)) return t;
  return null;
}

/** IPv4-ish (digits and dots) or IPv6-ish (hex and colons, at least one colon) prefixes. */
export function ipQuery(q: string): string | null {
  const t = q.trim().toLowerCase();
  if (/^[\d.]+$/.test(t) || (/^[\da-f:.]+$/.test(t) && t.includes(':'))) return t;
  return null;
}

const contains = (term: string) => `%${escapeLike(term)}%`;

/** ORDER BY for "exact first, then shortest, then alphabetical" on a text expression. */
const relevance = (expr: SQL, term: string) =>
  sql`(lower(${expr}) = ${term}) desc, length(${expr}), ${expr}`;

export async function search(db: Database, user: User, q: string): Promise<SearchResponse> {
  const can = (p: Parameters<typeof hasPermission>[1]) => hasPermission(user.role, p);
  const owner = user.role === 'asset_owner';
  const readDomains = can('domains:read') && !owner;
  const readAssets = can('assets:read');
  const readFindings = can('findings:read');

  const term = q.trim().toLowerCase();
  // Hostnames are stored as A-labels: a Unicode search term is converted first.
  const n = normaliseDomain(term);
  const hostTerm = n.ok ? n.fqdn : term;
  const like = contains(term);
  const hostLike = contains(hostTerm);
  const aVis = assetVisibility(user);
  const port = portQuery(term);
  const cve = cveQuery(term);
  const ip = ipQuery(term);

  const domainsP = readDomains
    ? rowsOf<{ id: string; fqdn: string }>(
        db,
        sql`select d.id, d.fqdn from domains d
            where d.fqdn ilike ${hostLike} or d.fqdn ilike ${like}
            order by ${relevance(sql`d.fqdn`, hostTerm)}
            limit ${LIMIT}`,
      )
    : Promise.resolve([]);

  const assetsP = readAssets
    ? rowsOf<{ id: string; hostname: string; domain_id: string; fqdn: string }>(
        db,
        sql`select a.id, a.hostname, a.domain_id, d.fqdn
            from assets a join domains d on d.id = a.domain_id
            where ${aVis} and (a.hostname ilike ${hostLike} or a.hostname ilike ${like})
            order by ${relevance(sql`a.hostname`, hostTerm)}, a.id
            limit ${LIMIT}`,
      )
    : Promise.resolve([]);

  const ipsP =
    readAssets && ip !== null
      ? rowsOf<{ ip: string; assets: { id: string; hostname: string }[] }>(
          db,
          sql`select m.ip,
                (select coalesce(json_agg(json_build_object('id', x.id, 'hostname', x.hostname)
                                          order by x.hostname), '[]'::json)
                 from (select a.id, a.hostname from asset_ips ai join assets a on a.id = ai.asset_id
                       where ai.is_current and host(ai.ip_address) = m.ip and ${aVis}
                       order by a.hostname limit ${IP_ASSET_LIMIT}) x) as assets
              from (
                select distinct host(ai.ip_address) as ip
                from asset_ips ai join assets a on a.id = ai.asset_id
                where ai.is_current and ${aVis} and host(ai.ip_address) like ${`${escapeLike(ip)}%`}
              ) m
              order by (m.ip = ${ip}) desc, length(m.ip), m.ip
              limit ${LIMIT}`,
        )
      : Promise.resolve([]);

  const portsP =
    readAssets && port !== null
      ? rowsOf<{ ip: string; port: number; service: string | null; hostname: string | null }>(
          db,
          sql`with latest as (
                select distinct on (p.ip_address, p.protocol) p.ip_address, p.protocol, p.state,
                       p.service
                from port_observations p
                where p.port = ${port} and p.result_status = 'success'
                order by p.ip_address, p.protocol, p.observed_at desc, p.id desc
              ),
              open as (
                select distinct on (l.ip_address) l.ip_address, l.service
                from latest l where l.state = 'open'
                order by l.ip_address, (l.protocol = 'tcp') desc, l.protocol
              )
              select host(o.ip_address) as ip, ${port}::int as port, o.service,
                (select min(a.hostname) from asset_ips ai join assets a on a.id = ai.asset_id
                  where ai.is_current and ai.ip_address = o.ip_address and ${aVis}) as hostname
              from open o
              ${
                owner
                  ? sql`where exists (select 1 from asset_ips ai join assets a on a.id = ai.asset_id
                          where ai.is_current and ai.ip_address = o.ip_address and ${aVis})`
                  : sql``
              }
              order by o.ip_address
              limit ${LIMIT}`,
        )
      : Promise.resolve([]);

  // Software: product key, catalogue label or version.
  const labelProducts = SOFTWARE_PRODUCTS.filter((p) => p.label.toLowerCase().includes(term)).map(
    (p) => p.key,
  );
  const labelMatch =
    labelProducts.length > 0
      ? sql`or s.product in (${sql.join(
          labelProducts.map((p) => sql`${p}`),
          sql`, `,
        )})`
      : sql``;
  const softwareP = readFindings
    ? rowsOf<{
        product: string;
        version: string | null;
        hostname: string | null;
        domain_id: string;
        fqdn: string;
      }>(
        db,
        sql`select distinct s.product, s.version, coalesce(s.hostname, host(s.ip_address)) as hostname,
                   s.domain_id, d.fqdn,
                   (lower(s.product) = ${term} or lower(coalesce(s.version, '')) = ${term}) as exact
            from software_inventory s join domains d on d.id = s.domain_id
            where ${softwareVisibility(user)}
              and (s.product ilike ${like} or s.version ilike ${like} ${labelMatch})
            order by exact desc, s.product, s.version nulls last, hostname nulls last, d.fqdn
            limit ${LIMIT}`,
      )
    : Promise.resolve([]);

  const findingsP = readFindings
    ? rowsOf<{ id: string; title: string; severity: Severity; domain_id: string; fqdn: string }>(
        db,
        sql`select f.id, f.title, f.severity, f.domain_id, d.fqdn
            from findings f join domains d on d.id = f.domain_id
            where ${findingVisibility(user)} and f.title ilike ${like}
            order by ${relevance(sql`f.title`, term)}, f.id
            limit ${LIMIT}`,
      )
    : Promise.resolve([]);

  const vulnerabilitiesP =
    readFindings && cve !== null ? searchVulnerabilities(db, user, cve) : Promise.resolve([]);

  const [domainRows, assetRows, ipRows, portRows, softwareRows, findingRows, vulnerabilities] =
    await Promise.all([domainsP, assetsP, ipsP, portsP, softwareP, findingsP, vulnerabilitiesP]);

  return {
    q: q.trim(),
    domains: domainRows.map((r) => ({ id: r.id, fqdn: r.fqdn })),
    assets: assetRows.map((r) => ({
      id: r.id,
      hostname: r.hostname,
      domain: { id: r.domain_id, fqdn: r.fqdn },
    })),
    ips: ipRows.map((r) => ({
      ipAddress: r.ip,
      assets: (typeof r.assets === 'string'
        ? (JSON.parse(r.assets) as { id: string; hostname: string }[])
        : r.assets
      ).map((a) => ({ id: a.id, hostname: a.hostname })),
    })),
    ports: portRows.map((r) => ({
      ipAddress: r.ip,
      port: Number(r.port),
      service: r.service,
      hostname: r.hostname,
    })),
    software: softwareRows.map((r) => ({
      product: r.product,
      productLabel: softwareProduct(r.product)?.label ?? r.product,
      version: r.version,
      hostname: r.hostname,
      domain: { id: r.domain_id, fqdn: r.fqdn },
    })),
    vulnerabilities,
    findings: findingRows.map((r) => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      domain: { id: r.domain_id, fqdn: r.fqdn },
    })),
  };
}

/**
 * CVEs whose id contains `cveTerm` and that POSSIBLY affect at least one visible reported version
 * (the SOFT-002 / GET /vulnerabilities matching: KEV advisory with NVD ranges). `affectedHosts` =
 * distinct hosts (hostname, else IP) reporting an affected version.
 */
async function searchVulnerabilities(
  db: Database,
  user: User,
  cveTerm: string,
): Promise<SearchResponse['vulnerabilities']> {
  const candidates = await rowsOf<{ cve: string; kev: boolean; products: string[] }>(
    db,
    sql`select v.cve_id as cve, bool_or(v.kev) as kev, array_agg(distinct v.product) as products
        from vulnerability_advisories v
        where v.cve_id ilike ${contains(cveTerm)}
        group by v.cve_id
        order by v.cve_id
        limit ${CVE_CANDIDATE_LIMIT}`,
  );
  if (candidates.length === 0) return [];
  const products = [...new Set(candidates.flatMap((c) => c.products))];
  const [intel, groups] = await Promise.all([
    loadSoftwareIntel(db, products),
    softwareGroups(db, user, products),
  ]);
  if (!intel) return [];
  const wanted = new Set(candidates.map((c) => c.cve));
  const hosts = new Map<string, Set<string>>();
  for (const g of groups) {
    if (g.version === null) continue;
    for (const a of matchAdvisories(g.product, g.version, intel.advisories)) {
      if (!wanted.has(a.cveId)) continue;
      const set = hosts.get(a.cveId) ?? new Set<string>();
      for (const h of g.hosts) set.add(h);
      hosts.set(a.cveId, set);
    }
  }
  const upper = cveTerm.toUpperCase();
  return candidates
    .filter((c) => (hosts.get(c.cve)?.size ?? 0) > 0)
    .sort(
      (a, b) =>
        Number(b.cve === upper) - Number(a.cve === upper) ||
        a.cve.length - b.cve.length ||
        a.cve.localeCompare(b.cve),
    )
    .slice(0, LIMIT)
    .map((c) => ({ cve: c.cve, kev: c.kev, affectedHosts: hosts.get(c.cve)?.size ?? 0 }));
}
