import type { Database } from '@exdomainvault/database';
import { matchAdvisories, preciseEnough } from '@exdomainvault/rules';
import {
  CERTIFICATE_EXPIRING_DAYS,
  CERTIFICATE_STATUSES,
  softwareProduct,
  type CertificateItem,
  type CertificateStatus,
  type CertificatesResponse,
  type CurrentUser,
  type PortItem,
  type PortsResponse,
  type VulnerabilitiesResponse,
  type VulnerabilityItem,
  type certificatesQuerySchema,
  type portsQuerySchema,
  type vulnerabilitiesQuerySchema,
} from '@exdomainvault/shared';
import { canonicalIp } from '@exdomainvault/shared/net';
import { sql, type SQL } from 'drizzle-orm';
import type { z } from 'zod';
import { loadSoftwareIntel } from './software.ts';

/**
 * Cross-domain inventory views (Milestone 13): GET /ports, /certificates, /vulnerabilities.
 * Read-only projections of collected observations. Each endpoint is a fixed handful of set-based
 * statements (DISTINCT ON for "latest per key", GROUP BY for counts), whatever the portfolio size.
 * Asset owners see only rows tied to assets they own.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;
type PortsQuery = z.output<typeof portsQuerySchema>;
type CertificatesQuery = z.output<typeof certificatesQuerySchema>;
type VulnerabilitiesQuery = z.output<typeof vulnerabilitiesQuerySchema>;

const DAY_MS = 86_400_000;
/** TLS observations older than this are ignored (same window as the reports' certificate list). */
export const CERT_LOOKBACK_DAYS = 90;
/** (product, version) groups read for GET /vulnerabilities (bounded; far above real portfolios). */
export const VULN_GROUP_LIMIT = 5000;

async function rowsOf<T>(db: Database, query: SQL): Promise<T[]> {
  const res = (await db.execute(query)) as unknown as { rows: T[] };
  return res.rows;
}

const toDate = (v: Date | string) => (v instanceof Date ? v : new Date(v));
const isoOf = (v: Date | string) => toDate(v).toISOString();
const ts = (d: Date) => sql`${d.toISOString()}::timestamptz`;
const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);
const like = (q: string) => `%${escapeLike(q)}%`;
const displayIp = (v: string | null) => (v === null ? '' : (canonicalIp(v) ?? v));
const owner = (user: User) => user.role === 'asset_owner';

// --- GET /ports ---------------------------------------------------------------------------------

interface PortRow {
  ip: string;
  port: number;
  protocol: string;
  state: PortItem['state'];
  service: string | null;
  first_observed: Date | string;
  last_observed: Date | string;
  hostnames: { assetId: string; hostname: string; domainId: string; fqdn: string }[] | null;
  job_domain_id: string | null;
  job_fqdn: string | null;
  country: string | null;
  violation: boolean;
}

const PORT_ORDER: Record<PortsQuery['sort'], SQL> = {
  port: sql`r.port, r.ip_address, r.protocol`,
  ip: sql`r.ip_address, r.port, r.protocol`,
  last_observed: sql`r.last_observed desc, r.ip_address, r.port, r.protocol`,
};

/**
 * Latest successful port observation per (address, port, protocol). Hostnames are the visible
 * assets currently resolving to the address; asset owners see only addresses one of their assets
 * currently resolves to. `counts` cover every filter except `state` (so a UI can show all tabs);
 * `total` is the count for the requested state.
 */
export async function listPorts(db: Database, user: User, q: PortsQuery): Promise<PortsResponse> {
  const ownerOnly = owner(user) ? sql`and a.owner_user_id = ${user.id}` : sql``;
  const filters: SQL[] = [];
  if (owner(user)) filters.push(sql`h.ip_address is not null`);
  if (q.port !== undefined) filters.push(sql`l.port = ${q.port}`);
  if (q.domainId) {
    filters.push(
      sql`(l.job_domain_id = ${q.domainId}::uuid or ${q.domainId}::uuid = any(h.domain_ids))`,
    );
  }
  if (q.q) {
    const p = like(q.q.toLowerCase());
    filters.push(
      sql`(host(l.ip_address) ilike ${p} or coalesce(l.service, '') ilike ${p} or coalesce(h.names, '') ilike ${p})`,
    );
  }
  const where = filters.length > 0 ? sql.join(filters, sql` and `) : sql`true`;
  const base = sql`
    latest as (
      select distinct on (p.ip_address, p.port, p.protocol)
             p.ip_address, p.port, p.protocol, p.state, p.service, p.observed_at as last_observed,
             j.domain_id as job_domain_id
      from port_observations p
      join scan_jobs j on j.id = p.scan_job_id
      where p.result_status = 'success'
      order by p.ip_address, p.port, p.protocol, p.observed_at desc, p.id desc
    ),
    hosts as (
      select ai.ip_address,
             json_agg(json_build_object('assetId', a.id, 'hostname', a.hostname,
                                        'domainId', a.domain_id, 'fqdn', d.fqdn)
                      order by a.hostname, a.id) as hostnames,
             array_agg(distinct a.domain_id) as domain_ids,
             string_agg(a.hostname, ' ') as names
      from asset_ips ai
      join assets a on a.id = ai.asset_id
      join domains d on d.id = a.domain_id
      where ai.is_current ${ownerOnly}
      group by ai.ip_address
    ),
    r as (
      select l.*, h.hostnames
      from latest l left join hosts h on h.ip_address = l.ip_address
      where ${where}
    )`;
  const counts = { open: 0, closed: 0, filtered: 0 };
  for (const c of await rowsOf<{ state: string; n: number }>(
    db,
    sql`with ${base} select r.state, count(*)::int as n from r group by r.state`,
  )) {
    if (c.state in counts) counts[c.state as keyof typeof counts] = c.n;
  }
  const total =
    q.state === 'all' ? counts.open + counts.closed + counts.filtered : (counts[q.state] ?? 0);
  const stateFilter = q.state === 'all' ? sql`true` : sql`r.state = ${q.state}`;
  const rows = await rowsOf<PortRow>(
    db,
    sql`with ${base},
      page as (
        select r.* from r where ${stateFilter}
        order by ${PORT_ORDER[q.sort]}
        limit ${q.pageSize} offset ${(q.page - 1) * q.pageSize}
      )
      select host(pg.ip_address) as ip, pg.port, pg.protocol, pg.state, pg.service,
             pg.last_observed, pg.hostnames, pg.job_domain_id, jd.fqdn as job_fqdn,
             (select min(x.observed_at) from port_observations x
               where x.ip_address = pg.ip_address and x.port = pg.port
                 and x.protocol = pg.protocol and x.result_status = 'success') as first_observed,
             (select g.country_code from asset_ips g
               where g.ip_address = pg.ip_address and g.country_code is not null
               order by g.is_current desc, g.last_seen_at desc, g.country_code
               limit 1) as country,
             exists (
               select 1 from findings f
               where f.rule_id = 'EXP-002' and f.status <> 'resolved'
                 and f.component = case when family(pg.ip_address) = 6
                                        then '[' || host(pg.ip_address) || ']:' || pg.port
                                        else host(pg.ip_address) || ':' || pg.port end
             ) as violation
      from page pg
      left join domains jd on jd.id = pg.job_domain_id
      order by ${sql.raw(orderOnPage(q.sort))}`,
  );
  return {
    items: rows.map((r) => {
      const hostnames = r.hostnames ?? [];
      const first = hostnames[0];
      return {
        ipAddress: displayIp(r.ip),
        port: Number(r.port),
        protocol: r.protocol,
        state: r.state,
        service: r.service,
        hostnames: hostnames.map((h) => ({ assetId: h.assetId, hostname: h.hostname })),
        domain: first
          ? { id: first.domainId, fqdn: first.fqdn }
          : r.job_domain_id && r.job_fqdn
            ? { id: r.job_domain_id, fqdn: r.job_fqdn }
            : null,
        country: r.country,
        policyViolation: r.violation,
        firstObservedAt: isoOf(r.first_observed),
        lastObservedAt: isoOf(r.last_observed),
      };
    }),
    page: q.page,
    pageSize: q.pageSize,
    total,
    counts,
  };
}

/** The page's ORDER BY again on the outer select (column aliases of `page`). */
function orderOnPage(sort: PortsQuery['sort']): string {
  switch (sort) {
    case 'ip':
      return 'pg.ip_address, pg.port, pg.protocol';
    case 'last_observed':
      return 'pg.last_observed desc, pg.ip_address, pg.port, pg.protocol';
    default:
      return 'pg.port, pg.ip_address, pg.protocol';
  }
}

// --- GET /certificates --------------------------------------------------------------------------

interface CertRow {
  hostname: string;
  port: number;
  ip: string | null;
  domain_id: string;
  fqdn: string;
  asset_id: string | null;
  issuer: string | null;
  subject: string | null;
  sans: string[] | null;
  not_before: Date | string | null;
  not_after: Date | string | null;
  hostname_matches: boolean | null;
  trusted: boolean | null;
  protocol_version: string | null;
  status: CertificateStatus;
  observed_at: Date | string;
}

const CERT_ORDER: Record<CertificatesQuery['sort'], SQL> = {
  expiry: sql`c.not_after asc nulls last, c.hostname, c.port`,
  hostname: sql`c.hostname, c.port`,
};

/**
 * Latest successful certificate observation (`tls_certificate`) per (hostname, port) within the
 * last 90 days. Status precedence: expired > mismatch > untrusted > expiring (≤ 30 days) > valid;
 * `trusted` comes from the worker's chain validation (`evidence.trusted`), null when not recorded.
 * Asset owners see only hostnames of assets they own. `counts` cover every filter except `status`.
 */
export async function listCertificates(
  db: Database,
  user: User,
  q: CertificatesQuery,
  now: Date,
): Promise<CertificatesResponse> {
  const since = new Date(now.getTime() - CERT_LOOKBACK_DAYS * DAY_MS);
  const expiringBy = new Date(now.getTime() + CERTIFICATE_EXPIRING_DAYS * DAY_MS);
  const filters: SQL[] = [];
  if (q.domainId) filters.push(sql`latest.domain_id = ${q.domainId}::uuid`);
  if (q.q) {
    const p = like(q.q.toLowerCase());
    filters.push(
      sql`(latest.hostname ilike ${p} or coalesce(latest.issuer, '') ilike ${p} or coalesce(latest.subject, '') ilike ${p})`,
    );
  }
  const where = filters.length > 0 ? sql.join(filters, sql` and `) : sql`true`;
  const base = sql`
    latest as (
      select distinct on (t.hostname, t.port)
             t.hostname, t.port, host(t.ip_address) as ip, t.issuer, t.subject,
             t.subject_alt_names as sans, t.not_before, t.not_after, t.hostname_matches,
             t.protocol_version, t.observed_at, a.id as asset_id,
             coalesce(a.domain_id, j.domain_id) as domain_id,
             case when jsonb_typeof(t.evidence->'trusted') = 'boolean'
                  then (t.evidence->>'trusted')::boolean end as trusted
      from tls_observations t
      join scan_jobs j on j.id = t.scan_job_id
      left join assets a on a.id = t.asset_id
      where t.result_status = 'success'
        and coalesce(t.evidence->>'check', 'tls_certificate') = 'tls_certificate'
        and t.observed_at >= ${ts(since)}
        ${owner(user) ? sql`and a.owner_user_id = ${user.id}` : sql``}
      order by t.hostname, t.port, t.observed_at desc, t.id desc
    ),
    c as (
      select latest.*, d.fqdn,
        case
          when latest.not_after is not null and latest.not_after < ${ts(now)} then 'expired'
          when latest.hostname_matches = false then 'mismatch'
          when latest.trusted = false then 'untrusted'
          when latest.not_after is not null and latest.not_after <= ${ts(expiringBy)} then 'expiring'
          else 'valid'
        end as status
      from latest join domains d on d.id = latest.domain_id
      where ${where}
    )`;
  const counts = Object.fromEntries(CERTIFICATE_STATUSES.map((s) => [s, 0])) as Record<
    CertificateStatus,
    number
  >;
  for (const r of await rowsOf<{ status: CertificateStatus; n: number }>(
    db,
    sql`with ${base} select c.status, count(*)::int as n from c group by c.status`,
  )) {
    counts[r.status] = r.n;
  }
  const total = q.status ? counts[q.status] : Object.values(counts).reduce((sum, n) => sum + n, 0);
  const rows = await rowsOf<CertRow>(
    db,
    sql`with ${base}
      select c.* from c
      where ${q.status ? sql`c.status = ${q.status}` : sql`true`}
      order by ${CERT_ORDER[q.sort]}
      limit ${q.pageSize} offset ${(q.page - 1) * q.pageSize}`,
  );
  return {
    items: rows.map((r): CertificateItem => {
      const notAfter = r.not_after === null ? null : toDate(r.not_after);
      return {
        hostname: r.hostname,
        domain: { id: r.domain_id, fqdn: r.fqdn },
        assetId: r.asset_id,
        ipAddress: displayIp(r.ip),
        port: Number(r.port),
        issuer: r.issuer,
        subject: r.subject,
        subjectAltNames: r.sans ?? [],
        notBefore: r.not_before === null ? null : isoOf(r.not_before),
        notAfter: notAfter ? notAfter.toISOString() : null,
        daysLeft: notAfter ? Math.floor((notAfter.getTime() - now.getTime()) / DAY_MS) : null,
        hostnameMatches: r.hostname_matches,
        trusted: r.trusted,
        protocolVersion: r.protocol_version,
        status: r.status,
        observedAt: isoOf(r.observed_at),
      };
    }),
    page: q.page,
    pageSize: q.pageSize,
    total,
    counts,
  };
}

// --- GET /vulnerabilities -----------------------------------------------------------------------

interface VersionGroup {
  product: string;
  version: string;
  hosts: string[];
  domains: string[];
}

/** Numeric CVE ordering (`CVE-2021-4` < `CVE-2021-44228`), ascending. */
function compareCve(a: string, b: string): number {
  const pa = a.split('-');
  const pb = b.split('-');
  return (
    Number(pa[1]) - Number(pb[1]) || Number(pa[2]) - Number(pb[2]) || (a < b ? -1 : a > b ? 1 : 0)
  );
}

/**
 * One row per CVE that possibly affects at least one disclosed version in the (visible) software
 * inventory, matched exactly like SOFT-002: a version precise enough to range-match inside any NVD
 * range of a CISA KEV advisory for the product (`matchAdvisories`). Hosts are distinct inventory
 * locations (hostname, else address); `openFindings` counts active SOFT-002 findings naming the CVE
 * (`evidence.cveId`). Asset owners see only inventory rows and findings on assets they own.
 * Every advisory the matcher considers is a KEV entry, so `kev=false` yields an empty list.
 */
export async function listVulnerabilities(
  db: Database,
  user: User,
  q: VulnerabilitiesQuery,
): Promise<VulnerabilitiesResponse> {
  const empty = { items: [], page: q.page, pageSize: q.pageSize, total: 0 };
  const ownerOnly = owner(user)
    ? sql`and si.asset_id in (select id from assets where owner_user_id = ${user.id})`
    : sql``;
  const groups = await rowsOf<VersionGroup>(
    db,
    sql`select si.product, si.version,
               array_agg(distinct coalesce(si.hostname, host(si.ip_address))) as hosts,
               array_agg(distinct si.domain_id::text) as domains
        from software_inventory si
        where si.version is not null
          and si.product in (
            select va.product from vulnerability_advisories va
            where va.kev and va.nvd_status = 'ok')
          ${ownerOnly}
        group by si.product, si.version
        order by si.product, si.version
        limit ${VULN_GROUP_LIMIT}`,
  );
  if (q.kev === false || groups.length === 0) return empty;
  const intel = await loadSoftwareIntel(
    db,
    groups.map((g) => g.product),
  );
  if (!intel) return empty;

  interface Acc {
    item: Omit<VulnerabilityItem, 'affectedHosts' | 'affectedDomains' | 'openFindings'>;
    products: Map<string, string>;
    hosts: Set<string>;
    domains: Set<string>;
  }
  const byCve = new Map<string, Acc>();
  for (const g of groups) {
    if (!preciseEnough(g.version)) continue;
    for (const a of matchAdvisories(g.product, g.version, intel.advisories)) {
      let acc = byCve.get(a.cveId);
      if (!acc) {
        acc = {
          item: {
            cve: a.cveId,
            title: a.title,
            cvss: a.cvss,
            kev: a.kev,
            knownRansomwareUse: a.ransomware,
            products: [],
            kevDateAdded: a.kevDateAdded,
            // Not stored by the KEV sync (Milestone 11 keeps dateAdded only).
            kevDueDate: null,
          },
          products: new Map(),
          hosts: new Set(),
          domains: new Set(),
        };
        byCve.set(a.cveId, acc);
      }
      if (a.cvss !== null && (acc.item.cvss === null || a.cvss > acc.item.cvss)) {
        acc.item.cvss = a.cvss;
      }
      if (a.ransomware) acc.item.knownRansomwareUse = true;
      acc.products.set(g.product, softwareProduct(g.product)?.label ?? g.product);
      for (const h of g.hosts) acc.hosts.add(h);
      for (const d of g.domains) acc.domains.add(d);
    }
  }
  if (byCve.size === 0) return empty;

  const findingVis = owner(user)
    ? sql`and f.asset_id in (select id from assets where owner_user_id = ${user.id})`
    : sql``;
  const open = new Map(
    (
      await rowsOf<{ cve: string; n: number }>(
        db,
        sql`select f.evidence->>'cveId' as cve, count(*)::int as n
            from findings f
            where f.rule_id = 'SOFT-002' and f.status <> 'resolved' ${findingVis}
            group by 1`,
      )
    ).map((r) => [r.cve, r.n]),
  );

  let items: VulnerabilityItem[] = [...byCve.values()].map((acc) => ({
    ...acc.item,
    products: [...acc.products]
      .map(([product, productLabel]) => ({ product, productLabel }))
      .sort((a, b) => (a.product < b.product ? -1 : a.product > b.product ? 1 : 0)),
    affectedHosts: acc.hosts.size,
    affectedDomains: acc.domains.size,
    openFindings: open.get(acc.item.cve) ?? 0,
  }));
  if (q.q) {
    const needle = q.q.toLowerCase();
    items = items.filter(
      (i) =>
        i.cve.toLowerCase().includes(needle) ||
        (i.title ?? '').toLowerCase().includes(needle) ||
        i.products.some(
          (p) =>
            p.product.toLowerCase().includes(needle) ||
            p.productLabel.toLowerCase().includes(needle),
        ),
    );
  }
  const bySort: Record<
    VulnerabilitiesQuery['sort'],
    (a: VulnerabilityItem, b: VulnerabilityItem) => number
  > = {
    cvss: (a, b) => (b.cvss ?? -1) - (a.cvss ?? -1) || compareCve(a.cve, b.cve),
    hosts: (a, b) =>
      b.affectedHosts - a.affectedHosts ||
      (b.cvss ?? -1) - (a.cvss ?? -1) ||
      compareCve(a.cve, b.cve),
    cve: (a, b) => compareCve(a.cve, b.cve),
  };
  items.sort(bySort[q.sort]);
  const offset = (q.page - 1) * q.pageSize;
  return {
    items: items.slice(offset, offset + q.pageSize),
    page: q.page,
    pageSize: q.pageSize,
    total: items.length,
  };
}
