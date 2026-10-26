import type { Database } from '@exdomainvault/database';
import {
  SEVERITIES,
  hasPermission,
  softwareProduct,
  type AssetRole,
  type CurrentUser,
  type DashboardRange,
  type DashboardResponse,
  type DashboardStat,
  type Permission,
  type Severity,
} from '@exdomainvault/shared';
import { sql, type SQL } from 'drizzle-orm';
import { rowsOf } from '../lib/db.ts';
import { assetRolesFor } from './asset-roles.ts';
import { SUMMARY_GROUP_LIMIT, statusComputer } from './software.ts';

/**
 * Overview dashboard (Milestone 13): `GET /dashboard`. Every card is one set-based statement
 * (aggregates, `generate_series` for daily series, `DISTINCT ON` for latest observations), so the
 * cost is a fixed number of queries regardless of portfolio size. All values are database
 * aggregates of stored data — nothing is estimated.
 *
 * Scoping mirrors the lists the cards link to: asset owners see only findings, assets, certificates
 * and software on assets they own; sections need the permission of their list (domain counts:
 * `domains:read`; scans: `scans:read`; assets and certificates: `assets:read`; findings and
 * software: `findings:read`) and are zero / empty without it.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;

const DAY_MS = 86_400_000;
/** TLS observations older than this are ignored (same look-back as the reports summary). */
const CERT_LOOKBACK_DAYS = 90;
/** "Expiring" certificates: notAfter within this many days (expired included). */
const CERT_EXPIRY_DAYS = 30;
const LIST_LIMIT = 5;
const TOP_VERSIONS = 3;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

const toDate = (v: Date | string) => (v instanceof Date ? v : new Date(v));
const iso = (v: Date | string) => toDate(v).toISOString();
const ts = (d: Date) => sql`${d.toISOString()}::timestamptz`;
const utcDay = (d: Date) => d.toISOString().slice(0, 10);
const daysLeft = (at: Date, now: Date) => Math.floor((at.getTime() - now.getTime()) / DAY_MS);

const zeros = <K extends string>(keys: readonly K[]) =>
  Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>;

/** Findings visible to the user, on alias `f` (asset owners: findings on assets they own). */
export function findingVisibility(user: User): SQL {
  return user.role === 'asset_owner'
    ? sql`f.asset_id in (select oa.id from assets oa where oa.owner_user_id = ${user.id})`
    : sql`true`;
}

/** Assets visible to the user, on alias `a`. */
export function assetVisibility(user: User): SQL {
  return user.role === 'asset_owner' ? sql`a.owner_user_id = ${user.id}` : sql`true`;
}

/** Software inventory rows visible to the user, on alias `s` (owners: rows on their assets). */
export function softwareVisibility(user: User): SQL {
  return user.role === 'asset_owner'
    ? sql`s.asset_id in (select oa.id from assets oa where oa.owner_user_id = ${user.id})`
    : sql`true`;
}

const stat = (value: number, series: readonly (number | string)[]): DashboardStat => {
  const points = series.map(Number);
  const first = points[0];
  const last = points[points.length - 1];
  return {
    value,
    delta: first === undefined || last === undefined ? null : last - first,
    series: points,
  };
};
const noHistory = (value: number): DashboardStat => ({ value, delta: null, series: [] });

// --- Software groups (shared with search) --------------------------------------------------------

export interface SoftwareGroup {
  product: string;
  version: string | null;
  rows: number;
  /** Distinct host keys: coalesce(hostname, ip). */
  hosts: string[];
}

/**
 * Visible inventory grouped by (product, version), with the distinct hosts reporting each pair.
 * Bounded by SUMMARY_GROUP_LIMIT pairs, like GET /software/summary.
 */
export async function softwareGroups(
  db: Database,
  user: User,
  products?: readonly string[],
): Promise<SoftwareGroup[]> {
  if (products && products.length === 0) return [];
  const only = products
    ? sql`and s.product in (${sql.join(
        products.map((p) => sql`${p}`),
        sql`, `,
      )})`
    : sql``;
  const rows = await rowsOf<{
    product: string;
    version: string | null;
    rows: number;
    hosts: (string | null)[] | null;
  }>(
    db,
    sql`select s.product, s.version, count(*)::int as rows,
               array_agg(distinct coalesce(s.hostname, host(s.ip_address))) as hosts
        from software_inventory s
        where ${softwareVisibility(user)} ${only}
        group by s.product, s.version
        order by s.product, count(*) desc, s.version nulls last
        limit ${SUMMARY_GROUP_LIMIT}`,
  );
  return rows.map((r) => ({
    product: r.product,
    version: r.version,
    rows: Number(r.rows),
    hosts: (r.hosts ?? []).filter((h): h is string => h !== null),
  }));
}

// --- Dashboard ------------------------------------------------------------------------------------

/** GET /dashboard?range=7|30|90. */
export async function dashboard(
  db: Database,
  user: User,
  range: DashboardRange,
  now: Date,
): Promise<DashboardResponse> {
  const can = (p: Permission) => hasPermission(user.role, p);
  const owner = user.role === 'asset_owner';
  const readDomains = can('domains:read') && !owner;
  const readScans = can('scans:read') && !owner;
  const readAssets = can('assets:read');
  const readFindings = can('findings:read');
  const fVis = findingVisibility(user);
  const aVis = assetVisibility(user);

  const today = utcDay(now);
  const start = utcDay(new Date(now.getTime() - range * DAY_MS));
  const startTs = ts(new Date(`${start}T00:00:00.000Z`));
  const days = sql`days as (
    select d::date as d from generate_series(${start}::date, ${today}::date, interval '1 day') as d
  )`;
  /** End (exclusive) of the series day `days.d`, as a UTC timestamp. */
  const dayEnd = sql`((days.d + 1)::timestamp at time zone 'UTC')`;

  const domainCard = readDomains
    ? rowsOf<{ value: number; active: number; n: number }>(
        db,
        sql`with ${days}
            select (select count(*) from domains)::int as value,
                   (select count(*) from domains where monitoring_enabled)::int as active,
                   (select count(*) from domains x where x.created_at < ${dayEnd})::int as n
            from days order by days.d`,
      )
    : Promise.resolve([]);

  const assetCard = readAssets
    ? rowsOf<{ value: number; pending: number; n: number }>(
        db,
        sql`with ${days}
            select (select count(*) from assets a
                     where ${aVis} and a.verification_status = 'approved')::int as value,
                   (select count(*) from assets a
                     where ${aVis} and a.verification_status = 'pending')::int as pending,
                   (select count(*) from assets a
                     where ${aVis} and a.verification_status = 'approved'
                       and a.approved_at < ${dayEnd})::int as n
            from days order by days.d`,
      )
    : Promise.resolve([]);

  const findingSeries = readFindings
    ? rowsOf<{ open: number; ch: number }>(
        db,
        sql`with ${days}
            select
              (select count(*) from findings f
                where ${fVis} and f.first_seen_at < ${dayEnd}
                  and (f.resolved_at is null or f.resolved_at >= ${dayEnd}))::int as open,
              (select count(*) from findings f
                where ${fVis} and f.severity in ('critical', 'high') and f.first_seen_at < ${dayEnd}
                  and (f.resolved_at is null or f.resolved_at >= ${dayEnd}))::int as ch
            from days order by days.d`,
      )
    : Promise.resolve([]);

  const severityRows = readFindings
    ? rowsOf<{ severity: Severity; n: number }>(
        db,
        sql`select f.severity, count(*)::int as n from findings f
            where ${fVis} and f.status <> 'resolved' group by f.severity`,
      )
    : Promise.resolve([]);

  const trendRows = readFindings
    ? rowsOf<{
        date: string;
        critical: number;
        high: number;
        medium: number;
        low: number;
        informational: number;
        resolved: number;
      }>(
        db,
        sql`with ${days},
            c as (
              select (f.first_seen_at at time zone 'UTC')::date as d, f.severity, count(*) as n
              from findings f where ${fVis} and f.first_seen_at >= ${startTs} group by 1, 2
            ),
            r as (
              select (f.resolved_at at time zone 'UTC')::date as d, count(*) as n
              from findings f where ${fVis} and f.resolved_at >= ${startTs} group by 1
            )
            select to_char(days.d, 'YYYY-MM-DD') as date,
              coalesce(sum(c.n) filter (where c.severity = 'critical'), 0)::int as critical,
              coalesce(sum(c.n) filter (where c.severity = 'high'), 0)::int as high,
              coalesce(sum(c.n) filter (where c.severity = 'medium'), 0)::int as medium,
              coalesce(sum(c.n) filter (where c.severity = 'low'), 0)::int as low,
              coalesce(sum(c.n) filter (where c.severity = 'informational'), 0)::int as informational,
              coalesce((select r.n from r where r.d = days.d), 0)::int as resolved
            from days left join c on c.d = days.d
            group by days.d order by days.d`,
      )
    : Promise.resolve([]);

  // Remediation queue: actionable findings (accepted risks are excluded — they are not to-dos).
  const remediationRows = readFindings
    ? rowsOf<{
        id: string;
        title: string;
        rule_id: string;
        severity: Severity;
        risk_score: number;
        domain_id: string;
        fqdn: string;
        hostname: string | null;
        asset_id: string | null;
        cve: string | null;
      }>(
        db,
        sql`select f.id, f.title, f.rule_id, f.severity, f.risk_score, f.domain_id, d.fqdn,
                   f.hostname, f.asset_id, f.evidence->>'cveId' as cve
            from findings f join domains d on d.id = f.domain_id
            where ${fVis} and f.status in ('open', 'acknowledged', 'remediation_in_progress')
            order by f.risk_score desc, f.severity desc, f.first_seen_at, f.id
            limit ${LIST_LIMIT}`,
      )
    : Promise.resolve([]);

  const scanRows = readScans
    ? rowsOf<{
        id: string;
        job_type: 'scan' | 'discovery';
        domain_id: string;
        fqdn: string;
        profile: string;
        status: string;
        created_at: Date | string;
        completed_at: Date | string | null;
      }>(
        db,
        sql`select j.id, j.job_type, j.domain_id, d.fqdn, coalesce(p.name, j.profile) as profile,
                   j.status::text as status, j.created_at, j.completed_at
            from scan_jobs j
            join domains d on d.id = j.domain_id
            left join scan_profiles p on p.key = j.profile
            order by j.created_at desc, j.id desc
            limit ${LIST_LIMIT}`,
      )
    : Promise.resolve([]);
  const lastScanRow = readScans
    ? rowsOf<{ last_scan: Date | string | null }>(
        db,
        sql`select max(completed_at) as last_scan from scan_jobs where status = 'succeeded'`,
      )
    : Promise.resolve([]);

  const certRows = readAssets
    ? rowsOf<{
        domain_id: string;
        fqdn: string;
        hostname: string;
        not_after: Date | string;
        issuer: string | null;
        total: number;
      }>(
        db,
        sql`select latest.domain_id, d.fqdn, latest.hostname, latest.not_after, latest.issuer,
                   (count(*) over ())::int as total
            from (
              select distinct on (t.hostname) t.hostname, t.not_after, t.issuer,
                     coalesce(a.domain_id, j.domain_id) as domain_id
              from tls_observations t
              left join assets a on a.id = t.asset_id
              join scan_jobs j on j.id = t.scan_job_id
              where t.result_status = 'success'
                and t.observed_at >= ${ts(new Date(now.getTime() - CERT_LOOKBACK_DAYS * DAY_MS))}
                ${owner ? sql`and a.owner_user_id = ${user.id}` : sql``}
              order by t.hostname, t.observed_at desc, t.id desc
            ) latest
            join domains d on d.id = latest.domain_id
            where latest.not_after is not null
              and latest.not_after <= ${ts(new Date(now.getTime() + CERT_EXPIRY_DAYS * DAY_MS))}
            order by latest.not_after, latest.hostname
            limit ${LIST_LIMIT}`,
      )
    : Promise.resolve([]);

  const recentRows = readAssets
    ? rowsOf<{
        id: string;
        hostname: string;
        domain_id: string;
        fqdn: string;
        status: DashboardResponse['recentAssets'][number]['status'];
        source: DashboardResponse['recentAssets'][number]['source'];
        first_seen_at: Date | string;
      }>(
        db,
        sql`select a.id, a.hostname, a.domain_id, d.fqdn, a.verification_status as status,
                   a.discovery_source as source, a.first_seen_at
            from assets a join domains d on d.id = a.domain_id
            where ${aVis}
            order by a.first_seen_at desc, a.hostname, a.id
            limit ${LIST_LIMIT}`,
      )
    : Promise.resolve([]);

  const groupsP = readFindings ? softwareGroups(db, user) : Promise.resolve([]);

  const [
    domainRows,
    assetRows,
    seriesRows,
    sevRows,
    trend,
    remediation,
    scans,
    lastScan,
    certs,
    recent,
    groups,
  ] = await Promise.all([
    domainCard,
    assetCard,
    findingSeries,
    severityRows,
    trendRows,
    remediationRows,
    scanRows,
    lastScanRow,
    certRows,
    recentRows,
    groupsP,
  ]);

  // Roles for remediation targets and recent assets (one statement).
  const roleIds = [
    ...new Set([
      ...remediation.map((r) => r.asset_id).filter((id): id is string => id !== null),
      ...recent.map((r) => r.id),
    ]),
  ];
  const roles: Map<string, AssetRole> =
    roleIds.length > 0 ? await assetRolesFor(db, roleIds) : new Map();

  // Severity / open counts.
  const severity = zeros(SEVERITIES);
  for (const r of sevRows) severity[r.severity] = Number(r.n);
  const open = SEVERITIES.reduce((n, s) => n + severity[s], 0);

  // Software: end-of-life rows, KEV rows and the top products.
  const status = await statusComputer(
    db,
    groups.map((g) => g.product),
    now,
  );
  let eolRows = 0;
  let kevRows = 0;
  const products = new Map<
    string,
    {
      hosts: Set<string>;
      eolHosts: Set<string>;
      cves: Set<string>;
      versions: { version: string; hosts: number }[];
    }
  >();
  for (const g of groups) {
    const s = status(g.product, g.version);
    if (s.eol?.isEol) eolRows += g.rows;
    if (s.knownExploited.length > 0) kevRows += g.rows;
    let p = products.get(g.product);
    if (!p) {
      p = { hosts: new Set(), eolHosts: new Set(), cves: new Set(), versions: [] };
      products.set(g.product, p);
    }
    for (const h of g.hosts) {
      p.hosts.add(h);
      if (s.eol?.isEol) p.eolHosts.add(h);
    }
    for (const k of s.knownExploited) p.cves.add(k.cveId);
    if (g.version !== null) p.versions.push({ version: g.version, hosts: g.hosts.length });
  }
  const topSoftware = [...products.entries()]
    .map(([product, p]) => ({
      product,
      productLabel: softwareProduct(product)?.label ?? product,
      versions: [...p.versions]
        .sort((a, b) => b.hosts - a.hosts || a.version.localeCompare(b.version))
        .slice(0, TOP_VERSIONS)
        .map((v) => v.version),
      hosts: p.hosts.size,
      eolHosts: p.eolHosts.size,
      kevCves: p.cves.size,
    }))
    .sort((a, b) => b.hosts - a.hosts || a.product.localeCompare(b.product))
    .slice(0, LIST_LIMIT);

  const last = lastScan[0]?.last_scan ?? null;
  const firstDomain = domainRows[0];
  const firstAsset = assetRows[0];

  return {
    generatedAt: now.toISOString(),
    range,
    lastScanAt: last === null ? null : iso(last),
    stats: {
      domains: readDomains
        ? {
            ...stat(
              Number(firstDomain?.value ?? 0),
              domainRows.map((r) => r.n),
            ),
            active: Number(firstDomain?.active ?? 0),
          }
        : { ...noHistory(0), active: 0 },
      assets: readAssets
        ? {
            ...stat(
              Number(firstAsset?.value ?? 0),
              assetRows.map((r) => r.n),
            ),
            pending: Number(firstAsset?.pending ?? 0),
          }
        : { ...noHistory(0), pending: 0 },
      openFindings: readFindings
        ? stat(
            open,
            seriesRows.map((r) => r.open),
          )
        : noHistory(0),
      criticalHigh: readFindings
        ? stat(
            severity.critical + severity.high,
            seriesRows.map((r) => r.ch),
          )
        : noHistory(0),
      expiringCertificates: noHistory(Number(certs[0]?.total ?? 0)),
      eolSoftware: { ...noHistory(eolRows), kev: kevRows },
    },
    severity,
    trend: trend.map((r) => ({
      date: r.date,
      critical: Number(r.critical),
      high: Number(r.high),
      medium: Number(r.medium),
      low: Number(r.low),
      informational: Number(r.informational),
      resolved: Number(r.resolved),
    })),
    topRemediation: remediation.map((r) => ({
      findingId: r.id,
      title: r.title,
      ruleId: r.rule_id,
      severity: r.severity,
      riskScore: Number(r.risk_score),
      domain: { id: r.domain_id, fqdn: r.fqdn },
      hostname: r.hostname,
      cves: r.cve !== null && CVE_RE.test(r.cve) ? [r.cve] : [],
      assetRole: r.asset_id === null ? null : (roles.get(r.asset_id) ?? 'unclassified'),
    })),
    latestScans: scans.map((r) => ({
      id: r.id,
      jobType: r.job_type,
      domain: { id: r.domain_id, fqdn: r.fqdn },
      profile: r.profile,
      status: r.status,
      createdAt: iso(r.created_at),
      completedAt: r.completed_at === null ? null : iso(r.completed_at),
    })),
    certificateExpiry: certs.map((r) => {
      const at = toDate(r.not_after);
      return {
        hostname: r.hostname,
        domain: { id: r.domain_id, fqdn: r.fqdn },
        notAfter: at.toISOString(),
        daysLeft: daysLeft(at, now),
        issuer: r.issuer,
      };
    }),
    recentAssets: recent.map((r) => ({
      id: r.id,
      hostname: r.hostname,
      domain: { id: r.domain_id, fqdn: r.fqdn },
      status: r.status,
      source: r.source,
      role: roles.get(r.id) ?? 'unclassified',
      firstSeenAt: iso(r.first_seen_at),
    })),
    topSoftware,
  };
}
