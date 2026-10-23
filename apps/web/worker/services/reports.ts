import { schema, type Database } from '@exdomainvault/database';
import {
  FINDING_STATUSES,
  REPORT_CSV_COLUMNS,
  REPORT_CSV_MAX_ROWS,
  REPORT_EXPIRY_DAYS,
  REPORT_TREND_DAYS,
  RULE_CATEGORIES,
  SEVERITIES,
  type CurrentUser,
  type Criticality,
  type FindingListQuery,
  type ReportSummaryResponse,
  type Severity,
} from '@exdomainvault/shared';
import { eq, sql, type SQL } from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';
import { auditFilters, csvLine, UTF8_BOM } from '../lib/csv-export.ts';
import { writeAudit } from './audit.ts';
import type { Actor } from './domains.ts';
import { findingFilters, orderFor } from './findings.ts';

const { domains, findings, users } = schema;

type User = Pick<CurrentUser, 'id' | 'role'>;
type FindingStatus = (typeof FINDING_STATUSES)[number];
type Category = (typeof RULE_CATEGORIES)[number];

const DAY_MS = 86_400_000;
/** Window for mean time to resolve. */
const MTTR_DAYS = 90;
/** TLS observations older than this are ignored (hosts no longer scanned would show forever). */
const CERT_LOOKBACK_DAYS = 90;
const LIST_LIMIT = 50;
const OWNER_LIMIT = 100;

/** Rows of a raw statement (node-postgres and PGlite both return `{ rows }`). */
async function rowsOf<T>(db: Database, query: SQL): Promise<T[]> {
  const res = (await db.execute(query)) as unknown as { rows: T[] };
  return res.rows;
}

const toDate = (v: Date | string) => (v instanceof Date ? v : new Date(v));
const ts = (d: Date) => sql`${d.toISOString()}::timestamptz`;
const daysLeft = (at: Date, now: Date) => Math.floor((at.getTime() - now.getTime()) / DAY_MS);
const utcDay = (d: Date) => d.toISOString().slice(0, 10);

/**
 * Object-level visibility as raw SQL on the alias `f` (findings) — the same rule as `visibleTo`:
 * asset owners see only findings on assets they own.
 */
function findingVisibility(user: User): SQL {
  return user.role === 'asset_owner'
    ? sql`f.asset_id in (select a.id from assets a where a.owner_user_id = ${user.id})`
    : sql`true`;
}

const zeros = <K extends string>(keys: readonly K[]) =>
  Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>;

/**
 * GET /reports/summary. Every section is a single aggregate statement (GROUP BY, generate_series,
 * DISTINCT ON), so the response costs a fixed handful of queries regardless of portfolio size.
 * Asset owners get the finding sections for findings they can see, their own assets' counts and
 * certificates; domain-level sections (domain counts, last scan, top domains, business owners,
 * registrations) are zero or empty for them.
 */
export async function reportSummary(
  db: Database,
  user: User,
  now: Date,
): Promise<ReportSummaryResponse> {
  const owner = user.role === 'asset_owner';
  const vis = findingVisibility(user);

  const [coverage] = await rowsOf<{
    domains: number;
    monitored: number;
    verified: number;
    approved: number;
    pending: number;
    last_scan: Date | string | null;
  }>(
    db,
    owner
      ? sql`select 0 as domains, 0 as monitored, 0 as verified,
          (select count(*) from assets where owner_user_id = ${user.id} and verification_status = 'approved')::int as approved,
          (select count(*) from assets where owner_user_id = ${user.id} and verification_status = 'pending')::int as pending,
          null::timestamptz as last_scan`
      : sql`select
          (select count(*) from domains)::int as domains,
          (select count(*) from domains where monitoring_enabled)::int as monitored,
          (select count(*) from domains where verification_status = 'verified')::int as verified,
          (select count(*) from assets where verification_status = 'approved')::int as approved,
          (select count(*) from assets where verification_status = 'pending')::int as pending,
          (select max(completed_at) from scan_jobs where status = 'succeeded') as last_scan`,
  );

  const counts = await rowsOf<{
    status: FindingStatus;
    severity: Severity;
    category: string;
    n: number;
  }>(
    db,
    sql`select f.status, f.severity, f.category, count(*)::int as n
        from findings f where ${vis}
        group by f.status, f.severity, f.category`,
  );
  const bySeverity = zeros(SEVERITIES);
  const byStatus = zeros(FINDING_STATUSES);
  const byCategory = zeros(RULE_CATEGORIES);
  let open = 0;
  for (const r of counts) {
    byStatus[r.status] += r.n;
    if (r.status === 'resolved') continue;
    open += r.n;
    bySeverity[r.severity] += r.n;
    if (r.category in byCategory) byCategory[r.category as Category] += r.n;
  }

  const [mttr] = await rowsOf<{ days: number | null }>(
    db,
    sql`select avg(extract(epoch from (f.resolved_at - f.first_seen_at)))::float8 / 86400 as days
        from findings f
        where ${vis} and f.status = 'resolved'
          and f.resolved_at >= ${ts(new Date(now.getTime() - MTTR_DAYS * DAY_MS))}`,
  );

  const today = utcDay(now);
  const start = utcDay(new Date(now.getTime() - (REPORT_TREND_DAYS - 1) * DAY_MS));
  const startTs = ts(new Date(`${start}T00:00:00.000Z`));
  const trend = await rowsOf<{ date: string; created: number; resolved: number }>(
    db,
    sql`with days as (
          select d::date as d from generate_series(${start}::date, ${today}::date, interval '1 day') as d
        ),
        c as (
          select (f.first_seen_at at time zone 'UTC')::date as d, count(*) as n
          from findings f where ${vis} and f.first_seen_at >= ${startTs} group by 1
        ),
        r as (
          select (f.resolved_at at time zone 'UTC')::date as d, count(*) as n
          from findings f where ${vis} and f.resolved_at >= ${startTs} group by 1
        )
        select to_char(days.d, 'YYYY-MM-DD') as date,
               coalesce(c.n, 0)::int as created, coalesce(r.n, 0)::int as resolved
        from days left join c on c.d = days.d left join r on r.d = days.d
        order by days.d`,
  );

  const topDomains = owner
    ? []
    : await rowsOf<{
        id: string;
        fqdn: string;
        criticality: Criticality;
        open: number;
        risk: number;
        highest: Severity;
      }>(
        db,
        sql`select d.id, d.fqdn, d.criticality, count(*)::int as open,
                   sum(f.risk_score)::int as risk, max(f.severity) as highest
            from findings f join domains d on d.id = f.domain_id
            where f.status <> 'resolved'
            group by d.id
            order by risk desc, open desc, d.fqdn
            limit 10`,
      );

  const byOwner = owner
    ? []
    : await rowsOf<{ owner: string | null; domains: number; open: number; high: number }>(
        db,
        sql`select d.business_owner as owner, count(distinct d.id)::int as domains,
                   count(f.id)::int as open,
                   (count(f.id) filter (where f.severity in ('high', 'critical')))::int as high
            from domains d
            left join findings f on f.domain_id = d.id and f.status <> 'resolved'
            group by d.business_owner
            order by open desc, high desc, d.business_owner nulls last
            limit ${OWNER_LIMIT}`,
      );

  const registrations = owner
    ? []
    : await rowsOf<{ id: string; fqdn: string; expires_at: Date | string }>(
        db,
        sql`select d.id, d.fqdn, d.expires_at from domains d
            where d.expires_at is not null
              and d.expires_at <= ${ts(new Date(now.getTime() + REPORT_EXPIRY_DAYS.registration * DAY_MS))}
            order by d.expires_at, d.fqdn
            limit ${LIST_LIMIT}`,
      );

  const certificates = await rowsOf<{
    domain_id: string;
    fqdn: string;
    hostname: string;
    not_after: Date | string;
    issuer: string | null;
  }>(
    db,
    sql`select latest.domain_id, d.fqdn, latest.hostname, latest.not_after, latest.issuer
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
          and latest.not_after <= ${ts(new Date(now.getTime() + REPORT_EXPIRY_DAYS.certificate * DAY_MS))}
        order by latest.not_after, latest.hostname
        limit ${LIST_LIMIT}`,
  );

  const risks = await rowsOf<{
    id: string;
    title: string;
    domain_id: string;
    fqdn: string;
    review_at: Date | string;
  }>(
    db,
    sql`select f.id, f.title, f.domain_id, d.fqdn, f.accepted_risk_review_at as review_at
        from findings f join domains d on d.id = f.domain_id
        where ${vis} and f.status = 'accepted_risk'
          and f.accepted_risk_review_at <= ${ts(new Date(now.getTime() + REPORT_EXPIRY_DAYS.acceptedRisk * DAY_MS))}
        order by f.accepted_risk_review_at, f.id
        limit ${LIST_LIMIT}`,
  );

  const c = coverage ?? {
    domains: 0,
    monitored: 0,
    verified: 0,
    approved: 0,
    pending: 0,
    last_scan: null,
  };
  const mean = mttr?.days;
  return {
    generatedAt: now.toISOString(),
    coverage: {
      domains: c.domains,
      monitoredDomains: c.monitored,
      verifiedDomains: c.verified,
      approvedAssets: c.approved,
      pendingAssets: c.pending,
      lastScanAt: c.last_scan === null ? null : toDate(c.last_scan).toISOString(),
    },
    findings: {
      open,
      bySeverity,
      byStatus,
      byCategory,
      meanDaysToResolve:
        mean === null || mean === undefined ? null : Math.round(Number(mean) * 100) / 100,
    },
    trendDays: REPORT_TREND_DAYS,
    trend: trend.map((r) => ({ date: r.date, created: r.created, resolved: r.resolved })),
    topDomains: topDomains.map((r) => ({
      domain: { id: r.id, fqdn: r.fqdn },
      criticality: r.criticality,
      openFindings: r.open,
      riskTotal: r.risk,
      highestSeverity: r.highest,
    })),
    byBusinessOwner: byOwner.map((r) => ({
      businessOwner: r.owner,
      domains: r.domains,
      openFindings: r.open,
      highOrCritical: r.high,
    })),
    expiringRegistrations: registrations.map((r) => {
      const at = toDate(r.expires_at);
      return {
        domain: { id: r.id, fqdn: r.fqdn },
        expiresAt: at.toISOString(),
        daysLeft: daysLeft(at, now),
      };
    }),
    expiringCertificates: certificates.map((r) => {
      const at = toDate(r.not_after);
      return {
        domain: { id: r.domain_id, fqdn: r.fqdn },
        hostname: r.hostname,
        notAfter: at.toISOString(),
        daysLeft: daysLeft(at, now),
        issuer: r.issuer,
      };
    }),
    acceptedRisksDue: risks.map((r) => ({
      findingId: r.id,
      title: r.title,
      domain: { id: r.domain_id, fqdn: r.fqdn },
      reviewAt: toDate(r.review_at).toISOString(),
    })),
  };
}

// --- CSV export ---------------------------------------------------------------------------------

const assignee = alias(users, 'csv_assignee');

export interface FindingsCsv {
  csv: string;
  rows: number;
  truncated: boolean;
}

type CsvFilters = Omit<FindingListQuery, 'page' | 'pageSize'>;

/**
 * GET /reports/findings.csv: the findings matching the GET /findings filters (visibility applies),
 * in its sort order, at most REPORT_CSV_MAX_ROWS rows, UTF-8 BOM first. Audited `report.exported` in the same
 * transaction as the read.
 */
export async function exportFindingsCsv(
  db: Database,
  user: User,
  q: CsvFilters,
  actor: Actor,
): Promise<FindingsCsv> {
  return db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const rows = await tx
      .select({
        id: findings.id,
        ruleId: findings.ruleId,
        severity: findings.severity,
        riskScore: findings.riskScore,
        status: findings.status,
        fqdn: domains.fqdn,
        hostname: findings.hostname,
        component: findings.component,
        title: findings.title,
        firstSeenAt: findings.firstSeenAt,
        lastSeenAt: findings.lastSeenAt,
        resolvedAt: findings.resolvedAt,
        assignee: assignee.email,
        businessOwner: domains.businessOwner,
      })
      .from(findings)
      .innerJoin(domains, eq(domains.id, findings.domainId))
      .leftJoin(assignee, eq(assignee.id, findings.assignedTo))
      .where(findingFilters(tx, user, q))
      .orderBy(...orderFor(q.sort))
      .limit(REPORT_CSV_MAX_ROWS + 1);
    const truncated = rows.length > REPORT_CSV_MAX_ROWS;
    const kept = truncated ? rows.slice(0, REPORT_CSV_MAX_ROWS) : rows;

    let csv = UTF8_BOM + csvLine(REPORT_CSV_COLUMNS);
    for (const r of kept) {
      csv += csvLine([
        r.id,
        r.ruleId,
        r.severity,
        r.riskScore,
        r.status,
        r.fqdn,
        r.hostname,
        r.component,
        r.title,
        r.firstSeenAt,
        r.lastSeenAt,
        r.resolvedAt,
        r.assignee,
        r.businessOwner,
      ]);
    }

    const filters = auditFilters(q);
    await writeAudit(tx, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'report.exported',
      resourceType: 'report',
      resourceId: 'findings.csv',
      requestId: actor.requestId,
      metadata: { report: 'findings', format: 'csv', filters, rows: kept.length, truncated },
    });
    return { csv, rows: kept.length, truncated };
  });
}
