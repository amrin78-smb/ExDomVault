import type { Database } from '@exdomainvault/database';
import { RATE_LIMITS } from '@exdomainvault/shared';
import { sql, type SQL } from 'drizzle-orm';
import { rateLimited } from '../lib/errors.ts';

const HOUR_MS = 3600_000;
const DAY_MS = 24 * HOUR_MS;

/** User-requested jobs (manual scans, reassessment, discovery requests); schedules are excluded. */
const userRequested = sql`(scope_snapshot ->> 'trigger') = 'manual'`;
const activeProfile = sql`(scope_snapshot -> 'profile' -> 'config' ->> 'active') = 'true'`;

interface Quota {
  limit: number;
  windowMs: number;
  where: SQL;
  message: string;
}

/**
 * Seconds until the window holds fewer than `limit` matching jobs: when the `limit`-th newest job
 * ages out. Exact for a rolling window.
 */
async function retryAfterSeconds(db: Database, q: Quota, now: Date): Promise<number | null> {
  const since = new Date(now.getTime() - q.windowMs);
  const res = (await db.execute(
    sql`select created_at from scan_jobs
        where ${q.where} and created_at > ${since.toISOString()}::timestamptz
        order by created_at desc offset ${q.limit - 1} limit 1`,
  )) as unknown as { rows: { created_at: Date | string }[] };
  const row = res.rows[0];
  if (!row) return null;
  const at = row.created_at instanceof Date ? row.created_at : new Date(row.created_at);
  return (at.getTime() + q.windowMs - now.getTime()) / 1000;
}

/**
 * Scan quotas (RATE_LIMITS), exact counts over `scan_jobs` at creation time. Call inside the
 * creating transaction after the domain row is locked (`FOR UPDATE`, which serialises the per-domain
 * quotas); the per-user quota takes a transaction-scoped advisory lock on the user, so concurrent
 * requests cannot both pass a limit. Throws 429 `rate_limited` with `Retry-After`.
 */
export async function enforceScanQuotas(
  tx: Database,
  job: { userId: string; domainId: string; active: boolean; jobType: 'scan' | 'discovery' },
  now: Date,
): Promise<void> {
  await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`scan_quota:${job.userId}`}))`);

  const quotas: Quota[] = [
    {
      limit: RATE_LIMITS.scanRequestsPerUserPerHour,
      windowMs: HOUR_MS,
      where: sql`requested_by = ${job.userId} and ${userRequested}`,
      message: `You can request at most ${RATE_LIMITS.scanRequestsPerUserPerHour} scans per hour.`,
    },
  ];
  if (job.jobType === 'scan' && job.active) {
    quotas.push({
      limit: RATE_LIMITS.activeScansPerDomainPerDay,
      windowMs: DAY_MS,
      where: sql`domain_id = ${job.domainId} and job_type = 'scan' and ${activeProfile} and ${userRequested}`,
      message: `This domain has reached its limit of ${RATE_LIMITS.activeScansPerDomainPerDay} requested active scans per day.`,
    });
  }
  if (job.jobType === 'discovery') {
    quotas.push({
      limit: RATE_LIMITS.discoveryPerDomainPerDay,
      windowMs: DAY_MS,
      where: sql`domain_id = ${job.domainId} and job_type = 'discovery' and ${userRequested}`,
      message: `This domain has reached its limit of ${RATE_LIMITS.discoveryPerDomainPerDay} discovery requests per day.`,
    });
  }

  for (const q of quotas) {
    const since = new Date(now.getTime() - q.windowMs);
    const res = (await tx.execute(
      sql`select count(*)::int as n from scan_jobs
          where ${q.where} and created_at > ${since.toISOString()}::timestamptz`,
    )) as unknown as { rows: { n: number }[] };
    const n = Number(res.rows[0]?.n ?? 0);
    if (n >= q.limit) {
      const retry = (await retryAfterSeconds(tx, q, now)) ?? q.windowMs / 1000;
      throw rateLimited(q.message, retry);
    }
  }
}
