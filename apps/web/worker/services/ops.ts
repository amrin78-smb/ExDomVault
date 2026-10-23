import { schema, type Database } from '@exdomainvault/database';
import {
  RETENTION_POLICY,
  WORKER_OFFLINE_AFTER_SECONDS,
  WORKER_STALE_AFTER_SECONDS,
  type OpsAlertsResponse,
  type OpsHealthResponse,
} from '@exdomainvault/shared';
import { eq, sql, type SQL } from 'drizzle-orm';
import type { Logger } from '../lib/logger.ts';
import { feedStatus } from './intel-feeds.ts';
import { readScanSchedule } from './scan-schedule.ts';

const { applicationSettings } = schema;

/** `application_settings` key holding operational state written by the cron. */
export const OPS_STATE_KEY = 'ops_state';

/** A feed (that has work to do) with no successful sync for this long raises `feeds_stale`. */
export const FEED_STALE_AFTER_SECONDS = 3 * 86_400;

/** Rows of failure codes reported by /ops/health. */
const FAILURE_CODES_LIMIT = 10;

export interface OpsState {
  /** Start of the current worker outage (cron-detected); null when there is none. */
  outageSince: string | null;
  retention: {
    lastRunAt: string | null;
    deletedLastRun: number;
    /** Rows deleted per table in the last run (diagnostics). */
    byTable?: Record<string, number>;
    /** The last run hit the batch limit somewhere (more to delete; the next cron tick continues). */
    more?: boolean;
    /** Tables whose step failed in the last run. */
    failed?: string[];
  };
}

const EMPTY_STATE: OpsState = {
  outageSince: null,
  retention: { lastRunAt: null, deletedLastRun: 0 },
};

/** Rows of a raw statement (node-postgres and PGlite both return `{ rows }`). */
async function rowsOf<T>(db: Database, query: SQL): Promise<T[]> {
  const res = (await db.execute(query)) as unknown as { rows: T[] };
  return res.rows;
}

const toDate = (v: Date | string | null): Date | null =>
  v === null ? null : v instanceof Date ? v : new Date(v);
const tsParam = (d: Date) => sql`${d.toISOString()}::timestamptz`;

function parseState(value: unknown): OpsState {
  if (!value || typeof value !== 'object') return structuredClone(EMPTY_STATE);
  const v = value as Partial<OpsState>;
  const retention = (v.retention ?? {}) as Partial<OpsState['retention']>;
  return {
    outageSince: typeof v.outageSince === 'string' ? v.outageSince : null,
    retention: {
      lastRunAt: typeof retention.lastRunAt === 'string' ? retention.lastRunAt : null,
      deletedLastRun:
        typeof retention.deletedLastRun === 'number' && Number.isInteger(retention.deletedLastRun)
          ? retention.deletedLastRun
          : 0,
      ...(retention.byTable ? { byTable: retention.byTable } : {}),
      ...(retention.more !== undefined ? { more: retention.more === true } : {}),
      ...(retention.failed ? { failed: retention.failed } : {}),
    },
  };
}

export async function readOpsState(db: Database): Promise<OpsState> {
  const [row] = await db
    .select({ value: applicationSettings.value })
    .from(applicationSettings)
    .where(eq(applicationSettings.key, OPS_STATE_KEY));
  return parseState(row?.value);
}

/**
 * Merges top-level keys into the stored state atomically (`value || patch`), so concurrent writers
 * of different keys (outage detector, retention) never overwrite each other.
 */
export async function mergeOpsState(
  db: Database,
  patch: Partial<OpsState>,
  now: Date,
): Promise<void> {
  await db
    .insert(applicationSettings)
    .values({ key: OPS_STATE_KEY, value: { ...EMPTY_STATE, ...patch }, updatedAt: now })
    .onConflictDoUpdate({
      target: applicationSettings.key,
      set: {
        value: sql`${applicationSettings.value} || ${JSON.stringify(patch)}::jsonb`,
        updatedAt: now,
      },
    });
}

// --- Worker outage ------------------------------------------------------------------------------

export interface OutageStatus {
  active: boolean;
  /** When the outage began by the stored data: the later of last-seen + threshold and the oldest queued job. */
  computedSince: Date | null;
  queuedJobs: number;
  lastSeenAt: Date | null;
}

/**
 * Persistent worker outage: jobs are queued and no active worker has been seen for
 * WORKER_OFFLINE_AFTER_SECONDS (a worker never seen counts as not seen).
 */
export async function workerOutage(db: Database, now: Date): Promise<OutageStatus> {
  const [row] = await rowsOf<{
    queued: number;
    oldest: Date | string | null;
    last_seen: Date | string | null;
  }>(
    db,
    sql`select
      (select count(*)::int from scan_jobs where status = 'queued') as queued,
      (select min(created_at) from scan_jobs where status = 'queued') as oldest,
      (select max(last_seen_at) from worker_registry where status = 'active') as last_seen`,
  );
  const queued = row?.queued ?? 0;
  const lastSeen = toDate(row?.last_seen ?? null);
  const oldest = toDate(row?.oldest ?? null);
  const threshold = now.getTime() - WORKER_OFFLINE_AFTER_SECONDS * 1000;
  const unseen = !lastSeen || lastSeen.getTime() < threshold;
  const active = queued > 0 && unseen;
  let since: Date | null = null;
  if (active) {
    const offlineFrom = lastSeen ? lastSeen.getTime() + WORKER_OFFLINE_AFTER_SECONDS * 1000 : 0;
    since = new Date(Math.max(offlineFrom, oldest?.getTime() ?? 0));
    if (since.getTime() > now.getTime()) since = now;
  }
  return { active, computedSince: since, queuedJobs: queued, lastSeenAt: lastSeen };
}

/**
 * Cron step: detects outage transitions and logs each exactly once — `worker_outage_started`
 * (error) and `worker_outage_ended` (info) — keeping `outageSince` in `ops_state`. The state row is
 * locked for the comparison, so concurrent cron runs cannot both log the same transition. These
 * log lines are what the Workers Logs alert (docs/deployment.md) matches on.
 * Returns 1 when a transition was recorded, else 0.
 */
export async function checkWorkerOutage(db: Database, now: Date, logger: Logger): Promise<number> {
  const status = await workerOutage(db, now);
  await db
    .insert(applicationSettings)
    .values({ key: OPS_STATE_KEY, value: EMPTY_STATE, updatedAt: now })
    .onConflictDoNothing();
  const transition = await db.transaction(async (tx) => {
    const [row] = await tx
      .select({ value: applicationSettings.value })
      .from(applicationSettings)
      .where(eq(applicationSettings.key, OPS_STATE_KEY))
      .for('update');
    const state = parseState(row?.value);
    const t = tx as unknown as Database;
    if (status.active && !state.outageSince) {
      const since = (status.computedSince ?? now).toISOString();
      await mergeOpsState(t, { outageSince: since }, now);
      return { kind: 'started' as const, since };
    }
    if (!status.active && state.outageSince) {
      await mergeOpsState(t, { outageSince: null }, now);
      return { kind: 'ended' as const, since: state.outageSince };
    }
    return null;
  });
  if (!transition) return 0;
  const lastSeenAt = status.lastSeenAt?.toISOString() ?? null;
  if (transition.kind === 'started') {
    logger.error('worker_outage_started', {
      alert: 'worker_outage',
      since: transition.since,
      queuedJobs: status.queuedJobs,
      lastSeenAt,
    });
  } else {
    logger.info('worker_outage_ended', {
      alert: 'worker_outage',
      since: transition.since,
      durationSeconds: Math.max(
        0,
        Math.round((now.getTime() - new Date(transition.since).getTime()) / 1000),
      ),
      lastSeenAt,
    });
  }
  return 1;
}

// --- Health -------------------------------------------------------------------------------------

type ScanWindow = OpsHealthResponse['scans']['last24h'];

async function scanWindow(db: Database, since: Date): Promise<ScanWindow> {
  const [r] = await rowsOf<{
    succeeded: number;
    failed: number;
    cancelled: number;
    p50: number | string | null;
    p95: number | string | null;
  }>(
    db,
    sql`select
      count(*) filter (where status = 'succeeded')::int as succeeded,
      count(*) filter (where status = 'failed')::int as failed,
      count(*) filter (where status = 'cancelled')::int as cancelled,
      percentile_cont(0.5) within group (order by extract(epoch from (completed_at - started_at)))
        filter (where status = 'succeeded' and started_at is not null) as p50,
      percentile_cont(0.95) within group (order by extract(epoch from (completed_at - started_at)))
        filter (where status = 'succeeded' and started_at is not null) as p95
      from scan_jobs
      where status in ('succeeded', 'failed', 'cancelled')
        and completed_at >= ${tsParam(since)}`,
  );
  const succeeded = r?.succeeded ?? 0;
  const failed = r?.failed ?? 0;
  const num = (v: number | string | null | undefined) =>
    v === null || v === undefined ? null : Math.round(Number(v) * 10) / 10;
  return {
    succeeded,
    failed,
    cancelled: r?.cancelled ?? 0,
    successRate:
      succeeded + failed === 0
        ? null
        : Math.round((succeeded / (succeeded + failed)) * 1000) / 1000,
    p50DurationSeconds: num(r?.p50),
    p95DurationSeconds: num(r?.p95),
  };
}

const workerStatusOf = (
  lastSeen: Date | null,
  now: Date,
): OpsHealthResponse['workers'][number]['status'] => {
  if (!lastSeen) return 'never_seen';
  const age = (now.getTime() - lastSeen.getTime()) / 1000;
  if (age <= WORKER_STALE_AFTER_SECONDS) return 'online';
  if (age <= WORKER_OFFLINE_AFTER_SECONDS) return 'stale';
  return 'offline';
};

/** GET /ops/health. Everything is computed from stored state with SQL aggregation. */
export async function opsHealth(db: Database, now: Date): Promise<OpsHealthResponse> {
  const pingStarted = Date.now();
  await db.execute(sql`select 1`);
  const latencyMs = Date.now() - pingStarted;

  const workers = await rowsOf<{
    id: string;
    name: string;
    last_seen_at: Date | string | null;
    version: string | null;
  }>(db, sql`select id, name, last_seen_at, version from worker_registry order by name, id`);

  const queueRows = await rowsOf<{ profile: string; queued: number; running: number }>(
    db,
    sql`select profile,
        count(*) filter (where status = 'queued')::int as queued,
        count(*) filter (where status in ('claimed', 'running'))::int as running
      from scan_jobs where status in ('queued', 'claimed', 'running')
      group by profile order by profile`,
  );
  const [oldest] = await rowsOf<{ oldest: Date | string | null }>(
    db,
    sql`select min(created_at) as oldest from scan_jobs where status = 'queued'`,
  );
  const oldestQueued = toDate(oldest?.oldest ?? null);

  const dayAgo = new Date(now.getTime() - 86_400_000);
  const [last24h, last7d] = await Promise.all([
    scanWindow(db, dayAgo),
    scanWindow(db, new Date(now.getTime() - 7 * 86_400_000)),
  ]);

  const failures = await rowsOf<{ code: string; count: number }>(
    db,
    sql`select code, count(*)::int as count from (
        select error_code as code from scan_jobs
          where status = 'failed' and error_code is not null and completed_at >= ${tsParam(dayAgo)}
        union all
        select error_code as code from scan_job_targets
          where error_code is not null and completed_at >= ${tsParam(dayAgo)}
      ) f group by code order by count desc, code asc limit ${FAILURE_CODES_LIMIT}`,
  );

  const [outage, state, feeds] = await Promise.all([
    workerOutage(db, now),
    readOpsState(db),
    feedStatus(db),
  ]);

  return {
    generatedAt: now.toISOString(),
    workers: workers.map((w) => {
      const lastSeen = toDate(w.last_seen_at);
      return {
        id: w.id,
        name: w.name,
        lastSeenAt: lastSeen?.toISOString() ?? null,
        status: workerStatusOf(lastSeen, now),
        version: w.version,
      };
    }),
    outage: {
      active: outage.active,
      since: outage.active
        ? (state.outageSince ?? outage.computedSince?.toISOString() ?? null)
        : null,
      queuedJobs: outage.queuedJobs,
    },
    queue: {
      queued: queueRows.reduce((n, r) => n + r.queued, 0),
      running: queueRows.reduce((n, r) => n + r.running, 0),
      oldestQueuedAgeSeconds: oldestQueued
        ? Math.max(0, Math.floor((now.getTime() - oldestQueued.getTime()) / 1000))
        : null,
      byProfile: queueRows.map((r) => ({
        profile: r.profile,
        queued: r.queued,
        running: r.running,
      })),
    },
    scans: { last24h, last7d },
    failuresByCode: failures.map((f) => ({ code: f.code, count: f.count })),
    database: { ok: true, latencyMs },
    feeds: feeds.feeds,
    retention: {
      lastRunAt: state.retention.lastRunAt,
      deletedLastRun: state.retention.deletedLastRun,
      policy: {
        observationDays: RETENTION_POLICY.observationDays,
        scanJobDays: RETENTION_POLICY.scanJobDays,
      },
    },
  };
}

// --- Alerts -------------------------------------------------------------------------------------

/**
 * GET /ops/alerts. Administrators (`settings:manage`) get specific messages; everyone else learns
 * only that something is delayed, with no worker, feed or configuration detail.
 */
export async function opsAlerts(
  db: Database,
  now: Date,
  opts: { admin: boolean; activeScanningEnabled: boolean },
): Promise<OpsAlertsResponse> {
  const alerts: OpsAlertsResponse['alerts'] = [];

  const outage = await workerOutage(db, now);
  if (outage.active) {
    const state = await readOpsState(db);
    alerts.push({
      kind: 'worker_outage',
      severity: 'critical',
      message: opts.admin
        ? `No scanning worker has been seen for over ${WORKER_OFFLINE_AFTER_SECONDS / 60} minutes while ${outage.queuedJobs} job(s) are queued. Check the worker service on the scan host.`
        : 'Scans are delayed. Administrators have been alerted.',
      since: state.outageSince ?? outage.computedSince?.toISOString() ?? null,
    });
  }

  const staleCutoff = now.getTime() - FEED_STALE_AFTER_SECONDS * 1000;
  const stale = (await feedStatus(db)).feeds.filter((f) => {
    // NVD only syncs while KEV CVEs wait for their record; idle is not stale.
    if (f.feed === 'nvd' && f.pending === 0) return false;
    if (f.lastSuccessAt) return new Date(f.lastSuccessAt).getTime() < staleCutoff;
    // Never succeeded: stale once an attempt has been made (a fresh install has not tried yet).
    return f.lastAttemptAt !== null;
  });
  if (stale.length > 0) {
    const successes = stale
      .map((f) => (f.lastSuccessAt ? new Date(f.lastSuccessAt).getTime() : null))
      .filter((v): v is number => v !== null);
    alerts.push({
      kind: 'feeds_stale',
      severity: 'warning',
      message: opts.admin
        ? `Vulnerability intelligence feed(s) not updated for over 3 days: ${stale
            .map((f) => f.feed + (f.lastError ? ` (${f.lastError})` : ''))
            .join(', ')}.`
        : 'Vulnerability intelligence may be out of date.',
      since:
        successes.length === stale.length
          ? new Date(Math.min(...successes) + FEED_STALE_AFTER_SECONDS * 1000).toISOString()
          : null,
    });
  }

  if (!opts.activeScanningEnabled) {
    const { schedule } = await readScanSchedule(db);
    if (schedule.enabled) {
      alerts.push({
        kind: 'active_scanning_disabled',
        severity: 'warning',
        message: opts.admin
          ? 'Scheduled active scans are enabled, but active scanning is switched off on the server (ACTIVE_SCANNING_ENABLED). No active scans will run.'
          : 'Scheduled active scans are paused.',
        since: null,
      });
    }
  }

  return { alerts };
}
