import type { Database } from '@exdomainvault/database';
import { RETENTION_POLICY } from '@exdomainvault/shared';
import { sql, type SQL } from 'drizzle-orm';
import { errorFields, type Logger } from '../lib/logger.ts';
import { mergeOpsState, readOpsState } from './ops.ts';

/** Rows deleted per table per run (bounded so one run never holds long locks). */
export const RETENTION_BATCH = 5000;
/** Retention runs at most this often (the cron fires every 5 minutes). */
export const RETENTION_INTERVAL_MS = 3600_000;

const DAY_MS = 86_400_000;

/**
 * Observation tables and the key whose latest observation is always kept (RETENTION_POLICY).
 * `o` is the observation, `j` its scan job; keys are scoped to the job's domain, the same grouping
 * the read models and change detection use.
 */
const OBSERVATION_TABLES: { table: string; key: string }[] = [
  { table: 'dns_observations', key: 'j.domain_id, o.hostname, o.record_type' },
  { table: 'registration_observations', key: 'o.domain_id' },
  { table: 'tls_observations', key: 'j.domain_id, o.hostname, o.ip_address, o.port' },
  { table: 'http_observations', key: 'j.domain_id, o.url' },
  { table: 'port_observations', key: 'j.domain_id, o.ip_address, o.port' },
  // Source too: the last discovery job's set is the "previous" set for change detection.
  { table: 'discovery_observations', key: 'o.domain_id, o.hostname, o.source' },
];

async function deletedCount(db: Database, query: SQL): Promise<number> {
  const res = (await db.execute(query)) as unknown as { rows: { n: number }[] };
  return Number(res.rows[0]?.n ?? 0);
}

/**
 * Deletes up to `limit` observations older than `cutoff`, never the latest successful observation
 * per key and never the latest observation of any status per key (the read models show it). Ties
 * on `observed_at` are broken by id, matching the read models' ordering.
 */
export async function pruneObservations(
  db: Database,
  table: string,
  key: string,
  cutoff: Date,
  limit = RETENTION_BATCH,
): Promise<number> {
  // `table` and `key` are compile-time constants above, never user input.
  return deletedCount(
    db,
    sql`with ranked as (
        select o.id, o.observed_at, o.result_status,
          row_number() over (partition by ${sql.raw(key)}
            order by o.observed_at desc, o.id desc) as rn_any,
          row_number() over (partition by ${sql.raw(key)}, (o.result_status = 'success')
            order by o.observed_at desc, o.id desc) as rn_status
        from ${sql.raw(table)} o
        join scan_jobs j on j.id = o.scan_job_id
      ), victims as (
        select id from ranked
        where observed_at < ${cutoff.toISOString()}::timestamptz
          and rn_any > 1
          and not (result_status = 'success' and rn_status = 1)
        limit ${limit}
      ), deleted as (
        delete from ${sql.raw(table)} where id in (select id from victims) returning 1
      )
      select count(*)::int as n from deleted`,
  );
}

/**
 * Deletes up to `limit` finished scan jobs (succeeded/failed/cancelled) that completed before
 * `cutoff`. Their targets and result receipts cascade; `software_inventory.last_scan_job_id` is set
 * null. Kept: jobs referenced by a finding's status history, jobs that still own any observation
 * (observations cascade with their job, so a job holding a latest-per-key observation must stay),
 * and succeeded jobs the rules engine has not evaluated. Queued/claimed/running jobs never match.
 */
export async function pruneScanJobs(
  db: Database,
  cutoff: Date,
  limit = RETENTION_BATCH,
): Promise<number> {
  const noObservations = sql.join(
    OBSERVATION_TABLES.map(
      ({ table }) => sql`not exists (select 1 from ${sql.raw(table)} x where x.scan_job_id = j.id)`,
    ),
    sql` and `,
  );
  return deletedCount(
    db,
    sql`with victims as (
        select j.id from scan_jobs j
        where j.status in ('succeeded', 'failed', 'cancelled')
          and coalesce(j.completed_at, j.created_at) < ${cutoff.toISOString()}::timestamptz
          and j.created_at < ${cutoff.toISOString()}::timestamptz
          and not (j.status = 'succeeded' and j.rules_evaluated_at is null)
          and not exists (select 1 from finding_status_history h where h.scan_job_id = j.id)
          and ${noObservations}
        order by j.created_at
        limit ${limit}
      ), deleted as (
        delete from scan_jobs where id in (select id from victims) returning 1
      )
      select count(*)::int as n from deleted`,
  );
}

export interface RetentionResult {
  ran: boolean;
  deleted: number;
  byTable: Record<string, number>;
  failed: string[];
}

/**
 * Cron step: applies RETENTION_POLICY in bounded batches, at most once per RETENTION_INTERVAL_MS
 * (unless `force`, or the previous run hit the batch limit and left work behind). Each table is failure-isolated. Audit logs, findings, finding status history
 * and comments are never touched. Records the outcome in `ops_state.retention`.
 */
export async function runRetention(
  db: Database,
  now: Date,
  logger: Logger,
  opts: { force?: boolean; batch?: number } = {},
): Promise<RetentionResult> {
  const state = await readOpsState(db);
  const last = state.retention.lastRunAt ? new Date(state.retention.lastRunAt).getTime() : null;
  // A run that hit the batch limit left work behind: continue on the next cron tick.
  const due =
    opts.force ||
    last === null ||
    state.retention.more === true ||
    now.getTime() - last >= RETENTION_INTERVAL_MS;
  if (!due) {
    return { ran: false, deleted: 0, byTable: {}, failed: [] };
  }

  const batch = opts.batch ?? RETENTION_BATCH;
  const observationCutoff = new Date(now.getTime() - RETENTION_POLICY.observationDays * DAY_MS);
  const jobCutoff = new Date(now.getTime() - RETENTION_POLICY.scanJobDays * DAY_MS);
  const byTable: Record<string, number> = {};
  const failed: string[] = [];

  const steps: [string, () => Promise<number>][] = [
    ...OBSERVATION_TABLES.map(
      ({ table, key }) =>
        [table, () => pruneObservations(db, table, key, observationCutoff, batch)] as [
          string,
          () => Promise<number>,
        ],
    ),
    // After observations, so jobs whose old observations were just pruned can go in this run.
    ['scan_jobs', () => pruneScanJobs(db, jobCutoff, batch)],
  ];
  for (const [table, step] of steps) {
    try {
      byTable[table] = await step();
    } catch (err) {
      failed.push(table);
      logger.error('retention_step_failed', { table, ...errorFields(err) });
    }
  }
  const deleted = Object.values(byTable).reduce((a, b) => a + b, 0);
  const more = Object.values(byTable).some((n) => n >= batch);
  await mergeOpsState(
    db,
    {
      retention: {
        lastRunAt: now.toISOString(),
        deletedLastRun: deleted,
        byTable,
        more,
        ...(failed.length ? { failed } : {}),
      },
    },
    now,
  );
  logger.info('retention_run', { deleted, byTable, failed, more });
  return { ran: true, deleted, byTable, failed };
}
