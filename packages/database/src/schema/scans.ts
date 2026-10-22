import { sql } from 'drizzle-orm';
import {
  check,
  index,
  inet,
  integer,
  jsonb,
  pgTable,
  smallint,
  text,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { assets } from './assets.ts';
import { createdAt, id, ts } from './common.ts';
import { domains } from './domains.ts';
import { scanJobStatus, scanJobType, scanTargetStatus } from './enums.ts';
import { scanProfiles, workerRegistry } from './system.ts';
import { users } from './users.ts';

/**
 * Durable scan job state. PostgreSQL is the source of truth (workers poll; no queue is used).
 * `scope_snapshot` is immutable once created so scope changes cannot enlarge a running job.
 */
export const scanJobs = pgTable(
  'scan_jobs',
  {
    id: id(),
    jobType: scanJobType('job_type').notNull(),
    profile: text('profile')
      .notNull()
      .references(() => scanProfiles.key),
    domainId: uuid('domain_id').references(() => domains.id, { onDelete: 'set null' }),
    status: scanJobStatus('status').notNull().default('queued'),
    priority: smallint('priority').notNull().default(100),
    requestedBy: uuid('requested_by').references(() => users.id, { onDelete: 'set null' }),
    reason: text('reason'),
    scopeSnapshot: jsonb('scope_snapshot').$type<Record<string, unknown>>().notNull(),
    idempotencyKey: text('idempotency_key'),
    createdAt: createdAt(),
    scheduledAt: ts('scheduled_at').notNull().defaultNow(),
    startedAt: ts('started_at'),
    completedAt: ts('completed_at'),
    leaseExpiresAt: ts('lease_expires_at'),
    attempts: integer('attempts').notNull().default(0),
    maxAttempts: integer('max_attempts').notNull().default(3),
    workerId: uuid('worker_id').references(() => workerRegistry.id, { onDelete: 'set null' }),
    progress: jsonb('progress').$type<Record<string, unknown>>(),
    cancelRequestedAt: ts('cancel_requested_at'),
    errorCode: text('error_code'),
    errorSummary: text('error_summary'),
    /**
     * When the rules engine evaluated this (succeeded) job's observations. Null = not yet; only
     * succeeded jobs are ever evaluated. Set atomically so each job is evaluated once.
     */
    rulesEvaluatedAt: ts('rules_evaluated_at'),
  },
  (t) => [
    uniqueIndex('scan_jobs_idempotency_key').on(t.idempotencyKey),
    // Claim path: oldest eligible queued job by priority.
    index('scan_jobs_claim_idx')
      .on(t.priority, t.scheduledAt)
      .where(sql`${t.status} = 'queued'`),
    // Lease reaper path.
    index('scan_jobs_lease_idx')
      .on(t.leaseExpiresAt)
      .where(sql`${t.status} IN ('claimed', 'running')`),
    index('scan_jobs_domain_idx').on(t.domainId, t.createdAt),
    // Rules evaluation backlog: succeeded jobs not yet evaluated, oldest first.
    index('scan_jobs_rules_pending_idx')
      .on(t.completedAt)
      .where(sql`${t.status} = 'succeeded' AND ${t.rulesEvaluatedAt} IS NULL`),
    // At most one queued/active job per domain and profile: duplicate requests and overlapping
    // schedules cannot pile up work for the same target.
    uniqueIndex('scan_jobs_one_active_per_domain_profile')
      .on(t.domainId, t.profile)
      .where(sql`${t.status} IN ('queued', 'claimed', 'running')`),
    check(
      'scan_jobs_attempts_bounded',
      sql`${t.attempts} >= 0 AND ${t.attempts} <= ${t.maxAttempts}`,
    ),
    check(
      'scan_jobs_lease_when_active',
      sql`${t.status} NOT IN ('claimed', 'running') OR (${t.leaseExpiresAt} IS NOT NULL AND ${t.workerId} IS NOT NULL)`,
    ),
  ],
);

/** Snapshot of approved targets for a job. */
export const scanJobTargets = pgTable(
  'scan_job_targets',
  {
    id: id(),
    scanJobId: uuid('scan_job_id')
      .notNull()
      .references(() => scanJobs.id, { onDelete: 'cascade' }),
    assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'set null' }),
    targetHostname: text('target_hostname').notNull(),
    targetIp: inet('target_ip'),
    status: scanTargetStatus('status').notNull().default('pending'),
    startedAt: ts('started_at'),
    completedAt: ts('completed_at'),
    errorCode: text('error_code'),
  },
  (t) => [
    unique('scan_job_targets_key').on(t.scanJobId, t.targetHostname, t.targetIp).nullsNotDistinct(),
    index('scan_job_targets_asset_idx').on(t.assetId),
  ],
);

/**
 * Result submissions already processed, keyed by the worker's idempotency key. A duplicate delivery
 * finds its key here and changes nothing.
 */
export const scanJobResults = pgTable(
  'scan_job_results',
  {
    id: id(),
    scanJobId: uuid('scan_job_id')
      .notNull()
      .references(() => scanJobs.id, { onDelete: 'cascade' }),
    resultId: text('result_id').notNull(),
    attempt: integer('attempt').notNull(),
    workerId: uuid('worker_id').references(() => workerRegistry.id, { onDelete: 'set null' }),
    receivedAt: ts('received_at').notNull().defaultNow(),
    summary: jsonb('summary').$type<Record<string, unknown>>().notNull().default({}),
  },
  (t) => [uniqueIndex('scan_job_results_key').on(t.scanJobId, t.resultId)],
);
