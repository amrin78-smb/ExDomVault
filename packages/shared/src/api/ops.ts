import { z } from 'zod';
import { intelFeedStatusSchema } from './software.ts';

/**
 * Operations and production hardening (Milestone 12; design §12–13).
 *
 * `GET /ops/health` (`settings:manage`): worker liveness, queue depth and oldest-job age, scan
 * success rates and durations, top failure reasons, database latency, feed and retention status.
 * Everything is computed from stored state; nothing is estimated.
 */

const isoDateTime = z.iso.datetime();

/** A worker is `online` if seen within 5 minutes, `stale` within 30, else `offline`. */
export const WORKER_STALE_AFTER_SECONDS = 5 * 60;
export const WORKER_OFFLINE_AFTER_SECONDS = 30 * 60;

const scanWindowSchema = z.object({
  succeeded: z.int(),
  failed: z.int(),
  cancelled: z.int(),
  /** succeeded / (succeeded + failed); null when there were none. */
  successRate: z.number().nullable(),
  /** Run time (started → completed) of succeeded jobs, seconds. */
  p50DurationSeconds: z.number().nullable(),
  p95DurationSeconds: z.number().nullable(),
});

export const opsHealthResponseSchema = z.object({
  generatedAt: isoDateTime,
  workers: z.array(
    z.object({
      id: z.uuid(),
      name: z.string(),
      lastSeenAt: isoDateTime.nullable(),
      status: z.enum(['online', 'stale', 'offline', 'never_seen']),
      version: z.string().nullable(),
    }),
  ),
  /**
   * Persistent worker outage: no active worker has been seen for WORKER_OFFLINE_AFTER_SECONDS
   * while jobs are queued. Raised as an in-app alert and a `worker_outage` log line (cron).
   */
  outage: z.object({
    active: z.boolean(),
    since: isoDateTime.nullable(),
    queuedJobs: z.int(),
  }),
  queue: z.object({
    queued: z.int(),
    running: z.int(),
    oldestQueuedAgeSeconds: z.int().nullable(),
    byProfile: z.array(z.object({ profile: z.string(), queued: z.int(), running: z.int() })),
  }),
  scans: z.object({ last24h: scanWindowSchema, last7d: scanWindowSchema }),
  /** Most frequent job/target error codes in the last 24 hours. */
  failuresByCode: z.array(z.object({ code: z.string(), count: z.int() })),
  database: z.object({ ok: z.boolean(), latencyMs: z.int().nullable() }),
  feeds: z.array(intelFeedStatusSchema),
  retention: z.object({
    lastRunAt: isoDateTime.nullable(),
    deletedLastRun: z.int(),
    policy: z.object({ observationDays: z.int(), scanJobDays: z.int() }),
  }),
});
export type OpsHealthResponse = z.infer<typeof opsHealthResponseSchema>;

/**
 * `GET /ops/alerts` (any authenticated user): currently active operational alerts shown as a banner.
 * Non-admins only learn that scanning is delayed; details are for administrators.
 */
export const opsAlertsResponseSchema = z.object({
  alerts: z.array(
    z.object({
      kind: z.enum(['worker_outage', 'feeds_stale', 'active_scanning_disabled']),
      severity: z.enum(['info', 'warning', 'critical']),
      message: z.string(),
      since: isoDateTime.nullable(),
    }),
  ),
});
export type OpsAlertsResponse = z.infer<typeof opsAlertsResponseSchema>;

/**
 * Retention (cron, bounded batches). Observations older than `observationDays` are deleted EXCEPT
 * the latest successful observation per key (DNS name+type, registration per domain, TLS
 * host+ip+port, HTTP url, port ip+port, discovery hostname per domain), so change detection and
 * the read models keep working. Finished scan jobs older than `scanJobDays` are deleted with their
 * targets/results unless referenced by a finding's status history (`ON DELETE SET NULL` already
 * keeps findings intact). Audit logs, findings, status history and comments are never deleted.
 */
export const RETENTION_POLICY = { observationDays: 180, scanJobDays: 365 } as const;

/**
 * Rate limits and scan quotas (429 `rate_limited`, `Retry-After` header). Per authenticated user:
 * all API requests, and mutating requests separately. Scan quotas count jobs a user requested
 * (manual/reassess/discovery), and active scans per domain per day, across users.
 */
export const RATE_LIMITS = {
  requestsPerMinute: 300,
  mutationsPerMinute: 60,
  scanRequestsPerUserPerHour: 60,
  activeScansPerDomainPerDay: 24,
  discoveryPerDomainPerDay: 6,
} as const;
