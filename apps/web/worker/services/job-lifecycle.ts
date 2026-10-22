import { schema, type Database } from '@exdomainvault/database';
import {
  scopeSnapshotSchema,
  type ClaimedJob,
  type Observation,
  type ScanTargetStatus,
} from '@exdomainvault/shared';
import { and, asc, eq, inArray, lte, notInArray, sql } from 'drizzle-orm';
import { ApiError } from '../lib/errors.ts';
import { writeAudit } from './audit.ts';
import { activeNetworkCidrs, intersectNetworks } from './networks.ts';
import {
  EMPTY_OBSERVATION_COUNTS,
  ingestObservations,
  type JobTargetRef,
  type ObservationCounts,
} from './observations.ts';
import { domainAuthorisedForActive, type ScanJobRow, type ScanPolicy } from './scans.ts';

const { domains, scanJobResults, scanJobs, scanJobTargets } = schema;

/**
 * Durable job lifecycle (design §5.6, §13). PostgreSQL is the only source of truth:
 *  - claim: atomic (`FOR UPDATE SKIP LOCKED`), sets an expiring lease and increments `attempts`;
 *  - the attempt number is a fencing token: heartbeats, results and failures for an older attempt
 *    (a worker that lost its lease) are rejected;
 *  - results carry an idempotency key, so duplicate deliveries change nothing;
 *  - failures retry with exponential backoff up to `max_attempts`, then fail terminally;
 *  - the reaper requeues or fails jobs whose lease expired.
 */
export const LEASE_SECONDS = 300;
export const HEARTBEAT_SECONDS = 60;
const BACKOFF_BASE_SECONDS = 60;
const BACKOFF_MAX_SECONDS = 30 * 60;

export interface WorkerIdentity {
  id: string;
  name: string;
}

const leaseUntil = (now: Date) => new Date(now.getTime() + LEASE_SECONDS * 1000);

/** Delay before retry `attempt + 1` (attempt is the number that just failed). */
export function backoffSeconds(attempt: number): number {
  return Math.min(BACKOFF_BASE_SECONDS * 2 ** Math.max(0, attempt - 1), BACKOFF_MAX_SECONDS);
}

const TERMINAL_TARGET: ScanTargetStatus[] = ['succeeded', 'failed', 'skipped'];
const leaseLost = () =>
  new ApiError(409, 'conflict', 'The job lease is no longer held by this worker attempt.');

// --- Claim --------------------------------------------------------------------------------------

export async function claimJob(
  db: Database,
  worker: WorkerIdentity,
  profiles: string[] | undefined,
  now: Date,
  policy: ScanPolicy,
): Promise<ClaimedJob | null> {
  // A few candidates may be refused (authorisation withdrawn); look at a bounded number.
  for (let i = 0; i < 5; i++) {
    const outcome = await db.transaction(async (tx) => {
      const [job] = await tx
        .select()
        .from(scanJobs)
        .where(
          and(
            eq(scanJobs.status, 'queued'),
            lte(scanJobs.scheduledAt, now),
            sql`${scanJobs.attempts} < ${scanJobs.maxAttempts}`,
            profiles && profiles.length > 0 ? inArray(scanJobs.profile, profiles) : undefined,
          ),
        )
        .orderBy(asc(scanJobs.priority), asc(scanJobs.scheduledAt))
        .limit(1)
        .for('update', { skipLocked: true });
      if (!job) return { kind: 'none' as const };

      const snapshot = scopeSnapshotSchema.safeParse(job.scopeSnapshot);
      const refusal = snapshot.success
        ? await claimRefusal(
            tx as unknown as Database,
            job,
            snapshot.data.profile.config.active,
            snapshot.data.trigger,
            now,
            policy,
          )
        : 'invalid_snapshot';
      if (refusal || !snapshot.success) {
        await tx
          .update(scanJobs)
          .set({
            status: 'cancelled',
            completedAt: now,
            errorCode: refusal ?? 'invalid_snapshot',
            errorSummary: 'Refused at claim time: the job is no longer authorised to run.',
          })
          .where(eq(scanJobs.id, job.id));
        await tx
          .update(scanJobTargets)
          .set({ status: 'skipped', errorCode: refusal ?? 'invalid_snapshot', completedAt: now })
          .where(and(eq(scanJobTargets.scanJobId, job.id), eq(scanJobTargets.status, 'pending')));
        await writeAudit(tx as unknown as Database, {
          actorType: 'system',
          action: 'scan.refused',
          resourceType: 'scan_job',
          resourceId: job.id,
          metadata: { reason: refusal ?? 'invalid_snapshot', profile: job.profile },
        });
        return { kind: 'refused' as const };
      }

      const attempt = job.attempts + 1;
      const leaseExpiresAt = leaseUntil(now);
      await tx
        .update(scanJobs)
        .set({
          status: 'claimed',
          workerId: worker.id,
          leaseExpiresAt,
          attempts: attempt,
          startedAt: job.startedAt ?? now,
        })
        .where(eq(scanJobs.id, job.id));
      const targets = await tx
        .select()
        .from(scanJobTargets)
        .where(
          and(
            eq(scanJobTargets.scanJobId, job.id),
            notInArray(scanJobTargets.status, TERMINAL_TARGET),
          ),
        )
        .orderBy(asc(scanJobTargets.targetHostname));

      // Revocation or expiry since creation shrinks the job's network scope; nothing is added.
      const approvedNetworks =
        snapshot.data.approvedNetworks.length > 0
          ? intersectNetworks(
              snapshot.data.approvedNetworks,
              await activeNetworkCidrs(tx as unknown as Database, now),
            )
          : [];
      const claimed: ClaimedJob = {
        id: job.id,
        attempt,
        profile: job.profile,
        leaseExpiresAt: leaseExpiresAt.toISOString(),
        leaseSeconds: LEASE_SECONDS,
        heartbeatSeconds: HEARTBEAT_SECONDS,
        snapshot: { ...snapshot.data, approvedNetworks },
        targets: targets.map((t) => ({ id: t.id, hostname: t.targetHostname, ip: t.targetIp })),
      };
      return { kind: 'claimed' as const, job: claimed };
    });
    if (outcome.kind === 'claimed') return outcome.job;
    if (outcome.kind === 'none') return null;
  }
  return null;
}

/**
 * Jobs are re-checked at claim time, because things change while they wait: active jobs need the
 * domain to still be authorised (verification may have lapsed or been revoked); scheduled jobs need
 * monitoring to still be on.
 */
async function claimRefusal(
  db: Database,
  job: ScanJobRow,
  active: boolean,
  trigger: 'manual' | 'schedule',
  now: Date,
  policy: ScanPolicy,
): Promise<string | null> {
  if (!active && trigger === 'manual') return null;
  if (active && !policy.activeScanningEnabled) return 'active_scanning_disabled';
  if (!job.domainId) return 'domain_missing';
  const [domain] = await db.select().from(domains).where(eq(domains.id, job.domainId));
  if (!domain) return 'domain_missing';
  if (active && !domainAuthorisedForActive(domain, now)) return 'domain_not_authorised';
  if (trigger === 'schedule' && !domain.monitoringEnabled) return 'monitoring_disabled';
  return null;
}

// --- Ownership check ----------------------------------------------------------------------------

async function lockOwnedJob(
  tx: Database,
  worker: WorkerIdentity,
  jobId: string,
  attempt: number,
): Promise<ScanJobRow> {
  const [job] = await tx.select().from(scanJobs).where(eq(scanJobs.id, jobId)).for('update');
  if (!job) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  if (
    job.workerId !== worker.id ||
    job.attempts !== attempt ||
    (job.status !== 'claimed' && job.status !== 'running')
  ) {
    throw leaseLost();
  }
  return job;
}

// --- Heartbeat ----------------------------------------------------------------------------------

export async function heartbeat(
  db: Database,
  worker: WorkerIdentity,
  req: {
    jobId: string;
    attempt: number;
    progress?: { completedTargets: number; totalTargets: number; message?: string };
  },
  now: Date,
): Promise<{ leaseExpiresAt: string; cancelRequested: boolean }> {
  return db.transaction(async (tx) => {
    const job = await lockOwnedJob(tx as unknown as Database, worker, req.jobId, req.attempt);
    const leaseExpiresAt = leaseUntil(now);
    await tx
      .update(scanJobs)
      .set({
        status: 'running',
        leaseExpiresAt,
        ...(req.progress ? { progress: req.progress } : {}),
      })
      .where(eq(scanJobs.id, job.id));
    return {
      leaseExpiresAt: leaseExpiresAt.toISOString(),
      cancelRequested: job.cancelRequestedAt !== null,
    };
  });
}

// --- Results ------------------------------------------------------------------------------------

interface ResultsSubmission {
  jobId: string;
  attempt: number;
  resultId: string;
  targets: {
    targetId: string;
    status: Exclude<ScanTargetStatus, 'pending'>;
    errorCode?: string;
  }[];
  observations?: Observation[];
  complete: boolean;
}

/** Applies a result submission; returns the HTTP response body (`{ accepted, status }`). */
export async function submitResults(
  db: Database,
  worker: WorkerIdentity,
  req: ResultsSubmission,
  now: Date,
): Promise<{ accepted: boolean; status: string }> {
  const { accepted, status } = await submitResultsDetailed(db, worker, req, now);
  return { accepted, status };
}

/** As `submitResults`, also returning how many observations were stored (for logging). */
export async function submitResultsDetailed(
  db: Database,
  worker: WorkerIdentity,
  req: ResultsSubmission,
  now: Date,
): Promise<{ accepted: boolean; status: string; observations: ObservationCounts }> {
  const none: ObservationCounts = EMPTY_OBSERVATION_COUNTS;
  return db.transaction(async (tx) => {
    const t = tx as unknown as Database;
    // Duplicate delivery: already processed, whatever state the job is in now.
    const [seen] = await tx
      .select({ id: scanJobResults.id })
      .from(scanJobResults)
      .where(
        and(
          eq(scanJobResults.scanJobId, req.jobId),
          eq(scanJobResults.resultId, req.resultId),
          // Only this worker's own submissions: no probing of other workers' jobs.
          eq(scanJobResults.workerId, worker.id),
        ),
      );
    if (seen) {
      const [job] = await tx
        .select({ status: scanJobs.status })
        .from(scanJobs)
        .where(eq(scanJobs.id, req.jobId));
      return { accepted: false, status: job?.status ?? 'unknown', observations: none };
    }

    const job = await lockOwnedJob(t, worker, req.jobId, req.attempt);

    // Only targets in this job's immutable snapshot can be reported on.
    const ids = [...new Set(req.targets.map((x) => x.targetId))];
    if (ids.length !== req.targets.length) {
      throw new ApiError(
        400,
        'validation_failed',
        'Each target may be reported once per submission.',
      );
    }
    const observations = req.observations ?? [];
    const referenced = [...new Set([...ids, ...observations.map((o) => o.targetId)])];
    const targetsById = new Map<string, JobTargetRef>();
    if (referenced.length > 0) {
      const known = await tx
        .select({
          id: scanJobTargets.id,
          assetId: scanJobTargets.assetId,
          targetHostname: scanJobTargets.targetHostname,
        })
        .from(scanJobTargets)
        .where(and(eq(scanJobTargets.scanJobId, job.id), inArray(scanJobTargets.id, referenced)));
      if (known.length !== referenced.length) {
        throw new ApiError(400, 'validation_failed', 'A reported target is not part of this job.');
      }
      for (const k of known) targetsById.set(k.id, k);
    }

    const inserted = await tx
      .insert(scanJobResults)
      .values({
        scanJobId: job.id,
        resultId: req.resultId,
        attempt: req.attempt,
        workerId: worker.id,
        receivedAt: now,
        summary: { targets: req.targets.length, complete: req.complete },
      })
      .onConflictDoNothing()
      .returning({ id: scanJobResults.id });
    if (inserted.length === 0) return { accepted: false, status: job.status, observations: none };

    let counts = none;
    if (observations.length > 0) {
      const snapshot = scopeSnapshotSchema.safeParse(job.scopeSnapshot);
      if (!snapshot.success) {
        throw new ApiError(409, 'conflict', 'The job scope snapshot is invalid.');
      }
      counts = await ingestObservations(
        t,
        job,
        snapshot.data,
        targetsById,
        observations,
        req.resultId,
        now,
      );
    }

    for (const target of req.targets) {
      const terminal = target.status !== 'running';
      await tx
        .update(scanJobTargets)
        .set({
          status: target.status,
          errorCode: target.errorCode ?? null,
          startedAt: sql`coalesce(${scanJobTargets.startedAt}, ${now})`,
          ...(terminal ? { completedAt: now } : {}),
        })
        // A target that already reached a final status keeps it.
        .where(
          and(
            eq(scanJobTargets.id, target.targetId),
            notInArray(scanJobTargets.status, TERMINAL_TARGET),
          ),
        );
    }

    let status: ScanJobRow['status'] = job.status === 'claimed' ? 'running' : job.status;
    if (req.complete) {
      // Anything the worker did not report on cannot count as checked.
      await tx
        .update(scanJobTargets)
        .set({ status: 'failed', errorCode: 'not_reported', completedAt: now })
        .where(
          and(
            eq(scanJobTargets.scanJobId, job.id),
            notInArray(scanJobTargets.status, TERMINAL_TARGET),
          ),
        );
      status = 'succeeded';
      await tx
        .update(scanJobs)
        .set({
          status,
          completedAt: now,
          leaseExpiresAt: null,
          errorCode: null,
          errorSummary: null,
        })
        .where(eq(scanJobs.id, job.id));
    } else {
      await tx
        .update(scanJobs)
        .set({ status, leaseExpiresAt: leaseUntil(now) })
        .where(eq(scanJobs.id, job.id));
    }
    return { accepted: true, status, observations: counts };
  });
}

// --- Failures -----------------------------------------------------------------------------------

/** Moves a held job to its next state after a failure (shared by worker reports and the reaper). */
async function failHeldJob(
  tx: Database,
  job: ScanJobRow,
  error: { code: string; summary: string; retryable: boolean },
  now: Date,
): Promise<{ status: ScanJobRow['status']; retryAt: Date | null }> {
  const cancel = job.cancelRequestedAt !== null;
  const retry = !cancel && error.retryable && job.attempts < job.maxAttempts;

  if (retry) {
    const retryAt = new Date(now.getTime() + backoffSeconds(job.attempts) * 1000);
    await tx
      .update(scanJobs)
      .set({
        status: 'queued',
        scheduledAt: retryAt,
        workerId: null,
        leaseExpiresAt: null,
        errorCode: error.code,
        errorSummary: error.summary,
      })
      .where(eq(scanJobs.id, job.id));
    await tx
      .update(scanJobTargets)
      .set({ status: 'pending' })
      .where(and(eq(scanJobTargets.scanJobId, job.id), eq(scanJobTargets.status, 'running')));
    return { status: 'queued', retryAt };
  }

  const status = cancel ? 'cancelled' : 'failed';
  await tx
    .update(scanJobs)
    .set({
      status,
      completedAt: now,
      leaseExpiresAt: null,
      errorCode: cancel ? 'cancelled' : error.code,
      errorSummary: error.summary,
    })
    .where(eq(scanJobs.id, job.id));
  await tx
    .update(scanJobTargets)
    .set({
      status: cancel ? 'skipped' : 'failed',
      errorCode: cancel ? 'cancelled' : error.code,
      completedAt: now,
    })
    .where(
      and(eq(scanJobTargets.scanJobId, job.id), notInArray(scanJobTargets.status, TERMINAL_TARGET)),
    );
  return { status, retryAt: null };
}

export async function reportFailure(
  db: Database,
  worker: WorkerIdentity,
  req: {
    jobId: string;
    attempt: number;
    errorCode: string;
    errorSummary: string;
    retryable: boolean;
  },
  now: Date,
): Promise<{ status: string; retryAt: string | null }> {
  return db.transaction(async (tx) => {
    const t = tx as unknown as Database;
    const job = await lockOwnedJob(t, worker, req.jobId, req.attempt);
    const result = await failHeldJob(
      t,
      job,
      { code: req.errorCode, summary: req.errorSummary, retryable: req.retryable },
      now,
    );
    return { status: result.status, retryAt: result.retryAt?.toISOString() ?? null };
  });
}

// --- Lease reaper -------------------------------------------------------------------------------

/** Requeues (or fails, after the last attempt) jobs whose worker stopped renewing the lease. */
export async function reapExpiredLeases(db: Database, now: Date, limit = 100): Promise<number> {
  return db.transaction(async (tx) => {
    const expired = await tx
      .select()
      .from(scanJobs)
      .where(
        and(inArray(scanJobs.status, ['claimed', 'running']), lte(scanJobs.leaseExpiresAt, now)),
      )
      .orderBy(asc(scanJobs.leaseExpiresAt))
      .limit(limit)
      .for('update', { skipLocked: true });
    for (const job of expired) {
      await failHeldJob(
        tx as unknown as Database,
        job,
        {
          code: 'lease_expired',
          summary: 'The worker stopped renewing its lease.',
          retryable: true,
        },
        now,
      );
    }
    return expired.length;
  });
}
