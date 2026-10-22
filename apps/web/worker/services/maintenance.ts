import { schema, type Database } from '@exdomainvault/database';
import { and, asc, eq, inArray, lt, notExists, or, sql } from 'drizzle-orm';
import type { Logger } from '../lib/logger.ts';
import { writeAudit } from './audit.ts';
import { expireStaleChallenges } from './domain-verification.ts';
import { evaluatePendingJobs } from './evaluation.ts';
import { reapExpiredLeases } from './job-lifecycle.ts';
import { buildSnapshot, listProfiles } from './scans.ts';
import { WORKER_SIGNATURE_MAX_SKEW_SECONDS } from '@exdomainvault/shared';
import { isWithinDomain } from '@exdomainvault/shared/hostname';

const { assets, domains, scanJobs, scanJobTargets, workerRequestNonces } = schema;

/** Passive monitoring runs at most this often per domain. */
const PASSIVE_INTERVAL_HOURS = 23;
/** Domains scheduled per cron run, so a large inventory is spread over several runs. */
const SCHEDULE_BATCH = 200;

/**
 * Creates the daily passive monitoring job for each domain with monitoring on that has none queued,
 * running or created recently. Passive jobs never contact the domain's hosts, so verification is
 * not required (owner decision). Set-based and idempotent: the one-active-job index absorbs races.
 */
export async function schedulePassiveMonitoring(db: Database, now: Date): Promise<number> {
  const profile = (await listProfiles(db)).find((p) => p.key === 'passive');
  if (!profile || !profile.enabled || profile.config.active) return 0;

  const since = new Date(now.getTime() - PASSIVE_INTERVAL_HOURS * 3600 * 1000);
  const due = await db
    .select()
    .from(domains)
    .where(
      and(
        eq(domains.monitoringEnabled, true),
        notExists(
          db
            .select({ one: sql`1` })
            .from(scanJobs)
            .where(
              and(
                eq(scanJobs.domainId, domains.id),
                eq(scanJobs.profile, profile.key),
                or(
                  inArray(scanJobs.status, ['queued', 'claimed', 'running']),
                  sql`${scanJobs.createdAt} > ${since}`,
                ),
              ),
            ),
        ),
      ),
    )
    .orderBy(asc(domains.fqdn))
    .limit(SCHEDULE_BATCH);
  if (due.length === 0) return 0;

  const approved = await db
    .select({ id: assets.id, domainId: assets.domainId, hostname: assets.hostname })
    .from(assets)
    .where(
      and(
        inArray(
          assets.domainId,
          due.map((d) => d.id),
        ),
        eq(assets.verificationStatus, 'approved'),
      ),
    );

  return db.transaction(async (tx) => {
    const jobs = due.map((domain) => {
      const targets = [
        { assetId: null as string | null, hostname: domain.fqdn },
        ...approved
          .filter(
            (a) =>
              a.domainId === domain.id &&
              a.hostname !== domain.fqdn &&
              isWithinDomain(a.hostname, domain.fqdn),
          )
          .map((a) => ({ assetId: a.id, hostname: a.hostname })),
      ].slice(0, profile.config.maxTargets);
      return {
        domain,
        targets,
        snapshot: buildSnapshot(domain, profile, targets, 'schedule', null, now),
      };
    });
    const inserted = await tx
      .insert(scanJobs)
      .values(
        jobs.map((j) => ({
          jobType: 'scan' as const,
          profile: profile.key,
          domainId: j.domain.id,
          priority: 200, // behind user-requested scans
          reason: 'Scheduled passive monitoring',
          scopeSnapshot: j.snapshot,
          createdAt: now,
          scheduledAt: now,
        })),
      )
      .onConflictDoNothing()
      .returning({ id: scanJobs.id, domainId: scanJobs.domainId });
    if (inserted.length === 0) return 0;

    const byDomain = new Map(jobs.map((j) => [j.domain.id, j]));
    await tx.insert(scanJobTargets).values(
      inserted.flatMap((row) =>
        (byDomain.get(row.domainId ?? '')?.targets ?? []).map((t) => ({
          scanJobId: row.id,
          assetId: t.assetId,
          targetHostname: t.hostname,
        })),
      ),
    );
    await writeAudit(tx as unknown as Database, {
      actorType: 'system',
      action: 'scan.scheduled',
      resourceType: 'scan_job',
      metadata: { profile: profile.key, jobs: inserted.length },
    });
    return inserted.length;
  });
}

/** Deletes request nonces older than the signature window (they can no longer be replayed). */
export async function pruneNonces(db: Database, now: Date): Promise<number> {
  const cutoff = new Date(now.getTime() - 2 * WORKER_SIGNATURE_MAX_SKEW_SECONDS * 1000);
  const deleted = await db
    .delete(workerRequestNonces)
    .where(lt(workerRequestNonces.createdAt, cutoff))
    .returning({ nonce: workerRequestNonces.nonce });
  return deleted.length;
}

/**
 * Periodic housekeeping (Cron Trigger). Each step is independent: one failing does not stop the
 * others, and every step is safe to run repeatedly or concurrently.
 */
export async function runMaintenance(db: Database, now: Date, logger: Logger): Promise<void> {
  const steps: [string, () => Promise<number>][] = [
    ['leases_reaped', () => reapExpiredLeases(db, now)],
    ['verifications_expired', () => expireStaleChallenges(db, now)],
    ['nonces_pruned', () => pruneNonces(db, now)],
    ['passive_jobs_scheduled', () => schedulePassiveMonitoring(db, now)],
    // Rules evaluation of succeeded jobs (oldest first, bounded batch). Results submissions also
    // trigger evaluation right after the response; this step is the guaranteed path (≤5 min lag).
    ['evaluate_pending_jobs', () => evaluatePendingJobs(db, now, { logger })],
  ];
  for (const [name, step] of steps) {
    try {
      const n = await step();
      logger.info('maintenance_step', { step: name, count: n });
    } catch (err) {
      logger.error('maintenance_step_failed', {
        step: name,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
}
