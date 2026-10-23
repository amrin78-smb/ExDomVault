import { schema, type Database } from '@exdomainvault/database';
import {
  DEFAULT_SCAN_SCHEDULE,
  SCAN_SCHEDULE_SETTING_KEY,
  scanScheduleSchema,
  type ScanSchedule,
  type ScanScheduleResponse,
} from '@exdomainvault/shared';
import {
  and,
  asc,
  count,
  eq,
  exists,
  gt,
  inArray,
  isNull,
  notExists,
  or,
  sql,
  type SQL,
} from 'drizzle-orm';
import { errorFields, type Logger } from '../lib/logger.ts';
import { writeAudit } from './audit.ts';
import type { Actor } from './domains.ts';
import { activeNetworkCidrs } from './networks.ts';
import {
  buildSnapshot,
  domainAuthorisedForActive,
  listProfiles,
  resolveTargets,
  type ScanPolicy,
} from './scans.ts';

const { applicationSettings, domains, scanJobs, scanJobTargets, users } = schema;

/** Scheduled active jobs created per cron run, so a large inventory spreads over several runs. */
export const ACTIVE_SCHEDULE_BATCH = 30;
/** Behind user-requested scans (100) and passive monitoring (200), ahead of discovery (250). */
export const ACTIVE_SCHEDULE_PRIORITY = 220;

// --- Setting ------------------------------------------------------------------------------------

/**
 * The stored schedule, or the default (disabled) when missing. A stored value that no longer
 * validates is treated as disabled: fail closed rather than guess an active-scan schedule.
 */
export async function readScanSchedule(db: Database): Promise<{
  schedule: ScanSchedule;
  row: typeof applicationSettings.$inferSelect | null;
}> {
  const [row] = await db
    .select()
    .from(applicationSettings)
    .where(eq(applicationSettings.key, SCAN_SCHEDULE_SETTING_KEY));
  if (!row) return { schedule: { ...DEFAULT_SCAN_SCHEDULE }, row: null };
  const parsed = scanScheduleSchema.safeParse(row.value);
  return {
    schedule: parsed.success ? parsed.data : { ...DEFAULT_SCAN_SCHEDULE, enabled: false },
    row,
  };
}

/**
 * Domains eligible for scheduled active scans right now: monitoring on and authorised for active
 * scanning (verified or administrator-authorised, review date not passed). Same condition as
 * `domainAuthorisedForActive`, expressed in SQL.
 */
const eligibleNow = (now: Date) =>
  and(
    eq(domains.monitoringEnabled, true),
    eq(domains.verificationStatus, 'verified'),
    or(isNull(domains.verificationExpiresAt), gt(domains.verificationExpiresAt, now)),
  );

const isScheduledJob = sql`(${scanJobs.scopeSnapshot} ->> 'trigger') = 'schedule'`;

export async function getScanScheduleResponse(
  db: Database,
  now: Date,
  policy: ScanPolicy,
): Promise<ScanScheduleResponse> {
  const { schedule, row } = await readScanSchedule(db);
  const since = new Date(now.getTime() - 24 * 3600 * 1000);
  const [[eligible], [recent], updater] = await Promise.all([
    db.select({ n: count() }).from(domains).where(eligibleNow(now)),
    db
      .select({ n: count() })
      .from(scanJobs)
      .where(
        and(eq(scanJobs.profile, schedule.profile), isScheduledJob, gt(scanJobs.createdAt, since)),
      ),
    row?.updatedBy
      ? db
          .select({ id: users.id, email: users.email })
          .from(users)
          .where(eq(users.id, row.updatedBy))
      : Promise.resolve([]),
  ]);
  return {
    schedule,
    updatedAt: row ? row.updatedAt.toISOString() : null,
    updatedBy: updater[0] ?? null,
    eligibleDomains: eligible?.n ?? 0,
    activeScanningEnabled: policy.activeScanningEnabled,
    scheduledLast24h: recent?.n ?? 0,
  };
}

/**
 * Saves the schedule (audited with before/after in the same transaction). Saving `enabled: true`
 * while the server switch is off is allowed; nothing is scheduled until the switch is on.
 */
export async function updateScanSchedule(
  db: Database,
  input: ScanSchedule,
  actor: Actor,
  now: Date,
): Promise<void> {
  await db.transaction(async (tx) => {
    const db2 = tx as unknown as Database;
    const [existing] = await tx
      .select()
      .from(applicationSettings)
      .where(eq(applicationSettings.key, SCAN_SCHEDULE_SETTING_KEY))
      .for('update');
    const before = existing
      ? (scanScheduleSchema.safeParse(existing.value).data ?? existing.value)
      : null;
    await tx
      .insert(applicationSettings)
      .values({
        key: SCAN_SCHEDULE_SETTING_KEY,
        value: input,
        updatedBy: actor.userId,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: applicationSettings.key,
        set: { value: input, updatedBy: actor.userId, updatedAt: now },
      });
    await writeAudit(db2, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'settings.scan_schedule_updated',
      resourceType: 'application_setting',
      requestId: actor.requestId,
      metadata: { key: SCAN_SCHEDULE_SETTING_KEY, before, after: input },
    });
  });
}

// --- Scheduler ----------------------------------------------------------------------------------

/** Thrown inside a per-domain transaction to roll it back without failing the run. */
class SkipDomain extends Error {
  readonly reason: 'not_eligible' | 'no_targets' | 'already_queued';
  constructor(reason: SkipDomain['reason']) {
    super(reason);
    this.reason = reason;
  }
}

/**
 * Cron step: queues the configured active profile for each eligible domain that is due. Does
 * nothing unless the schedule is enabled AND the server's ACTIVE_SCANNING_ENABLED switch is on.
 *
 * Due = monitoring on, authorised for active scanning, and no job of the profile (scheduled or
 * manual) queued/claimed/running or created within the interval. Staggered like discovery: a domain
 * that has never had a job of the profile waits for its slot (stable hash of its id) within the
 * interval; afterwards it recurs about one interval after its previous job. Capped per run, least
 * recently scanned first.
 *
 * Each job is created in its own transaction, exactly as a user-requested scan is: the domain row
 * is locked and re-checked (`domainAuthorisedForActive`, monitoring), targets come from
 * `resolveTargets` (approved assets; the apex is implicitly approved by the system on behalf of the
 * administrator who enabled the schedule, audited), the
 * snapshot carries the currently approved networks, and the claim-time re-checks apply unchanged.
 * The one-active-job index absorbs races with users and concurrent cron runs. One `scan.scheduled`
 * audit row records each run that created or skipped anything.
 */
export async function scheduleActiveScans(
  db: Database,
  now: Date,
  policy: ScanPolicy,
  logger?: Logger,
): Promise<number> {
  if (!policy.activeScanningEnabled) return 0;
  const { schedule, row } = await readScanSchedule(db);
  if (!schedule.enabled) return 0;
  const approver = row?.updatedBy ?? null;
  const profile = (await listProfiles(db)).find((p) => p.key === schedule.profile);
  // Only enabled active profiles are scheduled here (passive monitoring has its own step).
  if (!profile || !profile.enabled || !profile.config.active) return 0;

  const intervalSeconds = schedule.intervalDays * 86_400;
  const since = new Date(now.getTime() - intervalSeconds * 1000);
  const phase = Math.floor(now.getTime() / 1000) % intervalSeconds;
  const profileJobs = (extra: SQL) =>
    db
      .select({ one: sql`1` })
      .from(scanJobs)
      .where(and(eq(scanJobs.domainId, domains.id), eq(scanJobs.profile, profile.key), extra));
  const recentOrUnfinished = or(
    inArray(scanJobs.status, ['queued', 'claimed', 'running']),
    gt(scanJobs.createdAt, since),
  ) as SQL;
  const slot = sql`(abs(hashtext(${domains.id}::text)::bigint) % ${intervalSeconds})`;
  const lastJob = sql`(select max(${scanJobs.createdAt}) from ${scanJobs} where ${scanJobs.domainId} = ${domains.id} and ${scanJobs.profile} = ${profile.key})`;

  const due = await db
    .select({ id: domains.id })
    .from(domains)
    .where(
      and(
        eligibleNow(now),
        notExists(profileJobs(recentOrUnfinished)),
        or(exists(profileJobs(sql`true`)), sql`${slot} <= ${phase}`),
      ),
    )
    .orderBy(sql`${lastJob} asc nulls first`, asc(domains.fqdn))
    .limit(ACTIVE_SCHEDULE_BATCH);
  if (due.length === 0) return 0;

  const created: string[] = [];
  const skipped: Record<string, number> = {};
  let failed = 0;
  for (const { id } of due) {
    try {
      created.push(await scheduleOne(db, id, profile, approver, now));
    } catch (err) {
      if (err instanceof SkipDomain) skipped[err.reason] = (skipped[err.reason] ?? 0) + 1;
      else {
        // Isolated: one domain's failure never stops the rest.
        failed += 1;
        logger?.error('scheduled_scan_failed', {
          domainId: id,
          ...errorFields(err),
        });
      }
    }
  }

  await writeAudit(db, {
    actorType: 'system',
    action: 'scan.scheduled',
    resourceType: 'scan_job',
    metadata: {
      profile: profile.key,
      active: true,
      intervalDays: schedule.intervalDays,
      due: due.length,
      jobs: created.length,
      jobIds: created,
      skipped,
      failed,
    },
  });
  return created.length;
}

async function scheduleOne(
  db: Database,
  domainId: string,
  profile: Awaited<ReturnType<typeof listProfiles>>[number],
  approver: string | null,
  now: Date,
): Promise<string> {
  return db.transaction(async (tx) => {
    const db2 = tx as unknown as Database;
    const [domain] = await tx.select().from(domains).where(eq(domains.id, domainId)).for('update');
    // Re-check under the lock with the same logic as user-requested scans.
    if (!domain || !domain.monitoringEnabled || !domainAuthorisedForActive(domain, now)) {
      throw new SkipDomain('not_eligible');
    }
    const [unfinished] = await tx
      .select({ id: scanJobs.id })
      .from(scanJobs)
      .where(
        and(
          eq(scanJobs.domainId, domain.id),
          eq(scanJobs.profile, profile.key),
          inArray(scanJobs.status, ['queued', 'claimed', 'running']),
        ),
      )
      .limit(1);
    if (unfinished) throw new SkipDomain('already_queued');

    const targets = await resolveTargets(db2, domain, profile, null, now, approver);
    if (targets.length === 0) throw new SkipDomain('no_targets');
    const networks = await activeNetworkCidrs(db2, now);
    const snapshot = buildSnapshot(domain, profile, targets, 'schedule', null, now, networks);
    const [job] = await tx
      .insert(scanJobs)
      .values({
        jobType: 'scan',
        profile: profile.key,
        domainId: domain.id,
        priority: ACTIVE_SCHEDULE_PRIORITY,
        reason: `Scheduled ${profile.key} scan`,
        scopeSnapshot: snapshot,
        createdAt: now,
        scheduledAt: now,
      })
      .onConflictDoNothing()
      .returning({ id: scanJobs.id });
    // Lost a race with a user request or another run: roll back (incl. any implicit approval).
    if (!job) throw new SkipDomain('already_queued');
    await tx
      .insert(scanJobTargets)
      .values(
        targets.map((t) => ({ scanJobId: job.id, assetId: t.assetId, targetHostname: t.hostname })),
      );
    return job.id;
  });
}
