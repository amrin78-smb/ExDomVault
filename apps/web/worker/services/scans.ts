import { schema, type Database } from '@exdomainvault/database';
import {
  DISCOVERY_PROFILE_KEY,
  SCAN_TARGET_STATUSES,
  scanProfileConfigSchema,
  type ScanJob,
  type ScanJobDetailResponse,
  type ScanJobListQuery,
  type ScanJobListResponse,
  type ScanProfile,
  type ScanTargetStatus,
  type ScopeSnapshot,
} from '@exdomainvault/shared';
import { isWithinDomain } from '@exdomainvault/shared/hostname';
import { and, asc, count, desc, eq, inArray, isNull, or, sql, type SQL } from 'drizzle-orm';
import { firstRow } from '../lib/db.ts';
import { ApiError } from '../lib/errors.ts';
import { writeAudit, writeAuditMany } from './audit.ts';
import type { Actor } from './domains.ts';
import { isUniqueViolation } from './domains.ts';
import { activeNetworkCidrs } from './networks.ts';

const { assets, domains, scanJobs, scanJobTargets, scanProfiles, users, workerRegistry } = schema;

export type ScanJobRow = typeof scanJobs.$inferSelect;
type DomainRow = typeof domains.$inferSelect;

const iso = (d: Date | null) => (d ? d.toISOString() : null);

// --- Profiles -----------------------------------------------------------------------------------

/** Loads profiles, rejecting any whose stored config fails validation (fail closed). */
export async function listProfiles(db: Database): Promise<ScanProfile[]> {
  const rows = await db.select().from(scanProfiles).orderBy(asc(scanProfiles.createdAt));
  return rows.flatMap((r) => {
    const config = scanProfileConfigSchema.safeParse(r.config);
    if (!config.success) return [];
    return [
      {
        key: r.key,
        name: r.name,
        description: r.description,
        version: r.version,
        defaultSchedule: r.defaultSchedule,
        enabled: r.enabled,
        config: config.data,
      },
    ];
  });
}

export async function getProfile(db: Database, key: string): Promise<ScanProfile> {
  const profile = (await listProfiles(db)).find((p) => p.key === key);
  if (!profile || !profile.enabled) {
    throw new ApiError(400, 'validation_failed', 'The scan profile is invalid.', [
      { path: 'profile', message: 'Unknown or disabled scan profile.' },
    ]);
  }
  return profile;
}

/** Whether a domain's authorisation for active scanning is currently valid. */
export function domainAuthorisedForActive(domain: DomainRow, now: Date): boolean {
  return (
    domain.verificationStatus === 'verified' &&
    (domain.verificationExpiresAt === null || domain.verificationExpiresAt > now)
  );
}

// --- Creation -----------------------------------------------------------------------------------

/**
 * Targets for a job. Passive profiles look up public data about the apex and approved hostnames.
 * Active profiles contact hosts, so only approved assets of a currently authorised domain qualify;
 * the apex becomes an approved asset implicitly through domain verification (audited).
 *
 * `actor` null means the system (the active-scan scheduler). An approval must name an accountable
 * user (`approved_by`), so the system records `systemApprover` (the administrator who enabled the
 * schedule) and audits the approval as a system action on their behalf; without one, the apex is
 * not approved implicitly and only already-approved assets are targeted.
 */
export async function resolveTargets(
  tx: Database,
  domain: DomainRow,
  profile: ScanProfile,
  actor: Actor | null,
  now: Date,
  systemApprover: string | null = null,
): Promise<{ assetId: string | null; hostname: string }[]> {
  const approved = await tx
    .select({ id: assets.id, hostname: assets.hostname })
    .from(assets)
    .where(and(eq(assets.domainId, domain.id), eq(assets.verificationStatus, 'approved')))
    .orderBy(asc(assets.hostname));

  let apex = approved.find((a) => a.hostname === domain.fqdn);
  const approverId = actor ? actor.userId : systemApprover;
  if (!apex && profile.config.active && approverId) {
    // Domain verification authorises its apex hostname. Record that as an approved asset.
    const [existing] = await tx
      .select()
      .from(assets)
      .where(and(eq(assets.domainId, domain.id), eq(assets.hostname, domain.fqdn)));
    if (existing && existing.verificationStatus !== 'pending') {
      // Rejected or suspended explicitly: never re-approve implicitly.
    } else {
      const row = existing
        ? firstRow(
            await tx
              .update(assets)
              .set({ verificationStatus: 'approved', approvedBy: approverId, approvedAt: now })
              .where(eq(assets.id, existing.id))
              .returning(),
          )
        : firstRow(
            await tx
              .insert(assets)
              .values({
                domainId: domain.id,
                hostname: domain.fqdn,
                assetType: 'apex',
                discoverySource: 'manual',
                verificationStatus: 'approved',
                approvedBy: approverId,
                approvedAt: now,
              })
              .returning(),
          );
      await writeAudit(tx, {
        actorType: actor ? 'user' : 'system',
        actorUserId: actor?.userId,
        action: 'asset.approved',
        resourceType: 'asset',
        resourceId: row.id,
        requestId: actor?.requestId,
        metadata: {
          hostname: row.hostname,
          basis: 'domain_verification',
          domainId: domain.id,
          ...(actor ? {} : { trigger: 'schedule', onBehalfOf: approverId }),
        },
      });
      apex = { id: row.id, hostname: row.hostname };
      approved.unshift(apex);
    }
  }

  const targets: { assetId: string | null; hostname: string }[] = approved
    // Defensive: an approved asset must sit within the domain on a label boundary.
    .filter((a) => isWithinDomain(a.hostname, domain.fqdn))
    .map((a) => ({ assetId: a.id, hostname: a.hostname }));
  if (!profile.config.active && !targets.some((t) => t.hostname === domain.fqdn)) {
    targets.unshift({ assetId: null, hostname: domain.fqdn });
  }
  return targets.slice(0, profile.config.maxTargets);
}

export function buildSnapshot(
  domain: DomainRow,
  profile: ScanProfile,
  targets: { assetId: string | null; hostname: string }[],
  trigger: 'manual' | 'schedule',
  requestedBy: string | null,
  now: Date,
  /** Active approved networks (active profiles only; passive snapshots never carry any). */
  approvedNetworks: readonly string[] = [],
): ScopeSnapshot {
  return {
    version: 1,
    createdAt: now.toISOString(),
    requestedBy,
    trigger,
    domain: {
      id: domain.id,
      fqdn: domain.fqdn,
      verificationStatus: domain.verificationStatus,
      verificationMethod: domain.verificationMethod,
      verificationExpiresAt: iso(domain.verificationExpiresAt),
    },
    profile: { key: profile.key, version: profile.version, config: profile.config },
    targets,
    approvedNetworks: profile.config.active ? [...approvedNetworks] : [],
  };
}

export interface ScanPolicy {
  activeScanningEnabled: boolean;
}

/**
 * Creates a job. `jobType: 'scan'` (POST /domains/:id/scans) refuses the discovery profile;
 * `jobType: 'discovery'` (POST /domains/:id/discovery) only accepts it. Discovery jobs are passive
 * and target the apex name only (assetId null): candidates they find never become targets.
 */
export async function createScan(
  db: Database,
  domainId: string,
  input: { profile: string; reason?: string | null },
  actor: Actor,
  now: Date,
  policy: ScanPolicy,
  jobType: 'scan' | 'discovery' = 'scan',
): Promise<string> {
  const isDiscoveryProfile = input.profile === DISCOVERY_PROFILE_KEY;
  if (isDiscoveryProfile !== (jobType === 'discovery')) {
    throw new ApiError(400, 'validation_failed', 'The scan profile is invalid.', [
      {
        path: 'profile',
        message: isDiscoveryProfile
          ? 'Discovery is not a scan profile; use POST /domains/:id/discovery.'
          : 'Discovery jobs use the discovery profile.',
      },
    ]);
  }
  const profile = await getProfile(db, input.profile);
  if (
    jobType === 'discovery' &&
    (profile.config.active || !profile.config.checks.includes('discovery'))
  ) {
    // Fail closed on a misconfigured profile: discovery must stay passive.
    throw new ApiError(409, 'conflict', 'The discovery profile is misconfigured.');
  }
  if (profile.config.active && !policy.activeScanningEnabled) {
    throw new ApiError(
      409,
      'conflict',
      'Active scanning is disabled until target-safety validation is in place. Passive scans are available.',
    );
  }

  try {
    return await db.transaction(async (tx) => {
      const [domain] = await tx
        .select()
        .from(domains)
        .where(eq(domains.id, domainId))
        .for('update');
      if (!domain) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
      if (profile.config.active && !domainAuthorisedForActive(domain, now)) {
        throw new ApiError(
          409,
          'conflict',
          'Active scans need a verified or administrator-authorised domain.',
        );
      }

      const db2 = tx as unknown as Database;
      const targets =
        jobType === 'discovery'
          ? [{ assetId: null, hostname: domain.fqdn }]
          : await resolveTargets(db2, domain, profile, actor, now);
      if (targets.length === 0) {
        throw new ApiError(
          409,
          'conflict',
          'There are no approved targets to scan for this domain.',
        );
      }
      // Networks are organisation-wide: an active job may probe any currently approved network.
      const networks = profile.config.active ? await activeNetworkCidrs(db2, now) : [];
      const snapshot = buildSnapshot(
        domain,
        profile,
        targets,
        'manual',
        actor.userId,
        now,
        networks,
      );
      const job = firstRow(
        await tx
          .insert(scanJobs)
          .values({
            jobType,
            profile: profile.key,
            domainId: domain.id,
            requestedBy: actor.userId,
            reason: input.reason ?? null,
            scopeSnapshot: snapshot,
            createdAt: now,
            scheduledAt: now,
          })
          .returning({ id: scanJobs.id }),
      );
      await tx.insert(scanJobTargets).values(
        targets.map((t) => ({
          scanJobId: job.id,
          assetId: t.assetId,
          targetHostname: t.hostname,
        })),
      );
      await writeAudit(db2, {
        actorType: 'user',
        actorUserId: actor.userId,
        action: 'scan.requested',
        resourceType: 'scan_job',
        resourceId: job.id,
        requestId: actor.requestId,
        metadata: {
          domainId: domain.id,
          fqdn: domain.fqdn,
          jobType,
          profile: profile.key,
          active: profile.config.active,
          targets: targets.length,
          approvedNetworks: networks.length,
          reason: input.reason ?? null,
        },
      });
      return job.id;
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new ApiError(
        409,
        'conflict',
        `A ${profile.name} scan is already queued or running for this domain.`,
      );
    }
    throw err;
  }
}

async function unfinishedJob(db: Database, domainId: string, profile: string) {
  const [job] = await db
    .select({ id: scanJobs.id })
    .from(scanJobs)
    .where(
      and(
        eq(scanJobs.domainId, domainId),
        eq(scanJobs.profile, profile),
        inArray(scanJobs.status, ['queued', 'claimed', 'running']),
      ),
    )
    .limit(1);
  return job;
}

/**
 * POST /domains/:id/discovery — queues passive discovery for the domain, or returns the discovery
 * job already queued/running (`created: false`). Passive, so no verification is needed.
 */
export async function requestDiscovery(
  db: Database,
  domainId: string,
  actor: Actor,
  now: Date,
  policy: ScanPolicy,
): Promise<{ scanJobId: string; created: boolean }> {
  const [domain] = await db
    .select({ id: domains.id })
    .from(domains)
    .where(eq(domains.id, domainId));
  if (!domain) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  const existing = await unfinishedJob(db, domainId, DISCOVERY_PROFILE_KEY);
  if (existing) return { scanJobId: existing.id, created: false };
  try {
    const id = await createScan(
      db,
      domainId,
      { profile: DISCOVERY_PROFILE_KEY, reason: 'Passive discovery requested' },
      actor,
      now,
      policy,
      'discovery',
    );
    return { scanJobId: id, created: true };
  } catch (err) {
    // Lost a race with a concurrent request or the scheduler: return that job.
    if (err instanceof ApiError && err.status === 409) {
      const raced = await unfinishedJob(db, domainId, DISCOVERY_PROFILE_KEY);
      if (raced) return { scanJobId: raced.id, created: false };
    }
    throw err;
  }
}

// --- Reading ------------------------------------------------------------------------------------

const emptyCounts = (): Record<ScanTargetStatus, number> =>
  Object.fromEntries(SCAN_TARGET_STATUSES.map((s) => [s, 0])) as Record<ScanTargetStatus, number>;

async function targetCounts(db: Database, jobIds: string[]) {
  const counts = new Map<string, Record<ScanTargetStatus, number>>();
  if (jobIds.length === 0) return counts;
  const rows = await db
    .select({ jobId: scanJobTargets.scanJobId, status: scanJobTargets.status, n: count() })
    .from(scanJobTargets)
    .where(inArray(scanJobTargets.scanJobId, jobIds))
    .groupBy(scanJobTargets.scanJobId, scanJobTargets.status);
  for (const r of rows) {
    const c = counts.get(r.jobId) ?? emptyCounts();
    c[r.status] = r.n;
    counts.set(r.jobId, c);
  }
  return counts;
}

const jobSelect = {
  job: scanJobs,
  fqdn: domains.fqdn,
  requesterEmail: users.email,
  workerName: workerRegistry.name,
};

function baseJobQuery(db: Database) {
  return db
    .select(jobSelect)
    .from(scanJobs)
    .leftJoin(domains, eq(domains.id, scanJobs.domainId))
    .leftJoin(users, eq(users.id, scanJobs.requestedBy))
    .leftJoin(workerRegistry, eq(workerRegistry.id, scanJobs.workerId));
}

type JobJoinRow = {
  job: ScanJobRow;
  fqdn: string | null;
  requesterEmail: string | null;
  workerName: string | null;
};

function toJobDto(r: JobJoinRow, counts: Record<ScanTargetStatus, number> | undefined): ScanJob {
  const j = r.job;
  const snapshot = j.scopeSnapshot as Partial<ScopeSnapshot>;
  return {
    id: j.id,
    jobType: j.jobType,
    profile: j.profile,
    domain: j.domainId && r.fqdn ? { id: j.domainId, fqdn: r.fqdn } : null,
    status: j.status,
    priority: j.priority,
    reason: j.reason,
    trigger: snapshot.trigger === 'schedule' ? 'schedule' : 'manual',
    requestedBy:
      j.requestedBy && r.requesterEmail ? { id: j.requestedBy, email: r.requesterEmail } : null,
    createdAt: j.createdAt.toISOString(),
    scheduledAt: j.scheduledAt.toISOString(),
    startedAt: iso(j.startedAt),
    completedAt: iso(j.completedAt),
    leaseExpiresAt: iso(j.leaseExpiresAt),
    attempts: j.attempts,
    maxAttempts: j.maxAttempts,
    worker: j.workerId && r.workerName ? { id: j.workerId, name: r.workerName } : null,
    progress: (j.progress as ScanJob['progress']) ?? null,
    cancelRequestedAt: iso(j.cancelRequestedAt),
    errorCode: j.errorCode,
    errorSummary: j.errorSummary,
    targetCounts: counts ?? emptyCounts(),
  };
}

export async function listScans(db: Database, q: ScanJobListQuery): Promise<ScanJobListResponse> {
  const filters: SQL[] = [];
  if (q.status) filters.push(eq(scanJobs.status, q.status));
  if (q.domainId) filters.push(eq(scanJobs.domainId, q.domainId));
  if (q.profile) filters.push(eq(scanJobs.profile, q.profile));
  const where = filters.length > 0 ? and(...filters) : undefined;

  const [rows, [total]] = await Promise.all([
    baseJobQuery(db)
      .where(where)
      .orderBy(desc(scanJobs.createdAt), desc(scanJobs.id))
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize),
    db.select({ n: count() }).from(scanJobs).where(where),
  ]);
  const counts = await targetCounts(
    db,
    rows.map((r) => r.job.id),
  );
  return {
    items: rows.map((r) => toJobDto(r, counts.get(r.job.id))),
    page: q.page,
    pageSize: q.pageSize,
    total: total?.n ?? 0,
  };
}

export async function getScan(db: Database, id: string): Promise<ScanJobDetailResponse> {
  const [row] = await baseJobQuery(db).where(eq(scanJobs.id, id)).limit(1);
  if (!row) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  const targets = await db
    .select()
    .from(scanJobTargets)
    .where(eq(scanJobTargets.scanJobId, id))
    .orderBy(asc(scanJobTargets.targetHostname));
  const counts = await targetCounts(db, [id]);
  return {
    job: toJobDto(row, counts.get(id)),
    targets: targets.map((t) => ({
      id: t.id,
      assetId: t.assetId,
      hostname: t.targetHostname,
      ip: t.targetIp,
      status: t.status,
      startedAt: iso(t.startedAt),
      completedAt: iso(t.completedAt),
      errorCode: t.errorCode,
    })),
    scopeSnapshot: row.job.scopeSnapshot as ScopeSnapshot,
  };
}

/**
 * Cancels a job. Queued jobs stop immediately; claimed/running jobs are flagged and the worker
 * stops at its next heartbeat (or the lease reaper cancels it when the lease expires).
 */
export async function cancelScan(db: Database, id: string, actor: Actor, now: Date): Promise<void> {
  await db.transaction(async (tx) => {
    const [job] = await tx.select().from(scanJobs).where(eq(scanJobs.id, id)).for('update');
    if (!job) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    const audit = (action: string) =>
      writeAudit(tx as unknown as Database, {
        actorType: 'user',
        actorUserId: actor.userId,
        action,
        resourceType: 'scan_job',
        resourceId: id,
        requestId: actor.requestId,
        metadata: { status: job.status, profile: job.profile },
      });

    if (job.status === 'queued') {
      await tx
        .update(scanJobs)
        .set({
          status: 'cancelled',
          completedAt: now,
          cancelRequestedAt: now,
          errorCode: 'cancelled',
        })
        .where(eq(scanJobs.id, id));
      await tx
        .update(scanJobTargets)
        .set({ status: 'skipped' })
        .where(
          and(
            eq(scanJobTargets.scanJobId, id),
            or(eq(scanJobTargets.status, 'pending'), eq(scanJobTargets.status, 'running')),
          ),
        );
      await audit('scan.cancelled');
    } else if (job.status === 'claimed' || job.status === 'running') {
      if (job.cancelRequestedAt) return;
      await tx
        .update(scanJobs)
        .set({ cancelRequestedAt: now })
        .where(and(eq(scanJobs.id, id), isNull(scanJobs.cancelRequestedAt)));
      await audit('scan.cancel_requested');
    } else {
      throw new ApiError(409, 'conflict', 'This scan has already finished.');
    }
  });
}

/** Jobs whose snapshot profile is active (contacts target hosts). */
const isActiveJob = sql`(${scanJobs.scopeSnapshot} #>> '{profile,config,active}') = 'true'`;

/**
 * Stops the given domains' active jobs because their authorisation was withdrawn (revoked or
 * lapsed). Must run in the same transaction as the withdrawal. Queued jobs are cancelled outright;
 * claimed/running jobs are flagged so the worker stops at its next heartbeat (and its active
 * evidence is refused from now on). Passive jobs are unaffected. Returns the jobs touched.
 */
export async function stopActiveJobsForDomains(
  tx: Database,
  domainIds: readonly string[],
  reason: string,
  actor: Actor | null,
  now: Date,
): Promise<number> {
  if (domainIds.length === 0) return 0;
  const forDomains = and(inArray(scanJobs.domainId, [...domainIds]), isActiveJob);
  const cancelled = await tx
    .update(scanJobs)
    .set({ status: 'cancelled', completedAt: now, cancelRequestedAt: now, errorCode: reason })
    .where(and(forDomains, eq(scanJobs.status, 'queued')))
    .returning({ id: scanJobs.id, profile: scanJobs.profile });
  if (cancelled.length > 0) {
    await tx
      .update(scanJobTargets)
      .set({ status: 'skipped', errorCode: reason, completedAt: now })
      .where(
        and(
          inArray(
            scanJobTargets.scanJobId,
            cancelled.map((j) => j.id),
          ),
          or(eq(scanJobTargets.status, 'pending'), eq(scanJobTargets.status, 'running')),
        ),
      );
  }
  const flagged = await tx
    .update(scanJobs)
    .set({ cancelRequestedAt: now })
    .where(
      and(
        forDomains,
        inArray(scanJobs.status, ['claimed', 'running']),
        isNull(scanJobs.cancelRequestedAt),
      ),
    )
    .returning({ id: scanJobs.id, profile: scanJobs.profile });
  const audit = (action: string, j: { id: string; profile: string }) =>
    writeAudit(tx, {
      actorType: actor ? 'user' : 'system',
      actorUserId: actor?.userId,
      action,
      resourceType: 'scan_job',
      resourceId: j.id,
      requestId: actor?.requestId,
      metadata: { reason, profile: j.profile },
    });
  for (const j of cancelled) await audit('scan.cancelled', j);
  for (const j of flagged) await audit('scan.cancel_requested', j);
  return cancelled.length + flagged.length;
}

/**
 * Stops in-flight ACTIVE jobs that target any of the given assets because their approval was
 * withdrawn (suspended). Must run in the same transaction as the withdrawal. The assets' unfinished
 * targets are skipped (queued jobs then drop them at claim time, cancelling a job left with none);
 * claimed/running jobs are flagged so the worker stops at its next heartbeat, and active evidence for
 * the asset is refused from now on. Passive jobs are unaffected. Set-based; returns jobs flagged.
 */
export async function stopActiveJobsForAssets(
  tx: Database,
  assetIds: readonly string[],
  reason: string,
  actor: Actor | null,
  now: Date,
): Promise<number> {
  if (assetIds.length === 0) return 0;
  const targetingAssets = inArray(
    scanJobs.id,
    tx
      .select({ id: scanJobTargets.scanJobId })
      .from(scanJobTargets)
      .where(inArray(scanJobTargets.assetId, [...assetIds])),
  );
  const unfinished = inArray(scanJobs.status, ['queued', 'claimed', 'running']);
  await tx
    .update(scanJobTargets)
    .set({ status: 'skipped', errorCode: reason, completedAt: now })
    .where(
      and(
        inArray(scanJobTargets.assetId, [...assetIds]),
        eq(scanJobTargets.status, 'pending'),
        inArray(
          scanJobTargets.scanJobId,
          tx.select({ id: scanJobs.id }).from(scanJobs).where(and(unfinished, isActiveJob)),
        ),
      ),
    );
  const flagged = await tx
    .update(scanJobs)
    .set({ cancelRequestedAt: now })
    .where(
      and(
        targetingAssets,
        isActiveJob,
        inArray(scanJobs.status, ['claimed', 'running']),
        isNull(scanJobs.cancelRequestedAt),
      ),
    )
    .returning({ id: scanJobs.id, profile: scanJobs.profile });
  await writeAuditMany(
    tx,
    flagged.map((j) => ({
      actorType: actor ? ('user' as const) : ('system' as const),
      actorUserId: actor?.userId,
      action: 'scan.cancel_requested',
      resourceType: 'scan_job',
      resourceId: j.id,
      requestId: actor?.requestId,
      metadata: { reason, profile: j.profile },
    })),
  );
  return flagged.length;
}
