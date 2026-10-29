import { schema, type Database } from '@exdomainvault/database';
import type { LookalikeObservation as RuleLookalikeObservation } from '@exdomainvault/rules';
import {
  BRAND_PROFILE_KEY,
  LOOKALIKE_GENERATOR_VERSION,
  generateLookalikes,
  type LookalikeItem,
  type LookalikeListQuery,
  type LookalikeListResponse,
  type LookalikeObservation,
  type ScanProfile,
  type ScopeSnapshot,
} from '@exdomainvault/shared';
import { isWithinDomain, normaliseDomain } from '@exdomainvault/shared/hostname';
import { and, asc, desc, eq, inArray, notExists, or, sql, type SQL } from 'drizzle-orm';
import { ApiError } from '../lib/errors.ts';
import { writeAudit } from './audit.ts';
import type { Actor } from './domains.ts';
import { isUniqueViolation } from './domains.ts';
import type { JobTargetRef } from './observations.ts';
import { enforceScanQuotas } from './quotas.ts';
import { buildSnapshot, listProfiles } from './scans.ts';

/**
 * Milestone 15 — lookalike-domain (brand) monitoring.
 *
 * - Jobs: profile `brand` (job type `scan`, passive, one target = the apex with no asset). The
 *   candidate list is generated HERE (`generateLookalikes`, shared package) and frozen into the
 *   job's scope snapshot (`snapshot.lookalike`); the worker resolves exactly those names through
 *   public resolvers and never contacts them.
 * - Ingest: lookalike observations are accepted only for candidates in the snapshot (technique
 *   taken from the snapshot) and never for a name within any of our monitored domains.
 * - Rules: LOOK-001 gets the job's candidate list and completeness (`lookalikeContext`): the brand
 *   target succeeded = every candidate was checked. Unregistered candidates produce no observation,
 *   so absence in a complete run means "checked and not registered".
 */

const { domains, findings, lookalikeObservations, scanJobTargets, scanJobs } = schema;

type DomainRow = typeof domains.$inferSelect;

/** Brand jobs run at most this often per domain. */
const BRAND_INTERVAL_SECONDS = 7 * 24 * 3600;
/** Brand jobs created per cron run. */
export const BRAND_SCHEDULE_BATCH = 20;
/** Behind discovery (250): a weekly background task. */
export const BRAND_PRIORITY = 260;

const notFound = () => new ApiError(404, 'not_found', 'The requested resource was not found.');

// --- Profile and snapshot -------------------------------------------------------------------------

/** The enabled, passive brand profile listing the lookalike check, or null (fail closed). */
export async function brandProfile(db: Database): Promise<ScanProfile | null> {
  const profile = (await listProfiles(db)).find((p) => p.key === BRAND_PROFILE_KEY);
  if (
    !profile ||
    !profile.enabled ||
    profile.config.active ||
    !profile.config.checks.includes('lookalike')
  ) {
    return null;
  }
  return profile;
}

/** Every monitored domain's name: candidates equal to or beneath one are never generated. */
async function ownDomainNames(db: Database): Promise<string[]> {
  return (await db.select({ fqdn: domains.fqdn }).from(domains)).map((d) => d.fqdn);
}

/** Lookalike candidates of the domain (deterministic), excluding our own domains. */
export function lookalikeCandidates(fqdn: string, own: readonly string[]) {
  const n = normaliseDomain(fqdn);
  return generateLookalikes(fqdn, {
    ...(n.ok ? { suffix: n.publicSuffix } : {}),
    exclude: own,
  });
}

export function buildBrandSnapshot(
  domain: DomainRow,
  profile: ScanProfile,
  own: readonly string[],
  trigger: 'manual' | 'schedule',
  requestedBy: string | null,
  now: Date,
): ScopeSnapshot {
  return {
    ...buildSnapshot(
      domain,
      profile,
      [{ assetId: null, hostname: domain.fqdn }],
      trigger,
      requestedBy,
      now,
    ),
    lookalike: {
      generatorVersion: LOOKALIKE_GENERATOR_VERSION,
      candidates: lookalikeCandidates(domain.fqdn, own),
    },
  };
}

// --- Manual request -------------------------------------------------------------------------------

async function unfinishedBrandJob(db: Database, domainId: string) {
  const [job] = await db
    .select({ id: scanJobs.id })
    .from(scanJobs)
    .where(
      and(
        eq(scanJobs.domainId, domainId),
        eq(scanJobs.profile, BRAND_PROFILE_KEY),
        inArray(scanJobs.status, ['queued', 'claimed', 'running']),
      ),
    )
    .limit(1);
  return job;
}

/**
 * POST /domains/:id/lookalikes/check — queues a brand job now, or returns the one already queued or
 * running (`created: false`). Brand monitoring must be on for the domain (the owner's explicit
 * opt-in). Passive, so no verification is needed. Counts against the per-user scan quota.
 */
export async function requestLookalikeCheck(
  db: Database,
  domainId: string,
  actor: Actor,
  now: Date,
): Promise<{ scanJobId: string; created: boolean }> {
  const [domain] = await db.select().from(domains).where(eq(domains.id, domainId));
  if (!domain) throw notFound();
  if (!domain.brandMonitoring) {
    throw new ApiError(
      409,
      'conflict',
      'Brand monitoring is off for this domain. An administrator can turn it on in the domain settings.',
    );
  }
  const existing = await unfinishedBrandJob(db, domainId);
  if (existing) return { scanJobId: existing.id, created: false };
  const profile = await brandProfile(db);
  if (!profile) throw new ApiError(409, 'conflict', 'The brand monitoring profile is unavailable.');

  try {
    const id = await db.transaction(async (tx) => {
      const t = tx as unknown as Database;
      const [locked] = await tx
        .select()
        .from(domains)
        .where(eq(domains.id, domainId))
        .for('update');
      if (!locked) throw notFound();
      await enforceScanQuotas(
        t,
        { userId: actor.userId, domainId, active: false, jobType: 'scan' },
        now,
      );
      const snapshot = buildBrandSnapshot(
        locked,
        profile,
        await ownDomainNames(t),
        'manual',
        actor.userId,
        now,
      );
      const [job] = await tx
        .insert(scanJobs)
        .values({
          jobType: 'scan',
          profile: profile.key,
          domainId,
          requestedBy: actor.userId,
          reason: 'Lookalike check requested',
          scopeSnapshot: snapshot,
          createdAt: now,
          scheduledAt: now,
        })
        .returning({ id: scanJobs.id });
      if (!job) throw new Error('scan job insert returned no row');
      await tx
        .insert(scanJobTargets)
        .values({ scanJobId: job.id, assetId: null, targetHostname: locked.fqdn });
      await writeAudit(t, {
        actorType: 'user',
        actorUserId: actor.userId,
        action: 'scan.requested',
        resourceType: 'scan_job',
        resourceId: job.id,
        requestId: actor.requestId,
        metadata: {
          domainId,
          fqdn: locked.fqdn,
          jobType: 'scan',
          profile: profile.key,
          active: false,
          targets: 1,
          lookalikeCandidates: snapshot.lookalike?.candidates.length ?? 0,
        },
      });
      return job.id;
    });
    return { scanJobId: id, created: true };
  } catch (err) {
    if (isUniqueViolation(err)) {
      const raced = await unfinishedBrandJob(db, domainId);
      if (raced) return { scanJobId: raced.id, created: false };
    }
    throw err;
  }
}

// --- Scheduler ------------------------------------------------------------------------------------

/**
 * Cron step: the weekly brand job for every domain with brand monitoring on. Staggered like
 * discovery (a domain that has never had one waits for its slot in the week, a stable hash of its
 * id; afterwards it recurs ~7 days after its previous job), capped per run, idempotent (the
 * one-active-job index absorbs races). Nothing is scheduled while the profile is missing,
 * disabled or misconfigured.
 */
export async function scheduleBrandMonitoring(db: Database, now: Date): Promise<number> {
  const profile = await brandProfile(db);
  if (!profile) return 0;
  const since = new Date(now.getTime() - BRAND_INTERVAL_SECONDS * 1000);
  const phase = Math.floor(now.getTime() / 1000) % BRAND_INTERVAL_SECONDS;
  const brandJobs = (extra: SQL) =>
    db
      .select({ one: sql`1` })
      .from(scanJobs)
      .where(and(eq(scanJobs.domainId, domains.id), eq(scanJobs.profile, profile.key), extra));
  const slot = sql`(abs(hashtext(${domains.id}::text)::bigint) % ${BRAND_INTERVAL_SECONDS})`;
  const due = await db
    .select()
    .from(domains)
    .where(
      and(
        eq(domains.brandMonitoring, true),
        notExists(
          brandJobs(
            or(
              inArray(scanJobs.status, ['queued', 'claimed', 'running']),
              sql`${scanJobs.createdAt} > ${since}`,
            ) as SQL,
          ),
        ),
        or(sql`exists (${brandJobs(sql`true`)})`, sql`${slot} <= ${phase}`),
      ),
    )
    .orderBy(asc(domains.fqdn))
    .limit(BRAND_SCHEDULE_BATCH);
  if (due.length === 0) return 0;

  const own = await ownDomainNames(db);
  return db.transaction(async (tx) => {
    const inserted = await tx
      .insert(scanJobs)
      .values(
        due.map((domain) => ({
          jobType: 'scan' as const,
          profile: profile.key,
          domainId: domain.id,
          priority: BRAND_PRIORITY,
          reason: 'Scheduled lookalike-domain check',
          scopeSnapshot: buildBrandSnapshot(domain, profile, own, 'schedule', null, now),
          createdAt: now,
          scheduledAt: now,
        })),
      )
      .onConflictDoNothing()
      .returning({ id: scanJobs.id, domainId: scanJobs.domainId });
    if (inserted.length === 0) return 0;
    const fqdnOf = new Map(due.map((d) => [d.id, d.fqdn]));
    await tx.insert(scanJobTargets).values(
      inserted.map((row) => ({
        scanJobId: row.id,
        assetId: null,
        targetHostname: fqdnOf.get(row.domainId ?? '') ?? '',
      })),
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

// --- Ingest ---------------------------------------------------------------------------------------

const invalid = (index: number, field: string, message: string) =>
  new ApiError(400, 'validation_failed', 'An observation is invalid.', [
    { path: `observations.${index}.${field}`, message },
  ]);

/**
 * Synchronous checks of one lookalike observation (called from `validate` in observations.ts):
 * only from a job whose profile lists the check, for its apex target, for a candidate in the job's
 * snapshot with the snapshot's technique, never a name within the job's own domain.
 */
export function validateLookalikeObservation(
  snapshot: ScopeSnapshot,
  target: JobTargetRef,
  o: LookalikeObservation,
  index: number,
): void {
  if (!snapshot.profile.config.checks.includes('lookalike') || !snapshot.lookalike) {
    throw invalid(index, 'kind', "This job's scan profile does not include this check.");
  }
  if (target.targetHostname !== snapshot.domain.fqdn) {
    throw invalid(index, 'targetId', 'Lookalike observations are accepted for the apex only.');
  }
  if (isWithinDomain(o.candidate, snapshot.domain.fqdn)) {
    throw invalid(index, 'candidate', "The candidate is within this job's domain.");
  }
  const listed = snapshot.lookalike.candidates.find((c) => c.candidate === o.candidate);
  if (!listed) throw invalid(index, 'candidate', "The candidate is not in this job's list.");
  if (listed.technique !== o.technique) {
    throw invalid(index, 'technique', "The technique does not match this job's list.");
  }
}

/** Every suffix of a name on a label boundary (`a.b.c` → `a.b.c`, `b.c`, `c`). */
const suffixes = (name: string) => name.split('.').map((_, i, l) => l.slice(i).join('.'));

export interface LookalikeRow {
  index: number;
  o: LookalikeObservation;
  row: {
    resultId: string;
    assetId: string | null;
    scanJobId: string;
    scanJobTargetId: string;
    observedAt: Date;
    checker: string;
    checkerVersion: string;
    resultStatus: LookalikeObservation['resultStatus'];
    evidence: Record<string, unknown>;
  };
}

/**
 * Stores lookalike observations (after `validateLookalikeObservation`). Rejects the whole batch if
 * any candidate is one of OUR monitored domains or beneath one (it would be our own asset, not a
 * lookalike). Idempotent on `result_id`. Returns rows inserted.
 */
export async function ingestLookalikes(
  tx: Database,
  domainId: string,
  rows: readonly LookalikeRow[],
): Promise<number> {
  if (rows.length === 0) return 0;
  const names = [...new Set(rows.flatMap((r) => suffixes(r.o.candidate)))];
  const own = await tx
    .select({ fqdn: domains.fqdn })
    .from(domains)
    .where(inArray(domains.fqdn, names));
  if (own.length > 0) {
    const ownSet = new Set(own.map((d) => d.fqdn));
    const bad = rows.find((r) => suffixes(r.o.candidate).some((s) => ownSet.has(s)));
    if (bad)
      throw invalid(bad.index, 'candidate', 'The candidate is one of our monitored domains.');
  }
  const values = rows.map(({ o, row }) => ({
    ...row,
    domainId,
    candidate: o.candidate,
    technique: o.technique,
    registered: o.registered,
    records: Object.fromEntries(
      (['A', 'AAAA', 'MX', 'NS'] as const).flatMap((k) =>
        o.records[k] ? [[k, [...o.records[k]].sort()]] : [],
      ),
    ),
  }));
  return (
    await tx
      .insert(lookalikeObservations)
      .values(values)
      .onConflictDoNothing({ target: lookalikeObservations.resultId })
      .returning({ id: lookalikeObservations.id })
  ).length;
}

// --- Evaluation -----------------------------------------------------------------------------------

/** The job's lookalike observations as the rules see them. */
export async function loadLookalikeObservations(
  tx: Database,
  jobId: string,
  cap = 5000,
): Promise<RuleLookalikeObservation[]> {
  const rows = await tx
    .select()
    .from(lookalikeObservations)
    .where(eq(lookalikeObservations.scanJobId, jobId))
    .orderBy(asc(lookalikeObservations.candidate), asc(lookalikeObservations.resultId))
    .limit(cap);
  return rows.map((r) => ({
    resultStatus: r.resultStatus,
    observedAt: r.observedAt.toISOString(),
    scanJobId: r.scanJobId,
    evidence: r.evidence,
    candidate: r.candidate,
    technique: r.technique,
    registered: r.registered,
    records: r.records,
  }));
}

/**
 * Rules context for a brand job: its candidate list and whether the run was complete (every target
 * succeeded: the worker checked every candidate within the time budget). `{}` for other jobs.
 */
export async function lookalikeContext(
  tx: Database,
  jobId: string,
  snapshot: ScopeSnapshot,
): Promise<{ lookalike?: { complete: boolean; candidates: string[] } }> {
  if (!snapshot.lookalike || !snapshot.profile.config.checks.includes('lookalike')) return {};
  const targets = await tx
    .select({ status: scanJobTargets.status })
    .from(scanJobTargets)
    .where(eq(scanJobTargets.scanJobId, jobId));
  const complete = targets.length > 0 && targets.every((t) => t.status === 'succeeded');
  return {
    lookalike: { complete, candidates: snapshot.lookalike.candidates.map((c) => c.candidate) },
  };
}

// --- Read model -----------------------------------------------------------------------------------

/** Rows loaded per request (registered lookalikes are few; this bounds a pathological case). */
const MAX_LIST_ROWS = 10_000;
const WEEK_MS = 7 * 86_400_000;

const toRecords = (r: Record<string, string[]>) => ({
  A: r.A ?? [],
  AAAA: r.AAAA ?? [],
  MX: r.MX ?? [],
  NS: r.NS ?? [],
});
const hasMail = (mx: string[]) => mx.some((v) => !/^\d+\s+\.$/.test(v.trim()));

/**
 * GET /lookalikes. One item per (domain, candidate) ever seen registered. State: `registered` unless
 * the domain's latest COMPLETE brand run finished after the candidate was last seen registered and
 * did not fail to resolve it (`gone`). Sorted: registered first, mail-capable first, newest first.
 */
export async function listLookalikes(
  db: Database,
  q: LookalikeListQuery,
  now: Date,
): Promise<LookalikeListResponse> {
  const o = lookalikeObservations;
  const good = inArray(o.resultStatus, ['success', 'partial']);
  const domainFilter = q.domainId ? eq(o.domainId, q.domainId) : undefined;

  const [latest, firsts, lastComplete, [monitored]] = await Promise.all([
    db
      .selectDistinctOn([o.domainId, o.candidate], {
        domainId: o.domainId,
        fqdn: domains.fqdn,
        candidate: o.candidate,
        technique: o.technique,
        records: o.records,
        observedAt: o.observedAt,
        jobCompletedAt: scanJobs.completedAt,
      })
      .from(o)
      .innerJoin(domains, eq(domains.id, o.domainId))
      .innerJoin(scanJobs, eq(scanJobs.id, o.scanJobId))
      .where(and(eq(o.registered, true), good, domainFilter))
      .orderBy(asc(o.domainId), asc(o.candidate), desc(o.observedAt), desc(o.id))
      .limit(MAX_LIST_ROWS),
    db
      .select({
        domainId: o.domainId,
        candidate: o.candidate,
        first: sql<string>`min(${o.observedAt})`.mapWith((v: unknown) =>
          v instanceof Date ? v : new Date(String(v)),
        ),
      })
      .from(o)
      .where(and(eq(o.registered, true), good, domainFilter))
      .groupBy(o.domainId, o.candidate)
      .limit(MAX_LIST_ROWS),
    // Latest complete brand job per domain (every target succeeded).
    db
      .selectDistinctOn([scanJobs.domainId], {
        id: scanJobs.id,
        domainId: scanJobs.domainId,
        completedAt: scanJobs.completedAt,
        candidates:
          sql<number>`coalesce(jsonb_array_length(${scanJobs.scopeSnapshot} -> 'lookalike' -> 'candidates'), 0)`.mapWith(
            Number,
          ),
      })
      .from(scanJobs)
      .where(
        and(
          eq(scanJobs.profile, BRAND_PROFILE_KEY),
          eq(scanJobs.status, 'succeeded'),
          q.domainId ? eq(scanJobs.domainId, q.domainId) : undefined,
          notExists(
            db
              .select({ one: sql`1` })
              .from(scanJobTargets)
              .where(
                and(
                  eq(scanJobTargets.scanJobId, scanJobs.id),
                  sql`${scanJobTargets.status} <> 'succeeded'`,
                ),
              ),
          ),
        ),
      )
      .orderBy(asc(scanJobs.domainId), desc(scanJobs.completedAt), desc(scanJobs.id)),
    db
      .select({ n: sql<number>`count(*)`.mapWith(Number) })
      .from(domains)
      .where(
        and(eq(domains.brandMonitoring, true), q.domainId ? eq(domains.id, q.domainId) : undefined),
      ),
  ]);

  const completeOf = new Map(lastComplete.map((j) => [j.domainId ?? '', j]));
  // Candidates the latest complete run could not resolve: unknown, so not "gone".
  const completeIds = lastComplete.map((j) => j.id);
  const failed = new Set(
    completeIds.length === 0
      ? []
      : (
          await db
            .select({ domainId: o.domainId, candidate: o.candidate })
            .from(o)
            .where(
              and(
                inArray(o.scanJobId, completeIds),
                sql`${o.resultStatus} not in ('success', 'partial')`,
              ),
            )
            .limit(MAX_LIST_ROWS)
        ).map((r) => `${r.domainId}|${r.candidate}`),
  );
  const firstOf = new Map(firsts.map((f) => [`${f.domainId}|${f.candidate}`, f.first]));

  const domainIds = [...new Set(latest.map((r) => r.domainId))];
  const findingRows =
    domainIds.length === 0
      ? []
      : await db
          .select({
            id: findings.id,
            domainId: findings.domainId,
            component: findings.component,
            status: findings.status,
            severity: findings.severity,
            updatedAt: findings.updatedAt,
          })
          .from(findings)
          .where(and(eq(findings.ruleId, 'LOOK-001'), inArray(findings.domainId, domainIds)))
          .orderBy(desc(findings.updatedAt));
  const findingOf = new Map<string, (typeof findingRows)[number]>();
  for (const f of findingRows) {
    const key = `${f.domainId}|${f.component}`;
    const prev = findingOf.get(key);
    // Prefer an active finding over a resolved one; otherwise the most recently updated.
    if (!prev || (prev.status === 'resolved' && f.status !== 'resolved')) findingOf.set(key, f);
  }

  const all: LookalikeItem[] = latest.map((r) => {
    const key = `${r.domainId}|${r.candidate}`;
    const complete = completeOf.get(r.domainId);
    const gone =
      complete?.completedAt != null &&
      r.jobCompletedAt != null &&
      complete.completedAt > r.jobCompletedAt &&
      !failed.has(key);
    const records = toRecords(r.records);
    const f = findingOf.get(key);
    return {
      domain: { id: r.domainId, fqdn: r.fqdn },
      candidate: r.candidate,
      technique: r.technique as LookalikeItem['technique'],
      state: gone ? 'gone' : 'registered',
      records,
      hasMail: hasMail(records.MX),
      firstSeenAt: (firstOf.get(key) ?? r.observedAt).toISOString(),
      lastSeenAt: r.observedAt.toISOString(),
      lastCheckedAt: complete?.completedAt ? complete.completedAt.toISOString() : null,
      finding: f ? { id: f.id, status: f.status, severity: f.severity } : null,
    };
  });

  const current = all.filter((i) => i.state === 'registered');
  const weekAgo = now.getTime() - WEEK_MS;
  const lastChecked = lastComplete
    .map((j) => j.completedAt?.getTime() ?? 0)
    .reduce((a, b) => Math.max(a, b), 0);
  const summary = {
    domainsMonitored: monitored?.n ?? 0,
    candidatesChecked: lastComplete.reduce((sum, j) => sum + j.candidates, 0),
    registered: current.length,
    withMail: current.filter((i) => i.hasMail).length,
    newThisWeek: current.filter((i) => Date.parse(i.firstSeenAt) >= weekAgo).length,
    lastCheckedAt: lastChecked > 0 ? new Date(lastChecked).toISOString() : null,
  };

  const needle = q.q?.toLowerCase();
  const items = all
    .filter((i) =>
      q.registered === undefined ? true : (i.state === 'registered') === (q.registered === 'true'),
    )
    .filter((i) => (q.technique ? i.technique === q.technique : true))
    .filter((i) => (needle ? i.candidate.includes(needle) : true))
    .sort(
      (a, b) =>
        Number(b.state === 'registered') - Number(a.state === 'registered') ||
        Number(b.hasMail) - Number(a.hasMail) ||
        b.firstSeenAt.localeCompare(a.firstSeenAt) ||
        a.candidate.localeCompare(b.candidate),
    );
  const start = (q.page - 1) * q.pageSize;
  return {
    items: items.slice(start, start + q.pageSize),
    page: q.page,
    pageSize: q.pageSize,
    total: items.length,
    summary,
  };
}
