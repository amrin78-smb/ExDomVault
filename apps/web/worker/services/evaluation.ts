import { schema, type Database } from '@exdomainvault/database';
import {
  DEFAULT_ADMINISTRATIVE_SERVICES,
  RULES,
  evaluate,
  extractSoftware,
  type DnsRecordSetObservation,
  type EvaluationInput,
  type FindingUpsert,
  type ObservationSet,
  type Rule,
} from '@exdomainvault/rules';
import { DNS_RECORD_TYPES, scopeSnapshotSchema, type DnsRecordType } from '@exdomainvault/shared';
import { canonicalIp } from '@exdomainvault/shared/net';
import { and, asc, desc, eq, inArray, isNull, lt, ne, or, sql, type SQL } from 'drizzle-orm';
import type { Logger } from '../lib/logger.ts';
import { domainAuthorisedForActive, type ScanJobRow } from './scans.ts';
import { loadSoftwareIntel, upsertSoftwareInventory } from './software.ts';

const {
  advisories,
  assets,
  discoveryObservations,
  dnsObservations,
  domains,
  findingStatusHistory,
  findings,
  httpObservations,
  portObservations,
  registrationObservations,
  scanJobs,
  tlsObservations,
} = schema;

/**
 * Rules evaluation (design §8, Milestone 7). Turns one SUCCEEDED job's observations into findings:
 *
 *  - only `succeeded` jobs are evaluated, each exactly once (`rules_evaluated_at` is claimed
 *    atomically in the same transaction that persists the result, so a failure rolls the claim back
 *    and the job is retried by maintenance);
 *  - a domain's jobs are evaluated in completion order: a job waits ("deferred") while an earlier
 *    succeeded job of the same domain is still unevaluated, and evaluations of one domain are
 *    serialised by an advisory lock;
 *  - upserts create, refresh or reopen (recurrence) the finding with that fingerprint; resolutions
 *    resolve an active finding only when the rule checked the component with successful evidence
 *    (the pure evaluator guarantees this). Failed/cancelled jobs never resolve anything.
 */

export type EvaluationStatus = 'evaluated' | 'not_eligible' | 'deferred' | 'skipped';

export interface EvaluationSummary {
  status: EvaluationStatus;
  jobId: string;
  created: number;
  refreshed: number;
  reopened: number;
  resolved: number;
  skippedRules: number;
  ruleErrors: number;
  /** Software inventory rows upserted from this job's sightings. */
  software: number;
}

/** Per-kind cap on observations loaded for one evaluation (current and previous each). */
const MAX_OBSERVATIONS_PER_KIND = 5000;

class Deferred extends Error {}

const summary = (jobId: string, status: EvaluationStatus): EvaluationSummary => ({
  status,
  jobId,
  created: 0,
  refreshed: 0,
  reopened: 0,
  resolved: 0,
  skippedRules: 0,
  ruleErrors: 0,
  software: 0,
});

/**
 * Evaluates one job. Safe to call repeatedly and concurrently: only the first call for a succeeded
 * job does anything (`not_eligible` otherwise).
 */
export async function evaluateJob(
  db: Database,
  jobId: string,
  now: Date,
  rules: readonly Rule[] = RULES,
  logger?: Logger,
): Promise<EvaluationSummary> {
  try {
    const result = await db.transaction(async (tx) =>
      evaluateInTx(tx as unknown as Database, jobId, now, rules, logger),
    );
    if (result.status === 'evaluated') {
      logger?.info('rules_evaluated', { ...result });
    }
    return result;
  } catch (err) {
    if (err instanceof Deferred) return summary(jobId, 'deferred');
    throw err;
  }
}

async function evaluateInTx(
  tx: Database,
  jobId: string,
  now: Date,
  rules: readonly Rule[],
  logger: Logger | undefined,
): Promise<EvaluationSummary> {
  const [job] = await tx
    .update(scanJobs)
    .set({ rulesEvaluatedAt: now })
    .where(
      and(
        eq(scanJobs.id, jobId),
        eq(scanJobs.status, 'succeeded'),
        isNull(scanJobs.rulesEvaluatedAt),
      ),
    )
    .returning();
  if (!job) return summary(jobId, 'not_eligible');
  const domainId = job.domainId;
  if (!domainId) return summary(jobId, 'skipped'); // domain deleted: nothing to attach findings to

  // One evaluation per domain at a time (fingerprint upserts must not race).
  await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`findings:${domainId}`}))`);

  // Evidence time: first/last seen, resolved_at and system history entries use the job's completion
  // time (not the evaluation time), so a backlog evaluated in one run keeps its true order.
  const seenAt = job.completedAt ?? now;
  const [earlierPending] = await tx
    .select({ id: scanJobs.id })
    .from(scanJobs)
    .where(
      and(
        eq(scanJobs.domainId, domainId),
        eq(scanJobs.status, 'succeeded'),
        isNull(scanJobs.rulesEvaluatedAt),
        ne(scanJobs.id, job.id),
        earlierThan(job, seenAt),
      ),
    )
    .limit(1);
  if (earlierPending) throw new Deferred(); // rolls back the claim; maintenance goes oldest first

  const [domain] = await tx.select().from(domains).where(eq(domains.id, domainId));
  if (!domain) return summary(jobId, 'skipped');
  const snapshot = scopeSnapshotSchema.safeParse(job.scopeSnapshot);
  if (!snapshot.success) {
    logger?.warn('rules_evaluation_skipped', { jobId, reason: 'invalid_snapshot' });
    return summary(jobId, 'skipped');
  }

  const domainAssets = await tx
    .select({
      id: assets.id,
      hostname: assets.hostname,
      status: assets.verificationStatus,
      monitoringEnabled: assets.monitoringEnabled,
    })
    .from(assets)
    .where(eq(assets.domainId, domainId))
    .orderBy(asc(assets.hostname));

  const current = await currentObservations(tx, job.id);
  // Exposed software (Milestone 11): what hosts reported about themselves in this job, and the
  // feed intelligence for just those products (undefined if no feed ever synced: rules skip).
  const sightings = extractSoftware(current);
  const softwareIntel = await loadSoftwareIntel(
    tx,
    sightings.map((s) => s.product),
  );

  const input: EvaluationInput = {
    context: {
      now: seenAt.toISOString(),
      domain: {
        id: domain.id,
        fqdn: domain.fqdn,
        criticality: domain.criticality,
        verified: domainAuthorisedForActive(domain, seenAt),
      },
      scanJobId: job.id,
      checks: snapshot.data.profile.config.checks,
      assets: domainAssets.map((a) => ({
        hostname: a.hostname,
        assetId: a.id,
        status: a.status,
        monitoringEnabled: a.monitoringEnabled,
      })),
      administrativeServices: DEFAULT_ADMINISTRATIVE_SERVICES,
      ...(softwareIntel ? { softwareIntel } : {}),
    },
    current,
    previous: await previousObservations(tx, job, domainId, seenAt),
  };

  const result = evaluate(input, rules);
  for (const e of result.errors) {
    logger?.error('rule_failed', { jobId, ruleId: e.ruleId, error: e.message });
  }

  const out = summary(jobId, 'evaluated');
  out.skippedRules = result.skipped.length;
  out.ruleErrors = result.errors.length;

  const categoryOf = new Map(rules.map((r) => [r.id, r.category]));
  const assetOf = new Map(domainAssets.map((a) => [a.hostname, a.id]));

  // Inventory follows the evidence, not the findings: updated for every evaluated job.
  out.software = await upsertSoftwareInventory(tx, {
    domainId,
    jobId: job.id,
    sightings,
    current,
    assetOf,
    seenAt,
    now,
  });
  const fingerprints = [
    ...result.upserts.map((u) => u.fingerprint),
    ...result.resolutions.map((r) => r.fingerprint),
  ];
  // Locked (in id order, like user bulk changes) so a concurrent user status change either
  // commits first, and is seen here, or waits for this evaluation: history `from_status` is never
  // stale and an acceptance cannot be written onto a finding this job is resolving.
  const existing =
    fingerprints.length > 0
      ? (
          await tx
            .select()
            .from(findings)
            .where(inArray(findings.fingerprint, [...new Set(fingerprints)]))
            .orderBy(asc(findings.id))
            .for('update')
        ).sort(latestFirst)
      : [];
  const activeByFp = new Map<string, (typeof existing)[number]>();
  const resolvedByFp = new Map<string, (typeof existing)[number]>();
  for (const f of existing) {
    if (f.status !== 'resolved') activeByFp.set(f.fingerprint, f);
    else if (!resolvedByFp.has(f.fingerprint)) resolvedByFp.set(f.fingerprint, f); // latest first
  }

  for (const u of result.upserts) {
    const category = categoryOf.get(u.ruleId);
    if (!category) continue; // cannot happen: upserts come from `rules`
    const fields = {
      ruleVersion: u.ruleVersion,
      title: u.title,
      description: u.description,
      severity: u.severity,
      confidence: u.confidence,
      riskScore: u.riskScore,
      riskInputs: { ...u.riskInputs },
      evidence: u.evidence,
      category,
      updatedAt: now,
    };
    const assetId = assetOf.get(u.hostname) ?? null;
    const active = activeByFp.get(u.fingerprint);
    if (active) {
      // Triage state (acknowledged, remediation in progress, accepted risk) is kept: only the
      // evidence and the rule's current output are refreshed. Never move backwards in time.
      if (seenAt < active.lastSeenAt) continue;
      await tx
        .update(findings)
        .set({ ...fields, lastSeenAt: seenAt, assetId: assetId ?? active.assetId })
        .where(eq(findings.id, active.id));
      await upsertAdvisory(tx, active.id, u, now);
      out.refreshed++;
      continue;
    }
    const resolved = resolvedByFp.get(u.fingerprint);
    if (resolved) {
      if (seenAt < (resolved.resolvedAt ?? resolved.lastSeenAt)) continue;
      await tx
        .update(findings)
        .set({
          ...fields,
          status: 'open',
          resolvedAt: null,
          lastSeenAt: seenAt,
          recurrenceCount: resolved.recurrenceCount + 1,
          // A recurrence needs a fresh decision: no acceptance carries over.
          acceptedRiskReason: null,
          acceptedRiskApprovedBy: null,
          acceptedRiskReviewAt: null,
          assetId: assetId ?? resolved.assetId,
        })
        .where(eq(findings.id, resolved.id));
      await tx.insert(findingStatusHistory).values({
        findingId: resolved.id,
        fromStatus: 'resolved',
        toStatus: 'open',
        reason: 'recurrence',
        scanJobId: job.id,
        createdAt: seenAt,
      });
      await upsertAdvisory(tx, resolved.id, u, now);
      out.reopened++;
      continue;
    }
    const [row] = await tx
      .insert(findings)
      .values({
        ...fields,
        domainId,
        assetId,
        hostname: u.hostname,
        component: u.component,
        ruleId: u.ruleId,
        fingerprint: u.fingerprint,
        status: 'open',
        firstSeenAt: seenAt,
        lastSeenAt: seenAt,
        createdAt: now,
      })
      .returning({ id: findings.id });
    if (!row) throw new Error('finding insert returned no row');
    await tx.insert(findingStatusHistory).values({
      findingId: row.id,
      fromStatus: null,
      toStatus: 'open',
      reason: 'detected',
      scanJobId: job.id,
      createdAt: seenAt,
    });
    await upsertAdvisory(tx, row.id, u, now);
    out.created++;
  }

  for (const r of result.resolutions) {
    const active = activeByFp.get(r.fingerprint);
    // Evidence older than the finding's latest sighting cannot resolve it.
    if (!active || active.lastSeenAt > seenAt) continue;
    // Accepted risk is resolved too: the accepted condition is no longer present. Should it
    // recur, it reopens as `open` and needs a fresh decision.
    await tx
      .update(findings)
      .set({
        status: 'resolved',
        resolvedAt: seenAt,
        acceptedRiskReason: null,
        acceptedRiskApprovedBy: null,
        acceptedRiskReviewAt: null,
        updatedAt: now,
      })
      .where(and(eq(findings.id, active.id), ne(findings.status, 'resolved')));
    await tx.insert(findingStatusHistory).values({
      findingId: active.id,
      fromStatus: active.status,
      toStatus: 'resolved',
      reason: 'condition_absent',
      scanJobId: job.id,
      createdAt: seenAt,
    });
    out.resolved++;
  }
  return out;
}

/** Latest resolution first, then most recently updated (picks the finding a recurrence reopens). */
function latestFirst(
  a: { resolvedAt: Date | null; updatedAt: Date },
  b: { resolvedAt: Date | null; updatedAt: Date },
): number {
  // ORDER BY resolved_at DESC puts NULLs first in PostgreSQL; keep that order.
  const ra = a.resolvedAt?.getTime() ?? Infinity;
  const rb = b.resolvedAt?.getTime() ?? Infinity;
  if (ra !== rb) return rb - ra;
  return b.updatedAt.getTime() - a.updatedAt.getTime();
}

async function upsertAdvisory(tx: Database, findingId: string, u: FindingUpsert, now: Date) {
  const values = {
    title: u.advisory.title,
    summary: u.advisory.summary,
    businessImpact: u.advisory.businessImpact,
    recommendedActions: u.advisory.recommendedActions,
    referenceLinks: u.advisory.references,
    updatedAt: now,
  };
  await tx
    .insert(advisories)
    .values({ findingId, ...values, createdAt: now })
    .onConflictDoUpdate({ target: advisories.findingId, set: values });
}

/** Jobs that completed before `job` (ties broken by id, so the order is total). */
function earlierThan(job: ScanJobRow, completedAt: Date): SQL {
  return or(
    lt(scanJobs.completedAt, completedAt),
    and(eq(scanJobs.completedAt, completedAt), lt(scanJobs.id, job.id)),
  ) as SQL;
}

// --- Observation loading ------------------------------------------------------------------------

const RECORD_TYPES: ReadonlySet<string> = new Set(DNS_RECORD_TYPES);
const ipText = (v: string | null) => (v === null ? '' : (canonicalIp(v) ?? v));
const isoOrNull = (d: Date | null) => (d ? d.toISOString() : null);

type DnsRow = typeof dnsObservations.$inferSelect;
type RegRow = typeof registrationObservations.$inferSelect;
type TlsRow = typeof tlsObservations.$inferSelect;
type HttpRow = typeof httpObservations.$inferSelect;
type PortRow = typeof portObservations.$inferSelect;
type DiscoveryRow = typeof discoveryObservations.$inferSelect;

const base = (r: {
  resultStatus: DnsRow['resultStatus'];
  observedAt: Date;
  scanJobId: string;
  evidence: Record<string, unknown>;
}) => ({
  resultStatus: r.resultStatus,
  observedAt: r.observedAt.toISOString(),
  scanJobId: r.scanJobId,
  evidence: r.evidence,
});

function toSet(rows: {
  dns: DnsRow[];
  registration: RegRow[];
  tls: TlsRow[];
  http: HttpRow[];
  ports: PortRow[];
  discovery: DiscoveryRow[];
}): ObservationSet {
  return {
    dns: rows.dns
      .filter((r) => RECORD_TYPES.has(r.recordType))
      .map((r): DnsRecordSetObservation => ({
        ...base(r),
        hostname: r.hostname,
        recordType: r.recordType as DnsRecordType,
        ttl: r.ttl,
        values: [...r.recordValues].sort(),
      })),
    registration: rows.registration.map((r) => ({
      ...base(r),
      registrar: r.registrar,
      registeredAt: isoOrNull(r.registeredAt),
      expiresAt: isoOrNull(r.expiresAt),
      nameservers: [...r.nameservers],
      dataStatus: r.dataStatus === 'unknown' ? 'unavailable' : r.dataStatus,
    })),
    tls: rows.tls.map((r) => ({
      ...base(r),
      hostname: r.hostname,
      ipAddress: ipText(r.ipAddress),
      port: r.port,
      protocolVersion: r.protocolVersion,
      notBefore: isoOrNull(r.notBefore),
      notAfter: isoOrNull(r.notAfter),
      issuer: r.issuer,
      subject: r.subject,
      subjectAltNames: [...r.subjectAltNames],
      fingerprintSha256: r.fingerprintSha256,
      hostnameMatches: r.hostnameMatches,
    })),
    http: rows.http.map((r) => ({
      ...base(r),
      url: r.url,
      ipAddress: ipText(r.ipAddress),
      statusCode: r.statusCode,
      finalUrl: r.finalUrl,
      redirectCount: r.redirectCount,
      hstsEnabled: r.hstsEnabled,
    })),
    ports: rows.ports
      .filter((r) => r.state === 'open' || r.state === 'closed' || r.state === 'filtered')
      .map((r) => ({
        ...base(r),
        ipAddress: ipText(r.ipAddress),
        port: r.port,
        protocol: 'tcp' as const,
        state: r.state as 'open' | 'closed' | 'filtered',
        service: r.service,
      })),
    discovery: rows.discovery.map((r) => ({
      ...base(r),
      hostname: r.hostname,
      source: r.source,
    })),
  };
}

/** Every observation of this job (any result status: rules need failures to avoid resolving). */
async function currentObservations(tx: Database, jobId: string): Promise<ObservationSet> {
  const cap = MAX_OBSERVATIONS_PER_KIND;
  const [dns, registration, tls, http, ports, discovery] = await Promise.all([
    tx
      .select()
      .from(dnsObservations)
      .where(eq(dnsObservations.scanJobId, jobId))
      .orderBy(
        asc(dnsObservations.hostname),
        asc(dnsObservations.recordType),
        asc(dnsObservations.observedAt),
        asc(dnsObservations.resultId),
      )
      .limit(cap),
    tx
      .select()
      .from(registrationObservations)
      .where(eq(registrationObservations.scanJobId, jobId))
      .orderBy(asc(registrationObservations.observedAt), asc(registrationObservations.resultId))
      .limit(cap),
    tx
      .select()
      .from(tlsObservations)
      .where(eq(tlsObservations.scanJobId, jobId))
      .orderBy(
        asc(tlsObservations.hostname),
        asc(tlsObservations.ipAddress),
        asc(tlsObservations.port),
        asc(tlsObservations.resultId),
      )
      .limit(cap),
    tx
      .select()
      .from(httpObservations)
      .where(eq(httpObservations.scanJobId, jobId))
      .orderBy(asc(httpObservations.url), asc(httpObservations.resultId))
      .limit(cap),
    tx
      .select()
      .from(portObservations)
      .where(eq(portObservations.scanJobId, jobId))
      .orderBy(
        asc(portObservations.ipAddress),
        asc(portObservations.port),
        asc(portObservations.resultId),
      )
      .limit(cap),
    tx
      .select()
      .from(discoveryObservations)
      .where(eq(discoveryObservations.scanJobId, jobId))
      .orderBy(asc(discoveryObservations.hostname), asc(discoveryObservations.resultId))
      .limit(cap),
  ]);
  return toSet({ dns, registration, tls, http, ports, discovery });
}

/**
 * The last known-good state before this job, for change detection: the latest SUCCESSFUL
 * observation per key from earlier succeeded jobs of the same domain. Discovery: the successful
 * hostnames of the most recent earlier job that produced any.
 */
async function previousObservations(
  tx: Database,
  job: ScanJobRow,
  domainId: string,
  completedAt: Date,
): Promise<ObservationSet> {
  const cap = MAX_OBSERVATIONS_PER_KIND;
  const earlier = and(
    eq(scanJobs.domainId, domainId),
    eq(scanJobs.status, 'succeeded'),
    earlierThan(job, completedAt),
  );

  const d = dnsObservations;
  const dns = (
    await tx
      .selectDistinctOn([d.hostname, d.recordType], { o: d })
      .from(d)
      .innerJoin(scanJobs, eq(scanJobs.id, d.scanJobId))
      .where(and(earlier, eq(d.resultStatus, 'success')))
      .orderBy(asc(d.hostname), asc(d.recordType), desc(d.observedAt), desc(d.id))
      .limit(cap)
  ).map((r) => r.o);

  const g = registrationObservations;
  const registration = (
    await tx
      .select({ o: g })
      .from(g)
      .innerJoin(scanJobs, eq(scanJobs.id, g.scanJobId))
      .where(and(earlier, eq(g.domainId, domainId), eq(g.resultStatus, 'success')))
      .orderBy(desc(g.observedAt), desc(g.id))
      .limit(1)
  ).map((r) => r.o);

  const t = tlsObservations;
  const tls = (
    await tx
      .selectDistinctOn([t.hostname, t.ipAddress, t.port], { o: t })
      .from(t)
      .innerJoin(scanJobs, eq(scanJobs.id, t.scanJobId))
      .where(and(earlier, eq(t.resultStatus, 'success')))
      .orderBy(asc(t.hostname), asc(t.ipAddress), asc(t.port), desc(t.observedAt), desc(t.id))
      .limit(cap)
  ).map((r) => r.o);

  const h = httpObservations;
  const http = (
    await tx
      .selectDistinctOn([h.url], { o: h })
      .from(h)
      .innerJoin(scanJobs, eq(scanJobs.id, h.scanJobId))
      .where(and(earlier, eq(h.resultStatus, 'success')))
      .orderBy(asc(h.url), desc(h.observedAt), desc(h.id))
      .limit(cap)
  ).map((r) => r.o);

  const p = portObservations;
  const ports = (
    await tx
      .selectDistinctOn([p.ipAddress, p.port], { o: p })
      .from(p)
      .innerJoin(scanJobs, eq(scanJobs.id, p.scanJobId))
      .where(and(earlier, eq(p.resultStatus, 'success')))
      .orderBy(asc(p.ipAddress), asc(p.port), desc(p.observedAt), desc(p.id))
      .limit(cap)
  ).map((r) => r.o);

  const x = discoveryObservations;
  const [lastDiscovery] = await tx
    .select({ jobId: x.scanJobId })
    .from(x)
    .innerJoin(scanJobs, eq(scanJobs.id, x.scanJobId))
    .where(and(earlier, eq(x.domainId, domainId), eq(x.resultStatus, 'success')))
    .orderBy(desc(scanJobs.completedAt), desc(scanJobs.id))
    .limit(1);
  const discovery = lastDiscovery
    ? await tx
        .select()
        .from(x)
        .where(and(eq(x.scanJobId, lastDiscovery.jobId), eq(x.resultStatus, 'success')))
        .orderBy(asc(x.hostname), asc(x.resultId))
        .limit(cap)
    : [];

  return toSet({ dns, registration, tls, http, ports, discovery });
}

// --- Backlog ------------------------------------------------------------------------------------

/** Succeeded jobs evaluated per maintenance run (oldest first). */
export const EVALUATION_BATCH = 25;

/**
 * Evaluates the oldest unevaluated succeeded jobs (maintenance step `evaluate_pending_jobs`).
 * A job that fails to evaluate stays pending and is retried on the next run.
 */
export async function evaluatePendingJobs(
  db: Database,
  now: Date,
  opts: { limit?: number; rules?: readonly Rule[]; logger?: Logger } = {},
): Promise<number> {
  const pending = await db
    .select({ id: scanJobs.id })
    .from(scanJobs)
    .where(and(eq(scanJobs.status, 'succeeded'), isNull(scanJobs.rulesEvaluatedAt)))
    .orderBy(asc(scanJobs.completedAt), asc(scanJobs.id))
    .limit(opts.limit ?? EVALUATION_BATCH);
  let evaluated = 0;
  for (const { id } of pending) {
    try {
      const r = await evaluateJob(db, id, now, opts.rules ?? RULES, opts.logger);
      if (r.status === 'evaluated' || r.status === 'skipped') evaluated++;
    } catch (err) {
      opts.logger?.error('rules_evaluation_failed', {
        jobId: id,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return evaluated;
}
