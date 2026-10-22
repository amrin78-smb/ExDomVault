import { schema, type Database } from '@exdomainvault/database';
import {
  DNS_RECORD_TYPES,
  type DnsObservation,
  type DomainObservationsResponse,
  type Observation,
  type RegistrationObservation,
} from '@exdomainvault/shared';
import { isWithinDomain } from '@exdomainvault/shared/hostname';
import { and, asc, desc, eq, max } from 'drizzle-orm';
import { ApiError } from '../lib/errors.ts';
import type { ScanJobRow } from './scans.ts';

const { dnsObservations, domains, registrationObservations, scanJobs } = schema;

/**
 * Observation ingestion (design §5.8). Observations are evidence submitted by the worker with job
 * results; they are stored as-is (idempotently, keyed by a deterministic result id) and never
 * create, change or resolve findings here — that is the rules engine's job (Milestone 7).
 */

/** Clock sanity: the worker's observedAt may lead the server clock a little, never by much. */
export const OBSERVATION_MAX_FUTURE_MS = 5 * 60 * 1000;
export const OBSERVATION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

export interface JobTargetRef {
  id: string;
  assetId: string | null;
  targetHostname: string;
}

export interface ObservationCounts {
  dns: number;
  registration: number;
}

const invalid = (index: number, field: string, message: string) =>
  new ApiError(400, 'validation_failed', 'An observation is invalid.', [
    { path: `observations.${index}.${field}`, message },
  ]);

/** Pure validation; throws a 400 naming the first offending observation. */
function validate(
  snapshotDomainFqdn: string,
  targetsById: ReadonlyMap<string, JobTargetRef>,
  observations: readonly Observation[],
  now: Date,
): void {
  const latest = now.getTime() + OBSERVATION_MAX_FUTURE_MS;
  const earliest = now.getTime() - OBSERVATION_MAX_AGE_MS;
  observations.forEach((o, i) => {
    const target = targetsById.get(o.targetId);
    if (!target) throw invalid(i, 'targetId', 'The target is not part of this job.');
    const observedAt = Date.parse(o.observedAt);
    if (!(observedAt <= latest && observedAt >= earliest)) {
      throw invalid(i, 'observedAt', 'The observation time is outside the accepted window.');
    }
    if (o.kind === 'dns') {
      if (!isWithinDomain(o.hostname, snapshotDomainFqdn)) {
        throw invalid(i, 'hostname', "The hostname is not within this job's domain.");
      }
    } else if (target.targetHostname !== snapshotDomainFqdn) {
      throw invalid(i, 'targetId', 'Registration observations are accepted for the apex only.');
    }
  });
}

/**
 * Validates and stores observations for a newly accepted result submission. Must run inside the
 * submission's transaction, after its `scan_job_results` row was inserted (duplicates store nothing).
 */
export async function ingestObservations(
  tx: Database,
  job: ScanJobRow,
  snapshotDomainFqdn: string,
  targetsById: ReadonlyMap<string, JobTargetRef>,
  observations: readonly Observation[],
  resultId: string,
  now: Date,
): Promise<ObservationCounts> {
  if (observations.length === 0) return { dns: 0, registration: 0 };
  validate(snapshotDomainFqdn, targetsById, observations, now);

  const common = (o: Observation, index: number) => {
    const target = targetsById.get(o.targetId) as JobTargetRef;
    return {
      // Deterministic: a retried batch maps onto the same rows.
      resultId: `${job.id}:${resultId}:${index}`,
      assetId: target.assetId,
      scanJobId: job.id,
      scanJobTargetId: target.id,
      observedAt: new Date(o.observedAt),
      checkerVersion: o.checkerVersion,
      resultStatus: o.resultStatus,
      evidence: o.evidence,
    };
  };

  const dnsRows = observations.flatMap((o, i) =>
    o.kind === 'dns'
      ? [
          {
            ...common(o, i),
            checker: 'dns',
            hostname: o.hostname,
            recordType: o.recordType,
            ttl: o.ttl,
            recordValues: o.values,
          },
        ]
      : [],
  );
  // Registration data is stored against the job's domain; a deleted domain has nothing to update.
  const domainId = job.domainId;
  const registration = observations.flatMap((o, i) =>
    o.kind === 'registration' ? [{ o, i }] : [],
  );
  const registrationRows = domainId
    ? registration.map(({ o, i }) => ({
        ...common(o, i),
        checker: 'rdap',
        domainId,
        registrar: o.registrar,
        registeredAt: o.registeredAt ? new Date(o.registeredAt) : null,
        expiresAt: o.expiresAt ? new Date(o.expiresAt) : null,
        nameservers: o.nameservers,
        dataStatus: o.dataStatus,
      }))
    : [];

  let dns = 0;
  if (dnsRows.length > 0) {
    dns = (
      await tx
        .insert(dnsObservations)
        .values(dnsRows)
        .onConflictDoNothing({ target: dnsObservations.resultId })
        .returning({ id: dnsObservations.id })
    ).length;
  }

  let reg = 0;
  if (domainId && registrationRows.length > 0) {
    // Read the newest applied registration observation before inserting this batch.
    const [prior] = await tx
      .select({ at: max(registrationObservations.observedAt) })
      .from(registrationObservations)
      .where(
        and(
          eq(registrationObservations.domainId, domainId),
          eq(registrationObservations.resultStatus, 'success'),
        ),
      );
    reg = (
      await tx
        .insert(registrationObservations)
        .values(registrationRows)
        .onConflictDoNothing({ target: registrationObservations.resultId })
        .returning({ id: registrationObservations.id })
    ).length;
    await applyRegistration(
      tx,
      domainId,
      registration.map(({ o }) => o),
      prior?.at ?? null,
    );
  }
  return { dns, registration: reg };
}

/** Copies the newest successful registration observation onto the domain, never regressing it. */
async function applyRegistration(
  tx: Database,
  domainId: string,
  observations: RegistrationObservation[],
  appliedAt: Date | null,
): Promise<void> {
  const newest = observations
    .filter((o) => o.resultStatus === 'success')
    .reduce<RegistrationObservation | null>(
      (best, o) => (!best || Date.parse(o.observedAt) > Date.parse(best.observedAt) ? o : best),
      null,
    );
  if (!newest) return;
  if (appliedAt && Date.parse(newest.observedAt) <= appliedAt.getTime()) return;
  await tx
    .update(domains)
    .set(
      newest.dataStatus === 'unavailable'
        ? // No data obtained: record that, but keep what we knew.
          { registrationDataStatus: 'unavailable' }
        : {
            registrationDataStatus: newest.dataStatus,
            registrar: newest.registrar,
            registeredAt: newest.registeredAt ? new Date(newest.registeredAt) : null,
            expiresAt: newest.expiresAt ? new Date(newest.expiresAt) : null,
          },
    )
    .where(eq(domains.id, domainId));
}

// --- Read model ---------------------------------------------------------------------------------

export const MAX_DNS_RECORD_SETS = 500;
const recordTypeOrder = new Map<string, number>(DNS_RECORD_TYPES.map((t, i) => [t, i]));

/** Latest observation per (hostname, record type) and the latest registration observation. */
export async function domainObservations(
  db: Database,
  domainId: string,
): Promise<DomainObservationsResponse> {
  const dnsRows = await db
    .selectDistinctOn([dnsObservations.hostname, dnsObservations.recordType], {
      hostname: dnsObservations.hostname,
      recordType: dnsObservations.recordType,
      ttl: dnsObservations.ttl,
      values: dnsObservations.recordValues,
      resultStatus: dnsObservations.resultStatus,
      observedAt: dnsObservations.observedAt,
      scanJobId: dnsObservations.scanJobId,
    })
    .from(dnsObservations)
    .innerJoin(scanJobs, eq(scanJobs.id, dnsObservations.scanJobId))
    .where(eq(scanJobs.domainId, domainId))
    .orderBy(
      asc(dnsObservations.hostname),
      asc(dnsObservations.recordType),
      desc(dnsObservations.observedAt),
      desc(dnsObservations.id),
    )
    .limit(MAX_DNS_RECORD_SETS);

  const dns = dnsRows
    .filter((r) => recordTypeOrder.has(r.recordType))
    .map((r) => ({
      hostname: r.hostname,
      recordType: r.recordType as DnsObservation['recordType'],
      ttl: r.ttl,
      values: r.values,
      resultStatus: r.resultStatus,
      observedAt: r.observedAt.toISOString(),
      scanJobId: r.scanJobId,
    }))
    .sort(
      (a, b) =>
        (a.hostname < b.hostname ? -1 : a.hostname > b.hostname ? 1 : 0) ||
        (recordTypeOrder.get(a.recordType) ?? 0) - (recordTypeOrder.get(b.recordType) ?? 0),
    );

  const [reg] = await db
    .select()
    .from(registrationObservations)
    .where(eq(registrationObservations.domainId, domainId))
    .orderBy(desc(registrationObservations.observedAt), desc(registrationObservations.id))
    .limit(1);

  return {
    dns,
    registration: reg
      ? {
          registrar: reg.registrar,
          registeredAt: reg.registeredAt?.toISOString() ?? null,
          expiresAt: reg.expiresAt?.toISOString() ?? null,
          nameservers: reg.nameservers,
          dataStatus: reg.dataStatus === 'unknown' ? 'unavailable' : reg.dataStatus,
          resultStatus: reg.resultStatus,
          observedAt: reg.observedAt.toISOString(),
          scanJobId: reg.scanJobId,
        }
      : null,
  };
}
