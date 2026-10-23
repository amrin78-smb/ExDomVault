import { schema, type Database } from '@exdomainvault/database';
import {
  DNS_RECORD_TYPES,
  classifyHosting,
  type DiscoveryObservation,
  type DnsObservation,
  type DomainObservationsResponse,
  type HttpSnapshot,
  type Observation,
  type PortSnapshot,
  type RegistrationObservation,
  type ScanCheck,
  type ScopeSnapshot,
  type TlsSnapshot,
} from '@exdomainvault/shared';
import { isValidHostname, isWithinDomain } from '@exdomainvault/shared/hostname';
import { canonicalIp, cidrContains, isProhibitedAddress } from '@exdomainvault/shared/net';
import { and, asc, desc, eq, inArray, max, sql } from 'drizzle-orm';
import { ApiError } from '../lib/errors.ts';
import { activeNetworkCidrs, intersectNetworks } from './networks.ts';
import type { ScanJobRow } from './scans.ts';

const {
  assetIps,
  assets,
  discoveryObservations,
  dnsObservations,
  domains,
  httpObservations,
  portObservations,
  registrationObservations,
  scanJobs,
  tlsObservations,
} = schema;

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
  discovery: number;
  dns: number;
  registration: number;
  tls: number;
  http: number;
  port: number;
}

export const EMPTY_OBSERVATION_COUNTS: ObservationCounts = Object.freeze({
  discovery: 0,
  dns: 0,
  registration: 0,
  tls: 0,
  http: 0,
  port: 0,
});

/** Checks that may produce each active observation kind (the profile must list one of them). */
const CHECKS_FOR_KIND: Record<'http' | 'port', readonly ScanCheck[]> = {
  http: ['http_availability', 'http_headers'],
  port: ['tcp_ports', 'service_identification'],
};

/**
 * Strict `http(s)://host[:port][/path]` parser. Deliberately not WHATWG `URL`, which would rewrite
 * alternative encodings (e.g. `http://0x7f.1/` → `127.0.0.1`) instead of rejecting them. No userinfo,
 * no IP literals, lowercase LDH A-label hostnames only (each label 1–63 chars, no empty labels).
 */
const URL_RE = /^(https?):\/\/([a-z0-9.-]{1,253})(?::([1-9][0-9]{0,4}))?(\/[\x21-\x7e]*)?$/;

export function parseObservationUrl(
  url: string,
): { scheme: 'http' | 'https'; host: string; port: number | null } | null {
  const m = URL_RE.exec(url);
  if (!m || !isValidHostname(m[2] as string)) return null;
  const port = m[3] ? Number(m[3]) : null;
  if (port !== null && port > 65535) return null;
  return { scheme: m[1] as 'http' | 'https', host: m[2] as string, port };
}

/** Any absolute http(s) URL without whitespace or control characters (redirect stopping point). */
const LOOSE_URL_RE = /^https?:\/\/[\x21-\x7e]+$/;

const invalid = (index: number, field: string, message: string) =>
  new ApiError(400, 'validation_failed', 'An observation is invalid.', [
    { path: `observations.${index}.${field}`, message },
  ]);

/**
 * Pure validation; throws a 400 naming the first offending observation. `networks` is the job's
 * effective approved networks (snapshot ∩ currently active).
 */
function validate(
  job: ScanJobRow,
  snapshot: ScopeSnapshot,
  networks: readonly string[],
  targetsById: ReadonlyMap<string, JobTargetRef>,
  observations: readonly Observation[],
  now: Date,
): void {
  const snapshotDomainFqdn = snapshot.domain.fqdn;
  const config = snapshot.profile.config;
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
      return;
    }
    if (o.kind === 'registration') {
      if (target.targetHostname !== snapshotDomainFqdn) {
        throw invalid(i, 'targetId', 'Registration observations are accepted for the apex only.');
      }
      return;
    }
    if (o.kind === 'discovery') {
      // Passive discovery only from a discovery job whose (immutable) profile lists the check.
      if (job.jobType !== 'discovery' || !config.checks.includes('discovery')) {
        throw invalid(i, 'kind', "This job's scan profile does not include this check.");
      }
      // CT data is untrusted: the exact label boundary is re-checked here, whatever the worker did.
      if (!isWithinDomain(o.hostname, snapshotDomainFqdn)) {
        throw invalid(i, 'hostname', "The hostname is not within this job's domain.");
      }
      return;
    }

    // Active observations: only for an active profile that lists a producing check.
    const producing = o.kind === 'tls' ? [o.check] : CHECKS_FOR_KIND[o.kind];
    if (!config.active || !producing.some((c) => config.checks.includes(c))) {
      throw invalid(i, 'kind', "This job's scan profile does not include this check.");
    }
    if (isProhibitedAddress(o.ipAddress)) {
      throw invalid(i, 'ipAddress', 'The address is not a public unicast address.');
    }
    if (o.kind === 'tls') {
      // The SNI name must be the target's own (approved) hostname, not merely any name in the domain.
      if (o.hostname !== target.targetHostname || !isWithinDomain(o.hostname, snapshotDomainFqdn)) {
        throw invalid(i, 'hostname', "The hostname is not this observation's target.");
      }
      // Protocol probing is network tier: only inside the job's approved networks.
      if (o.check === 'tls_configuration' && !networks.some((n) => cidrContains(n, o.ipAddress))) {
        throw invalid(i, 'ipAddress', "The address is outside this job's approved networks.");
      }
    } else if (o.kind === 'http') {
      const url = parseObservationUrl(o.url);
      if (!url) throw invalid(i, 'url', 'The URL is not a plain http(s) URL.');
      if (url.host !== target.targetHostname || !isWithinDomain(url.host, snapshotDomainFqdn)) {
        throw invalid(i, 'url', "The URL's host is not this observation's target.");
      }
      if (o.finalUrl !== null && !LOOSE_URL_RE.test(o.finalUrl)) {
        throw invalid(i, 'finalUrl', 'The final URL is not an http(s) URL.');
      }
    } else {
      if (!config.tcpPorts.includes(o.port)) {
        throw invalid(i, 'port', "The port is not in this job's scan profile.");
      }
      if (!networks.some((n) => cidrContains(n, o.ipAddress))) {
        throw invalid(i, 'ipAddress', "The address is outside this job's approved networks.");
      }
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
  snapshot: ScopeSnapshot,
  targetsById: ReadonlyMap<string, JobTargetRef>,
  observations: readonly Observation[],
  resultId: string,
  now: Date,
): Promise<ObservationCounts> {
  if (observations.length === 0) return EMPTY_OBSERVATION_COUNTS;
  // Network-tier observations are checked against the networks the job may still probe right now.
  const needsNetworks = observations.some(
    (o) => o.kind === 'port' || (o.kind === 'tls' && o.check === 'tls_configuration'),
  );
  const networks =
    needsNetworks && snapshot.approvedNetworks.length > 0
      ? intersectNetworks(snapshot.approvedNetworks, await activeNetworkCidrs(tx, now))
      : [];
  validate(job, snapshot, networks, targetsById, observations, now);

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

  // Addresses are stored in canonical form (validated above, so canonicalIp never fails).
  const ip = (text: string) => canonicalIp(text) ?? text;
  const tlsRows = observations.flatMap((o, i) =>
    o.kind === 'tls'
      ? [
          {
            ...common(o, i),
            // Which TLS check produced it; server-set, so the worker cannot mislabel it.
            evidence: { ...o.evidence, check: o.check },
            checker: 'tls',
            hostname: o.hostname,
            ipAddress: ip(o.ipAddress),
            port: o.port,
            protocolVersion: o.protocolVersion,
            notBefore: o.notBefore ? new Date(o.notBefore) : null,
            notAfter: o.notAfter ? new Date(o.notAfter) : null,
            issuer: o.issuer,
            subject: o.subject,
            subjectAltNames: o.subjectAltNames,
            fingerprintSha256: o.fingerprintSha256,
            hostnameMatches: o.hostnameMatches,
          },
        ]
      : [],
  );
  const httpRows = observations.flatMap((o, i) =>
    o.kind === 'http'
      ? [
          {
            ...common(o, i),
            checker: 'http',
            url: o.url,
            ipAddress: ip(o.ipAddress),
            statusCode: o.statusCode,
            finalUrl: o.finalUrl,
            redirectCount: o.redirectCount,
            hstsEnabled: o.hstsEnabled,
          },
        ]
      : [],
  );
  const portRows = observations.flatMap((o, i) =>
    o.kind === 'port'
      ? [
          {
            ...common(o, i),
            checker: 'port',
            ipAddress: ip(o.ipAddress),
            port: o.port,
            protocol: o.protocol,
            state: o.state,
            service: o.service,
          },
        ]
      : [],
  );

  let tls = 0;
  if (tlsRows.length > 0) {
    tls = (
      await tx
        .insert(tlsObservations)
        .values(tlsRows)
        .onConflictDoNothing({ target: tlsObservations.resultId })
        .returning({ id: tlsObservations.id })
    ).length;
  }
  let http = 0;
  if (httpRows.length > 0) {
    http = (
      await tx
        .insert(httpObservations)
        .values(httpRows)
        .onConflictDoNothing({ target: httpObservations.resultId })
        .returning({ id: httpObservations.id })
    ).length;
  }
  let port = 0;
  if (portRows.length > 0) {
    port = (
      await tx
        .insert(portObservations)
        .values(portRows)
        .onConflictDoNothing({ target: portObservations.resultId })
        .returning({ id: portObservations.id })
    ).length;
  }

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

  let discovery = 0;
  if (domainId) {
    discovery = await ingestDiscovery(
      tx,
      domainId,
      snapshot.domain.fqdn,
      observations.flatMap((o, i) =>
        o.kind === 'discovery' ? [{ o, row: { ...common(o, i), checker: 'discovery' } }] : [],
      ),
    );
    // After discovery, so candidates resolved in the same batch get their addresses.
    await applyDnsToAssets(
      tx,
      domainId,
      observations.flatMap((o) => (o.kind === 'dns' ? [o] : [])),
    );
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
  return { discovery, dns, registration: reg, tls, http, port };
}

// --- Discovery and DNS → asset inventory ----------------------------------------------------------

type ObservationRowBase = {
  resultId: string;
  assetId: string | null;
  scanJobId: string;
  scanJobTargetId: string;
  observedAt: Date;
  checker: string;
  checkerVersion: string;
  resultStatus: Observation['resultStatus'];
  evidence: Record<string, unknown>;
};

/**
 * Stores discovery observations and upserts their SUCCESSFUL hostnames as assets, set-based (one
 * upsert + one insert per batch). New hostnames become `pending` candidates; existing assets only
 * have `last_seen_at` advanced and `wildcard_only` narrowed. Ingestion never changes an asset's
 * approval status, so CT data can never put a hostname into scan scope. Failed/partial runs are
 * stored as evidence only.
 */
async function ingestDiscovery(
  tx: Database,
  domainId: string,
  fqdn: string,
  items: { o: DiscoveryObservation; row: ObservationRowBase }[],
): Promise<number> {
  if (items.length === 0) return 0;
  // Aggregate per hostname: one statement cannot touch the same row twice.
  const candidates = new Map<string, { first: Date; last: Date; wildcard: boolean }>();
  for (const { o, row } of items) {
    if (o.resultStatus !== 'success') continue;
    const at = row.observedAt;
    const c = candidates.get(o.hostname);
    if (!c) candidates.set(o.hostname, { first: at, last: at, wildcard: o.wildcard });
    else {
      if (at < c.first) c.first = at;
      if (at > c.last) c.last = at;
      c.wildcard = c.wildcard && o.wildcard;
    }
  }
  const assetIdOf = new Map<string, string>();
  if (candidates.size > 0) {
    const upserted = await tx
      .insert(assets)
      .values(
        [...candidates].map(([hostname, c]) => ({
          domainId,
          hostname,
          assetType: hostname === fqdn ? ('apex' as const) : ('subdomain' as const),
          discoverySource: 'certificate_transparency' as const,
          firstSeenAt: c.first,
          lastSeenAt: c.last,
          wildcardOnly: c.wildcard,
        })),
      )
      .onConflictDoUpdate({
        target: [assets.domainId, assets.hostname],
        set: {
          lastSeenAt: sql`greatest(${assets.lastSeenAt}, excluded.last_seen_at)`,
          wildcardOnly: sql`${assets.wildcardOnly} and excluded.wildcard_only`,
        },
      })
      .returning({ id: assets.id, hostname: assets.hostname });
    for (const a of upserted) assetIdOf.set(a.hostname, a.id);
  }
  const inserted = await tx
    .insert(discoveryObservations)
    .values(
      items.map(({ o, row }) => ({
        ...row,
        assetId: assetIdOf.get(o.hostname) ?? row.assetId,
        domainId,
        hostname: o.hostname,
        source: o.source,
        wildcard: o.wildcard,
      })),
    )
    .onConflictDoNothing({ target: discoveryObservations.resultId })
    .returning({ id: discoveryObservations.id });
  return inserted.length;
}

const ipFamily = (canonical: string) => (canonical.includes(':') ? 6 : 4);

/**
 * Keeps the inventory's DNS view current from successful observations of the domain's asset
 * hostnames (any job type), set-based:
 *  - A/AAAA: each address is upserted into `asset_ips` (last seen advanced); every other address of
 *    the same family last seen before the newest answer stops being current (an empty answer leaves
 *    none current);
 *  - CNAME: `hosting_hint` is recomputed from the newest answer's targets (`classifyHosting`; an
 *    empty answer clears it). Hostnames without a CNAME observation keep their hint.
 */
async function applyDnsToAssets(
  tx: Database,
  domainId: string,
  observations: readonly DnsObservation[],
): Promise<void> {
  const relevant = observations.filter(
    (o) =>
      o.resultStatus === 'success' &&
      (o.recordType === 'A' || o.recordType === 'AAAA' || o.recordType === 'CNAME'),
  );
  if (relevant.length === 0) return;
  const hostnames = [...new Set(relevant.map((o) => o.hostname))];
  const known = await tx
    .select({ id: assets.id, hostname: assets.hostname })
    .from(assets)
    .where(and(eq(assets.domainId, domainId), inArray(assets.hostname, hostnames)));
  if (known.length === 0) return;
  const assetIdOf = new Map(known.map((a) => [a.hostname, a.id]));

  // Addresses: (asset, ip) → first/last seen; (asset, family) → newest answer time.
  const ips = new Map<string, { assetId: string; ip: string; first: Date; last: Date }>();
  const answers = new Map<string, { assetId: string; family: number; at: Date }>();
  // CNAME: newest answer per asset.
  const cnames = new Map<string, { at: Date; values: readonly string[] }>();
  for (const o of relevant) {
    const assetId = assetIdOf.get(o.hostname);
    if (!assetId) continue;
    const at = new Date(o.observedAt);
    if (o.recordType === 'CNAME') {
      const prev = cnames.get(assetId);
      if (!prev || at >= prev.at) cnames.set(assetId, { at, values: o.values });
      continue;
    }
    const family = o.recordType === 'A' ? 4 : 6;
    const key = `${assetId}|${family}`;
    const prev = answers.get(key);
    if (!prev || at > prev.at) answers.set(key, { assetId, family, at });
    for (const value of o.values) {
      const ip = canonicalIp(value);
      if (!ip || ipFamily(ip) !== family) continue; // not an address of the queried type
      const k = `${assetId}|${ip}`;
      const seen = ips.get(k);
      if (!seen) ips.set(k, { assetId, ip, first: at, last: at });
      else {
        if (at < seen.first) seen.first = at;
        if (at > seen.last) seen.last = at;
      }
    }
  }

  if (ips.size > 0) {
    await tx
      .insert(assetIps)
      .values(
        [...ips.values()].map((r) => ({
          assetId: r.assetId,
          ipAddress: r.ip,
          firstSeenAt: r.first,
          lastSeenAt: r.last,
          isCurrent: true,
          source: 'dns',
        })),
      )
      .onConflictDoUpdate({
        target: [assetIps.assetId, assetIps.ipAddress],
        set: {
          lastSeenAt: sql`greatest(${assetIps.lastSeenAt}, excluded.last_seen_at)`,
          // Provisional: the statement below keeps only the newest answer's addresses current.
          isCurrent: true,
        },
      });
  }
  if (answers.size > 0) {
    const rows = sql.join(
      [...answers.values()].map(
        (a) => sql`(${a.assetId}::uuid, ${a.family}::int, ${a.at.toISOString()}::timestamptz)`,
      ),
      sql`, `,
    );
    // Addresses of an answered family last seen before the newest answer known for it (this batch's
    // or a later one already stored) are no longer current, so an out-of-order older answer revives
    // nothing.
    await tx.execute(sql`
      update asset_ips set is_current = false
      from (values ${rows}) as v(asset_id, family, at)
      where asset_ips.asset_id = v.asset_id
        and family(asset_ips.ip_address) = v.family
        and asset_ips.is_current
        and asset_ips.last_seen_at < greatest(v.at, (
          select max(x.last_seen_at) from asset_ips x
          where x.asset_id = v.asset_id and family(x.ip_address) = v.family
        ))`);
  }
  if (cnames.size > 0) {
    const rows = sql.join(
      [...cnames].map(([assetId, c]) => {
        const hint = classifyHosting(c.values);
        return sql`(${assetId}::uuid, ${hint ? JSON.stringify(hint) : null}::jsonb)`;
      }),
      sql`, `,
    );
    await tx.execute(sql`
      update assets set hosting_hint = v.hint, updated_at = now()
      from (values ${rows}) as v(id, hint)
      where assets.id = v.id`);
  }
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

  const [tls, http, ports] = await Promise.all([
    latestTls(db, domainId),
    latestHttp(db, domainId),
    latestPorts(db, domainId),
  ]);

  return {
    dns,
    tls,
    http,
    ports,
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

export const MAX_ACTIVE_OBSERVATIONS = 500;

const readCommon = (r: {
  resultStatus: TlsSnapshot['resultStatus'];
  observedAt: Date;
  scanJobId: string;
  evidence: Record<string, unknown>;
}) => ({
  resultStatus: r.resultStatus,
  observedAt: r.observedAt.toISOString(),
  scanJobId: r.scanJobId,
  evidence: r.evidence,
});

const displayIp = (v: string | null) => (v === null ? '' : (canonicalIp(v) ?? v));

/** Latest TLS observation per (hostname, ip, port) for the domain's jobs. */
async function latestTls(db: Database, domainId: string): Promise<TlsSnapshot[]> {
  const t = tlsObservations;
  const rows = await db
    .selectDistinctOn([t.hostname, t.ipAddress, t.port], { o: t })
    .from(t)
    .innerJoin(scanJobs, eq(scanJobs.id, t.scanJobId))
    .where(eq(scanJobs.domainId, domainId))
    .orderBy(asc(t.hostname), asc(t.ipAddress), asc(t.port), desc(t.observedAt), desc(t.id))
    .limit(MAX_ACTIVE_OBSERVATIONS);
  return rows.map(({ o }) => ({
    hostname: o.hostname,
    ipAddress: displayIp(o.ipAddress),
    port: o.port,
    protocolVersion: o.protocolVersion,
    notBefore: o.notBefore?.toISOString() ?? null,
    notAfter: o.notAfter?.toISOString() ?? null,
    issuer: o.issuer,
    subject: o.subject,
    subjectAltNames: o.subjectAltNames,
    fingerprintSha256: o.fingerprintSha256,
    hostnameMatches: o.hostnameMatches,
    ...readCommon(o),
  }));
}

/** Latest HTTP observation per first URL for the domain's jobs. */
async function latestHttp(db: Database, domainId: string): Promise<HttpSnapshot[]> {
  const t = httpObservations;
  const rows = await db
    .selectDistinctOn([t.url], { o: t })
    .from(t)
    .innerJoin(scanJobs, eq(scanJobs.id, t.scanJobId))
    .where(eq(scanJobs.domainId, domainId))
    .orderBy(asc(t.url), desc(t.observedAt), desc(t.id))
    .limit(MAX_ACTIVE_OBSERVATIONS);
  return rows.map(({ o }) => ({
    url: o.url,
    ipAddress: displayIp(o.ipAddress),
    statusCode: o.statusCode,
    finalUrl: o.finalUrl,
    redirectCount: o.redirectCount,
    hstsEnabled: o.hstsEnabled,
    ...readCommon(o),
  }));
}

/** Latest port state per (ip, port) for the domain's jobs. */
async function latestPorts(db: Database, domainId: string): Promise<PortSnapshot[]> {
  const t = portObservations;
  const rows = await db
    .selectDistinctOn([t.ipAddress, t.port], { o: t })
    .from(t)
    .innerJoin(scanJobs, eq(scanJobs.id, t.scanJobId))
    .where(eq(scanJobs.domainId, domainId))
    .orderBy(asc(t.ipAddress), asc(t.port), desc(t.observedAt), desc(t.id))
    .limit(MAX_ACTIVE_OBSERVATIONS);
  return rows.map(({ o }) => ({
    ipAddress: displayIp(o.ipAddress),
    port: o.port,
    protocol: o.protocol,
    state: o.state as PortSnapshot['state'],
    service: o.service,
    ...readCommon(o),
  }));
}
