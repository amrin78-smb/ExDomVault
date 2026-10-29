import { schema, type Database } from '@exdomainvault/database';
import {
  DISCOVERY_ORG_NAMES_SETTING_KEY,
  orgNameMatches,
  type CurrentUser,
  type DiscoveredNetwork,
  type DiscoveredNetworksResponse,
  type DiscoverySettings,
  type DiscoverySettingsResponse,
  type HostingOrgSummary,
  type NetworkJobContext,
  type NetworkObservation,
  type ScopeSnapshot,
} from '@exdomainvault/shared';
import { canonicalIp, isProhibitedAddress, parseCidr, parseIp } from '@exdomainvault/shared/net';
import { eq, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { ApiError } from '../lib/errors.ts';
import { writeAudit } from './audit.ts';
import type { Actor } from './domains.ts';
import { validateNetwork } from './networks.ts';
import type { JobTargetRef } from './observations.ts';
import type { ScanJobRow } from './scans.ts';

const { applicationSettings, networkObservations } = schema;

/**
 * Milestone 15 — wider discovery, server side:
 *  - the organisation-name setting (`discovery_org_names`), read by the claim (job context) and
 *    by ingestion/listing (matching);
 *  - the `network` job context: the domain's current public addresses, computed at claim time;
 *  - ingestion of `network` observations (matchedOrg re-computed against the current setting —
 *    the worker's value is never trusted);
 *  - `GET /networks/discovered`: latest view per network, matched vs other hosting.
 * Network ownership is display/discovery only: nothing here grants scan scope. A matched network
 * can be proposed to the EXISTING approved-networks flow, where an administrator decides.
 */

type User = Pick<CurrentUser, 'id' | 'role'>;

/** Addresses sent to the worker per job (the worker caps at the same number). */
export const NETWORK_JOB_MAX_ADDRESSES = 256;
/** Networks considered by the listing (latest per network). */
export const DISCOVERED_NETWORKS_LIMIT = 2000;
export const HOSTING_SUMMARY_LIMIT = 10;

const orgNamesValue = z.array(z.string());

async function rowsOf<T>(db: Database, query: SQL): Promise<T[]> {
  const res = (await db.execute(query)) as unknown as { rows: T[] };
  return res.rows;
}

// --- Setting --------------------------------------------------------------------------------------

async function readSetting(db: Database) {
  const [row] = await db
    .select()
    .from(applicationSettings)
    .where(eq(applicationSettings.key, DISCOVERY_ORG_NAMES_SETTING_KEY));
  return row ?? null;
}

/** The configured organisation names; a missing or malformed value means none (matches nothing). */
export async function readOrgNames(db: Database): Promise<string[]> {
  const row = await readSetting(db);
  const parsed = orgNamesValue.safeParse(row?.value);
  return parsed.success ? parsed.data : [];
}

export async function getDiscoverySettings(db: Database): Promise<DiscoverySettingsResponse> {
  const row = await readSetting(db);
  const parsed = orgNamesValue.safeParse(row?.value);
  return {
    orgNames: parsed.success ? parsed.data : [],
    updatedAt: row ? row.updatedAt.toISOString() : null,
  };
}

/** PUT /settings/discovery (admin): replaces the organisation names; audited with before/after. */
export async function updateDiscoverySettings(
  db: Database,
  input: DiscoverySettings,
  actor: Actor,
  now: Date,
): Promise<void> {
  await db.transaction(async (tx) => {
    const [existing] = await tx
      .select()
      .from(applicationSettings)
      .where(eq(applicationSettings.key, DISCOVERY_ORG_NAMES_SETTING_KEY))
      .for('update');
    const value = input.orgNames;
    await tx
      .insert(applicationSettings)
      .values({
        key: DISCOVERY_ORG_NAMES_SETTING_KEY,
        value,
        updatedBy: actor.userId,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: applicationSettings.key,
        set: { value, updatedBy: actor.userId, updatedAt: now },
      });
    await writeAudit(tx as unknown as Database, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'settings.discovery_updated',
      resourceType: 'application_setting',
      requestId: actor.requestId,
      metadata: {
        key: DISCOVERY_ORG_NAMES_SETTING_KEY,
        before: existing?.value ?? null,
        after: value,
      },
    });
  });
}

// --- Job context ----------------------------------------------------------------------------------

/**
 * What the `network` check needs, computed at claim time: the organisation names and the distinct
 * current PUBLIC addresses of the domain's approved assets (sorted, at most
 * `NETWORK_JOB_MAX_ADDRESSES`). These are looked up in RDAP registries; they never become targets.
 */
export async function networkJobContext(
  db: Database,
  domainId: string,
): Promise<NetworkJobContext> {
  const rows = await rowsOf<{ ip: string }>(
    db,
    sql`select distinct host(ai.ip_address) as ip
        from asset_ips ai join assets a on a.id = ai.asset_id
        where a.domain_id = ${domainId} and a.verification_status = 'approved' and ai.is_current
        order by 1
        limit ${NETWORK_JOB_MAX_ADDRESSES * 2}`,
  );
  const addresses = rows
    .map((r) => canonicalIp(r.ip))
    .filter((ip): ip is string => ip !== null && !isProhibitedAddress(ip))
    .slice(0, NETWORK_JOB_MAX_ADDRESSES);
  return { orgNames: await readOrgNames(db), addresses };
}

// --- Ingestion ------------------------------------------------------------------------------------

const invalid = (index: number, field: string, message: string) =>
  new ApiError(400, 'validation_failed', 'An observation is invalid.', [
    { path: `observations.${index}.${field}`, message },
  ]);

/**
 * Pure validation of one `network` observation (called from `observations.ts`): only from a
 * discovery job whose immutable profile lists `network`, reported on the apex target; the address
 * (and range bounds) must be public unicast, the bounds of one family and ordered, every CIDR
 * well-formed. Registry data itself is untrusted display data.
 */
export function validateNetworkObservation(
  job: Pick<ScanJobRow, 'jobType'>,
  snapshot: ScopeSnapshot,
  target: JobTargetRef,
  o: NetworkObservation,
  i: number,
): void {
  if (job.jobType !== 'discovery' || !snapshot.profile.config.checks.includes('network')) {
    throw invalid(i, 'kind', "This job's scan profile does not include this check.");
  }
  if (target.targetHostname !== snapshot.domain.fqdn) {
    throw invalid(i, 'targetId', 'Network observations are accepted for the apex only.');
  }
  if (isProhibitedAddress(o.ipAddress)) {
    throw invalid(i, 'ipAddress', 'The address is not a public unicast address.');
  }
  if ((o.startAddress === null) !== (o.endAddress === null)) {
    throw invalid(i, 'endAddress', 'Give both ends of the range or neither.');
  }
  if (o.startAddress !== null && o.endAddress !== null) {
    const start = parseIp(canonicalIp(o.startAddress) ?? '');
    const end = parseIp(canonicalIp(o.endAddress) ?? '');
    const ip = parseIp(canonicalIp(o.ipAddress) ?? '');
    if (!start || !end || !ip || start.version !== end.version || start.value > end.value) {
      throw invalid(i, 'startAddress', 'The address range is invalid.');
    }
    if (ip.version !== start.version || ip.value < start.value || ip.value > end.value) {
      throw invalid(i, 'ipAddress', 'The address is outside the reported range.');
    }
  }
  o.cidrs.forEach((c, j) => {
    if (!parseCidr(c)) throw invalid(i, `cidrs.${j}`, 'The CIDR is invalid.');
  });
}

type ObservationRowBase = {
  resultId: string;
  assetId: string | null;
  scanJobId: string;
  scanJobTargetId: string;
  observedAt: Date;
  checker: string;
  checkerVersion: string;
  resultStatus: NetworkObservation['resultStatus'];
  evidence: Record<string, unknown>;
};

/** Candidate texts for matching: organisation, network name and `evidence.entityNames`. */
export function networkMatchCandidates(
  orgName: string | null,
  networkName: string | null,
  evidence: Record<string, unknown>,
): (string | null)[] {
  const raw = evidence.entityNames;
  const entityNames = Array.isArray(raw)
    ? raw.filter((v): v is string => typeof v === 'string').slice(0, 10)
    : [];
  return [orgName, networkName, ...entityNames];
}

/**
 * Stores `network` observations (validated by `observations.ts`). `matched_org` is re-computed
 * from the registry data against the CURRENT organisation names.
 */
export async function ingestNetworkObservations(
  tx: Database,
  domainId: string | null,
  items: { o: NetworkObservation; row: ObservationRowBase }[],
): Promise<number> {
  if (items.length === 0) return 0;
  const orgNames = await readOrgNames(tx);
  const ip = (text: string) => canonicalIp(text) ?? text;
  const inserted = await tx
    .insert(networkObservations)
    .values(
      items.map(({ o, row }) => ({
        ...row,
        checker: 'network',
        domainId,
        ipAddress: ip(o.ipAddress),
        startAddress: o.startAddress ? ip(o.startAddress) : null,
        endAddress: o.endAddress ? ip(o.endAddress) : null,
        cidrs: o.cidrs,
        registry: o.registry,
        handle: o.handle,
        networkName: o.networkName,
        orgName: o.orgName,
        country: o.country,
        matchedOrg:
          o.resultStatus === 'success' &&
          orgNameMatches(orgNames, networkMatchCandidates(o.orgName, o.networkName, o.evidence)),
      })),
    )
    .onConflictDoNothing({ target: networkObservations.resultId })
    .returning({ id: networkObservations.id });
  return inserted.length;
}

// --- Read model -----------------------------------------------------------------------------------

/** The first registered prefix the approved-networks form would accept, or null. */
export function proposedCidr(cidrs: readonly string[]): string | null {
  for (const cidr of cidrs) {
    try {
      return validateNetwork(cidr);
    } catch {
      // Too broad or not public: try the next prefix.
    }
  }
  return null;
}

interface NetworkRow {
  k: string;
  registry: string | null;
  handle: string | null;
  network_name: string | null;
  org_name: string | null;
  country: string | null;
  cidrs: string[] | string | null;
  ip: string;
  start_address: string | null;
  end_address: string | null;
  evidence: Record<string, unknown> | null;
  first_seen: string | Date;
  last_seen: string | Date;
}

const toIso = (v: string | Date) => (v instanceof Date ? v : new Date(v)).toISOString();

/** Postgres text[] may arrive as an array or (from some drivers) as a `{a,b}` literal. */
function textArray(v: string[] | string | null): string[] {
  if (Array.isArray(v)) return v;
  if (typeof v !== 'string' || v === '{}' || v === '') return [];
  return v
    .replace(/^\{|\}$/g, '')
    .split(',')
    .map((s) => s.replace(/^"|"$/g, ''));
}

/**
 * GET /networks/discovered: the latest successful observation per network (key: registry + handle,
 * else the address range, else the address), the current addresses of VISIBLE approved assets
 * inside each network (asset owners: their own assets only, and only networks containing one),
 * `matched` against the current organisation names, and a hosting summary of the other networks.
 */
export async function listDiscoveredNetworks(
  db: Database,
  user: User,
): Promise<DiscoveredNetworksResponse> {
  const scope =
    user.role === 'asset_owner'
      ? sql`a.verification_status = 'approved' and a.owner_user_id = ${user.id}`
      : sql`a.verification_status = 'approved'`;
  const [orgNames, networkRows, ipRows] = await Promise.all([
    readOrgNames(db),
    rowsOf<NetworkRow>(
      db,
      sql`with obs as (
            select coalesce(n.registry, '') || ':' || coalesce(
                     n.handle,
                     host(n.start_address) || '-' || host(n.end_address),
                     host(n.ip_address)
                   ) as k,
                   n.*
            from network_observations n
            where n.result_status = 'success'
          ),
          agg as (
            select k, min(observed_at) as first_seen, max(observed_at) as last_seen
            from obs group by k
          ),
          latest as (
            select distinct on (k) * from obs order by k, observed_at desc, id desc
          )
          select l.k, l.registry, l.handle, l.network_name, l.org_name, l.country, l.cidrs,
                 host(l.ip_address) as ip, host(l.start_address) as start_address,
                 host(l.end_address) as end_address, l.evidence, g.first_seen, g.last_seen
          from latest l join agg g on g.k = l.k
          order by g.last_seen desc, l.k
          limit ${DISCOVERED_NETWORKS_LIMIT}`,
    ),
    rowsOf<{ asset_id: string; hostname: string; ip: string }>(
      db,
      sql`select ai.asset_id, a.hostname, host(ai.ip_address) as ip
          from asset_ips ai join assets a on a.id = ai.asset_id
          where ai.is_current and ${scope}
          order by a.hostname, ai.ip_address`,
    ),
  ]);

  const ips = ipRows.flatMap((r) => {
    const parsed = parseIp(canonicalIp(r.ip) ?? r.ip);
    return parsed ? [{ ...r, parsed }] : [];
  });

  const networks: DiscoveredNetwork[] = [];
  /** Every visible asset inside each listed network (the response carries only ten). */
  const assetIdsOf = new Map<string, Set<string>>();
  for (const n of networkRows) {
    const start = n.start_address ? parseIp(n.start_address) : null;
    const end = n.end_address ? parseIp(n.end_address) : null;
    const single = parseIp(n.ip);
    const inside = ips.filter((r) =>
      start && end && start.version === end.version
        ? r.parsed.version === start.version &&
          r.parsed.value >= start.value &&
          r.parsed.value <= end.value
        : single !== null && r.parsed.version === single.version && r.parsed.value === single.value,
    );
    const evidence = n.evidence ?? {};
    const matched = orgNameMatches(
      orgNames,
      networkMatchCandidates(n.org_name, n.network_name, evidence),
    );
    // Asset owners see only networks that contain one of their assets; others also see matched
    // ranges without a current asset (owned space worth reviewing).
    if (inside.length === 0 && (user.role === 'asset_owner' || !matched)) continue;
    const assets = new Map<string, string>();
    for (const r of inside) if (!assets.has(r.asset_id)) assets.set(r.asset_id, r.hostname);
    assetIdsOf.set(n.k, new Set(assets.keys()));
    const cidrs = textArray(n.cidrs);
    networks.push({
      key: n.k,
      registry: n.registry,
      handle: n.handle,
      networkName: n.network_name,
      orgName: n.org_name,
      country: n.country,
      cidrs,
      startAddress: n.start_address,
      endAddress: n.end_address,
      matched,
      addresses: [...new Set(inside.map((r) => canonicalIp(r.ip) ?? r.ip))].slice(0, 50),
      assetCount: assets.size,
      assets: [...assets].slice(0, 10).map(([id, hostname]) => ({ id, hostname })),
      proposedCidr: proposedCidr(cidrs),
      firstSeenAt: toIso(n.first_seen),
      lastSeenAt: toIso(n.last_seen),
    });
  }

  const byOrg = new Map<string, { networks: number; assets: Set<string> }>();
  for (const n of networks) {
    if (n.matched) continue;
    const name = n.orgName ?? n.networkName ?? 'Unknown';
    const entry = byOrg.get(name) ?? { networks: 0, assets: new Set<string>() };
    entry.networks += 1;
    for (const id of assetIdsOf.get(n.key) ?? []) entry.assets.add(id);
    byOrg.set(name, entry);
  }
  const hosting: HostingOrgSummary[] = [...byOrg]
    .map(([orgName, e]) => ({ orgName, networks: e.networks, assetCount: e.assets.size }))
    .sort(
      (a, b) =>
        b.assetCount - a.assetCount ||
        b.networks - a.networks ||
        a.orgName.localeCompare(b.orgName),
    )
    .slice(0, HOSTING_SUMMARY_LIMIT);

  return {
    orgNames,
    matched: networks.filter((n) => n.matched),
    hosting,
    total: networks.length,
  };
}
