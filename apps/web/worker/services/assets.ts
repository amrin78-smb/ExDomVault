import { schema, type Database } from '@exdomainvault/database';
import { fingerprint } from '@exdomainvault/rules';
import {
  allowedAssetActions,
  hostingHintSchema,
  type Asset,
  type AssetBulkDecisionResponse,
  type AssetDetailResponse,
  type AssetListQuery,
  type AssetListResponse,
  type AssetStatus,
  type CurrentUser,
} from '@exdomainvault/shared';
import { canonicalIp } from '@exdomainvault/shared/net';
import {
  and,
  asc,
  count,
  desc,
  eq,
  ilike,
  inArray,
  isNotNull,
  isNull,
  ne,
  sql,
  type SQL,
} from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';
import { ApiError } from '../lib/errors.ts';
import { writeAuditMany, type AuditEntry } from './audit.ts';
import type { Actor } from './domains.ts';
import { stopActiveJobsForAssets } from './scans.ts';

const { assetIps, assets, discoveryObservations, domains, findingStatusHistory, findings, users } =
  schema;

/**
 * Asset inventory (design §5.4–5.5, §7, §10 Assets). Reads are visible to every role with
 * `assets:read`, except asset owners, who see only assets they own (others are 404). Decisions
 * (approve, reject, suspend) need `assets:approve`, follow `allowedAssetActions`, are audited in the
 * same transaction and resolve the hostname's active ASSET-001 finding at once. Everything is
 * set-based so a 500-asset bulk decision is a handful of statements.
 */

type AssetRow = typeof assets.$inferSelect;
type User = Pick<CurrentUser, 'id' | 'role'>;
type Action = 'approve' | 'reject' | 'suspend';

const notFound = () => new ApiError(404, 'not_found', 'The requested resource was not found.');
const iso = (d: Date | null) => (d ? d.toISOString() : null);
const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

/** Object-level visibility: asset owners see only their own assets. */
/**
 * 404 unless the domain exists and, for asset owners, they own at least one of its assets, so a
 * domain-scoped route never reveals whether another tenant's domain id exists.
 */
export async function assertDomainVisible(db: Database, user: User, domainId: string) {
  const [domain] = await db
    .select({ id: domains.id })
    .from(domains)
    .where(eq(domains.id, domainId));
  if (!domain) throw notFound();
  const visible = visibleAssets(user);
  if (visible) {
    const [own] = await db
      .select({ id: assets.id })
      .from(assets)
      .where(and(eq(assets.domainId, domainId), visible))
      .limit(1);
    if (!own) throw notFound();
  }
}

function visibleAssets(user: User): SQL | undefined {
  return user.role === 'asset_owner' ? eq(assets.ownerUserId, user.id) : undefined;
}

const decider = alias(users, 'decider');
const ownerUser = alias(users, 'owner_user');

/** Active (non-resolved) findings on the asset's hostname. */
const activeFindingCount = sql<number>`(
  select count(*)::int from ${findings}
  where ${findings.domainId} = ${assets.domainId}
    and ${findings.hostname} = ${assets.hostname}
    and ${findings.status} <> 'resolved'
)`;

const assetSelect = {
  a: assets,
  fqdn: domains.fqdn,
  deciderEmail: decider.email,
  ownerEmail: ownerUser.email,
  activeFindings: activeFindingCount,
};

function baseQuery(db: Database) {
  return db
    .select(assetSelect)
    .from(assets)
    .innerJoin(domains, eq(domains.id, assets.domainId))
    .leftJoin(decider, eq(decider.id, assets.decidedBy))
    .leftJoin(ownerUser, eq(ownerUser.id, assets.ownerUserId));
}

type JoinRow = {
  a: AssetRow;
  fqdn: string;
  deciderEmail: string | null;
  ownerEmail: string | null;
  activeFindings: number;
};

const displayIp = (v: string) => canonicalIp(v) ?? v;

async function currentIpsOf(db: Database, ids: string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  if (ids.length === 0) return out;
  const rows = await db
    .select({ assetId: assetIps.assetId, ip: assetIps.ipAddress })
    .from(assetIps)
    .where(and(inArray(assetIps.assetId, ids), eq(assetIps.isCurrent, true)))
    .orderBy(asc(assetIps.ipAddress));
  for (const r of rows) out.set(r.assetId, [...(out.get(r.assetId) ?? []), displayIp(r.ip)]);
  return out;
}

function toAssetDto(r: JoinRow, currentIps: string[]): Asset {
  const a = r.a;
  const hint = hostingHintSchema.safeParse(a.hostingHint);
  return {
    id: a.id,
    domain: { id: a.domainId, fqdn: r.fqdn },
    hostname: a.hostname,
    assetType: a.assetType,
    status: a.verificationStatus,
    source: a.discoverySource,
    firstSeenAt: a.firstSeenAt.toISOString(),
    lastSeenAt: a.lastSeenAt.toISOString(),
    currentIps,
    hostingHint: hint.success ? hint.data : null,
    wildcardOnly: a.wildcardOnly,
    owner: a.ownerUserId && r.ownerEmail ? { id: a.ownerUserId, email: r.ownerEmail } : null,
    decidedBy: a.decidedBy && r.deciderEmail ? { id: a.decidedBy, email: r.deciderEmail } : null,
    decidedAt: iso(a.decidedAt),
    decisionReason: a.decisionReason,
    activeFindings: Number(r.activeFindings),
  };
}

const SORTS: Record<AssetListQuery['sort'], SQL[]> = {
  hostname: [asc(assets.hostname), asc(assets.id)],
  '-lastSeenAt': [desc(assets.lastSeenAt), asc(assets.hostname), asc(assets.id)],
  '-firstSeenAt': [desc(assets.firstSeenAt), asc(assets.hostname), asc(assets.id)],
};

/**
 * GET /assets and GET /domains/:id/assets. `scopedDomainId` (the latter) must name an existing
 * domain; for an asset owner it must also hold at least one of their assets (404 otherwise, so the
 * endpoint does not reveal which domains exist).
 */
export async function listAssets(
  db: Database,
  user: User,
  q: AssetListQuery,
  scopedDomainId?: string,
): Promise<AssetListResponse> {
  const visible = visibleAssets(user);
  if (scopedDomainId) await assertDomainVisible(db, user, scopedDomainId);

  const filters: SQL[] = [];
  if (visible) filters.push(visible);
  if (q.domainId) filters.push(eq(assets.domainId, q.domainId));
  if (q.status) filters.push(eq(assets.verificationStatus, q.status));
  if (q.source) filters.push(eq(assets.discoverySource, q.source));
  if (q.thirdParty === 'true') filters.push(isNotNull(assets.hostingHint));
  if (q.thirdParty === 'false') filters.push(isNull(assets.hostingHint));
  if (q.q) filters.push(ilike(assets.hostname, `%${escapeLike(q.q.toLowerCase())}%`));
  const where = filters.length > 0 ? and(...filters) : undefined;

  const [rows, [total]] = await Promise.all([
    baseQuery(db)
      .where(where)
      .orderBy(...SORTS[q.sort])
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize),
    db.select({ n: count() }).from(assets).where(where),
  ]);
  const ips = await currentIpsOf(
    db,
    rows.map((r) => r.a.id),
  );
  return {
    items: rows.map((r) => toAssetDto(r, ips.get(r.a.id) ?? [])),
    page: q.page,
    pageSize: q.pageSize,
    total: total?.n ?? 0,
  };
}

async function visibleAsset(db: Database, user: User, id: string): Promise<JoinRow> {
  const visible = visibleAssets(user);
  const [row] = await baseQuery(db)
    .where(visible ? and(eq(assets.id, id), visible) : eq(assets.id, id))
    .limit(1);
  if (!row) throw notFound();
  return row;
}

export const MAX_DISCOVERY_SIGHTINGS = 50;

/** GET /assets/:id — the asset, its address history and its latest 50 discovery sightings. */
export async function getAsset(db: Database, user: User, id: string): Promise<AssetDetailResponse> {
  const row = await visibleAsset(db, user, id);
  const [ips, sightings] = await Promise.all([
    db
      .select()
      .from(assetIps)
      .where(eq(assetIps.assetId, id))
      .orderBy(desc(assetIps.isCurrent), desc(assetIps.lastSeenAt), asc(assetIps.ipAddress)),
    db
      .select()
      .from(discoveryObservations)
      .where(eq(discoveryObservations.assetId, id))
      .orderBy(desc(discoveryObservations.observedAt), desc(discoveryObservations.id))
      .limit(MAX_DISCOVERY_SIGHTINGS),
  ]);
  return {
    asset: toAssetDto(
      row,
      ips.filter((i) => i.isCurrent).map((i) => displayIp(i.ipAddress)),
    ),
    ips: ips.map((i) => ({
      ipAddress: displayIp(i.ipAddress),
      firstSeenAt: i.firstSeenAt.toISOString(),
      lastSeenAt: i.lastSeenAt.toISOString(),
      isCurrent: i.isCurrent,
      source: i.source,
    })),
    discovery: sightings.map((s) => ({
      source: s.source,
      observedAt: s.observedAt.toISOString(),
      wildcard: s.wildcard,
      scanJobId: s.scanJobId,
      evidence: s.evidence,
    })),
  };
}

// --- Decisions ----------------------------------------------------------------------------------

export type SkipCode =
  'not_found' | 'invalid_transition' | 'third_party_not_acknowledged' | 'no_change';

const TARGET_STATUS: Record<Action, AssetStatus> = {
  approve: 'approved',
  reject: 'rejected',
  suspend: 'suspended',
};

const AUDIT_ACTION: Record<Action, string> = {
  approve: 'asset.approved',
  reject: 'asset.rejected',
  suspend: 'asset.suspended',
};

export interface DecisionInput {
  action: Action;
  reason: string;
  acknowledgeThirdPartyHosting: boolean;
}

/**
 * Applies one decision to many assets in one transaction, set-based. Rows that cannot take the
 * decision are skipped with a code; the rest are updated, audited, and their active ASSET-001
 * findings resolved (`asset_decided`). Suspension also stops in-flight active jobs targeting them.
 */
export async function decideAssets(
  db: Database,
  user: User,
  ids: readonly string[],
  input: DecisionInput,
  actor: Actor,
  now: Date,
  bulk: boolean,
): Promise<AssetBulkDecisionResponse & { updatedIds: string[] }> {
  const unique = [...new Set(ids.map((id) => id.toLowerCase()))];
  return db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const visible = visibleAssets(user);
    const rows = await tx
      .select()
      .from(assets)
      .where(visible ? and(inArray(assets.id, unique), visible) : inArray(assets.id, unique))
      .orderBy(asc(assets.id))
      .for('update');
    const byId = new Map(rows.map((r) => [r.id, r]));

    const skipped: { id: string; code: SkipCode }[] = [];
    const eligible: AssetRow[] = [];
    const target = TARGET_STATUS[input.action];
    for (const id of unique) {
      const a = byId.get(id);
      if (!a) skipped.push({ id, code: 'not_found' });
      else if (a.verificationStatus === target) skipped.push({ id, code: 'no_change' });
      else if (!allowedAssetActions(a.verificationStatus, a.assetType).includes(input.action)) {
        skipped.push({ id, code: 'invalid_transition' });
      } else if (
        input.action === 'approve' &&
        a.hostingHint !== null &&
        !input.acknowledgeThirdPartyHosting
      ) {
        skipped.push({ id, code: 'third_party_not_acknowledged' });
      } else eligible.push(a);
    }
    if (eligible.length === 0) return { updated: 0, skipped, updatedIds: [] };
    const eligibleIds = eligible.map((a) => a.id);

    const decided = {
      verificationStatus: target,
      decidedBy: actor.userId,
      decidedAt: now,
      decisionReason: input.reason,
      updatedAt: now,
    };
    await tx
      .update(assets)
      .set(
        input.action === 'approve'
          ? { ...decided, approvedBy: actor.userId, approvedAt: now, monitoringEnabled: true }
          : { ...decided, monitoringEnabled: false },
      )
      .where(inArray(assets.id, eligibleIds));

    const audit: AuditEntry[] = eligible.map((a) => ({
      actorType: 'user',
      actorUserId: actor.userId,
      action: AUDIT_ACTION[input.action],
      resourceType: 'asset',
      resourceId: a.id,
      requestId: actor.requestId,
      metadata: {
        domainId: a.domainId,
        hostname: a.hostname,
        from: a.verificationStatus,
        to: target,
        reason: input.reason,
        hostingHint: a.hostingHint ?? null,
        acknowledgeThirdPartyHosting: input.acknowledgeThirdPartyHosting,
        ...(bulk ? { bulk: true } : {}),
      },
    }));

    if (input.action === 'suspend') {
      await stopActiveJobsForAssets(tx, eligibleIds, 'asset_suspended', actor, now);
    }

    audit.push(...(await resolveCandidateFindings(tx, eligible, input, actor, now)));
    await writeAuditMany(tx, audit);
    return { updated: eligible.length, skipped, updatedIds: eligibleIds };
  });
}

/**
 * Resolves the active ASSET-001 finding of each decided hostname (the decision is the review it
 * asked for). Serialised with rules evaluation through the per-domain findings lock, so an
 * evaluation that read the asset as pending cannot reopen what this just resolved.
 */
async function resolveCandidateFindings(
  tx: Database,
  decided: readonly AssetRow[],
  input: DecisionInput,
  actor: Actor,
  now: Date,
): Promise<AuditEntry[]> {
  const domainIds = [...new Set(decided.map((a) => a.domainId))].sort();
  const keys = sql.join(
    domainIds.map((d) => sql`(${`findings:${d}`})`),
    sql`, `,
  );
  await tx.execute(
    sql`select pg_advisory_xact_lock(hashtext(k)) from (values ${keys}) as v(k) order by k`,
  );
  const fps = decided.map((a) => fingerprint('ASSET-001', a.domainId, a.hostname, a.hostname));
  const active = await tx
    .select({ id: findings.id, status: findings.status, assetId: findings.assetId })
    .from(findings)
    .where(and(inArray(findings.fingerprint, fps), ne(findings.status, 'resolved')))
    .orderBy(asc(findings.id))
    .for('update');
  if (active.length === 0) return [];
  const ids = active.map((f) => f.id);
  await tx
    .update(findings)
    .set({
      status: 'resolved',
      resolvedAt: now,
      acceptedRiskReason: null,
      acceptedRiskApprovedBy: null,
      acceptedRiskReviewAt: null,
      updatedAt: now,
    })
    .where(inArray(findings.id, ids));
  const note = `Asset ${TARGET_STATUS[input.action]}: ${input.reason}`;
  await tx.insert(findingStatusHistory).values(
    active.map((f) => ({
      findingId: f.id,
      fromStatus: f.status,
      toStatus: 'resolved' as const,
      changedBy: actor.userId,
      reason: 'asset_decided',
      note,
      createdAt: now,
    })),
  );
  return active.map((f) => ({
    actorType: 'user' as const,
    actorUserId: actor.userId,
    action: 'finding.status_changed',
    resourceType: 'finding',
    resourceId: f.id,
    requestId: actor.requestId,
    metadata: {
      from: f.status,
      to: 'resolved',
      reason: 'asset_decided',
      ruleId: 'ASSET-001',
      assetDecision: input.action,
    },
  }));
}

/** Single-asset decision: skip codes become the shared error envelope. */
export async function decideAsset(
  db: Database,
  user: User,
  id: string,
  input: DecisionInput,
  actor: Actor,
  now: Date,
): Promise<void> {
  const res = await decideAssets(db, user, [id], input, actor, now, false);
  const skip = res.skipped[0];
  if (!skip) return;
  switch (skip.code) {
    case 'not_found':
      throw notFound();
    case 'third_party_not_acknowledged':
      throw new ApiError(
        400,
        'validation_failed',
        'This host is on third-party hosting; confirm the approval explicitly.',
        [
          {
            path: 'acknowledgeThirdPartyHosting',
            message:
              'Approving a third-party-hosted asset requires acknowledging that it is hosted by a provider.',
          },
        ],
      );
    case 'no_change':
    case 'invalid_transition':
      throw new ApiError(409, 'conflict', 'This asset cannot take that decision now.', [
        {
          path: 'status',
          message: `An asset in this status cannot be ${TARGET_STATUS[input.action]}.`,
        },
      ]);
  }
}

// --- Owner --------------------------------------------------------------------------------------

/**
 * PATCH /assets/:id: sets or clears the asset owner (asset owners see only assets they own). The
 * new owner must be an existing, active user. Audited `asset.owner_changed`; no-op if unchanged.
 */
export async function setAssetOwner(
  db: Database,
  id: string,
  ownerUserId: string | null,
  actor: Actor,
  now: Date,
): Promise<void> {
  const target = ownerUserId?.toLowerCase() ?? null;
  await db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    const [asset] = await tx.select().from(assets).where(eq(assets.id, id)).for('update');
    if (!asset) throw notFound();

    let ownerEmail: string | null = null;
    if (target !== null) {
      // Lock the user row so a concurrent deactivation cannot slip in before commit.
      const [owner] = await tx
        .select({ email: users.email, isActive: users.isActive })
        .from(users)
        .where(eq(users.id, target))
        .for('share');
      if (!owner?.isActive) {
        throw new ApiError(400, 'validation_failed', 'The owner must be an active user.', [
          { path: 'ownerUserId', message: 'Choose an active user.' },
        ]);
      }
      ownerEmail = owner.email;
    }
    if (asset.ownerUserId === target) return;

    const [previous] = asset.ownerUserId
      ? await tx.select({ email: users.email }).from(users).where(eq(users.id, asset.ownerUserId))
      : [];
    await tx.update(assets).set({ ownerUserId: target, updatedAt: now }).where(eq(assets.id, id));
    await writeAuditMany(tx, [
      {
        actorType: 'user',
        actorUserId: actor.userId,
        action: 'asset.owner_changed',
        resourceType: 'asset',
        resourceId: id,
        requestId: actor.requestId,
        metadata: {
          domainId: asset.domainId,
          hostname: asset.hostname,
          from: asset.ownerUserId
            ? { id: asset.ownerUserId, email: previous?.email ?? null }
            : null,
          to: target ? { id: target, email: ownerEmail } : null,
        },
      },
    ]);
  });
}
