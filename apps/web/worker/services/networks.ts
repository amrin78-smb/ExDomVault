import { schema, type Database } from '@exdomainvault/database';
import {
  APPROVED_NETWORK_MAX_MONTHS,
  type ApprovedNetwork,
  type CreateApprovedNetworkRequest,
} from '@exdomainvault/shared';
import {
  canonicalCidr,
  cidrsOverlap,
  parseCidr,
  prohibitedReason,
} from '@exdomainvault/shared/net';
import { and, desc, eq, gt, isNull, lte, sql } from 'drizzle-orm';
import { firstRow } from '../lib/db.ts';
import { ApiError } from '../lib/errors.ts';
import { writeAudit } from './audit.ts';
import { isUniqueViolation, type Actor } from './domains.ts';

const { approvedNetworks, users } = schema;

/**
 * Admin-approved networks: the only destinations network-tier checks may contact. An approval is
 * active while it is neither revoked nor past its review date; expiry is evaluated lazily wherever
 * the set is used (job creation, claim, ingestion), so there is no status column to drift.
 */

/** Broadest single approval: a /16 (IPv4) or /32 (IPv6), so one entry cannot cover a provider. */
export const MIN_PREFIX = { 4: 16, 6: 32 } as const;

type Row = typeof approvedNetworks.$inferSelect;

/** Advisory-lock key serialising network approvals (arbitrary constant, unique to this use). */
export const NETWORK_APPROVAL_LOCK_KEY = 0x45_44_56_4e; // "EDVN"

const iso = (d: Date | null) => (d ? d.toISOString() : null);

const invalid = (path: string, message: string) =>
  new ApiError(400, 'validation_failed', 'The approved network is invalid.', [{ path, message }]);

/** Review dates are calendar dates; the approval lapses at the end of that day (UTC). */
export function networkReviewDeadline(reviewBy: string, now: Date): Date {
  const deadline = new Date(`${reviewBy}T23:59:59.999Z`);
  const max = new Date(now);
  max.setUTCMonth(max.getUTCMonth() + APPROVED_NETWORK_MAX_MONTHS);
  if (Number.isNaN(deadline.getTime()) || deadline <= now) {
    throw invalid('reviewBy', 'The review date must be in the future.');
  }
  if (deadline > max) {
    throw invalid(
      'reviewBy',
      `The review date must be within ${APPROVED_NETWORK_MAX_MONTHS} months.`,
    );
  }
  return deadline;
}

/**
 * Canonicalises and validates a requested network: well-formed, entirely public unicast space,
 * and no broader than the per-family limit.
 */
export function validateNetwork(input: string): string {
  const parsed = parseCidr(input.trim());
  if (!parsed) {
    throw invalid('cidr', 'Enter an IPv4 or IPv6 network in CIDR notation, or a single address.');
  }
  const reason = prohibitedReason(parsed);
  if (reason) {
    throw invalid('cidr', `The network includes non-public address space (${reason}).`);
  }
  const min = MIN_PREFIX[parsed.version];
  if (parsed.prefix < min) {
    throw invalid(
      'cidr',
      `The network is too broad: approve at most a /${min} for IPv${parsed.version}.`,
    );
  }
  return canonicalCidr(input) as string;
}

const isActive = (r: Pick<Row, 'revokedAt' | 'expiresAt'>, now: Date) =>
  r.revokedAt === null && r.expiresAt > now;

/** Canonical CIDRs of every currently active approval. */
export async function activeNetworkCidrs(db: Database, now: Date): Promise<string[]> {
  const rows = await db
    .select({ cidr: approvedNetworks.cidr })
    .from(approvedNetworks)
    .where(and(isNull(approvedNetworks.revokedAt), gt(approvedNetworks.expiresAt, now)));
  return [...new Set(rows.map((r) => canonicalCidr(r.cidr)).filter((c) => c !== null))].sort();
}

/**
 * The networks a job may still probe: its snapshot's list intersected with the currently active
 * set. Revocation or expiry shrinks scope; nothing is ever added.
 */
export function intersectNetworks(snapshot: readonly string[], active: readonly string[]) {
  const current = new Set(active);
  return snapshot.filter((c) => {
    const canonical = canonicalCidr(c);
    return canonical !== null && current.has(canonical);
  });
}

function toDto(r: Row, email: string | null): ApprovedNetwork {
  return {
    id: r.id,
    cidr: canonicalCidr(r.cidr) ?? r.cidr,
    label: r.label,
    reason: r.reason,
    reference: r.reference,
    createdBy: r.createdBy && email ? { id: r.createdBy, email } : null,
    createdAt: r.createdAt.toISOString(),
    expiresAt: r.expiresAt.toISOString(),
    revokedAt: iso(r.revokedAt),
    revokeReason: r.revokeReason,
  };
}

export async function listNetworks(db: Database, id?: string): Promise<ApprovedNetwork[]> {
  const rows = await db
    .select({ n: approvedNetworks, email: users.email })
    .from(approvedNetworks)
    .leftJoin(users, eq(users.id, approvedNetworks.createdBy))
    .where(id ? eq(approvedNetworks.id, id) : undefined)
    .orderBy(desc(approvedNetworks.createdAt), desc(approvedNetworks.id));
  return rows.map((r) => toDto(r.n, r.email));
}

async function getNetwork(db: Database, id: string): Promise<ApprovedNetwork> {
  const [n] = await listNetworks(db, id);
  if (!n) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  return n;
}

type CreateInput = Omit<CreateApprovedNetworkRequest, 'reference'> & {
  reference?: string | null;
};

export async function createNetwork(
  db: Database,
  input: CreateInput,
  actor: Actor,
  now: Date,
): Promise<ApprovedNetwork> {
  const cidr = validateNetwork(input.cidr);
  const expiresAt = networkReviewDeadline(input.reviewBy, now);
  let id: string;
  try {
    id = await db.transaction(async (tx) => {
      const t = tx as unknown as Database;
      // Serialise approvals: the overlap check below reads the active set and then inserts, which two
      // concurrent transactions could otherwise both pass (the unique index only stops exact
      // duplicates). A transaction-scoped advisory lock, released at commit/rollback.
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${NETWORK_APPROVAL_LOCK_KEY})`);
      // A lapsed (never revoked) approval of the same network still holds the unique slot: close it.
      await tx
        .update(approvedNetworks)
        .set({
          revokedAt: approvedNetworks.expiresAt,
          revokeReason: 'Expired (review date passed).',
        })
        .where(
          and(
            eq(approvedNetworks.cidr, cidr),
            isNull(approvedNetworks.revokedAt),
            lte(approvedNetworks.expiresAt, now),
          ),
        );

      const active = await activeNetworkCidrs(t, now);
      if (active.includes(cidr)) {
        throw new ApiError(409, 'conflict', 'This network is already approved.');
      }
      const overlapping = active.find((c) => cidrsOverlap(c, cidr));
      if (overlapping) {
        throw new ApiError(
          409,
          'conflict',
          `The network overlaps the approved network ${overlapping}. Revoke it first.`,
        );
      }
      const row = firstRow(
        await tx
          .insert(approvedNetworks)
          .values({
            cidr,
            label: input.label,
            reason: input.reason,
            reference: input.reference ?? null,
            createdBy: actor.userId,
            createdAt: now,
            expiresAt,
          })
          .returning(),
      );
      await writeAudit(t, {
        actorType: 'user',
        actorUserId: actor.userId,
        action: 'network.approved',
        resourceType: 'approved_network',
        resourceId: row.id,
        requestId: actor.requestId,
        metadata: {
          cidr,
          label: input.label,
          reason: input.reason,
          reference: input.reference ?? null,
          expiresAt: expiresAt.toISOString(),
        },
      });
      return row.id;
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new ApiError(409, 'conflict', 'This network is already approved.');
    }
    throw err;
  }
  return getNetwork(db, id);
}

export async function revokeNetwork(
  db: Database,
  id: string,
  reason: string,
  actor: Actor,
  now: Date,
): Promise<ApprovedNetwork> {
  await db.transaction(async (tx) => {
    const [row] = await tx
      .select()
      .from(approvedNetworks)
      .where(eq(approvedNetworks.id, id))
      .for('update');
    if (!row) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    if (row.revokedAt !== null) {
      throw new ApiError(409, 'conflict', 'This network approval has already been revoked.');
    }
    await tx
      .update(approvedNetworks)
      .set({ revokedAt: now, revokeReason: reason, revokedBy: actor.userId })
      .where(eq(approvedNetworks.id, id));
    await writeAudit(tx as unknown as Database, {
      actorType: 'user',
      actorUserId: actor.userId,
      action: 'network.revoked',
      resourceType: 'approved_network',
      resourceId: id,
      requestId: actor.requestId,
      metadata: {
        cidr: canonicalCidr(row.cidr) ?? row.cidr,
        reason,
        wasActive: isActive(row, now),
      },
    });
  });
  return getNetwork(db, id);
}
