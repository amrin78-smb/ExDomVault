import { schema, type Database } from '@exdomainvault/database';
import type { Domain, DomainListQuery, DomainListResponse } from '@exdomainvault/shared';
import { normaliseDomain } from '@exdomainvault/shared/hostname';
import { and, asc, count, desc, eq, ilike, inArray, ne, sql, type SQL } from 'drizzle-orm';
import { firstRow } from '../lib/db.ts';
import { ApiError } from '../lib/errors.ts';
import { writeAudit, writeAuditMany } from './audit.ts';
import { asGrade, latestGradeSql, latestScoreSql } from './security-score.ts';

const { domains } = schema;

export type DomainRow = typeof domains.$inferSelect;

/** Who is acting, for audit records. */
export interface Actor {
  userId: string;
  requestId: string;
}

const iso = (d: Date | null) => (d ? d.toISOString() : null);

/** Latest security score snapshot of a domain (Milestone 14); null until it has been scored. */
export interface DomainScoreRef {
  score: number | null;
  grade: string | null;
}

export function toDomainDto(
  row: DomainRow,
  score: DomainScoreRef = { score: null, grade: null },
): Domain {
  // Stored names are canonical, so this only derives the display form and warnings.
  const n = normaliseDomain(row.fqdn);
  return {
    id: row.id,
    fqdn: row.fqdn,
    unicodeFqdn: n.ok ? n.unicode : row.fqdn,
    warnings: n.ok ? n.warnings : [],
    registrar: row.registrar,
    registeredAt: iso(row.registeredAt),
    expiresAt: iso(row.expiresAt),
    registrationDataStatus: row.registrationDataStatus,
    criticality: row.criticality,
    businessOwner: row.businessOwner,
    verificationStatus: row.verificationStatus,
    verifiedAt: iso(row.verifiedAt),
    verificationMethod: row.verificationMethod,
    verificationExpiresAt: iso(row.verificationExpiresAt),
    monitoringEnabled: row.monitoringEnabled,
    brandMonitoring: row.brandMonitoring,
    score: score.score === null ? null : Number(score.score),
    grade: asGrade(score.grade),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** True for PostgreSQL unique-constraint violations, however the driver wraps them. */
export function isUniqueViolation(err: unknown): boolean {
  for (let e: unknown = err, depth = 0; e && depth < 5; depth++) {
    if (typeof e === 'object' && 'code' in e && (e as { code: unknown }).code === '23505')
      return true;
    e = typeof e === 'object' && 'cause' in e ? (e as { cause: unknown }).cause : undefined;
  }
  return false;
}

const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

const SORT_COLUMNS = {
  fqdn: domains.fqdn,
  createdAt: domains.createdAt,
  criticality: domains.criticality,
} as const;

/** The WHERE clause of GET /domains (shared with the CSV export). */
export function domainListWhere(
  q: Pick<DomainListQuery, 'q' | 'verificationStatus' | 'criticality' | 'monitoring' | 'grade'>,
): SQL | undefined {
  const filters: SQL[] = [];
  if (q.q) {
    // Search the canonical form; a Unicode search term is converted to its A-label first.
    const n = normaliseDomain(q.q);
    const term = (n.ok ? n.fqdn : q.q).toLowerCase();
    filters.push(ilike(domains.fqdn, `%${escapeLike(term)}%`));
  }
  if (q.verificationStatus) filters.push(eq(domains.verificationStatus, q.verificationStatus));
  if (q.criticality) filters.push(eq(domains.criticality, q.criticality));
  if (q.monitoring) filters.push(eq(domains.monitoringEnabled, q.monitoring === 'true'));
  if (q.grade === 'none') filters.push(sql`${latestGradeSql} is null`);
  else if (q.grade) filters.push(sql`${latestGradeSql} = ${q.grade}`);
  return filters.length > 0 ? and(...filters) : undefined;
}

/** The ORDER BY of GET /domains (shared with the CSV export). */
export function domainListOrder(sort: DomainListQuery['sort']): SQL[] {
  const descending = sort.startsWith('-');
  if (sort === 'score' || sort === '-score') {
    return [
      sql`${latestScoreSql} ${descending ? sql`desc` : sql`asc`} nulls last`,
      asc(domains.fqdn),
    ];
  }
  const column = SORT_COLUMNS[sort.replace(/^-/, '') as keyof typeof SORT_COLUMNS];
  return [descending ? desc(column) : asc(column), asc(domains.fqdn)];
}

export async function listDomains(db: Database, q: DomainListQuery): Promise<DomainListResponse> {
  const where = domainListWhere(q);
  const [rows, [totalRow]] = await Promise.all([
    db
      .select({ d: domains, score: latestScoreSql, grade: latestGradeSql })
      .from(domains)
      .where(where)
      .orderBy(...domainListOrder(q.sort))
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize),
    db.select({ total: count() }).from(domains).where(where),
  ]);

  return {
    items: rows.map((r) => toDomainDto(r.d, { score: r.score, grade: r.grade })),
    page: q.page,
    pageSize: q.pageSize,
    total: totalRow?.total ?? 0,
  };
}

export async function getDomainRow(db: Database, id: string): Promise<DomainRow> {
  const [row] = await db.select().from(domains).where(eq(domains.id, id)).limit(1);
  if (!row) throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  return row;
}

/** Normalises user input or throws a 400 with a field-level explanation. */
export function normaliseOrThrow(input: string): { fqdn: string } {
  const n = normaliseDomain(input);
  if (!n.ok) {
    throw new ApiError(400, 'validation_failed', 'The domain name is invalid.', [
      { path: 'fqdn', message: n.message },
    ]);
  }
  return n;
}

export async function createDomain(
  db: Database,
  input: { fqdn: string; criticality: Domain['criticality']; businessOwner?: string | null },
  actor: Actor,
): Promise<DomainRow> {
  const { fqdn } = normaliseOrThrow(input.fqdn);
  try {
    return await db.transaction(async (tx) => {
      const row = firstRow(
        await tx
          .insert(domains)
          .values({
            fqdn,
            criticality: input.criticality,
            businessOwner: input.businessOwner ?? null,
            createdBy: actor.userId,
          })
          .returning(),
      );
      await writeAudit(tx as unknown as Database, {
        actorType: 'user',
        actorUserId: actor.userId,
        action: 'domain.created',
        resourceType: 'domain',
        resourceId: row.id,
        requestId: actor.requestId,
        metadata: { fqdn, criticality: input.criticality, source: 'manual' },
      });
      return row;
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new ApiError(409, 'conflict', `${fqdn} is already registered.`, [
        { path: 'fqdn', message: 'This domain is already registered.' },
      ]);
    }
    throw err;
  }
}

export async function updateDomain(
  db: Database,
  id: string,
  patch: {
    criticality?: Domain['criticality'];
    businessOwner?: string | null;
    monitoringEnabled?: boolean;
    brandMonitoring?: boolean;
  },
  actor: Actor,
): Promise<DomainRow> {
  return db.transaction(async (tx) => {
    const [current] = await tx.select().from(domains).where(eq(domains.id, id)).for('update');
    if (!current) throw new ApiError(404, 'not_found', 'The requested resource was not found.');

    const changes: Record<string, { from: unknown; to: unknown }> = {};
    const set: Partial<typeof domains.$inferInsert> = {};
    if (patch.criticality !== undefined && patch.criticality !== current.criticality) {
      set.criticality = patch.criticality;
      changes.criticality = { from: current.criticality, to: patch.criticality };
    }
    if (patch.businessOwner !== undefined && patch.businessOwner !== current.businessOwner) {
      set.businessOwner = patch.businessOwner;
      changes.businessOwner = { from: current.businessOwner, to: patch.businessOwner };
    }
    const monitoringChanged =
      patch.monitoringEnabled !== undefined &&
      patch.monitoringEnabled !== current.monitoringEnabled;
    if (monitoringChanged) set.monitoringEnabled = patch.monitoringEnabled;
    const brandChanged =
      patch.brandMonitoring !== undefined && patch.brandMonitoring !== current.brandMonitoring;
    if (brandChanged) set.brandMonitoring = patch.brandMonitoring;

    if (Object.keys(set).length === 0) return current;

    const updated = firstRow(
      await tx.update(domains).set(set).where(eq(domains.id, id)).returning(),
    );
    const audit = (action: string, metadata: Record<string, unknown>) =>
      writeAudit(tx as unknown as Database, {
        actorType: 'user',
        actorUserId: actor.userId,
        action,
        resourceType: 'domain',
        resourceId: id,
        requestId: actor.requestId,
        metadata: { fqdn: current.fqdn, ...metadata },
      });
    if (Object.keys(changes).length > 0) await audit('domain.updated', { changes });
    if (monitoringChanged) {
      await audit(
        patch.monitoringEnabled ? 'domain.monitoring_enabled' : 'domain.monitoring_disabled',
        {},
      );
    }
    if (brandChanged) {
      // Milestone 15: lookalike-domain monitoring is an explicit, audited opt-in per domain.
      await audit(
        patch.brandMonitoring
          ? 'domain.brand_monitoring_enabled'
          : 'domain.brand_monitoring_disabled',
        {},
      );
    }
    return updated;
  });
}

/**
 * Turns passive monitoring on or off for the listed domains (or all of them) in one statement.
 * Only domains whose setting actually changes are updated and audited (one record each).
 */
export async function setMonitoringBulk(
  db: Database,
  target: { domainIds: string[] } | { all: true },
  enabled: boolean,
  actor: Actor,
): Promise<{ updated: number }> {
  return db.transaction(async (tx) => {
    const scope =
      'all' in target
        ? undefined
        : inArray(
            domains.id,
            target.domainIds.map((id) => id.toLowerCase()),
          );
    const rows = await tx
      .update(domains)
      .set({ monitoringEnabled: enabled })
      .where(and(ne(domains.monitoringEnabled, enabled), scope))
      .returning({ id: domains.id, fqdn: domains.fqdn });
    await writeAuditMany(
      tx as unknown as Database,
      rows.map((row) => ({
        actorType: 'user' as const,
        actorUserId: actor.userId,
        action: enabled ? 'domain.monitoring_enabled' : 'domain.monitoring_disabled',
        resourceType: 'domain',
        resourceId: row.id,
        requestId: actor.requestId,
        metadata: { fqdn: row.fqdn, bulk: true },
      })),
    );
    return { updated: rows.length };
  });
}
