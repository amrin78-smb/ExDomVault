import { schema, type Database } from '@exdomainvault/database';
import type { AuditListQuery, AuditListResponse } from '@exdomainvault/shared';
import { and, count, desc, eq, gte, like, lte, type SQL } from 'drizzle-orm';

const { auditLogs, users } = schema;

const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

/**
 * GET /audit-logs (`audit:read`): newest first, with the acting user's email. `action` is an exact
 * match, or a prefix match when it ends with `.` (`finding.` → every finding action).
 */
/** The WHERE clause of GET /audit-logs (shared with the CSV export). */
export function auditListWhere(q: Omit<AuditListQuery, 'page' | 'pageSize'>): SQL | undefined {
  const filters: SQL[] = [];
  if (q.action) {
    filters.push(
      q.action.endsWith('.')
        ? like(auditLogs.action, `${escapeLike(q.action)}%`)
        : eq(auditLogs.action, q.action),
    );
  }
  if (q.resourceType) filters.push(eq(auditLogs.resourceType, q.resourceType));
  if (q.resourceId) filters.push(eq(auditLogs.resourceId, q.resourceId));
  if (q.actorUserId) filters.push(eq(auditLogs.actorUserId, q.actorUserId.toLowerCase()));
  if (q.actorType) filters.push(eq(auditLogs.actorType, q.actorType));
  if (q.from) filters.push(gte(auditLogs.createdAt, new Date(q.from)));
  if (q.to) filters.push(lte(auditLogs.createdAt, new Date(q.to)));
  return filters.length > 0 ? and(...filters) : undefined;
}

/** The ORDER BY of GET /audit-logs: newest first. */
export const AUDIT_ORDER = [desc(auditLogs.createdAt), desc(auditLogs.id)];

export async function listAuditLogs(db: Database, q: AuditListQuery): Promise<AuditListResponse> {
  const where = auditListWhere(q);
  const [rows, [total]] = await Promise.all([
    db
      .select({ a: auditLogs, email: users.email })
      .from(auditLogs)
      .leftJoin(users, eq(users.id, auditLogs.actorUserId))
      .where(where)
      .orderBy(...AUDIT_ORDER)
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize),
    db.select({ n: count() }).from(auditLogs).where(where),
  ]);
  return {
    items: rows.map(({ a, email }) => ({
      id: a.id,
      actorType: a.actorType,
      actor: a.actorUserId && email ? { id: a.actorUserId, email } : null,
      action: a.action,
      resourceType: a.resourceType,
      resourceId: a.resourceId,
      requestId: a.requestId,
      metadata: a.metadata,
      createdAt: a.createdAt.toISOString(),
    })),
    page: q.page,
    pageSize: q.pageSize,
    total: total?.n ?? 0,
  };
}
