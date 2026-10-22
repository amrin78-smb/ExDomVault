import { schema, type Database } from '@exdomainvault/database';

export interface AuditEntry {
  actorType: 'user' | 'worker' | 'system';
  actorUserId?: string | null;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  requestId?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Appends an audit record. Call inside the same transaction as the change being audited so a
 * privileged action is never committed without its audit entry. Never put secrets in metadata.
 */
export async function writeAudit(db: Database, entry: AuditEntry): Promise<void> {
  await db.insert(schema.auditLogs).values({
    actorType: entry.actorType,
    actorUserId: entry.actorUserId ?? null,
    action: entry.action,
    resourceType: entry.resourceType,
    resourceId: entry.resourceId ?? null,
    requestId: entry.requestId ?? null,
    metadata: entry.metadata ?? {},
  });
}
