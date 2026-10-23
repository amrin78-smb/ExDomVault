import { auditListQuerySchema, type AuditListResponse } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseQuery } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { listAuditLogs } from '../services/audit-log.ts';
import type { AppBindings } from '../types.ts';

/** Read-only audit log (`audit:read`). Mounted at /api/v1/audit-logs on the authenticated app. */
export function auditLogRoutes() {
  return new Hono<AppBindings>().get('/', requirePermission('audit:read'), async (c) => {
    const query = parseQuery(c, auditListQuerySchema);
    const db = await c.get('db')();
    const res: AuditListResponse = await listAuditLogs(db, query);
    return c.json(res);
  });
}
