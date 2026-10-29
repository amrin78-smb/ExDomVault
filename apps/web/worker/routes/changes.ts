import { changesQuerySchema, type ChangesResponse } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseQuery } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { listChanges } from '../services/changes.ts';
import type { AppBindings } from '../types.ts';

export interface ChangeRouteDeps {
  now?: () => Date;
}

/**
 * Change timeline (Milestone 14), mounted at /api/v1/changes. Read-only; `assets:read`, and asset
 * owners see only events on assets they own (enforced in the service).
 */
export function changeRoutes(deps: ChangeRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>().get('/', requirePermission('assets:read'), async (c) => {
    const query = parseQuery(c, changesQuerySchema);
    const db = await c.get('db')();
    const res: ChangesResponse = await listChanges(db, c.get('user'), query, now());
    return c.json(res);
  });
}
