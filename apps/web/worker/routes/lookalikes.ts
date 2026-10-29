import {
  lookalikeListQuerySchema,
  type LookalikeCheckResponse,
  type LookalikeListResponse,
} from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseQuery, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { listLookalikes, requestLookalikeCheck } from '../services/lookalikes.ts';
import type { AppBindings } from '../types.ts';

export interface LookalikeRouteDeps {
  now?: () => Date;
}

/**
 * Lookalike domains (Milestone 15), mounted at /api/v1/lookalikes. `domains:read`: brand data is
 * about the organisation's domains as a whole, not about any asset, so asset owners do not see it.
 */
export function lookalikeRoutes(deps: LookalikeRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>().get('/', requirePermission('domains:read'), async (c) => {
    const query = parseQuery(c, lookalikeListQuerySchema);
    const db = await c.get('db')();
    const res: LookalikeListResponse = await listLookalikes(db, query, now());
    return c.json(res);
  });
}

/** POST /api/v1/domains/:id/lookalikes/check — mounted beside the domain routes. */
export function domainLookalikeRoutes(deps: LookalikeRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>().post(
    '/:id/lookalikes/check',
    requirePermission('scans:request'),
    async (c) => {
      const id = uuidParam(c, 'id');
      const db = await c.get('db')();
      const user = c.get('user');
      const res: LookalikeCheckResponse = await requestLookalikeCheck(
        db,
        id,
        { userId: user.id, requestId: c.get('requestId') },
        now(),
      );
      c.get('logger').info('lookalike_check_requested', { domainId: id, ...res });
      // 201 when a job was queued; 200 when one was already queued or running.
      return c.json(res, res.created ? 201 : 200);
    },
  );
}
