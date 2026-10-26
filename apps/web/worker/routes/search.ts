import { searchQuerySchema, type SearchResponse } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseQuery } from '../lib/validation.ts';
import { requireAnyPermission } from '../middleware/auth.ts';
import { search } from '../services/search.ts';
import type { AppBindings } from '../types.ts';

/**
 * Global search (Milestone 13), mounted at /api/v1/search. Any role that can read domains, assets
 * or findings; groups the caller may not read are returned empty and results are scoped in the
 * service. Rate limiting is the global API middleware.
 */
export function searchRoutes() {
  return new Hono<AppBindings>().get(
    '/',
    requireAnyPermission('domains:read', 'assets:read', 'findings:read'),
    async (c) => {
      const { q } = parseQuery(c, searchQuerySchema);
      const db = await c.get('db')();
      const res: SearchResponse = await search(db, c.get('user'), q);
      return c.json(res);
    },
  );
}
