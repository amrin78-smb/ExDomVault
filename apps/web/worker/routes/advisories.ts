import { Hono } from 'hono';
import { z } from 'zod';
import { parseQuery } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { listAdvisories } from '../services/findings.ts';
import type { AppBindings } from '../types.ts';

/** GET /advisories query (also accepted, without paging, by GET /exports/advisories.csv). */
export const advisoryListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  /** `active` (default): advisories of non-resolved findings only. */
  status: z.enum(['active', 'all']).default('active'),
});

/** Remediation advisories, derived from findings (same visibility rules as findings). */
export function advisoryRoutes() {
  return new Hono<AppBindings>().get('/', requirePermission('findings:read'), async (c) => {
    const query = parseQuery(c, advisoryListQuerySchema);
    const db = await c.get('db')();
    return c.json(await listAdvisories(db, c.get('user'), query));
  });
}
