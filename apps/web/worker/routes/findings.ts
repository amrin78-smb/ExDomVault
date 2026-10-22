import { RULES, type Rule } from '@exdomainvault/rules';
import { findingListQuerySchema } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { z } from 'zod';
import { parseQuery, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { findingSummary, getFindingDetail, listFindings } from '../services/findings.ts';
import type { AppBindings } from '../types.ts';

export interface FindingRouteDeps {
  /** Rule registry used for rule documentation (defaults to the production registry). */
  rules?: readonly Rule[];
}

const summaryQuerySchema = z.object({ domainId: z.uuid().optional() });

/** Findings (read-only in Milestone 7). Asset owners are scoped to their own assets' findings. */
export function findingRoutes(deps: FindingRouteDeps = {}) {
  const rules = deps.rules ?? RULES;
  return new Hono<AppBindings>()
    .get('/', requirePermission('findings:read'), async (c) => {
      const query = parseQuery(c, findingListQuerySchema);
      const db = await c.get('db')();
      return c.json(await listFindings(db, c.get('user'), query));
    })
    .get('/summary', requirePermission('findings:read'), async (c) => {
      const { domainId } = parseQuery(c, summaryQuerySchema);
      const db = await c.get('db')();
      return c.json(await findingSummary(db, c.get('user'), domainId));
    })
    .get('/:id', requirePermission('findings:read'), async (c) => {
      const id = uuidParam(c, 'id');
      const db = await c.get('db')();
      return c.json(await getFindingDetail(db, c.get('user'), id, rules));
    });
}
