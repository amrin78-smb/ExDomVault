import {
  dashboardQuerySchema,
  type DashboardRange,
  type DashboardResponse,
} from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseQuery } from '../lib/validation.ts';
import { requireAnyPermission } from '../middleware/auth.ts';
import { dashboard } from '../services/dashboard.ts';
import type { AppBindings } from '../types.ts';

export interface DashboardRouteDeps {
  now?: () => Date;
}

/**
 * Overview dashboard (Milestone 13), mounted at /api/v1/dashboard. Any role that can read domains,
 * assets or findings; each section is gated by its own list's permission and scoped in the
 * service (asset owners: their assets only; domain counts and scans are empty for them).
 */
export function dashboardRoutes(deps: DashboardRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>().get(
    '/',
    requireAnyPermission('domains:read', 'assets:read', 'findings:read'),
    async (c) => {
      const { range } = parseQuery(c, dashboardQuerySchema);
      const db = await c.get('db')();
      const res: DashboardResponse = await dashboard(
        db,
        c.get('user'),
        range as DashboardRange,
        now(),
      );
      return c.json(res);
    },
  );
}
