import { findingListQuerySchema, type ReportSummaryResponse } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseQuery } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { exportFindingsCsv, reportSummary } from '../services/reports.ts';
import type { AppBindings } from '../types.ts';

export interface ReportRouteDeps {
  now?: () => Date;
}

/** CSV export filters: the GET /findings filters without paging. */
const csvQuerySchema = findingListQuerySchema.omit({ page: true, pageSize: true });

/** Reports (design §10, §14). Mounted at /api/v1/reports on the authenticated app. */
export function reportRoutes(deps: ReportRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .get('/summary', requirePermission('reports:read'), async (c) => {
      const db = await c.get('db')();
      const res: ReportSummaryResponse = await reportSummary(db, c.get('user'), now());
      return c.json(res);
    })
    .get('/findings.csv', requirePermission('reports:generate'), async (c) => {
      const query = parseQuery(c, csvQuerySchema);
      const db = await c.get('db')();
      const user = c.get('user');
      const { csv, rows, truncated } = await exportFindingsCsv(db, user, query, {
        userId: user.id,
        requestId: c.get('requestId'),
      });
      c.get('logger').info('report_exported', { report: 'findings.csv', rows, truncated });
      const stamp = now().toISOString().slice(0, 10).replace(/-/g, '');
      return c.body(csv, 200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="findings-${stamp}.csv"`,
        ...(truncated ? { 'X-Truncated': 'true' } : {}),
      });
    });
}
