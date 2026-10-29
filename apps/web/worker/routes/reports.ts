import {
  findingListQuerySchema,
  monthlyPeriodSchema,
  monthlyReportGenerateRequestSchema,
  type MonthlyReportListResponse,
  type MonthlyReportResponse,
  type ReportSummaryResponse,
} from '@exdomainvault/shared';
import { Hono, type Context } from 'hono';
import { ApiError } from '../lib/errors.ts';
import { csvHeaders, exportStamp } from '../lib/csv-export.ts';
import { parseJsonBody, parseQuery } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { exportFindingsCsv, reportSummary } from '../services/reports.ts';
import {
  generateMonthlyReport,
  getMonthlyReport,
  listMonthlyReports,
} from '../services/monthly-reports.ts';
import type { AppBindings } from '../types.ts';

export interface ReportRouteDeps {
  now?: () => Date;
}

/** CSV export filters: the GET /findings filters without paging. */
const csvQuerySchema = findingListQuerySchema.omit({ page: true, pageSize: true });

/**
 * Monthly reports are organisation-wide; asset owners (whose access is limited to their own assets)
 * are refused even though they hold `reports:read`.
 */
function refuseAssetOwners(c: Context<AppBindings>) {
  if (c.get('user').role === 'asset_owner') {
    throw new ApiError(
      403,
      'forbidden',
      'Monthly reports cover the whole organisation and are not available to asset owners.',
    );
  }
}

/** Reports (design §10, §14). Mounted at /api/v1/reports on the authenticated app. */
export function reportRoutes(deps: ReportRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return (
    new Hono<AppBindings>()
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
        return c.body(
          csv,
          200,
          csvHeaders({ filename: `findings-${exportStamp(now())}.csv`, truncated }),
        );
      })
      // Monthly executive reports (Milestone 14).
      .get('/monthly', requirePermission('reports:read'), async (c) => {
        refuseAssetOwners(c);
        const db = await c.get('db')();
        const res: MonthlyReportListResponse = await listMonthlyReports(db);
        return c.json(res);
      })
      .post('/monthly/generate', requirePermission('settings:manage'), async (c) => {
        const { period } = await parseJsonBody(c, monthlyReportGenerateRequestSchema);
        const db = await c.get('db')();
        const user = c.get('user');
        const report = await generateMonthlyReport(
          db,
          period,
          { userId: user.id, requestId: c.get('requestId') },
          now(),
        );
        c.get('logger').info('monthly_report_generated', { period: report.period });
        const res: MonthlyReportResponse = { report };
        return c.json(res, 201);
      })
      .get('/monthly/:period', requirePermission('reports:read'), async (c) => {
        refuseAssetOwners(c);
        const parsed = monthlyPeriodSchema.safeParse(c.req.param('period'));
        if (!parsed.success) {
          throw new ApiError(400, 'validation_failed', 'The report period is invalid.', [
            { path: 'period', message: 'Use the form YYYY-MM.' },
          ]);
        }
        const db = await c.get('db')();
        const res: MonthlyReportResponse = { report: await getMonthlyReport(db, parsed.data) };
        return c.json(res);
      })
  );
}
