import {
  EXPORT_MAX_ROWS,
  assetListQuerySchema,
  auditListQuerySchema,
  certificatesQuerySchema,
  domainListQuerySchema,
  portsQuerySchema,
  scanJobListQuerySchema,
  softwareListQuerySchema,
  userListQuerySchema,
  vulnerabilitiesQuerySchema,
  type ExportResource,
} from '@exdomainvault/shared';
import { Hono, type Context } from 'hono';
import type { z } from 'zod';
import { auditFilters, csvHeaders, exportStamp } from '../lib/csv-export.ts';
import { parseQuery } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import {
  loadAdvisories,
  loadAssets,
  loadAuditLogs,
  loadCertificates,
  loadDomains,
  loadPorts,
  loadScans,
  loadSoftware,
  loadUsers,
  loadVulnerabilities,
  runExport,
  type Loader,
} from '../services/exports.ts';
import type { AppBindings } from '../types.ts';
import { advisoryListQuerySchema } from './advisories.ts';

export interface ExportRouteDeps {
  now?: () => Date;
  /** Row cap (tests use a small one); defaults to EXPORT_MAX_ROWS. */
  maxRows?: number;
}

const NO_PAGING = { page: true, pageSize: true } as const;

/**
 * CSV exports, one per list (contract: packages/shared/src/api/exports.ts). Each accepts its
 * list's query schema (paging ignored) and permission. Mounted at /api/v1/exports.
 */
export function exportRoutes(deps: ExportRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  const maxRows = deps.maxRows ?? EXPORT_MAX_ROWS;

  const handler =
    <S extends z.ZodType<Record<string, unknown>>>(
      resource: ExportResource,
      querySchema: S,
      load: Loader<z.output<S>>,
    ) =>
    async (c: Context<AppBindings>) => {
      const q = parseQuery(c, querySchema);
      const db = await c.get('db')();
      const user = c.get('user');
      const at = now();
      const res = await runExport(
        db,
        {
          resource,
          filters: auditFilters(q),
          actor: { userId: user.id, requestId: c.get('requestId') },
          maxRows,
        },
        (tx, limit) => load(tx, user, q, at, limit),
      );
      c.get('logger').info('report_exported', {
        report: `${resource}.csv`,
        rows: res.rows,
        truncated: res.truncated,
      });
      return c.body(
        res.csv,
        200,
        csvHeaders({
          filename: `exdomainvault-${resource}-${exportStamp(at)}.csv`,
          truncated: res.truncated,
          totalRows: res.totalRows,
        }),
      );
    };

  return (
    new Hono<AppBindings>()
      .get(
        '/domains.csv',
        requirePermission('domains:read'),
        handler('domains', domainListQuerySchema.omit(NO_PAGING), loadDomains),
      )
      .get(
        '/assets.csv',
        requirePermission('assets:read'),
        handler('assets', assetListQuerySchema.omit(NO_PAGING), loadAssets),
      )
      .get(
        '/advisories.csv',
        requirePermission('findings:read'),
        handler('advisories', advisoryListQuerySchema.omit(NO_PAGING), loadAdvisories),
      )
      .get(
        '/software.csv',
        requirePermission('findings:read'),
        handler('software', softwareListQuerySchema.omit(NO_PAGING), loadSoftware),
      )
      .get(
        '/scans.csv',
        requirePermission('scans:read'),
        handler('scans', scanJobListQuerySchema.omit(NO_PAGING), loadScans),
      )
      .get(
        '/users.csv',
        requirePermission('users:manage'),
        handler('users', userListQuerySchema.omit(NO_PAGING), loadUsers),
      )
      .get(
        '/audit-logs.csv',
        requirePermission('audit:read'),
        handler('audit-logs', auditListQuerySchema.omit(NO_PAGING), loadAuditLogs),
      )
      // Milestone 13 inventory views: the list's permission (GET /ports, /certificates: assets:read;
      // GET /vulnerabilities: findings:read, like /software).
      .get(
        '/ports.csv',
        requirePermission('assets:read'),
        handler('ports', portsQuerySchema.omit(NO_PAGING), loadPorts),
      )
      .get(
        '/certificates.csv',
        requirePermission('assets:read'),
        handler('certificates', certificatesQuerySchema.omit(NO_PAGING), loadCertificates),
      )
      .get(
        '/vulnerabilities.csv',
        requirePermission('findings:read'),
        handler('vulnerabilities', vulnerabilitiesQuerySchema.omit(NO_PAGING), loadVulnerabilities),
      )
  );
}
