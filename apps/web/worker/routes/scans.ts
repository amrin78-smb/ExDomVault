import {
  DISCOVERY_PROFILE_KEY,
  scanJobListQuerySchema,
  type ScanJobDetailResponse,
  type ScanProfileListResponse,
} from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseQuery, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { cancelScan, getScan, listProfiles, listScans } from '../services/scans.ts';
import type { AppBindings } from '../types.ts';

export interface ScanRouteDeps {
  now?: () => Date;
}

export function scanProfileRoutes() {
  return new Hono<AppBindings>().get('/', requirePermission('scans:read'), async (c) => {
    const db = await c.get('db')();
    const res: ScanProfileListResponse = {
      // Discovery is a job type of its own (POST /domains/:id/discovery), not a scan profile.
      items: (await listProfiles(db)).filter((p) => p.key !== DISCOVERY_PROFILE_KEY),
      activeScanningEnabled: c.get('config').activeScanningEnabled,
    };
    return c.json(res);
  });
}

export function scanRoutes(deps: ScanRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .get('/', requirePermission('scans:read'), async (c) => {
      const query = parseQuery(c, scanJobListQuerySchema);
      const db = await c.get('db')();
      return c.json(await listScans(db, query));
    })
    .get('/:id', requirePermission('scans:read'), async (c) => {
      const id = uuidParam(c, 'id');
      const db = await c.get('db')();
      const res: ScanJobDetailResponse = await getScan(db, id);
      return c.json(res);
    })
    .post('/:id/cancel', requirePermission('scans:request'), async (c) => {
      const id = uuidParam(c, 'id');
      const db = await c.get('db')();
      await cancelScan(db, id, { userId: c.get('user').id, requestId: c.get('requestId') }, now());
      c.get('logger').info('scan_cancel', { jobId: id });
      return c.json(await getScan(db, id));
    });
}
