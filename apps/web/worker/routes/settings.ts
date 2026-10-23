import { scanScheduleSchema, type ScanScheduleResponse } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseJsonBody } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import { getScanScheduleResponse, updateScanSchedule } from '../services/scan-schedule.ts';
import type { AppBindings } from '../types.ts';

/** Application settings. Currently: the scheduled active-scan policy. */
export function settingsRoutes(deps: { now?: () => Date } = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .get('/scan-schedule', requirePermission('scans:read'), async (c) => {
      const db = await c.get('db')();
      const res: ScanScheduleResponse = await getScanScheduleResponse(db, now(), {
        activeScanningEnabled: c.get('config').activeScanningEnabled,
      });
      return c.json(res);
    })
    .put('/scan-schedule', requirePermission('scan_policies:manage'), async (c) => {
      const body = await parseJsonBody(c, scanScheduleSchema);
      const db = await c.get('db')();
      const at = now();
      await updateScanSchedule(
        db,
        body,
        { userId: c.get('user').id, requestId: c.get('requestId') },
        at,
      );
      c.get('logger').info('scan_schedule_updated', { ...body });
      const res: ScanScheduleResponse = await getScanScheduleResponse(db, at, {
        activeScanningEnabled: c.get('config').activeScanningEnabled,
      });
      return c.json(res);
    });
}
