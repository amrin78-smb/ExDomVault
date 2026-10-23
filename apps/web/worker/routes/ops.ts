import {
  hasPermission,
  type OpsAlertsResponse,
  type OpsHealthResponse,
} from '@exdomainvault/shared';
import { Hono } from 'hono';
import { requirePermission } from '../middleware/auth.ts';
import { opsAlerts, opsHealth } from '../services/ops.ts';
import type { AppBindings } from '../types.ts';

/** Operations: health dashboard (administrators) and the alert banner (every signed-in user). */
export function opsRoutes(deps: { now?: () => Date } = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .get('/health', requirePermission('settings:manage'), async (c) => {
      const db = await c.get('db')();
      const res: OpsHealthResponse = await opsHealth(db, now());
      return c.json(res);
    })
    .get('/alerts', async (c) => {
      const db = await c.get('db')();
      const res: OpsAlertsResponse = await opsAlerts(db, now(), {
        admin: hasPermission(c.get('user').role, 'settings:manage'),
        activeScanningEnabled: c.get('config').activeScanningEnabled,
      });
      return c.json(res);
    });
}
