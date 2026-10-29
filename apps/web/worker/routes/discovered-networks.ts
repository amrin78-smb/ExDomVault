import {
  discoverySettingsSchema,
  type DiscoveredNetworksResponse,
  type DiscoverySettingsResponse,
} from '@exdomainvault/shared';
import { Hono } from 'hono';
import { parseJsonBody } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import {
  getDiscoverySettings,
  listDiscoveredNetworks,
  updateDiscoverySettings,
} from '../services/discovered-networks.ts';
import type { AppBindings } from '../types.ts';

/**
 * Milestone 15 — wider discovery. `GET /networks/discovered`: IP networks (RDAP) hosting the
 * visible assets, matched against the organisation names (asset owners: only networks containing
 * their assets). Display only; approving a network for scanning stays in /approved-networks.
 */
export function discoveredNetworkRoutes() {
  return new Hono<AppBindings>().get('/discovered', requirePermission('assets:read'), async (c) => {
    const db = await c.get('db')();
    const res: DiscoveredNetworksResponse = await listDiscoveredNetworks(db, c.get('user'));
    return c.json(res);
  });
}

/** `GET|PUT /settings/discovery`: organisation names used to recognise our networks (admin). */
export function discoverySettingsRoutes(deps: { now?: () => Date } = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .use('*', requirePermission('settings:manage'))
    .get('/', async (c) => {
      const db = await c.get('db')();
      const res: DiscoverySettingsResponse = await getDiscoverySettings(db);
      return c.json(res);
    })
    .put('/', async (c) => {
      const body = await parseJsonBody(c, discoverySettingsSchema);
      const db = await c.get('db')();
      await updateDiscoverySettings(
        db,
        body,
        { userId: c.get('user').id, requestId: c.get('requestId') },
        now(),
      );
      c.get('logger').info('discovery_settings_updated', { orgNames: body.orgNames.length });
      const res: DiscoverySettingsResponse = await getDiscoverySettings(db);
      return c.json(res);
    });
}
