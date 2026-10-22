import {
  createApprovedNetworkRequestSchema,
  revokeApprovedNetworkRequestSchema,
} from '@exdomainvault/shared';
import { Hono, type Context } from 'hono';
import { parseJsonBody, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import type { Actor } from '../services/domains.ts';
import { createNetwork, listNetworks, revokeNetwork } from '../services/networks.ts';
import type { AppBindings } from '../types.ts';

const actorOf = (c: Context<AppBindings>): Actor => ({
  userId: c.get('user').id,
  requestId: c.get('requestId'),
});

/** Administration of the networks network-tier checks may probe (scan policy, admin only). */
export function approvedNetworkRoutes(deps: { now?: () => Date } = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .use('*', requirePermission('scan_policies:manage'))
    .get('/', async (c) => {
      const db = await c.get('db')();
      return c.json({ items: await listNetworks(db) });
    })
    .post('/', async (c) => {
      const body = await parseJsonBody(c, createApprovedNetworkRequestSchema);
      const db = await c.get('db')();
      const network = await createNetwork(db, body, actorOf(c), now());
      c.get('logger').info('network_approved', { networkId: network.id, cidr: network.cidr });
      return c.json(network, 201);
    })
    .post('/:id/revoke', async (c) => {
      const id = uuidParam(c, 'id');
      const { reason } = await parseJsonBody(c, revokeApprovedNetworkRequestSchema);
      const db = await c.get('db')();
      const network = await revokeNetwork(db, id, reason, actorOf(c), now());
      c.get('logger').info('network_revoked', { networkId: id });
      return c.json(network);
    });
}
