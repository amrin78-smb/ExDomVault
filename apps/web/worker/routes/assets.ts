import {
  assetApproveRequestSchema,
  assetBulkDecisionRequestSchema,
  assetDecisionRequestSchema,
  assetListQuerySchema,
  assetOwnerUpdateRequestSchema,
  type AssetBulkDecisionResponse,
  type AssetDetailResponse,
  type assetResponseSchema,
} from '@exdomainvault/shared';
import type { z } from 'zod';
import { Hono, type Context } from 'hono';
import { parseJsonBody, parseQuery, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import {
  decideAsset,
  decideAssets,
  getAsset,
  listAssets,
  setAssetOwner,
} from '../services/assets.ts';
import type { Actor } from '../services/domains.ts';
import type { AppBindings } from '../types.ts';

type AssetResponse = z.infer<typeof assetResponseSchema>;

export interface AssetRouteDeps {
  now?: () => Date;
}

const actorOf = (c: Context<AppBindings>): Actor => ({
  userId: c.get('user').id,
  requestId: c.get('requestId'),
});

/** Asset inventory (design §10 Assets). Mounted at /api/v1/assets on the authenticated app. */
export function assetRoutes(deps: AssetRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());

  return (
    new Hono<AppBindings>()
      .get('/', requirePermission('assets:read'), async (c) => {
        const query = parseQuery(c, assetListQuerySchema);
        const db = await c.get('db')();
        return c.json(await listAssets(db, c.get('user'), query));
      })
      // Registered before /:id so `bulk` is never read as an id.
      .post('/bulk', requirePermission('assets:approve'), async (c) => {
        const body = await parseJsonBody(c, assetBulkDecisionRequestSchema);
        const db = await c.get('db')();
        const { updated, skipped } = await decideAssets(
          db,
          c.get('user'),
          body.ids,
          {
            action: body.action,
            reason: body.reason,
            acknowledgeThirdPartyHosting: body.acknowledgeThirdPartyHosting,
          },
          actorOf(c),
          now(),
          true,
        );
        c.get('logger').info('assets_bulk_decision', {
          action: body.action,
          updated,
          skipped: skipped.length,
        });
        const res: AssetBulkDecisionResponse = { updated, skipped };
        return c.json(res);
      })
      .get('/:id', requirePermission('assets:read'), async (c) => {
        const id = uuidParam(c, 'id');
        const db = await c.get('db')();
        const res: AssetDetailResponse = await getAsset(db, c.get('user'), id);
        return c.json(res);
      })
      .patch('/:id', requirePermission('assets:approve'), async (c) => {
        const id = uuidParam(c, 'id');
        const { ownerUserId } = await parseJsonBody(c, assetOwnerUpdateRequestSchema);
        const db = await c.get('db')();
        await setAssetOwner(db, id, ownerUserId, actorOf(c), now());
        c.get('logger').info('asset_owner_changed', { assetId: id });
        const res: AssetResponse = { asset: (await getAsset(db, c.get('user'), id)).asset };
        return c.json(res);
      })
      .post('/:id/approve', requirePermission('assets:approve'), async (c) => {
        const id = uuidParam(c, 'id');
        const body = await parseJsonBody(c, assetApproveRequestSchema);
        const db = await c.get('db')();
        await decideAsset(db, c.get('user'), id, { action: 'approve', ...body }, actorOf(c), now());
        c.get('logger').info('asset_decision', { assetId: id, action: 'approve' });
        const res: AssetResponse = { asset: (await getAsset(db, c.get('user'), id)).asset };
        return c.json(res);
      })
      .post('/:id/reject', requirePermission('assets:approve'), async (c) => decision(c, 'reject'))
      .post('/:id/suspend', requirePermission('assets:approve'), async (c) =>
        decision(c, 'suspend'),
      )
  );

  async function decision(c: Context<AppBindings>, action: 'reject' | 'suspend') {
    const id = uuidParam(c, 'id');
    const { reason } = await parseJsonBody(c, assetDecisionRequestSchema);
    const db = await c.get('db')();
    await decideAsset(
      db,
      c.get('user'),
      id,
      { action, reason, acknowledgeThirdPartyHosting: false },
      actorOf(c),
      now(),
    );
    c.get('logger').info('asset_decision', { assetId: id, action });
    const res: AssetResponse = { asset: (await getAsset(db, c.get('user'), id)).asset };
    return c.json(res);
  }
}
