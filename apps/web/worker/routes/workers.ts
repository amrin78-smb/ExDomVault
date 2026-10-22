import {
  addWorkerCredentialRequestSchema,
  registerWorkerRequestSchema,
  updateWorkerRequestSchema,
} from '@exdomainvault/shared';
import { Hono, type Context } from 'hono';
import { parseJsonBody, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import type { Actor } from '../services/domains.ts';
import {
  addCredential,
  listWorkers,
  registerWorker,
  revokeCredential,
  setWorkerStatus,
} from '../services/workers.ts';
import type { AppBindings } from '../types.ts';

const actorOf = (c: Context<AppBindings>): Actor => ({
  userId: c.get('user').id,
  requestId: c.get('requestId'),
});

/** Administration of scanning workers and their public keys (admin only). */
export function workerAdminRoutes(deps: { now?: () => Date } = {}) {
  const now = deps.now ?? (() => new Date());
  return new Hono<AppBindings>()
    .use('*', requirePermission('settings:manage'))
    .get('/', async (c) => {
      const db = await c.get('db')();
      return c.json({ items: await listWorkers(db) });
    })
    .post('/', async (c) => {
      const body = await parseJsonBody(c, registerWorkerRequestSchema);
      const db = await c.get('db')();
      return c.json(await registerWorker(db, body, actorOf(c), now()), 201);
    })
    .patch('/:id', async (c) => {
      const id = uuidParam(c, 'id');
      const { status } = await parseJsonBody(c, updateWorkerRequestSchema);
      const db = await c.get('db')();
      return c.json({ worker: await setWorkerStatus(db, id, status, actorOf(c)) });
    })
    .post('/:id/credentials', async (c) => {
      const id = uuidParam(c, 'id');
      const body = await parseJsonBody(c, addWorkerCredentialRequestSchema);
      const db = await c.get('db')();
      return c.json(await addCredential(db, id, body, actorOf(c), now()), 201);
    })
    .post('/:id/credentials/:credentialId/revoke', async (c) => {
      const id = uuidParam(c, 'id');
      const credentialId = uuidParam(c, 'credentialId');
      const db = await c.get('db')();
      return c.json({ worker: await revokeCredential(db, id, credentialId, actorOf(c), now()) });
    });
}
