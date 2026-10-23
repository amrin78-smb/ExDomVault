import {
  userCreateRequestSchema,
  userListQuerySchema,
  userUpdateRequestSchema,
  type UserListResponse,
  type userResponseSchema,
} from '@exdomainvault/shared';
import { Hono, type Context } from 'hono';
import type { z } from 'zod';
import { ApiError } from '../lib/errors.ts';
import { parseJsonBody, parseQuery, uuidParam } from '../lib/validation.ts';
import { requirePermission } from '../middleware/auth.ts';
import type { Actor } from '../services/domains.ts';
import { listAssignableUsers } from '../services/finding-lifecycle.ts';
import { createUser, getUser, listUsers, updateUser } from '../services/user-admin.ts';
import type { AppBindings } from '../types.ts';

type UserResponse = z.infer<typeof userResponseSchema>;

export interface UserRouteDeps {
  now?: () => Date;
}

const actorOf = (c: Context<AppBindings>): Actor => ({
  userId: c.get('user').id,
  requestId: c.get('requestId'),
});

/**
 * Users: the assignee picker (`findings:assign`) and user administration (`users:manage`).
 * Mounted at /api/v1/users on the authenticated app.
 */
export function userRoutes(deps: UserRouteDeps = {}) {
  const now = deps.now ?? (() => new Date());
  return (
    new Hono<AppBindings>()
      // Registered before /:id so `assignable` is never read as an id.
      .get('/assignable', requirePermission('findings:assign'), async (c) => {
        const db = await c.get('db')();
        return c.json(await listAssignableUsers(db));
      })
      .get('/', requirePermission('users:manage'), async (c) => {
        const query = parseQuery(c, userListQuerySchema);
        const db = await c.get('db')();
        const res: UserListResponse = await listUsers(db, query);
        return c.json(res);
      })
      .post('/', requirePermission('users:manage'), async (c) => {
        const body = await parseJsonBody(c, userCreateRequestSchema);
        const auth = c.get('config').auth;
        // requireAuth has already refused requests when authentication is unconfigured.
        if (auth.kind === 'unconfigured') {
          throw new ApiError(503, 'service_unavailable', 'Authentication is not configured.');
        }
        const db = await c.get('db')();
        const user = await createUser(db, body, auth.kind, actorOf(c));
        c.get('logger').info('user_created', { userId: user.id, role: user.role });
        const res: UserResponse = { user };
        return c.json(res, 201);
      })
      .get('/:id', requirePermission('users:manage'), async (c) => {
        const id = uuidParam(c, 'id');
        const db = await c.get('db')();
        const res: UserResponse = { user: await getUser(db, id) };
        return c.json(res);
      })
      .patch('/:id', requirePermission('users:manage'), async (c) => {
        const id = uuidParam(c, 'id');
        const body = await parseJsonBody(c, userUpdateRequestSchema);
        const db = await c.get('db')();
        const user = await updateUser(db, id, body, actorOf(c), now());
        c.get('logger').info('user_updated', { userId: id });
        const res: UserResponse = { user };
        return c.json(res);
      })
  );
}
