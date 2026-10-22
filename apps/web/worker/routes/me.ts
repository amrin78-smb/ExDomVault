import { ROLE_PERMISSIONS, type MeResponse } from '@exdomainvault/shared';
import { Hono } from 'hono';
import type { AppBindings } from '../types.ts';

/** The signed-in user and their effective permissions. */
export const meRoutes = new Hono<AppBindings>().get('/', (c) => {
  const user = c.get('user');
  const body: MeResponse = {
    user,
    permissions: [...ROLE_PERMISSIONS[user.role]],
    authProvider: c.get('identity').provider,
  };
  return c.json(body);
});
