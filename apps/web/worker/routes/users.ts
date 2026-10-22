import { Hono } from 'hono';
import { requirePermission } from '../middleware/auth.ts';
import { listAssignableUsers } from '../services/finding-lifecycle.ts';
import type { AppBindings } from '../types.ts';

/** Users (Milestone 8: the assignee picker only; user administration comes later). */
export function userRoutes() {
  return new Hono<AppBindings>().get(
    '/assignable',
    requirePermission('findings:assign'),
    async (c) => {
      const db = await c.get('db')();
      return c.json(await listAssignableUsers(db));
    },
  );
}
