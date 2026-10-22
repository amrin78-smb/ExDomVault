import { createMiddleware } from 'hono/factory';
import { loadConfig } from '../config.ts';
import type { AppBindings } from '../types.ts';

/** Loads and validates configuration per request; invalid configuration fails the request closed. */
export const configMiddleware = () =>
  createMiddleware<AppBindings>(async (c, next) => {
    c.set('config', loadConfig(c.env as unknown as Record<string, unknown>));
    await next();
  });
