import { createMiddleware } from 'hono/factory';
import { ApiError } from '../lib/errors.ts';
import type { AppBindings } from '../types.ts';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * CSRF protection for cookie-authenticated (Cloudflare Access) requests: state-changing requests
 * must come from this origin. Browsers always send `Origin` on cross-origin and same-origin
 * POST/PUT/PATCH/DELETE requests made with fetch, so a missing or foreign Origin is rejected.
 */
export const sameOriginWrites = () =>
  createMiddleware<AppBindings>(async (c, next) => {
    if (!SAFE_METHODS.has(c.req.method)) {
      const origin = c.req.header('Origin');
      if (!origin || origin !== new URL(c.req.url).origin) {
        c.get('logger').warn('csrf_rejected', { origin: origin ?? null, method: c.req.method });
        throw new ApiError(403, 'forbidden', 'Cross-origin request rejected.');
      }
    }
    await next();
  });
