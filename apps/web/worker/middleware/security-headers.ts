import { createMiddleware } from 'hono/factory';
import type { AppBindings } from '../types.ts';

/** Baseline security headers for API responses. */
export const securityHeaders = () =>
  createMiddleware<AppBindings>(async (c, next) => {
    await next();
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('X-Frame-Options', 'DENY');
    c.header('Cache-Control', 'no-store');
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  });
