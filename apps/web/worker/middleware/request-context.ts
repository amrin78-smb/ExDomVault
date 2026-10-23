import type { Context } from 'hono';
import { createMiddleware } from 'hono/factory';
import { createLogger } from '../lib/logger.ts';
import type { AppBindings } from '../types.ts';

export const REQUEST_ID_HEADER = 'X-Request-Id';

/**
 * Assigns a server-generated request ID and a request-scoped logger. Client-supplied request IDs
 * are not trusted; the generated ID is returned in the response header for correlation.
 */
export const requestContext = () =>
  createMiddleware<AppBindings>(async (c, next) => {
    const requestId = crypto.randomUUID();
    const logger = createLogger({ requestId });
    c.set('requestId', requestId);
    c.set('logger', logger);
    c.set('logFields', {});

    const started = Date.now();
    await next();

    c.header(REQUEST_ID_HEADER, requestId);
    logger.info('request', {
      ...c.get('logFields'),
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
      durationMs: Date.now() - started,
    });
  });

/**
 * Adds correlation fields (user, worker, job IDs) to this request: they appear on the final
 * `request` log line and on every later line written through `c.var.logger`.
 */
export function annotateRequest(c: Context<AppBindings>, fields: Record<string, unknown>): void {
  c.set('logFields', { ...c.get('logFields'), ...fields });
  c.set('logger', c.get('logger').child(fields));
}
