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

    const started = Date.now();
    await next();

    c.header(REQUEST_ID_HEADER, requestId);
    logger.info('request', {
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
      durationMs: Date.now() - started,
    });
  });
