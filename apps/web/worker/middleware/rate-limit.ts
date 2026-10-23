import { createMiddleware } from 'hono/factory';
import { errorFields } from '../lib/logger.ts';
import { rateLimited } from '../lib/errors.ts';
import {
  RATE_LIMIT_BINDINGS,
  RATE_LIMIT_PERIOD_SECONDS,
  type RateLimitDeps,
  type RateLimiter,
  type RateLimiterName,
} from '../lib/rate-limit.ts';
import type { AppBindings } from '../types.ts';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Per-user request rate limits (RATE_LIMITS): every authenticated request counts against
 * `requestsPerMinute`; state-changing requests also count against `mutationsPerMinute`. Must run
 * after requireAuth (the key is the user ID, never an IP or a client-supplied value).
 *
 * Mechanism: Cloudflare Workers Rate Limiting bindings, which work across isolates. Degrades open:
 * a missing binding or a binding error lets the request through with a warning log, so a limiter
 * outage never takes the API down (Cloudflare Access still fronts every request).
 */
export const rateLimit = (deps: RateLimitDeps = {}) =>
  createMiddleware<AppBindings>(async (c, next) => {
    const user = c.get('user');
    const logger = c.get('logger');
    const env = c.env as unknown as Record<string, unknown> | undefined;

    const limiterFor = (name: RateLimiterName): RateLimiter | null => {
      const injected = deps.limiters?.[name];
      if (injected) return injected;
      const binding = env?.[RATE_LIMIT_BINDINGS[name].binding] as RateLimiter | undefined;
      return binding && typeof binding.limit === 'function' ? binding : null;
    };

    const check = async (name: RateLimiterName): Promise<boolean> => {
      const limiter = limiterFor(name);
      if (!limiter) {
        if (c.get('config').environment === 'production') {
          logger.warn('rate_limiter_unavailable', { limiter: name, reason: 'binding_missing' });
        }
        return true;
      }
      try {
        return (await limiter.limit({ key: `user:${user.id}` })).success;
      } catch (err) {
        logger.warn('rate_limiter_unavailable', { limiter: name, ...errorFields(err) });
        return true;
      }
    };

    const names: RateLimiterName[] = SAFE_METHODS.has(c.req.method)
      ? ['requests']
      : ['requests', 'mutations'];
    for (const name of names) {
      if (!(await check(name))) {
        logger.warn('rate_limited', { limiter: name, userId: user.id, method: c.req.method });
        throw rateLimited('Too many requests. Try again shortly.', RATE_LIMIT_PERIOD_SECONDS);
      }
    }
    await next();
  });
