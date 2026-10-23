import { RATE_LIMITS } from '@exdomainvault/shared';

/**
 * The shape of a Cloudflare Workers Rate Limiting binding (`ratelimits` in wrangler.jsonc).
 * Counters are kept per Cloudflare location and are eventually consistent across isolates, so the
 * limits are approximate (a burst may slightly exceed them). That is acceptable for abuse protection
 * of an authenticated API; exact limits (scan quotas) are counted in PostgreSQL instead.
 */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export type RateLimiterName = 'requests' | 'mutations';

export interface RateLimitDeps {
  /** Overrides the environment bindings (tests inject MemoryRateLimiter). */
  limiters?: Partial<Record<RateLimiterName, RateLimiter>>;
}

/** Window of both bindings (seconds); also the `Retry-After` answered when a limit is hit. */
export const RATE_LIMIT_PERIOD_SECONDS = 60;

/** Binding names in wrangler.jsonc and the limit each must be configured with. */
export const RATE_LIMIT_BINDINGS = {
  requests: { binding: 'API_RATE_LIMITER', limit: RATE_LIMITS.requestsPerMinute },
  mutations: { binding: 'MUTATION_RATE_LIMITER', limit: RATE_LIMITS.mutationsPerMinute },
} as const satisfies Record<RateLimiterName, { binding: string; limit: number }>;

/**
 * In-memory fixed-window limiter with the binding's interface. For tests and local reasoning only:
 * state lives in one isolate, so it is never used in production.
 */
export class MemoryRateLimiter implements RateLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  private readonly max: number;
  private readonly periodSeconds: number;
  private readonly clock: () => number;

  constructor(
    max: number,
    periodSeconds: number = RATE_LIMIT_PERIOD_SECONDS,
    clock: () => number = () => Date.now(),
  ) {
    this.max = max;
    this.periodSeconds = periodSeconds;
    this.clock = clock;
  }

  limit({ key }: { key: string }): Promise<{ success: boolean }> {
    const now = this.clock();
    const period = this.periodSeconds * 1000;
    const start = now - (now % period);
    const w = this.windows.get(key);
    if (!w || w.start !== start) {
      this.windows.set(key, { start, count: 1 });
      return Promise.resolve({ success: 1 <= this.max });
    }
    w.count += 1;
    return Promise.resolve({ success: w.count <= this.max });
  }
}
