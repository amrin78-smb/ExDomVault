// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { RATE_LIMITS, errorResponseSchema, type Role } from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  MemoryRateLimiter,
  RATE_LIMIT_BINDINGS,
  RATE_LIMIT_PERIOD_SECONDS,
  type RateLimiter,
} from '../lib/rate-limit.ts';
import { harness, userCall, type Harness } from '../testing/harness.ts';

let t: TestDatabase;
const clock = () => new Date('2026-10-23T12:00:00.000Z');
let warnings: string[] = [];

beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});
beforeEach(() => {
  warnings = [];
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation((line: unknown) => {
    warnings.push(String(line));
  });
});
afterEach(() => vi.restoreAllMocks());

function withLimiters(requests: RateLimiter, mutations: RateLimiter): Harness {
  return harness(() => t, clock, { rateLimit: { limiters: { requests, mutations } } });
}

const get = (h: Harness, role: Role = 'viewer', env?: Record<string, string>) =>
  userCall(h, t, role, 'GET', '/me', undefined, env);
// /me has no PUT handler: passes the middleware chain and answers 404 when not limited.
const put = (h: Harness, role: Role = 'viewer') => userCall(h, t, role, 'PUT', '/me', {});

describe('MemoryRateLimiter', () => {
  it('counts per key in fixed windows', async () => {
    let now = 0;
    const l = new MemoryRateLimiter(2, 60, () => now);
    expect((await l.limit({ key: 'a' })).success).toBe(true);
    expect((await l.limit({ key: 'a' })).success).toBe(true);
    expect((await l.limit({ key: 'a' })).success).toBe(false);
    expect((await l.limit({ key: 'b' })).success).toBe(true);
    now = 60_000;
    expect((await l.limit({ key: 'a' })).success).toBe(true);
  });
});

describe('per-user API rate limits', () => {
  it('answers 429 rate_limited with Retry-After and the error envelope over the request limit', async () => {
    const h = withLimiters(new MemoryRateLimiter(3), new MemoryRateLimiter(100));
    for (let i = 0; i < 3; i++) expect((await get(h)).status).toBe(200);
    const res = await get(h);
    expect(res.status).toBe(429);
    expect(res.headers.get('Retry-After')).toBe(String(RATE_LIMIT_PERIOD_SECONDS));
    expect(res.headers.get('X-Request-Id')).toBeTruthy();
    const body = errorResponseSchema.parse(await res.json());
    expect(body.error.code).toBe('rate_limited');
    expect(body.error.requestId).toBe(res.headers.get('X-Request-Id'));
    expect(warnings.some((w) => w.includes('"message":"rate_limited"'))).toBe(true);
  });

  it('keys limits by user: one user hitting the limit does not affect another', async () => {
    const h = withLimiters(new MemoryRateLimiter(1), new MemoryRateLimiter(100));
    expect((await get(h, 'viewer')).status).toBe(200);
    expect((await get(h, 'viewer')).status).toBe(429);
    expect((await get(h, 'analyst')).status).toBe(200);
  });

  it('limits mutations separately (and they also count as requests)', async () => {
    const requests = new MemoryRateLimiter(100);
    const h = withLimiters(requests, new MemoryRateLimiter(2));
    expect((await put(h)).status).toBe(404);
    expect((await put(h)).status).toBe(404);
    const res = await put(h);
    expect(res.status).toBe(429);
    expect(res.headers.get('Retry-After')).toBe('60');
    // Reads still work for the same user.
    expect((await get(h)).status).toBe(200);
  });

  it('degrades open when the binding throws, with a warning', async () => {
    const broken: RateLimiter = { limit: () => Promise.reject(new Error('binding down')) };
    const h = withLimiters(broken, broken);
    expect((await get(h)).status).toBe(200);
    expect((await put(h)).status).toBe(404);
    expect(warnings.some((w) => w.includes('rate_limiter_unavailable'))).toBe(true);
  });

  it('uses the environment bindings when nothing is injected', async () => {
    const h = harness(() => t, clock);
    const binding = new MemoryRateLimiter(1);
    const env = h.env('viewer');
    const app = (await import('../app.ts')).createApp(h.deps);
    const call = () =>
      app.request('/api/v1/me', {}, { ...env, API_RATE_LIMITER: binding } as unknown as Env);
    expect((await call()).status).toBe(200);
    expect((await call()).status).toBe(429);
  });

  it('runs after authentication: anonymous requests are never counted', async () => {
    const limiter = { limit: vi.fn(() => Promise.resolve({ success: false })) };
    const h = withLimiters(limiter, limiter);
    const app = (await import('../app.ts')).createApp(h.deps);
    const res = await app.request('/api/v1/me', {}, {
      ...h.env('viewer'),
      AUTH_PROVIDER: 'cloudflare_access',
      APP_ENV: 'production',
    } as unknown as Env);
    expect(res.status).not.toBe(429);
    expect(limiter.limit).not.toHaveBeenCalled();
  });
});

describe('wrangler.jsonc rate limit bindings', () => {
  it('match RATE_LIMITS', () => {
    const text = readFileSync(
      fileURLToPath(new URL('../../wrangler.jsonc', import.meta.url).href),
      'utf8',
    );
    for (const { binding, limit } of Object.values(RATE_LIMIT_BINDINGS)) {
      const block = new RegExp(
        `"name":\\s*"${binding}",\\s*"namespace_id":\\s*"\\d+",\\s*"simple":\\s*\\{\\s*"limit":\\s*(\\d+),\\s*"period":\\s*(\\d+)`,
      ).exec(text);
      expect(block, binding).not.toBeNull();
      expect(Number(block![1])).toBe(limit);
      expect(Number(block![2])).toBe(RATE_LIMIT_PERIOD_SECONDS);
    }
    expect(RATE_LIMIT_BINDINGS.requests.limit).toBe(RATE_LIMITS.requestsPerMinute);
    expect(RATE_LIMIT_BINDINGS.mutations.limit).toBe(RATE_LIMITS.mutationsPerMinute);
  });
});
