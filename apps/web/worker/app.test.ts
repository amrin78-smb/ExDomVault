// @vitest-environment node
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { schema } from '@exdomainvault/database';
import { errorResponseSchema, healthResponseSchema, meResponseSchema } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp, type AppDeps } from './app.ts';
import { createLogger } from './lib/logger.ts';
import { handleError } from './lib/errors.ts';
import { requirePermission } from './middleware/auth.ts';
import type { AppBindings } from './types.ts';

const HYPERDRIVE = { connectionString: 'postgres://u:p@db.example.invalid/app' };

const baseEnv = { APP_ENV: 'development', APP_VERSION: '0.1.0-test' };
const devAuthEnv = {
  ...baseEnv,
  AUTH_PROVIDER: 'dev',
  DEV_AUTH_EMAIL: 'dev@example.com',
  DEV_AUTH_NAME: 'Local Developer',
  BOOTSTRAP_ADMIN_EMAILS: 'dev@example.com',
  HYPERDRIVE,
};

let t: TestDatabase;
beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});

beforeEach(() => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

const testDeps: AppDeps = {
  connect: async () => ({ db: t.db, close: async () => {} }),
  health: { pingDatabase: async () => ({ status: 'ok', latencyMs: 1 }) },
};

function request(
  path: string,
  env: Record<string, unknown> = devAuthEnv,
  init?: RequestInit,
  deps: AppDeps = testDeps,
) {
  return createApp(deps).request(path, init, env as unknown as Env);
}

describe('health', () => {
  it('reports database and auth status without authentication', async () => {
    const res = await request('/api/v1/health');
    expect(res.status).toBe(200);
    const body = healthResponseSchema.parse(await res.json());
    expect(body).toMatchObject({
      status: 'ok',
      environment: 'development',
      components: { database: 'ok', auth: 'ok' },
    });
  });

  it('reports unconfigured dependencies as degraded', async () => {
    const res = await request('/api/v1/health', baseEnv);
    const body = healthResponseSchema.parse(await res.json());
    expect(body.status).toBe('degraded');
    expect(body.components).toEqual({ database: 'not_configured', auth: 'not_configured' });
  });

  it('reports the database as down without leaking the failure detail', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await request('/api/v1/health', devAuthEnv, undefined, {
      ...testDeps,
      health: {
        pingDatabase: async () => ({
          status: 'down',
          latencyMs: 3000,
          error: 'password authentication failed for user "secret_user"',
        }),
      },
    });
    const text = await res.text();
    expect(healthResponseSchema.parse(JSON.parse(text)).components.database).toBe('down');
    expect(text).not.toContain('secret_user');
  });
});

describe('authentication', () => {
  it('returns 503 on protected routes when authentication is unconfigured (fail closed)', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await request('/api/v1/me', { ...baseEnv, HYPERDRIVE });
    expect(res.status).toBe(503);
    expect(errorResponseSchema.parse(await res.json()).error.code).toBe('service_unavailable');
  });

  it('returns 401 when Cloudflare Access credentials are missing', async () => {
    const res = await request('/api/v1/me', {
      ...baseEnv,
      AUTH_PROVIDER: 'cloudflare_access',
      ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com',
      ACCESS_AUD: 'aud',
      HYPERDRIVE,
    });
    expect(res.status).toBe(401);
    expect(errorResponseSchema.parse(await res.json()).error.code).toBe('unauthenticated');
  });

  it('does not trust identity headers sent by the client', async () => {
    const res = await request(
      '/api/v1/me',
      {
        ...baseEnv,
        AUTH_PROVIDER: 'cloudflare_access',
        ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com',
        ACCESS_AUD: 'aud',
        HYPERDRIVE,
      },
      { headers: { 'Cf-Access-Authenticated-User-Email': 'dev@example.com' } },
    );
    expect(res.status).toBe(401);
  });

  it('GET /me bootstraps the configured admin and returns their permissions', async () => {
    const res = await request('/api/v1/me');
    expect(res.status).toBe(200);
    const body = meResponseSchema.parse(await res.json());
    expect(body.user).toMatchObject({ email: 'dev@example.com', role: 'admin' });
    expect(body.permissions).toContain('users:manage');
    expect(body.authProvider).toBe('dev');
  });

  it('returns 403 for an authenticated identity that is not provisioned', async () => {
    const res = await request('/api/v1/me', {
      ...devAuthEnv,
      DEV_AUTH_EMAIL: 'stranger@example.com',
    });
    expect(res.status).toBe(403);
    expect(errorResponseSchema.parse(await res.json()).error.message).toMatch(/not been granted/);
  });

  it('returns 503 when the database is unreachable', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await request('/api/v1/me', devAuthEnv, undefined, {
      ...testDeps,
      connect: async () => {
        throw new Error('connect ECONNREFUSED 10.0.0.5:5432');
      },
    });
    const text = await res.text();
    expect(res.status).toBe(503);
    expect(text).not.toContain('10.0.0.5');
  });

  it('requires authentication for unknown API paths too', async () => {
    const res = await request('/api/v1/does-not-exist', {
      ...baseEnv,
      AUTH_PROVIDER: 'cloudflare_access',
      ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com',
      ACCESS_AUD: 'aud',
      HYPERDRIVE,
    });
    expect(res.status).toBe(401);
  });

  it('returns the standard 404 envelope for unknown paths once authenticated', async () => {
    const res = await request('/api/v1/does-not-exist');
    expect(res.status).toBe(404);
    const body = errorResponseSchema.parse(await res.json());
    expect(body.error.requestId).toBe(res.headers.get('X-Request-Id'));
  });
});

describe('CSRF protection', () => {
  it('rejects state-changing requests without a same-origin Origin header', async () => {
    for (const headers of [{}, { Origin: 'https://evil.example' }] as Record<string, string>[]) {
      const res = await request('http://localhost/api/v1/me', devAuthEnv, {
        method: 'POST',
        headers,
      });
      expect(res.status).toBe(403);
    }
  });

  it('lets same-origin writes through to routing', async () => {
    const res = await request('http://localhost/api/v1/me', devAuthEnv, {
      method: 'POST',
      headers: { Origin: 'http://localhost' },
    });
    // Passes CSRF and auth; /me has no POST handler.
    expect(res.status).toBe(404);
  });
});

describe('requirePermission', () => {
  function appFor(role: 'admin' | 'viewer') {
    const app = new Hono<AppBindings>();
    app.use('*', async (c, next) => {
      c.set('requestId', 'r');
      c.set('logger', createLogger({ test: true }));
      c.set('user', { id: crypto.randomUUID(), email: 'x@example.com', displayName: null, role });
      await next();
    });
    app.post('/scans', requirePermission('scans:request'), (c) => c.json({ ok: true }));
    app.onError(handleError);
    return app;
  }

  it('allows roles holding the permission', async () => {
    expect((await appFor('admin').request('/scans', { method: 'POST' })).status).toBe(200);
  });

  it('rejects roles lacking the permission with 403', async () => {
    const res = await appFor('viewer').request('/scans', { method: 'POST' });
    expect(res.status).toBe(403);
    expect(errorResponseSchema.parse(await res.json()).error.code).toBe('forbidden');
  });
});

describe('response hygiene', () => {
  it('sets a server-generated request ID and security headers', async () => {
    const res = await request('/api/v1/health', devAuthEnv, {
      headers: { 'X-Request-Id': 'client-supplied' },
    });
    expect(res.headers.get('X-Request-Id')).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
  });

  it('fails closed with a safe 500 when configuration is invalid', async () => {
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await request('/api/v1/health', { APP_ENV: 'staging' });
    const text = await res.text();
    expect(res.status).toBe(500);
    expect(errorResponseSchema.parse(JSON.parse(text)).error.code).toBe('internal_error');
    expect(text).not.toContain('APP_ENV');
    expect(errorLog).toHaveBeenCalled();
  });

  it('refuses the dev identity when APP_ENV=production', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await request('/api/v1/me', { ...devAuthEnv, APP_ENV: 'production' });
    expect(res.status).toBe(500);
    expect(await t.db.select().from(schema.users)).not.toContainEqual(
      expect.objectContaining({ email: 'prod-dev@example.com' }),
    );
  });
});
