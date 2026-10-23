// @vitest-environment node
/**
 * Milestone 11/12 hardening: authorisation route matrix.
 *
 * Every route registered on the Hono app is enumerated from `createApp().routes`, so a route added
 * later cannot silently escape the matrix: the test fails until it has an entry in ROUTE_ACCESS.
 * For each route × caller (admin, analyst, asset_owner, viewer, unauthenticated, deactivated user)
 * the expected outcome is asserted: 401/403 where access must be refused, "neither 401 nor 403"
 * where the role is entitled to reach the handler (the handler may still answer 400/404 for the
 * synthetic, empty request).
 *
 * Expectations are written out by role (from docs/design.md §4), not derived from
 * ROLE_PERMISSIONS, so a change to the permission matrix or to a route's permission is caught.
 */
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { ROLES, errorResponseSchema, type Role } from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp, type AppDeps } from './app.ts';
import {
  ROUTE_ACCESS,
  concrete,
  enumerateRoutes,
  expectNoLeak,
  type Access,
} from './testing/route-matrix.ts';
import {
  ORIGIN,
  ensureUser,
  generateWorkerKey,
  signedHeaders,
  type TestWorkerKey,
} from './testing/harness.ts';

const HYPERDRIVE = { connectionString: 'postgres://u:p@db.example.invalid/app' };

let t: TestDatabase;
const clock = new Date('2026-10-23T10:00:00.000Z');

// External effects are stubbed: DNS TXT lookups and the public intelligence feeds never leave
// the process (tests never touch live third-party systems).
const deps = (): AppDeps => ({
  connect: async () => ({ db: t.db, close: async () => {} }),
  now: () => clock,
  domains: { now: () => clock, resolveTxt: async () => ({ status: 'nxdomain' }) },
  intel: {
    fetch: async () => {
      throw new Error('network disabled in tests');
    },
  },
  health: { pingDatabase: async () => ({ status: 'ok', latencyMs: 1 }) },
});

const ROUTES = enumerateRoutes();
const USER_ROUTES = ROUTES.filter((r) => ROUTE_ACCESS[r.key]?.kind === 'user');
const WORKER_ROUTES = ROUTES.filter((r) => ROUTE_ACCESS[r.key]?.kind === 'worker');
const MUTATING_USER_ROUTES = USER_ROUTES.filter((r) => !['GET', 'HEAD'].includes(r.method));

// ------------------------------------------------------------------------------------------------
// Callers

const ACCESS_ENV = {
  APP_ENV: 'production',
  APP_VERSION: 'test',
  AUTH_PROVIDER: 'cloudflare_access',
  ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com',
  ACCESS_AUD: 'aud-tag',
  HYPERDRIVE,
};
const devEnv = (email: string) => ({
  APP_ENV: 'development',
  APP_VERSION: 'test',
  AUTH_PROVIDER: 'dev',
  DEV_AUTH_EMAIL: email,
  HYPERDRIVE,
});
const DEACTIVATED_EMAIL = 'deactivated@example.com';

type Caller = Role | 'unauthenticated' | 'deactivated';

function envFor(caller: Caller): Record<string, unknown> {
  if (caller === 'unauthenticated') return ACCESS_ENV;
  if (caller === 'deactivated') return devEnv(DEACTIVATED_EMAIL);
  return devEnv(`${caller}@example.com`);
}

async function send(
  caller: Caller,
  method: string,
  path: string,
  init: { headers?: Record<string, string>; body?: string; env?: Record<string, unknown> } = {},
): Promise<Response> {
  const hasBody = !['GET', 'HEAD'].includes(method);
  return createApp(deps()).request(
    `/api/v1${path}`,
    {
      method,
      headers: {
        ...(hasBody ? { 'Content-Type': 'application/json', Origin: ORIGIN } : {}),
        ...init.headers,
      },
      ...(hasBody ? { body: init.body ?? '{}' } : {}),
    },
    (init.env ?? envFor(caller)) as unknown as Env,
  );
}

async function expectEnvelope(res: Response, status: number, code: string, context: string) {
  const text = await res.text();
  expect(res.status, `${context}: ${text.slice(0, 200)}`).toBe(status);
  const body = errorResponseSchema.parse(JSON.parse(text));
  expect(body.error.code, context).toBe(code);
  expect(body.error.requestId, context).toMatch(/^[0-9a-f-]{36}$/);
  expectNoLeak(text, context);
}

// ------------------------------------------------------------------------------------------------

beforeAll(async () => {
  t = await createTestDatabase();
  for (const role of ROLES) await ensureUser(t, role);
  await t.db.insert(schema.users).values({
    email: DEACTIVATED_EMAIL,
    role: 'admin', // the strongest role: deactivation alone must lock it out
    authProvider: 'dev',
    authProviderSubject: `dev:${DEACTIVATED_EMAIL}`,
    isActive: false,
  });
}, 30_000);
afterAll(async () => {
  await t?.close();
});
beforeEach(() => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

describe('route inventory', () => {
  it('enumerates the app routes (sanity)', () => {
    expect(ROUTES.length).toBeGreaterThan(50);
    expect(ROUTES.map((r) => r.key)).toContain('GET /health');
    expect(ROUTES.map((r) => r.key)).toContain('POST /internal/worker/claim');
  });

  it('every registered route has an access expectation', () => {
    const missing = ROUTES.map((r) => r.key).filter((k) => !(k in ROUTE_ACCESS));
    expect(missing, 'add these routes to ROUTE_ACCESS in authz.matrix.test.ts').toEqual([]);
  });

  it('every expectation refers to a registered route (no stale entries)', () => {
    const keys = new Set(ROUTES.map((r) => r.key));
    expect(Object.keys(ROUTE_ACCESS).filter((k) => !keys.has(k))).toEqual([]);
  });

  it('only the health endpoint is public and only /internal/worker uses worker auth', () => {
    const publicRoutes = Object.entries(ROUTE_ACCESS).filter(([, a]) => a.kind === 'public');
    expect(publicRoutes.map(([k]) => k).every((k) => k.startsWith('GET /health'))).toBe(true);
    for (const [k, a] of Object.entries(ROUTE_ACCESS)) {
      expect(a.kind === 'worker', k).toBe(k.includes(' /internal/worker/'));
    }
  });
});

describe('role matrix', () => {
  describe.each(ROLES)('as %s', (role) => {
    it.each(USER_ROUTES.map((r) => [r.key, r] as const))('%s', async (_key, route) => {
      const access = ROUTE_ACCESS[route.key] as Extract<Access, { kind: 'user' }>;
      const res = await send(role, route.method, concrete(route.path));
      const context = `${role} ${route.key}`;
      if (access.allow.includes(role)) {
        const text = await res.text();
        expect([401, 403], `${context} must be allowed, got ${res.status}: ${text}`).not.toContain(
          res.status,
        );
        expect(res.status, `${context}: ${text}`).toBeLessThan(500);
      } else {
        await expectEnvelope(res, 403, 'forbidden', context);
      }
    });
  });

  it.each(USER_ROUTES.map((r) => [r.key, r] as const))(
    'unauthenticated: %s → 401',
    async (_key, route) => {
      const res = await send('unauthenticated', route.method, concrete(route.path));
      await expectEnvelope(res, 401, 'unauthenticated', `anon ${route.key}`);
    },
  );

  it.each(USER_ROUTES.map((r) => [r.key, r] as const))(
    'deactivated admin: %s → 403',
    async (_key, route) => {
      const res = await send('deactivated', route.method, concrete(route.path));
      await expectEnvelope(res, 403, 'forbidden', `deactivated ${route.key}`);
    },
  );

  it('the public health endpoint answers every caller', async () => {
    for (const caller of [...ROLES, 'unauthenticated', 'deactivated'] as const) {
      const res = await send(caller, 'GET', '/health');
      expect([200, 503], caller).toContain(res.status);
    }
  });

  it('HEAD on protected GET routes still requires authentication', async () => {
    for (const route of USER_ROUTES.filter((r) => r.method === 'GET')) {
      const res = await send('unauthenticated', 'HEAD', concrete(route.path));
      expect(res.status, `HEAD ${route.key}`).toBe(401);
    }
  });

  it('a method-override header cannot turn a read into a write', async () => {
    const res = await send('viewer', 'GET', '/users', {
      headers: { 'X-HTTP-Method-Override': 'POST', 'X-Method-Override': 'POST' },
    });
    await expectEnvelope(res, 403, 'forbidden', 'viewer GET /users with override');
  });
});

describe('unknown paths', () => {
  const UNKNOWN = [
    '/nope',
    '/admin',
    '/domains/x/y/z',
    '/users/me/secret',
    '/internal',
    '/internal/workers/claim',
    '/me/..%2f..%2fusers',
  ];

  it.each(UNKNOWN)('unknown /api/v1%s requires authentication before revealing 404', async (p) => {
    const res = await send('unauthenticated', 'GET', p);
    await expectEnvelope(res, 401, 'unauthenticated', `anon GET ${p}`);
    const post = await send('unauthenticated', 'POST', p);
    await expectEnvelope(post, 401, 'unauthenticated', `anon POST ${p}`);
  });

  it('unknown paths under the worker API require a worker signature', async () => {
    for (const p of ['/internal/worker/unknown', '/internal/worker/claim/extra']) {
      const res = await send('admin', 'POST', p);
      await expectEnvelope(res, 401, 'unauthenticated', `admin POST ${p}`);
    }
  });

  it('dot-segment paths normalise out of /api/v1 and reveal nothing', async () => {
    const res = await send('unauthenticated', 'GET', '/%2e%2e/users');
    await expectEnvelope(res, 404, 'not_found', 'anon GET /api/v1/%2e%2e/users');
  });

  it('a signed-in user gets the standard 404 envelope for unknown paths', async () => {
    const res = await send('viewer', 'GET', '/nope');
    await expectEnvelope(res, 404, 'not_found', 'viewer GET /nope');
  });

  it('known paths with an unregistered method do not bypass authentication', async () => {
    for (const route of USER_ROUTES) {
      const method = route.method === 'DELETE' ? 'PUT' : 'DELETE';
      if (USER_ROUTES.some((r) => r.path === route.path && r.method === method)) continue;
      const res = await send('unauthenticated', method, concrete(route.path));
      expect(res.status, `${method} ${route.path}`).toBe(401);
    }
  });
});

describe('separation of user and worker authentication', () => {
  let key: TestWorkerKey;
  let keyId: string;

  beforeAll(async () => {
    key = await generateWorkerKey();
    const [w] = await t.db
      .insert(schema.workerRegistry)
      .values({ name: 'matrix-worker' })
      .returning();
    const [cred] = await t.db
      .insert(schema.workerCredentials)
      .values({
        workerId: w!.id,
        publicKey: key.publicKey,
        createdAt: clock,
        expiresAt: new Date(clock.getTime() + 86_400_000),
      })
      .returning();
    keyId = cred!.id;
  });

  it.each(WORKER_ROUTES.map((r) => [r.key, r] as const))(
    'the worker API refuses every user session: %s',
    async (_key, route) => {
      for (const role of ROLES) {
        const res = await send(role, route.method, route.path);
        await expectEnvelope(res, 401, 'unauthenticated', `${role} ${route.key}`);
      }
      // Even with a cookie / Access header that would be a valid user credential shape.
      const res = await send('admin', route.method, route.path, {
        headers: { 'Cf-Access-Jwt-Assertion': 'a.b.c', Cookie: 'CF_Authorization=a.b.c' },
      });
      await expectEnvelope(res, 401, 'unauthenticated', `cookie ${route.key}`);
    },
  );

  it('the worker signature itself is valid (positive control)', async () => {
    const path = '/api/v1/internal/worker/claim';
    const headers = await signedHeaders(key, keyId, 'POST', path, '{}', { now: clock });
    const res = await createApp(deps()).request(
      path,
      { method: 'POST', headers, body: '{}' },
      devEnv('viewer@example.com') as unknown as Env,
    );
    expect(res.status).toBe(200);
  });

  it.each(USER_ROUTES.map((r) => [r.key, r] as const))(
    'user routes refuse a valid worker signature: %s',
    async (_key, route) => {
      const path = `/api/v1${concrete(route.path)}`;
      const body = ['GET', 'HEAD'].includes(route.method) ? '' : '{}';
      const headers = await signedHeaders(key, keyId, route.method, path, body, { now: clock });
      const res = await createApp(deps()).request(
        path,
        {
          method: route.method,
          headers: { ...headers, ...(body ? { Origin: ORIGIN } : {}) },
          ...(body ? { body } : {}),
        },
        ACCESS_ENV as unknown as Env,
      );
      await expectEnvelope(res, 401, 'unauthenticated', `worker-signed ${route.key}`);
    },
  );
});

describe('CSRF on every mutating user route', () => {
  const FOREIGN = [
    undefined, // no Origin at all
    'https://evil.example',
    'null',
    'http://localhost:8080', // same host, other port
    'https://localhost', // same host, other scheme
    'http://localhost.evil.example',
    'http://evil.example/http://localhost',
    `${ORIGIN}/`, // not an exact origin
  ];

  it.each(MUTATING_USER_ROUTES.map((r) => [r.key, r] as const))(
    '%s refuses a missing or foreign Origin',
    async (_key, route) => {
      for (const origin of FOREIGN) {
        const res = await createApp(deps()).request(
          `/api/v1${concrete(route.path)}`,
          {
            method: route.method,
            headers: {
              'Content-Type': 'application/json',
              ...(origin !== undefined ? { Origin: origin } : {}),
              // A Referer from this origin does not substitute for Origin.
              Referer: `${ORIGIN}/domains`,
            },
            body: '{}',
          },
          envFor('admin') as unknown as Env,
        );
        await expectEnvelope(res, 403, 'forbidden', `${route.key} origin=${String(origin)}`);
      }
    },
  );

  it('CSRF is checked before authentication (no identity work for forged requests)', async () => {
    const route = MUTATING_USER_ROUTES[0]!;
    const res = await createApp(deps()).request(
      `/api/v1${concrete(route.path)}`,
      { method: route.method, headers: { 'Content-Type': 'application/json' }, body: '{}' },
      ACCESS_ENV as unknown as Env,
    );
    await expectEnvelope(res, 403, 'forbidden', 'anon without origin');
  });
});

describe('production configuration', () => {
  it.each(USER_ROUTES.map((r) => [r.key, r] as const))(
    'the dev auth provider is refused in production: %s',
    async (_key, route) => {
      const res = await send('admin', route.method, concrete(route.path), {
        env: { ...devEnv('admin@example.com'), APP_ENV: 'production' },
      });
      const text = await res.text();
      expect(res.status, text).toBe(500);
      expect(errorResponseSchema.parse(JSON.parse(text)).error.code).toBe('internal_error');
      expectNoLeak(text, route.key);
      expect(text).not.toContain('AUTH_PROVIDER');
    },
  );
});
