// @vitest-environment node
/**
 * Milestone 11/12 hardening: input validation on every route with a JSON body or a query schema.
 *
 * Each mutating user route must be listed in BODY_ROUTES (with a minimal valid body) or in
 * NO_BODY_ROUTES; the test fails when a new route is not classified. For each body route:
 * malformed JSON, wrong content type, non-object JSON, oversized bodies, deep nesting, wrong field
 * types, oversized fields, unknown keys and prototype keys must all be answered 400 with the
 * standard error envelope — never 500, and never with internal details.
 */
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { ROLES, errorResponseSchema } from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp, type AppDeps } from './app.ts';
import { ASSET_IMPORT_MAX_BODY_BYTES } from './services/asset-import.ts';
import { ROUTE_ACCESS, concrete, enumerateRoutes, expectNoLeak } from './testing/route-matrix.ts';
import { ORIGIN, ensureUser, generateWorkerKey, signedHeaders } from './testing/harness.ts';

const HYPERDRIVE = { connectionString: 'postgres://u:p@db.example.invalid/app' };
const clock = new Date('2026-10-23T10:00:00.000Z');
let t: TestDatabase;
let workerPublicKey: string;

const deps = (over: Partial<AppDeps> = {}): AppDeps => ({
  connect: async () => ({ db: t.db, close: async () => {} }),
  now: () => clock,
  domains: { now: () => clock, resolveTxt: async () => ({ status: 'nxdomain' }) },
  intel: {
    fetch: async () => {
      throw new Error('network disabled in tests');
    },
  },
  ...over,
});
const ADMIN_ENV = {
  APP_ENV: 'development',
  APP_VERSION: 'test',
  AUTH_PROVIDER: 'dev',
  DEV_AUTH_EMAIL: 'admin@example.com',
  HYPERDRIVE,
};

const uuid = () => crypto.randomUUID();
const REVIEW = '2027-03-31';
const REASON = 'Contract reference ACME-2026-17';

/** Minimal valid bodies (validation passes; the handler may still answer 404 etc.). */
const BODY_ROUTES: Record<string, () => Record<string, unknown>> = {
  'POST /domains': () => ({ fqdn: `v-${Math.random().toString(36).slice(2, 8)}.com` }),
  'POST /domains/import/preview': () => ({ csv: 'fqdn\nimport-preview.example.org\n' }),
  'POST /domains/import': () => ({ csv: 'fqdn\nimport.example.org\n', digest: '0'.repeat(64) }),
  'POST /domains/authorise': () => ({ domainIds: [uuid()], reason: REASON, reviewBy: REVIEW }),
  'POST /domains/monitoring': () => ({ domainIds: [uuid()], enabled: false }),
  'PATCH /domains/:id': () => ({ criticality: 'high' }),
  'POST /domains/:id/authorise': () => ({ reason: REASON, reviewBy: REVIEW }),
  'POST /domains/:id/revoke': () => ({ reason: REASON }),
  'POST /domains/:id/scans': () => ({ profile: 'passive' }),
  'POST /domains/:id/assets/import': () => ({
    entries: [{ hostname: 'www.example.com', cnameTarget: 'd1.cloudfront.net' }],
    dryRun: true,
    fileName: 'zone.txt',
  }),
  'POST /assets/bulk': () => ({ ids: [uuid()], action: 'reject', reason: REASON }),
  'PATCH /assets/:id': () => ({ ownerUserId: null }),
  'POST /assets/:id/approve': () => ({ reason: REASON }),
  'POST /assets/:id/reject': () => ({ reason: REASON }),
  'POST /assets/:id/suspend': () => ({ reason: REASON }),
  'POST /workers': () => ({
    name: `w-${Math.random().toString(36).slice(2, 8)}`,
    publicKey: workerPublicKey,
  }),
  'PATCH /workers/:id': () => ({ status: 'disabled' }),
  'POST /workers/:id/credentials': () => ({ publicKey: workerPublicKey }),
  'POST /approved-networks': () => ({
    cidr: '8.8.8.0/24',
    label: 'Hosting',
    reason: REASON,
    reviewBy: REVIEW,
  }),
  'POST /approved-networks/:id/revoke': () => ({ reason: REASON }),
  'POST /findings/bulk': () => ({ ids: [uuid()], status: 'acknowledged' }),
  'PATCH /findings/:id': () => ({ expectedStatus: 'open', status: 'acknowledged' }),
  'POST /findings/:id/comments': () => ({ body: 'Looking into it' }),
  'POST /users': () => ({
    email: `u-${Math.random().toString(36).slice(2, 8)}@example.com`,
    role: 'viewer',
  }),
  'PATCH /users/:id': () => ({ role: 'viewer' }),
  'PUT /settings/scan-schedule': () => ({ enabled: false, profile: 'quick', intervalDays: 1 }),
};

/** Routes with a larger body cap than parseJsonBody's 300 KB default (bytes). */
const LARGE_BODY_ROUTES: Record<string, number> = {
  'POST /domains/:id/assets/import': ASSET_IMPORT_MAX_BODY_BYTES,
};

/** Mutating routes that take no request body (the body is ignored). */
const NO_BODY_ROUTES = new Set([
  'POST /domains/:id/verification',
  'POST /domains/:id/discovery',
  'POST /domains/:id/verify',
  'POST /scans/:id/cancel',
  'POST /workers/:id/credentials/:credentialId/revoke',
  'POST /findings/:id/reassess',
  'POST /intel/feeds/sync',
]);

/** Query-string probes per GET route that has a query schema (each must give 400). */
const PAGE_PROBES = ['pageSize=101', 'pageSize=0', 'pageSize=abc', 'page=0', 'page=-1', 'page=1e9'];
const QUERY_ROUTES: Record<string, string[]> = {
  'GET /domains': [
    ...PAGE_PROBES,
    `q=${'a'.repeat(300)}`,
    'sort=evil',
    'verificationStatus=x',
    'monitoring=yes',
  ],
  'GET /domains/:id/assets': [
    ...PAGE_PROBES,
    'status=bogus',
    'sort=hostname;drop',
    `q=${'a'.repeat(300)}`,
  ],
  'GET /domains/:id/software': [...PAGE_PROBES, 'status=bogus', `product=${'p'.repeat(41)}`],
  'GET /assets': [...PAGE_PROBES, 'domainId=not-a-uuid', 'thirdParty=1', 'source=evil'],
  'GET /scans': [...PAGE_PROBES, 'status=bogus', 'domainId=1', `profile=${'p'.repeat(41)}`],
  'GET /findings': [
    ...PAGE_PROBES,
    'status=bogus',
    'severity=ultra',
    'assignee=root',
    `ruleId=${'r'.repeat(21)}`,
  ],
  'GET /findings/summary': ['domainId=not-a-uuid', "domainId=' OR 1=1--"],
  'GET /advisories': [...PAGE_PROBES, 'status=bogus'],
  'GET /users': [...PAGE_PROBES, 'role=root', 'active=yes', `q=${'a'.repeat(300)}`],
  'GET /audit-logs': [...PAGE_PROBES, 'action=DROP TABLE', `resourceId=${'a'.repeat(201)}`],
  'GET /reports/findings.csv': ['status=bogus', 'domainId=x', 'sort=evil'],
  'GET /software': [...PAGE_PROBES, 'status=bogus', 'domainId=x'],
  // Exports ignore paging parameters; their filters are validated like the list's.
  'GET /exports/domains.csv': [`q=${'a'.repeat(300)}`, 'sort=evil', 'monitoring=yes'],
  'GET /exports/assets.csv': ['domainId=not-a-uuid', 'thirdParty=1', 'source=evil'],
  'GET /exports/advisories.csv': ['status=bogus'],
  'GET /exports/software.csv': ['status=bogus', 'domainId=x', `product=${'p'.repeat(41)}`],
  'GET /exports/scans.csv': ['status=bogus', 'domainId=1', `profile=${'p'.repeat(41)}`],
  'GET /exports/users.csv': ['role=root', 'active=yes', `q=${'a'.repeat(300)}`],
  'GET /exports/audit-logs.csv': ['action=DROP TABLE', `resourceId=${'a'.repeat(201)}`],
};

const ROUTES = enumerateRoutes();
const MUTATING = ROUTES.filter(
  (r) => ROUTE_ACCESS[r.key]?.kind === 'user' && !['GET', 'HEAD'].includes(r.method),
);

beforeAll(async () => {
  t = await createTestDatabase();
  for (const role of ROLES) await ensureUser(t, role);
  workerPublicKey = (await generateWorkerKey()).publicKey;
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

function raw(
  method: string,
  path: string,
  body: string | undefined,
  headers: Record<string, string> = { 'Content-Type': 'application/json' },
  appDeps: AppDeps = deps(),
) {
  return createApp(appDeps).request(
    `/api/v1${path}`,
    { method, headers: { Origin: ORIGIN, ...headers }, ...(body !== undefined ? { body } : {}) },
    ADMIN_ENV as unknown as Env,
  );
}

async function expect400(
  res: Response,
  context: string,
  codes = ['validation_failed', 'bad_request'],
) {
  const text = await res.text();
  expect(res.status, `${context}: ${text.slice(0, 300)}`).toBe(400);
  const body = errorResponseSchema.parse(JSON.parse(text));
  expect(codes, `${context}: code ${body.error.code}`).toContain(body.error.code);
  expect(body.error.requestId).toMatch(/^[0-9a-f-]{36}$/);
  expectNoLeak(text, context);
  if (body.error.details) {
    expect(body.error.details.length).toBeLessThanOrEqual(20);
    // Field errors never echo submitted values back (they could be huge or sensitive).
    for (const d of body.error.details) expect(d.message.length, context).toBeLessThan(300);
  }
  return body.error;
}

function wrongType(value: unknown): unknown {
  if (typeof value === 'string') return 12345;
  if (typeof value === 'number') return '1';
  if (typeof value === 'boolean') return 'true';
  if (Array.isArray(value)) return 'not-an-array';
  if (value === null) return { nested: true };
  return 42;
}

describe('classification', () => {
  it('every mutating user route is classified as body or no-body', () => {
    const unclassified = MUTATING.map((r) => r.key).filter(
      (k) => !(k in BODY_ROUTES) && !NO_BODY_ROUTES.has(k),
    );
    expect(unclassified, 'add to BODY_ROUTES or NO_BODY_ROUTES').toEqual([]);
    const known = new Set(ROUTES.map((r) => r.key));
    expect(Object.keys(BODY_ROUTES).filter((k) => !known.has(k))).toEqual([]);
    expect([...NO_BODY_ROUTES].filter((k) => !known.has(k))).toEqual([]);
    expect(Object.keys(QUERY_ROUTES).filter((k) => !known.has(k))).toEqual([]);
  });
});

describe.each(Object.keys(BODY_ROUTES).map((k) => [k]))('%s', (key) => {
  const [method, pattern] = key.split(' ') as [string, string];
  const valid = BODY_ROUTES[key]!;

  it('accepts the minimal valid body (positive control)', async () => {
    const res = await raw(method, concrete(pattern), JSON.stringify(valid()));
    const text = await res.text();
    expect(res.status, text).toBeLessThan(500);
    if (res.status === 400) {
      expect(errorResponseSchema.parse(JSON.parse(text)).error.code, text).not.toBe(
        'validation_failed',
      );
    }
  });

  it('rejects malformed JSON, wrong content types and non-object JSON', async () => {
    const path = concrete(pattern);
    await expect400(await raw(method, path, '{"a":'), `${key} truncated JSON`, ['bad_request']);
    await expect400(await raw(method, path, "{'a': 1}"), `${key} single quotes`, ['bad_request']);
    await expect400(await raw(method, path, ''), `${key} empty body`, ['bad_request']);
    await expect400(await raw(method, path, '\u0000'), `${key} NUL`, ['bad_request']);
    const body = JSON.stringify(valid());
    for (const ct of [
      'text/plain',
      'application/x-www-form-urlencoded',
      'multipart/form-data; boundary=x',
      '',
    ]) {
      await expect400(
        await raw(method, path, body, ct ? { 'Content-Type': ct } : {}),
        `${key} content-type ${ct || '(none)'}`,
        ['bad_request'],
      );
    }
    for (const json of ['[]', 'null', '"text"', '42', 'true', `[${body}]`]) {
      await expect400(await raw(method, path, json), `${key} ${json.slice(0, 20)}`);
    }
  });

  it('rejects oversized and deeply nested bodies', async () => {
    const path = concrete(pattern);
    const cap = LARGE_BODY_ROUTES[key] ?? 300 * 1024;
    const big = JSON.stringify({ ...valid(), pad: 'x'.repeat(cap + 100 * 1024) });
    await expect400(await raw(method, path, big), `${key} body over the cap`, ['bad_request']);
    const nested = '['.repeat(20_000) + ']'.repeat(20_000);
    await expect400(await raw(method, path, nested), `${key} nested arrays`);
    const nestedObj = '{"a":'.repeat(5_000) + '1' + '}'.repeat(5_000);
    await expect400(await raw(method, path, nestedObj), `${key} nested objects`);
  });

  it('rejects wrong field types', async () => {
    const base = valid();
    for (const field of Object.keys(base)) {
      const body = { ...base, [field]: wrongType(base[field]) };
      await expect400(
        await raw(method, concrete(pattern), JSON.stringify(body)),
        `${key} ${field} wrong type`,
        ['validation_failed'],
      );
    }
  });

  it('rejects oversized string and array fields', async () => {
    const base = valid();
    for (const [field, value] of Object.entries(base)) {
      let oversized: unknown;
      if (typeof value === 'string') oversized = 'a'.repeat(270_000);
      else if (Array.isArray(value)) oversized = Array.from({ length: 5_001 }, () => value[0]);
      else continue;
      await expect400(
        await raw(method, concrete(pattern), JSON.stringify({ ...base, [field]: oversized })),
        `${key} oversized ${field}`,
      );
    }
  });

  it('rejects unknown keys (strict schema), including prototype keys', async () => {
    const body = JSON.stringify(valid());
    const extras = [
      '"unexpected":1',
      '"__proto__":{"role":"admin"}',
      '"constructor":{"prototype":{"isAdmin":true}}',
      '"role":"admin"',
      '"id":"00000000-0000-4000-8000-000000000000"',
    ];
    for (const extra of extras) {
      // Skip extras that name a real field of this body.
      const name = extra.slice(1, extra.indexOf('"', 1));
      if (name in valid()) continue;
      const withExtra = `${body.slice(0, -1)},${extra}}`;
      await expect400(await raw(method, concrete(pattern), withExtra), `${key} extra ${name}`, [
        'validation_failed',
      ]);
    }
    expect(({} as Record<string, unknown>).role).toBeUndefined();
    expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
  });
});

describe('routes without a body', () => {
  it.each([...NO_BODY_ROUTES].map((k) => [k]))(
    '%s never fails with 500 on garbage bodies or content types',
    async (key) => {
      const [method, pattern] = key.split(' ') as [string, string];
      for (const [body, ct] of [
        ['{"a":', 'application/json'],
        ['x'.repeat(400 * 1024), 'text/plain'],
        ['[]', 'application/json'],
      ] as const) {
        const res = await raw(method, concrete(pattern), body, { 'Content-Type': ct });
        const text = await res.text();
        expect(res.status, `${key}: ${text.slice(0, 200)}`).toBeLessThan(500);
        if (res.status >= 400) {
          errorResponseSchema.parse(JSON.parse(text));
          expectNoLeak(text, key);
        }
      }
    },
  );
});

describe('query strings', () => {
  it.each(Object.entries(QUERY_ROUTES))('%s rejects invalid query values', async (key, probes) => {
    const [, pattern] = key.split(' ') as [string, string];
    const path = concrete(pattern);
    for (const probe of probes) {
      await expect400(
        await raw('GET', `${path}?${probe}`, undefined, {}),
        `${key}?${probe.slice(0, 40)}`,
        ['validation_failed'],
      );
    }
    // Positive control: the route answers with no query at all.
    const ok = await raw('GET', path, undefined, {});
    expect([200, 404], key).toContain(ok.status);
  });

  it('every GET list route with pagination caps pageSize (no unbounded lists)', async () => {
    for (const [key, probes] of Object.entries(QUERY_ROUTES)) {
      if (!probes.includes('pageSize=101')) continue;
      const [, pattern] = key.split(' ') as [string, string];
      const res = await raw('GET', `${concrete(pattern)}?pageSize=100`, undefined, {});
      expect([200, 404], key).toContain(res.status);
    }
  });
});

describe('route parameters', () => {
  const BAD_IDS = [
    'not-a-uuid',
    "1' OR '1'='1",
    '..%2F..%2Fetc%2Fpasswd',
    '00000000-0000-0000-0000-00000000000g',
    '%00',
    'a'.repeat(5000),
    '123',
  ];
  const PARAM_ROUTES = ROUTES.filter(
    (r) => ROUTE_ACCESS[r.key]?.kind === 'user' && r.path.includes('/:'),
  );

  it.each(PARAM_ROUTES.map((r) => [r.key, r] as const))(
    '%s refuses malformed ids without a 500',
    async (key, route) => {
      for (const bad of BAD_IDS) {
        const path = route.path.replace(/:[A-Za-z]+/g, bad);
        const body = route.key in BODY_ROUTES ? JSON.stringify(BODY_ROUTES[route.key]!()) : '{}';
        const res = await raw(
          route.method,
          path,
          route.method === 'GET' ? undefined : body,
          route.method === 'GET' ? {} : { 'Content-Type': 'application/json' },
        );
        const text = await res.text();
        // Malformed ids are reported as not found (uuidParam, a documented decision) or 400.
        expect([400, 404], `${key} id=${bad.slice(0, 30)}: ${text.slice(0, 200)}`).toContain(
          res.status,
        );
        errorResponseSchema.parse(JSON.parse(text));
        expectNoLeak(text, key);
      }
    },
  );
});

describe('internal worker API input validation', () => {
  let key: Awaited<ReturnType<typeof generateWorkerKey>>;
  let keyId: string;

  beforeAll(async () => {
    const { schema } = await import('@exdomainvault/database');
    key = await generateWorkerKey();
    const [w] = await t.db.insert(schema.workerRegistry).values({ name: 'validator' }).returning();
    const [c] = await t.db
      .insert(schema.workerCredentials)
      .values({
        workerId: w!.id,
        publicKey: key.publicKey,
        createdAt: clock,
        expiresAt: new Date(clock.getTime() + 86_400_000),
      })
      .returning();
    keyId = c!.id;
  });

  async function signed(endpoint: string, body: string, contentType = 'application/json') {
    const path = `/api/v1/internal/worker/${endpoint}`;
    const headers = await signedHeaders(key, keyId, 'POST', path, body, { now: clock });
    return createApp(deps()).request(
      path,
      { method: 'POST', headers: { ...headers, 'Content-Type': contentType }, body },
      ADMIN_ENV as unknown as Env,
    );
  }

  const ref = () => ({ jobId: uuid(), attempt: 1 });
  const CASES: [string, string][] = [
    ['claim', '{"a":'],
    ['claim', '[]'],
    ['claim', JSON.stringify({ profiles: 'passive' })],
    ['claim', JSON.stringify({ profiles: Array.from({ length: 11 }, () => 'passive') })],
    ['claim', JSON.stringify({ profiles: ['x'.repeat(41)] })],
    ['claim', JSON.stringify({ unexpected: true })],
    ['heartbeat', JSON.stringify({ ...ref(), attempt: '1' })],
    ['heartbeat', JSON.stringify({ jobId: 'nope', attempt: 1 })],
    [
      'heartbeat',
      JSON.stringify({ ...ref(), progress: { completedTargets: -1, totalTargets: 1 } }),
    ],
    ['heartbeat', JSON.stringify({ ...ref(), extra: 1 })],
    ['results', JSON.stringify({ ...ref(), resultId: 'short', targets: [], complete: true })],
    [
      'results',
      JSON.stringify({ ...ref(), resultId: '../../etc/passwd', targets: [], complete: true }),
    ],
    [
      'failures',
      JSON.stringify({ ...ref(), errorCode: 'x'.repeat(500), errorSummary: 'x', retryable: true }),
    ],
    [
      'failures',
      JSON.stringify({ ...ref(), errorCode: 'dns_timeout', errorSummary: 'x', retryable: 'yes' }),
    ],
  ];

  it.each(CASES)('%s %s → 400', async (endpoint, body) => {
    await expect400(await signed(endpoint, body), `${endpoint} ${body.slice(0, 40)}`);
  });

  it('a signed text/plain body is still refused', async () => {
    await expect400(await signed('claim', '{}', 'text/plain'), 'claim text/plain', ['bad_request']);
  });
});

describe('internal failures never leak details', () => {
  const leakyError = () =>
    new Error(
      'connect ECONNREFUSED postgres://app:s3cret@ep-cool-123.eu-central-1.aws.neon.tech/neondb ' +
        'at Client._connect (/home/app/node_modules/pg/lib/client.js:12:3)',
    );
  /** A database whose every query throws an error carrying internals. */
  const explodingDb = new Proxy(
    {},
    {
      get: () => () => {
        throw leakyError();
      },
    },
  );

  it.each([
    ['connection failure', { connect: async () => Promise.reject(leakyError()) }],
    [
      'query failure',
      { connect: async () => ({ db: explodingDb as never, close: async () => {} }) },
    ],
  ] as const)('%s on an authenticated route', async (_label, over) => {
    for (const path of ['/me', '/domains', '/findings', '/audit-logs']) {
      const res = await raw('GET', path, undefined, {}, deps(over as Partial<AppDeps>));
      const text = await res.text();
      expect([500, 503], `${path}: ${text}`).toContain(res.status);
      errorResponseSchema.parse(JSON.parse(text));
      expectNoLeak(text, path);
      expect(text).not.toContain('s3cret');
      expect(text).not.toContain('ECONNREFUSED');
    }
  });

  it('a query failure on the worker API leaks nothing either', async () => {
    const path = '/api/v1/internal/worker/claim';
    const k = await generateWorkerKey();
    const headers = await signedHeaders(k, uuid(), 'POST', path, '{}', { now: clock });
    const res = await createApp(
      deps({ connect: async () => ({ db: explodingDb as never, close: async () => {} }) }),
    ).request(path, { method: 'POST', headers, body: '{}' }, ADMIN_ENV as unknown as Env);
    const text = await res.text();
    expect([500, 503]).toContain(res.status);
    expectNoLeak(text, 'worker claim');
  });
});
