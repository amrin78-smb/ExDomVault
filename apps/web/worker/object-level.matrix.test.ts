// @vitest-environment node
/**
 * Hardening: object-level authorisation for asset owners, enumerated over every route.
 *
 * Asset owners may read only the assets they own and the findings on those assets. For every
 * GET route an asset owner may call (from ROUTE_ACCESS), the route is called with each identifier
 * of another tenant's data substituted for its parameters (and with none): the response must never
 * contain that data. Mutating routes an asset owner may call are probed the same way and must not
 * succeed on foreign objects. Analysts are the positive control: they do see the other data.
 */
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { ROLES } from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { createApp } from './app.ts';
import { evaluateJob } from './services/evaluation.ts';
import { FAKE_RULES, dnsFor, seedDomain, seedJob } from './testing/findings-fixtures.ts';
import { ORIGIN, ensureUser } from './testing/harness.ts';
import { ROUTE_ACCESS, enumerateRoutes } from './testing/route-matrix.ts';

const clock = new Date('2026-10-23T10:00:00.000Z');
const HYPERDRIVE = { connectionString: 'postgres://u:p@db.example.invalid/app' };
const OWN = 'own-tenant.example';
const OTHER = 'other-tenant.example';

let t: TestDatabase;
let foreignIds: string[] = [];
let ownIds: string[] = [];

const app = () =>
  createApp({
    connect: async () => ({ db: t.db, close: async () => {} }),
    now: () => clock,
    domains: { now: () => clock, resolveTxt: async () => ({ status: 'nxdomain' }) },
    intel: {
      fetch: async () => {
        throw new Error('network disabled in tests');
      },
    },
  });

const call = (role: string, method: string, path: string, body?: unknown) =>
  app().request(
    `/api/v1${path}`,
    {
      method,
      headers: method === 'GET' ? {} : { 'Content-Type': 'application/json', Origin: ORIGIN },
      ...(method === 'GET' ? {} : { body: JSON.stringify(body ?? {}) }),
    },
    {
      APP_ENV: 'development',
      APP_VERSION: 'test',
      AUTH_PROVIDER: 'dev',
      DEV_AUTH_EMAIL: `${role}@example.com`,
      HYPERDRIVE,
    } as unknown as Env,
  );

const at = (h: number) => new Date(Date.parse('2026-10-20T00:00:00.000Z') + h * 3600_000);

beforeAll(async () => {
  t = await createTestDatabase();
  for (const role of ROLES) await ensureUser(t, role);
  vi.spyOn(console, 'log').mockImplementation(() => {});
  const own = await seedDomain(t, OWN, { owned: true });
  const other = await seedDomain(t, OTHER);
  for (const s of [own, other]) {
    const job = await seedJob(
      t,
      s.domainId,
      at(1),
      dnsFor(s.fqdn, { apexA: ['192.0.2.10'], wwwA: ['192.0.2.11'] }),
    );
    await evaluateJob(t.db, job, clock, FAKE_RULES);
  }
  const rows = await t.db.select().from(schema.findings);
  const assets = await t.db.select().from(schema.assets);
  const jobs = await t.db.select().from(schema.scanJobs);
  foreignIds = [
    other.domainId,
    other.wwwAssetId,
    ...rows.filter((f) => f.domainId === other.domainId).map((f) => f.id),
    ...jobs.filter((j) => j.domainId === other.domainId).map((j) => j.id),
  ];
  ownIds = [
    own.wwwAssetId,
    ...rows.filter((f) => f.assetId === own.wwwAssetId).map((f) => f.id),
    ...assets.filter((a) => a.domainId === own.domainId).map((a) => a.id),
  ];
  expect(rows.filter((f) => f.domainId === other.domainId).length).toBeGreaterThan(0);
  expect(rows.filter((f) => f.assetId === own.wwwAssetId).length).toBeGreaterThan(0);
  vi.restoreAllMocks();
}, 60_000);
afterAll(async () => {
  await t?.close();
});
beforeEach(() => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

const ROUTES = enumerateRoutes().filter((r) => {
  const a = ROUTE_ACCESS[r.key];
  return a?.kind === 'user' && a.allow.includes('asset_owner');
});
/**
 * Routes that answer 200 (with an empty, filtered body) for another tenant's existing object but
 * 404 for an unknown id, so an asset owner can tell that the id exists. Low impact (ids are random
 * UUIDs, no data is returned) — reported in the Milestone 12 hardening findings; remove the entry
 * once the route answers 404 like GET /domains/:id/assets does.
 */
const EXISTENCE_ORACLE_ACCEPTED = new Set<string>();

const GETS = ROUTES.filter((r) => r.method === 'GET');
const WRITES = ROUTES.filter((r) => r.method !== 'GET');

function leaks(text: string): string[] {
  const found: string[] = [];
  if (text.includes(OTHER)) found.push(OTHER);
  for (const id of foreignIds) if (text.includes(id)) found.push(id);
  return found;
}

describe('asset owner never sees another tenant’s data', () => {
  it('asset owners can call some routes (sanity)', () => {
    expect(GETS.length).toBeGreaterThan(8);
  });

  it.each(GETS.map((r) => [r.key, r] as const))('%s', async (_key, route) => {
    const params = route.path.includes('/:')
      ? [...foreignIds, ...ownIds].map((id) => route.path.replace(/:[A-Za-z]+/g, id))
      : [route.path];
    for (const path of params) {
      // Including filters that name the other tenant explicitly.
      for (const query of ['', `?domainId=${foreignIds[0]}`, `?q=${OTHER}`, '?status=all']) {
        const res = await call('asset_owner', 'GET', `${path}${query}`);
        const text = await res.text();
        const isForeignPath = foreignIds.some((id) => path.includes(id));
        // Echoing the requested id back in a 404/400 is not a leak; anything with a 200 is.
        const found = leaks(text).filter(
          (x) => !(res.status >= 400 && (path.includes(x) || query.includes(x))),
        );
        expect(found, `${path}${query} → ${res.status}`).toEqual([]);
        if (isForeignPath && !EXISTENCE_ORACLE_ACCEPTED.has(route.key)) {
          expect(res.status, `${path}${query}`).not.toBe(200);
        }
      }
    }
  });

  it('positive control: an analyst sees the other tenant', async () => {
    const res = await call('analyst', 'GET', '/findings?status=all');
    expect(await res.text()).toContain(OTHER);
  });

  it('summaries count only the asset owner’s own findings', async () => {
    const own = (await (await call('asset_owner', 'GET', '/findings?status=all')).json()) as {
      total?: number;
      items: unknown[];
    };
    const summary = (await (await call('asset_owner', 'GET', '/findings/summary')).json()) as {
      total: number;
    };
    expect(summary.total).toBe(own.items.length);
    const all = (await (await call('analyst', 'GET', '/findings/summary')).json()) as {
      total: number;
    };
    expect(all.total).toBeGreaterThan(summary.total);
  });
});

describe('asset owner cannot act on another tenant’s objects', () => {
  const BODIES: Record<string, (id: string) => unknown> = {
    'POST /findings/bulk': (id) => ({ ids: [id], status: 'in_progress' }),
    'PATCH /findings/:id': () => ({ expectedStatus: 'open', status: 'in_progress' }),
    'POST /findings/:id/comments': () => ({ body: 'probe' }),
  };

  it('every write route an asset owner may call is covered here', () => {
    expect(WRITES.map((r) => r.key).filter((k) => !(k in BODIES))).toEqual([]);
  });

  it.each(WRITES.map((r) => [r.key, r] as const))('%s', async (key, route) => {
    const foreignFindings = (
      await t.db
        .select()
        .from(schema.findings)
        .where(eq(schema.findings.hostname, `www.${OTHER}`))
    ).map((f) => f.id);
    for (const id of [...foreignFindings, ...foreignIds]) {
      const before = await t.db.select().from(schema.findings).where(eq(schema.findings.id, id));
      const path = route.path.replace(/:[A-Za-z]+/g, id);
      const res = await call('asset_owner', route.method, path, BODIES[key]!(id));
      const text = await res.text();
      if (res.status === 200) {
        // Bulk endpoints answer 200 with per-item skips; nothing may have been updated.
        expect(text, key).not.toMatch(/"updated":\s*[1-9]/);
      } else {
        expect([400, 403, 404, 409], `${key} ${id}: ${text}`).toContain(res.status);
      }
      const after = await t.db.select().from(schema.findings).where(eq(schema.findings.id, id));
      expect(after, key).toEqual(before);
    }
    const comments = await t.db.select().from(schema.findingComments);
    expect(comments.filter((c) => foreignFindings.includes(c.findingId))).toEqual([]);
  });
});
