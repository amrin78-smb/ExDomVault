// @vitest-environment node
// Exposed software (Milestone 11): inventory from evaluation, SOFT-001/002 end to end with seeded
// intelligence, the read API per role, and the intel feed endpoints (fetch mocked; no network).
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { RULES } from '@exdomainvault/rules';
import {
  intelFeedsResponseSchema,
  softwareListResponseSchema,
  softwareSummaryResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { asc, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FetchLike } from '../lib/feed-fetch.ts';
import { evaluateJob } from '../services/evaluation.ts';
import { ENDOFLIFE_BASE, KEV_URL } from '../services/intel-feeds.ts';
import { seedDomain, seedJob, type Seed } from '../testing/findings-fixtures.ts';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

let t: TestDatabase;
let clock: Date;
let feedFetch: FetchLike;
const h = harness(
  () => t,
  () => clock,
  { intel: { fetch: (url, init) => feedFetch(url, init) } },
);

beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});
beforeEach(async () => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  clock = new Date('2026-10-23T10:00:00.000Z');
  feedFetch = async (url) => {
    throw new Error(`unexpected fetch ${url}`);
  };
  await t.db.delete(schema.findings);
  await t.db.delete(schema.softwareInventory);
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
  await t.db.delete(schema.intelFeeds);
  await t.db.delete(schema.softwareEolCycles);
  await t.db.delete(schema.vulnerabilityAdvisories);
  await t.db.delete(schema.auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const at = (hours: number) => new Date(Date.parse('2026-10-20T00:00:00.000Z') + hours * 3600_000);
let seq = 0;

interface WebSpec {
  url: string;
  server?: string;
  xPoweredBy?: string;
  status?: 'success' | 'error';
}
interface PortSpec {
  ip: string;
  port: number;
  product: string;
  version?: string;
}

/** A succeeded job whose profile runs the software checks, with http/port/dns observations. */
async function softwareJob(
  s: Seed,
  completedAt: Date,
  web: WebSpec[],
  ports: PortSpec[] = [],
  dnsA: Record<string, string[]> = {},
): Promise<string> {
  const jobId = await seedJob(
    t,
    s.domainId,
    completedAt,
    Object.entries(dnsA).map(([hostname, values]) => ({ hostname, recordType: 'A', values })),
  );
  const [job] = await t.db.select().from(schema.scanJobs).where(eq(schema.scanJobs.id, jobId));
  const snapshot = job!.scopeSnapshot as {
    profile: { config: { active: boolean; checks: string[] } };
  };
  snapshot.profile.config.active = true;
  snapshot.profile.config.checks = ['dns', 'http_headers', 'service_identification'];
  await t.db
    .update(schema.scanJobs)
    .set({ scopeSnapshot: snapshot })
    .where(eq(schema.scanJobs.id, jobId));
  const common = {
    scanJobId: jobId,
    observedAt: completedAt,
    checkerVersion: 'test',
  };
  if (web.length > 0) {
    await t.db.insert(schema.httpObservations).values(
      web.map((w) => ({
        ...common,
        resultId: `sw-${seq++}`,
        checker: 'http',
        resultStatus: w.status ?? ('success' as const),
        url: w.url,
        ipAddress: '203.0.113.10',
        statusCode: 200,
        evidence: {
          ...(w.server ? { server: w.server } : {}),
          ...(w.xPoweredBy ? { xPoweredBy: w.xPoweredBy } : {}),
        },
      })),
    );
  }
  if (ports.length > 0) {
    await t.db.insert(schema.portObservations).values(
      ports.map((p) => ({
        ...common,
        resultId: `sw-${seq++}`,
        checker: 'nmap',
        resultStatus: 'success' as const,
        ipAddress: p.ip,
        port: p.port,
        state: 'open',
        service: 'x',
        evidence: { product: p.product, ...(p.version ? { version: p.version } : {}) },
      })),
    );
  }
  return jobId;
}

/** Intelligence as the feeds would have stored it. */
async function seedIntel(syncedAt = at(-1)) {
  await t.db.insert(schema.intelFeeds).values([
    { feed: 'endoflife', lastSuccessAt: syncedAt, items: 3 },
    { feed: 'cisa_kev', lastSuccessAt: syncedAt, items: 2, sourceVersion: '2026.10.22' },
    { feed: 'nvd', lastSuccessAt: syncedAt, items: 1 },
  ]);
  await t.db.insert(schema.softwareEolCycles).values([
    { product: 'php', cycle: '7.4', eolDate: '2022-11-28', latest: '7.4.33', fetchedAt: syncedAt },
    { product: 'php', cycle: '8.3', eolDate: '2027-12-31', latest: '8.3.12', fetchedAt: syncedAt },
    { product: 'nginx', cycle: '1.18', eolBoolean: true, latest: '1.18.0', fetchedAt: syncedAt },
  ]);
  await t.db.insert(schema.vulnerabilityAdvisories).values([
    {
      cveId: 'CVE-2019-11043',
      product: 'php',
      kev: true,
      ransomware: true,
      cvss: 9.8,
      title: 'PHP FPM buffer underflow',
      ranges: [{ startIncluding: '7.4.0', endExcluding: '7.4.4' }],
      nvdStatus: 'ok',
      nvdFetchedAt: syncedAt,
    },
    // Pending NVD: no ranges, never matched.
    { cveId: 'CVE-2024-0001', product: 'php', kev: true, title: 'Pending' },
  ]);
}

const softRows = () =>
  t.db
    .select()
    .from(schema.findings)
    .where(eq(schema.findings.category, 'software'))
    .orderBy(asc(schema.findings.ruleId), asc(schema.findings.component));
const inventory = () =>
  t.db.select().from(schema.softwareInventory).orderBy(asc(schema.softwareInventory.locationKey));

describe('evaluation integration', () => {
  it('upserts inventory and raises SOFT-001/SOFT-002 from seeded intelligence', async () => {
    const s = await seedDomain(t, 'example.com', { owned: true });
    await seedIntel();
    const job = await softwareJob(
      s,
      at(1),
      [{ url: 'https://www.example.com/', server: 'nginx', xPoweredBy: 'PHP/7.4.3' }],
      [{ ip: '203.0.113.10', port: 22, product: 'OpenSSH', version: '8.2p1 Ubuntu 4ubuntu0.5' }],
      { 'www.example.com': ['203.0.113.10'] },
    );
    const r = await evaluateJob(t.db, job, clock, RULES);
    expect(r).toMatchObject({ status: 'evaluated', software: 3 });

    const inv = await inventory();
    expect(
      inv.map((i) => [i.locationKey, i.version, i.backportDistribution, i.assetId, i.port]),
    ).toEqual([
      ['http_header|www.example.com|||nginx', null, null, s.wwwAssetId, null],
      ['http_header|www.example.com|||php', '7.4.3', null, s.wwwAssetId, null],
      // Unambiguous: only www resolved to this address in the job.
      ['service_identification||203.0.113.10|22|openssh', '8.2p1', 'Ubuntu', s.wwwAssetId, 22],
    ]);
    expect(inv[1]!.firstSeenAt).toEqual(at(1));
    expect(inv[1]!.lastScanJobId).toBe(job);

    const soft = await softRows();
    expect(soft.map((f) => [f.ruleId, f.hostname, f.component, f.status])).toEqual([
      ['SOFT-001', 'www.example.com', 'http_header:www.example.com:php', 'open'],
      ['SOFT-002', 'www.example.com', 'http_header:www.example.com:php:CVE-2019-11043', 'open'],
    ]);
    expect(soft[0]!.evidence).toMatchObject({ version: '7.4.3', cycle: '7.4' });
  });

  it('without any synced feed passes no intelligence: inventory only, no software findings', async () => {
    const s = await seedDomain(t, 'example.com');
    const job = await softwareJob(s, at(1), [
      { url: 'https://www.example.com/', xPoweredBy: 'PHP/7.4.3' },
    ]);
    await evaluateJob(t.db, job, clock, RULES);
    expect(await inventory()).toHaveLength(1);
    expect(await softRows()).toHaveLength(0);
  });

  it('advances last seen and the version, never moves back, never deletes', async () => {
    const s = await seedDomain(t, 'example.com');
    const j1 = await softwareJob(s, at(1), [
      { url: 'https://www.example.com/', xPoweredBy: 'PHP/7.4.3' },
      { url: 'https://api.example.com/', server: 'nginx/1.18.0' },
    ]);
    await evaluateJob(t.db, j1, clock, []);
    const j2 = await softwareJob(s, at(2), [
      { url: 'https://www.example.com/', xPoweredBy: 'PHP/8.3.1' },
      { url: 'https://api.example.com/', server: 'nginx/1.18.0', status: 'error' }, // failed
    ]);
    await evaluateJob(t.db, j2, clock, []);
    const inv = await inventory();
    expect(inv.map((i) => [i.hostname, i.version, i.lastSeenAt.toISOString()])).toEqual([
      ['api.example.com', '1.18.0', at(1).toISOString()],
      ['www.example.com', '8.3.1', at(2).toISOString()],
    ]);
    expect(inv[1]!.firstSeenAt).toEqual(at(1));
  });
});

// --- Read API -----------------------------------------------------------------------------------

interface World {
  owned: Seed;
  other: Seed;
}

/** Two domains; `owned`'s www asset belongs to the asset_owner user. */
async function world(): Promise<World> {
  const owned = await seedDomain(t, 'example.com', { owned: true });
  const other = await seedDomain(t, 'example.org');
  await seedIntel();
  await evaluateJob(
    t.db,
    await softwareJob(owned, at(1), [
      { url: 'https://www.example.com/', server: 'nginx/1.18.0', xPoweredBy: 'PHP/7.4.3' },
      { url: 'https://shop.example.com/', xPoweredBy: 'PHP/8.3.1' },
    ]),
    clock,
    [],
  );
  await evaluateJob(
    t.db,
    await softwareJob(other, at(1), [
      { url: 'https://www.example.org/', server: 'Apache/2.4.41 (Ubuntu)' },
    ]),
    clock,
    [],
  );
  return { owned, other };
}

const list = async (role: Role, qs = '') => {
  const res = await userCall(h, t, role, 'GET', `/software${qs}`);
  expect(res.status).toBe(200);
  return softwareListResponseSchema.parse(await res.json());
};

describe('GET /software', () => {
  it('lists inventory with computed end-of-life and known-exploited status', async () => {
    await world();
    const body = await list('viewer');
    expect(body.total).toBe(4);
    expect(body.items.map((i) => [i.domain.fqdn, i.hostname, i.product, i.version])).toEqual([
      ['example.com', 'shop.example.com', 'php', '8.3.1'],
      ['example.com', 'www.example.com', 'nginx', '1.18.0'],
      ['example.com', 'www.example.com', 'php', '7.4.3'],
      ['example.org', 'www.example.org', 'apache_httpd', '2.4.41'],
    ]);
    const php74 = body.items[2]!;
    expect(php74).toMatchObject({
      productLabel: 'PHP',
      source: 'http_header',
      eol: { cycle: '7.4', eolDate: '2022-11-28', isEol: true, latestInCycle: '7.4.33' },
      knownExploited: [{ cveId: 'CVE-2019-11043', cvss: 9.8, ransomware: true }],
    });
    expect(body.items[0]!.eol).toMatchObject({ cycle: '8.3', isEol: false });
    expect(body.items[1]!.eol).toMatchObject({ cycle: '1.18', isEol: true, eolDate: null });
    expect(body.items[3]!).toMatchObject({
      eol: null, // no cycles known for Apache in this fixture: unknown, not "supported"
      backportHint: { distribution: 'Ubuntu' },
    });
  });

  it('filters by status, product, domain and text; pages', async () => {
    const w = await world();
    const eol = await list('analyst', '?status=eol');
    expect(eol.total).toBe(2);
    expect(eol.items.map((i) => `${i.product} ${i.version}`)).toEqual([
      'nginx 1.18.0',
      'php 7.4.3',
    ]);
    const kev = await list('analyst', '?status=kev');
    expect(kev.items.map((i) => `${i.product} ${i.version}`)).toEqual(['php 7.4.3']);
    expect((await list('analyst', '?product=php')).total).toBe(2);
    expect((await list('analyst', `?domainId=${w.other.domainId}`)).total).toBe(1);
    expect((await list('analyst', '?q=shop')).total).toBe(1);
    const page2 = await list('analyst', '?pageSize=1&page=2&status=eol');
    expect(page2).toMatchObject({ page: 2, pageSize: 1, total: 2 });
    expect(page2.items[0]!.version).toBe('7.4.3');
    expect((await userCall(h, t, 'viewer', 'GET', '/software?pageSize=101')).status).toBe(400);
    expect((await userCall(h, t, 'viewer', 'GET', '/software?status=bad')).status).toBe(400);
  });

  it('shows asset owners only software on assets they own', async () => {
    await world();
    const mine = await list('asset_owner');
    expect(mine.items.map((i) => `${i.hostname} ${i.product}`)).toEqual([
      'www.example.com nginx',
      'www.example.com php',
    ]);
    expect((await list('asset_owner', '?status=kev')).total).toBe(1);
  });

  it('GET /domains/:id/software is scoped to the domain; unknown domain is 404', async () => {
    const w = await world();
    const res = await userCall(h, t, 'viewer', 'GET', `/domains/${w.other.domainId}/software`);
    expect(res.status).toBe(200);
    const body = softwareListResponseSchema.parse(await res.json());
    expect(body.items.map((i) => i.product)).toEqual(['apache_httpd']);
    const owner = await userCall(
      h,
      t,
      'asset_owner',
      'GET',
      `/domains/${w.other.domainId}/software`,
    );
    expect(softwareListResponseSchema.parse(await owner.json()).total).toBe(0);
    expect(
      (
        await userCall(
          h,
          t,
          'viewer',
          'GET',
          '/domains/00000000-0000-4000-8000-000000000000/software',
        )
      ).status,
    ).toBe(404);
  });
});

describe('GET /software/summary', () => {
  it('rolls up hosts, end-of-life and known-exploited counts per product', async () => {
    await world();
    const res = await userCall(h, t, 'viewer', 'GET', '/software/summary');
    const body = softwareSummaryResponseSchema.parse(await res.json());
    expect(body.products).toEqual([
      {
        product: 'php',
        productLabel: 'PHP',
        hosts: 2,
        eol: 1,
        knownExploited: 1,
        versions: [
          { version: '7.4.3', hosts: 1 },
          { version: '8.3.1', hosts: 1 },
        ],
      },
      {
        product: 'apache_httpd',
        productLabel: 'Apache HTTP Server',
        hosts: 1,
        eol: 0,
        knownExploited: 0,
        versions: [{ version: '2.4.41', hosts: 1 }],
      },
      {
        product: 'nginx',
        productLabel: 'nginx',
        hosts: 1,
        eol: 1,
        knownExploited: 0,
        versions: [{ version: '1.18.0', hosts: 1 }],
      },
    ]);
    const owner = softwareSummaryResponseSchema.parse(
      await (await userCall(h, t, 'asset_owner', 'GET', '/software/summary')).json(),
    );
    expect(owner.products.map((p) => [p.product, p.hosts])).toEqual([
      ['nginx', 1],
      ['php', 1],
    ]);
  });
});

// --- Intel feeds --------------------------------------------------------------------------------

describe('intel feed endpoints', () => {
  it('GET /intel/feeds reports every feed (findings:read)', async () => {
    await seedIntel(at(-1));
    const res = await userCall(h, t, 'viewer', 'GET', '/intel/feeds');
    expect(res.status).toBe(200);
    const body = intelFeedsResponseSchema.parse(await res.json());
    expect(body.feeds.map((f) => [f.feed, f.items, f.pending])).toEqual([
      ['endoflife', 3, 0],
      ['cisa_kev', 2, 0],
      ['nvd', 1, 1],
    ]);
    expect(body.feeds[1]!.sourceVersion).toBe('2026.10.22');
    expect((await userCall(h, t, 'asset_owner', 'GET', '/intel/feeds')).status).toBe(200);
  });

  it('POST /intel/feeds/sync needs settings:manage, syncs endoflife + KEV and is audited', async () => {
    for (const role of ['analyst', 'viewer', 'asset_owner'] as const) {
      expect((await userCall(h, t, role, 'POST', '/intel/feeds/sync')).status).toBe(403);
    }
    const urls: string[] = [];
    feedFetch = async (url) => {
      urls.push(url);
      if (url === KEV_URL) {
        return Response.json({
          catalogVersion: '2026.10.23',
          vulnerabilities: [
            {
              cveID: 'CVE-2019-11043',
              vendorProject: 'PHP',
              product: 'PHP',
              vulnerabilityName: 'PHP issue',
              dateAdded: '2024-01-10',
              shortDescription: 'Synthetic.',
              knownRansomwareCampaignUse: 'Unknown',
            },
          ],
        });
      }
      if (url.startsWith(ENDOFLIFE_BASE)) {
        return Response.json({
          result: { releases: [{ name: '1.0', isEol: false, eolFrom: null, latest: null }] },
        });
      }
      throw new Error(`unexpected fetch ${url}`);
    };
    const res = await userCall(h, t, 'admin', 'POST', '/intel/feeds/sync');
    expect(res.status).toBe(200);
    const body = intelFeedsResponseSchema.parse(await res.json());
    const byFeed = Object.fromEntries(body.feeds.map((f) => [f.feed, f]));
    expect(byFeed.cisa_kev).toMatchObject({
      items: 1,
      sourceVersion: '2026.10.23',
      lastError: null,
      lastSuccessAt: clock.toISOString(),
    });
    expect(byFeed.endoflife!.lastSuccessAt).toBe(clock.toISOString());
    expect(byFeed.nvd).toMatchObject({ lastSuccessAt: null, pending: 1 });
    expect(urls).toContain(KEV_URL);
    expect(urls.some((u) => u.includes('nvd'))).toBe(false);

    const admin = await ensureUser(t, 'admin');
    const audit = await t.db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'intel.sync_requested'));
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ actorType: 'user', actorUserId: admin });

    // Within a minute the sync is a no-op (still audited, no fetch).
    urls.length = 0;
    expect((await userCall(h, t, 'admin', 'POST', '/intel/feeds/sync')).status).toBe(200);
    expect(urls).toEqual([]);
  });

  it('requires a same-origin request for the sync', async () => {
    const { createApp } = await import('../app.ts');
    await ensureUser(t, 'admin');
    const res = await createApp(h.deps).request(
      '/api/v1/intel/feeds/sync',
      { method: 'POST' },
      h.env('admin') as unknown as Env,
    );
    expect(res.status).toBe(403);
  });
});
