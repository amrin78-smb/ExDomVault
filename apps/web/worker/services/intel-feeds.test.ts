// @vitest-environment node
// Intelligence feed sync against PGlite with a mocked fetch (synthetic feed content; no network).
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { SOFTWARE_PRODUCTS } from '@exdomainvault/shared';
import { asc, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FetchLike } from '../lib/feed-fetch.ts';
import { createLogger } from '../lib/logger.ts';
import {
  ENDOFLIFE_BASE,
  extractRanges,
  feedStatus,
  intelAsOf,
  kevProductsFor,
  KEV_URL,
  NVD_RETRY_BACKOFF_MS,
  NVD_URL,
  RateLimiter,
  selectCvss,
  syncEndOfLife,
  syncKev,
  syncNvd,
  type IntelDeps,
  type NvdCve,
} from './intel-feeds.ts';
import { runMaintenance } from './maintenance.ts';

let t: TestDatabase;
beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});
beforeEach(async () => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  await t.db.delete(schema.intelFeeds);
  await t.db.delete(schema.softwareEolCycles);
  await t.db.delete(schema.vulnerabilityAdvisories);
});
afterEach(() => vi.restoreAllMocks());

const NOW = new Date('2026-10-23T10:00:00.000Z');
const later = (ms: number) => new Date(NOW.getTime() + ms);
const HOUR = 3600_000;
const EOL_SLUGS = SOFTWARE_PRODUCTS.filter((p) => p.eolSlug).map((p) => p.eolSlug);

type Handler = (url: string, init?: RequestInit) => Response | Promise<Response>;

/** Routes requests by URL; unknown URLs fail the test loudly (nothing ever goes to the network). */
function router(routes: Record<string, Handler>, fallback?: Handler) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, headers: (init?.headers ?? {}) as Record<string, string> });
    const h = routes[url] ?? fallback;
    if (!h) throw new Error(`unexpected fetch ${url}`);
    return h(url, init);
  };
  return { fetch, calls };
}

const json = (body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status: 200, headers });

const deps = (fetch: FetchLike, extra: Partial<IntelDeps> = {}): IntelDeps => ({
  fetch,
  userAgent: 'ExDomainVault/test (+https://exdomainvault.amrin78.workers.dev)',
  ...extra,
});

const release = (
  name: string,
  eolFrom: string | null,
  isEol: boolean,
  latest: string | null = null,
) => ({
  name,
  codename: null,
  label: name,
  releaseDate: '2020-01-01',
  isLts: false,
  ltsFrom: null,
  isEol,
  eolFrom,
  isMaintained: !isEol,
  latest: latest ? { name: latest, date: null, link: null } : null,
});

const eolDoc = (releases: unknown[]) => ({
  schema_version: '1.2.0',
  generated_at: '2026-10-23T00:00:00Z',
  last_modified: '2026-10-22T00:00:00Z',
  result: { name: 'x', releases },
});

const feedRow = async (feed: string) =>
  (await t.db.select().from(schema.intelFeeds).where(eq(schema.intelFeeds.feed, feed)))[0];

describe('syncEndOfLife', () => {
  it('upserts release cycles for every catalogue product with a slug', async () => {
    const r = router({}, (url) =>
      url === `${ENDOFLIFE_BASE}php`
        ? json(
            eolDoc([
              release('8.3', '2027-12-31', false, '8.3.12'),
              release('7.4', '2022-11-28', true, '7.4.33'),
            ]),
          )
        : url === `${ENDOFLIFE_BASE}nginx`
          ? json(eolDoc([release('1.18', null, true, '1.18.0')]))
          : json(eolDoc([])),
    );
    expect(await syncEndOfLife(t.db, NOW, deps(r.fetch))).toBe('ok');
    expect(r.calls.map((c) => c.url).sort()).toEqual(
      EOL_SLUGS.map((s) => `${ENDOFLIFE_BASE}${s}`).sort(),
    );
    expect(r.calls[0]!.headers['User-Agent']).toMatch(/^ExDomainVault\/test \(\+https:/);
    const rows = await t.db
      .select()
      .from(schema.softwareEolCycles)
      .orderBy(asc(schema.softwareEolCycles.product), asc(schema.softwareEolCycles.cycle));
    expect(rows.map((c) => [c.product, c.cycle, c.eolDate, c.eolBoolean, c.latest])).toEqual([
      ['nginx', '1.18', null, true, '1.18.0'],
      ['php', '7.4', '2022-11-28', null, '7.4.33'],
      ['php', '8.3', '2027-12-31', null, '8.3.12'],
    ]);
    expect(await feedRow('endoflife')).toMatchObject({ items: 3, lastError: null });
    expect((await feedRow('endoflife'))!.lastSuccessAt).toEqual(NOW);
    expect(await intelAsOf(t.db)).toEqual(NOW);

    // Daily: a second run the same day does nothing; after a day it runs again and updates.
    expect(await syncEndOfLife(t.db, later(HOUR), deps(r.fetch))).toBe('skipped');
    const r2 = router({}, (url) =>
      url === `${ENDOFLIFE_BASE}php`
        ? json(eolDoc([release('8.3', '2027-12-31', false, '8.3.13')]))
        : json(eolDoc([])),
    );
    expect(await syncEndOfLife(t.db, later(25 * HOUR), deps(r2.fetch))).toBe('ok');
    const php83 = await t.db
      .select()
      .from(schema.softwareEolCycles)
      .where(eq(schema.softwareEolCycles.cycle, '8.3'));
    expect(php83[0]!.latest).toBe('8.3.13');
  });

  it('keeps going when one product fails and records a partial error', async () => {
    const r = router({}, (url) =>
      url === `${ENDOFLIFE_BASE}php`
        ? new Response('oops', { status: 500 })
        : url === `${ENDOFLIFE_BASE}nginx`
          ? json({ result: { releases: [{ name: 1 }] } }) // malformed
          : json(eolDoc([release('1.0', null, false)])),
    );
    expect(await syncEndOfLife(t.db, NOW, deps(r.fetch))).toBe('ok');
    expect(await feedRow('endoflife')).toMatchObject({ lastError: 'partial_http_500' });
    const products = new Set(
      (await t.db.select().from(schema.softwareEolCycles)).map((c) => c.product),
    );
    expect(products.has('php')).toBe(false);
    expect(products.has('nginx')).toBe(false);
    expect(products.has('postgresql')).toBe(true);
  });

  it('records a failure class (no body) when every product fails, and retries after an hour', async () => {
    const r = router({}, () => new Response('<html>internal details</html>', { status: 502 }));
    expect(await syncEndOfLife(t.db, NOW, deps(r.fetch))).toBe('error:http_502');
    const row = (await feedRow('endoflife'))!;
    expect(row).toMatchObject({ lastError: 'http_502', lastSuccessAt: null });
    expect(row.lastAttemptAt).toEqual(NOW);
    expect(await syncEndOfLife(t.db, later(10 * 60_000), deps(r.fetch))).toBe('skipped');
    expect(await syncEndOfLife(t.db, later(HOUR + 1000), deps(r.fetch))).toBe('error:http_502');
    expect(await intelAsOf(t.db)).toBeNull();
  });
});

// --- KEV -------------------------------------------------------------------------------------

const kevEntry = (
  cveID: string,
  vendorProject: string,
  product: string,
  extra: Record<string, unknown> = {},
) => ({
  cveID,
  vendorProject,
  product,
  vulnerabilityName: `${vendorProject} ${product} issue`,
  dateAdded: '2024-01-10',
  shortDescription: `Synthetic description for ${cveID}.`,
  requiredAction: 'Apply updates.',
  dueDate: '2024-01-31',
  knownRansomwareCampaignUse: 'Unknown',
  notes: '',
  ...extra,
});

const kevDoc = (version: string, vulnerabilities: unknown[]) => ({
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  catalogVersion: version,
  dateReleased: '2026-10-22T00:00:00.000Z',
  count: vulnerabilities.length,
  vulnerabilities,
});

describe('kevProductsFor', () => {
  it.each([
    ['PHP', 'PHP', ['php']],
    ['PHP', 'FastCGI Process Manager (FPM)', ['php']],
    ['phpMyAdmin', 'phpMyAdmin', []],
    ['Microsoft', 'Internet Information Services (IIS)', ['microsoft_iis']],
    ['Microsoft', 'IIS', ['microsoft_iis']],
    ['Acme', 'Tiiscan', []],
    ['Apache', 'HTTP Server', ['apache_httpd']],
    ['Apache', 'Tomcat', ['apache_tomcat']],
    ['Apache', 'Struts', []],
    ['Nginx', 'nginx', ['nginx']],
    ['Node.js', 'Node.js', ['nodejs']],
    ['Oracle', 'MySQL Server', ['mysql']],
    ['Exim', 'Exim', ['exim']],
    ['Eximious', 'Thing', []],
  ])('%s %s → %j', (vendor, product, expected) => {
    expect(kevProductsFor(vendor, product)).toEqual(expected);
  });
});

describe('syncKev', () => {
  it('upserts pre-matched entries, stores the catalogue version and validators', async () => {
    const r = router({
      [KEV_URL]: () =>
        json(
          kevDoc('2026.10.22', [
            kevEntry('CVE-2019-11043', 'PHP', 'FastCGI Process Manager (FPM)', {
              knownRansomwareCampaignUse: 'Known',
            }),
            kevEntry('CVE-2017-7269', 'Microsoft', 'Internet Information Services (IIS)'),
            kevEntry('CVE-2020-0001', 'phpMyAdmin', 'phpMyAdmin'),
            kevEntry('CVE-2021-0002', 'Acme', 'Router'),
            { cveID: 'not-a-cve', vendorProject: 'PHP', product: 'PHP' }, // malformed: skipped
          ]),
          { etag: '"kev-1"', 'last-modified': 'Thu, 22 Oct 2026 00:00:00 GMT' },
        ),
    });
    expect(await syncKev(t.db, NOW, deps(r.fetch))).toBe('ok');
    const rows = await t.db
      .select()
      .from(schema.vulnerabilityAdvisories)
      .orderBy(asc(schema.vulnerabilityAdvisories.cveId));
    expect(rows.map((a) => [a.cveId, a.product, a.kev, a.ransomware, a.nvdFetchedAt])).toEqual([
      ['CVE-2017-7269', 'microsoft_iis', true, false, null],
      ['CVE-2019-11043', 'php', true, true, null],
    ]);
    expect(rows[1]).toMatchObject({
      kevDateAdded: '2024-01-10',
      title: 'PHP FastCGI Process Manager (FPM) issue',
      description: 'Synthetic description for CVE-2019-11043.',
      ranges: [],
    });
    expect(await feedRow('cisa_kev')).toMatchObject({
      items: 2,
      sourceVersion: '2026.10.22',
      etag: '"kev-1"',
      lastModified: 'Thu, 22 Oct 2026 00:00:00 GMT',
      lastError: null,
    });
  });

  it('sends validators next time and treats 304 as success without changes', async () => {
    const first = router({
      [KEV_URL]: () =>
        json(kevDoc('v1', [kevEntry('CVE-2019-11043', 'PHP', 'PHP')]), { etag: '"e1"' }),
    });
    await syncKev(t.db, NOW, deps(first.fetch));
    const second = router({ [KEV_URL]: () => new Response(null, { status: 304 }) });
    expect(await syncKev(t.db, later(25 * HOUR), deps(second.fetch))).toBe('not_modified');
    expect(second.calls[0]!.headers['If-None-Match']).toBe('"e1"');
    const row = (await feedRow('cisa_kev'))!;
    expect(row).toMatchObject({ items: 1, sourceVersion: 'v1', etag: '"e1"' });
    expect(row.lastSuccessAt).toEqual(later(25 * HOUR));
  });

  it('keeps NVD data on refresh and marks CVEs that left the catalogue kev=false', async () => {
    await syncKev(
      t.db,
      NOW,
      deps(
        router({
          [KEV_URL]: () =>
            json(
              kevDoc('v1', [
                kevEntry('CVE-2019-11043', 'PHP', 'PHP'),
                kevEntry('CVE-2021-41773', 'Apache', 'HTTP Server'),
              ]),
            ),
        }).fetch,
      ),
    );
    await t.db
      .update(schema.vulnerabilityAdvisories)
      .set({ ranges: [{ endExcluding: '7.3.11' }], nvdStatus: 'ok', nvdFetchedAt: NOW })
      .where(eq(schema.vulnerabilityAdvisories.cveId, 'CVE-2019-11043'));
    await syncKev(
      t.db,
      later(25 * HOUR),
      deps(
        router({
          [KEV_URL]: () =>
            json(
              kevDoc('v2', [
                kevEntry('CVE-2019-11043', 'PHP', 'PHP', { knownRansomwareCampaignUse: 'Known' }),
              ]),
            ),
        }).fetch,
      ),
    );
    const rows = await t.db
      .select()
      .from(schema.vulnerabilityAdvisories)
      .orderBy(asc(schema.vulnerabilityAdvisories.cveId));
    expect(rows.map((a) => [a.cveId, a.kev, a.ransomware, a.nvdStatus, a.ranges])).toEqual([
      ['CVE-2019-11043', true, true, 'ok', [{ endExcluding: '7.3.11' }]],
      ['CVE-2021-41773', false, false, null, []],
    ]);
  });

  it('fails on a malformed envelope or an oversized body without writing', async () => {
    const bad = router({ [KEV_URL]: () => json({ vulnerabilities: 'nope' }) });
    expect(await syncKev(t.db, NOW, deps(bad.fetch))).toBe('error:invalid_schema');
    expect(await feedRow('cisa_kev')).toMatchObject({ lastError: 'invalid_schema' });
    const huge = router({
      [KEV_URL]: () =>
        new Response('{}', { status: 200, headers: { 'content-length': String(64 << 20) } }),
    });
    expect(await syncKev(t.db, later(2 * HOUR), deps(huge.fetch))).toBe('error:too_large');
    expect(await t.db.select().from(schema.vulnerabilityAdvisories)).toHaveLength(0);
  });

  it('refuses a redirect to another host', async () => {
    const r = router({
      [KEV_URL]: () =>
        new Response(null, { status: 302, headers: { location: 'https://evil.example/kev.json' } }),
    });
    expect(await syncKev(t.db, NOW, deps(r.fetch))).toBe('error:redirect_refused');
    expect(r.calls).toHaveLength(1);
  });
});

// --- NVD -------------------------------------------------------------------------------------

const cpe = (vendor: string, product: string, version = '*', update = '*') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:${update}:*:*:*:*:*:*`;

const nvdCve = (id: string, cpeMatch: unknown[], metrics: Record<string, unknown> = {}) => ({
  cve: {
    id,
    sourceIdentifier: 'secalert@example.org',
    published: '2019-10-28T15:15:10.997',
    lastModified: '2024-01-01T00:00:00.000',
    vulnStatus: 'Analyzed',
    descriptions: [{ lang: 'en', value: 'Synthetic.' }],
    metrics,
    configurations: [{ nodes: [{ operator: 'OR', negate: false, cpeMatch }] }],
  },
});

const nvdDoc = (...vulnerabilities: unknown[]) => ({
  resultsPerPage: vulnerabilities.length,
  startIndex: 0,
  totalResults: vulnerabilities.length,
  format: 'NVD_CVE',
  version: '2.0',
  timestamp: '2026-10-23T00:00:00.000',
  vulnerabilities,
});

const metric = (score: number, type = 'Primary') => [
  { source: 'nvd@nist.gov', type, cvssData: { baseScore: score } },
];

describe('extractRanges / selectCvss', () => {
  const asCve = (v: ReturnType<typeof nvdCve>) => v.cve as unknown as NvdCve;

  it('takes vulnerable application CPEs of the product, exact versions and bounds', () => {
    const cve = asCve(
      nvdCve('CVE-2023-0001', [
        { vulnerable: true, criteria: cpe('openbsd', 'openssh', '8.2', 'p1') },
        { vulnerable: true, criteria: cpe('openbsd', 'openssh', '7.4') },
        {
          vulnerable: true,
          criteria: cpe('openbsd', 'openssh'),
          versionStartIncluding: '8.5',
          versionEndExcluding: '9.3',
        },
        { vulnerable: false, criteria: cpe('openbsd', 'openssh', '6.0') }, // not vulnerable
        { vulnerable: true, criteria: cpe('openbsd', 'openssh', '-') }, // not applicable
        { vulnerable: true, criteria: cpe('openbsd', 'openbsd', '7.0') }, // other product
        { vulnerable: true, criteria: 'cpe:2.3:o:openbsd:openssh:1.0:*:*:*:*:*:*:*' }, // not `a`
        { vulnerable: true, criteria: cpe('openbsd', 'openssh', '7.4') }, // duplicate
      ]),
    );
    expect(extractRanges(cve, { vendor: 'openbsd', product: 'openssh' })).toEqual([
      { startIncluding: '8.2p1', endIncluding: '8.2p1' },
      { startIncluding: '7.4', endIncluding: '7.4' },
      { startIncluding: '8.5', endExcluding: '9.3' },
    ]);
  });

  it('handles escaped characters, negated nodes and "every version"', () => {
    const cve = {
      id: 'CVE-2023-0002',
      configurations: [
        {
          nodes: [
            {
              negate: true,
              cpeMatch: [{ vulnerable: true, criteria: cpe('nodejs', 'node.js', '1.0.0') }],
            },
            {
              cpeMatch: [
                { vulnerable: true, criteria: cpe('nodejs', 'node.js', '18.0.0\\-rc1') },
                { vulnerable: true, criteria: cpe('nodejs', 'node.js') },
              ],
            },
          ],
        },
      ],
    } as NvdCve;
    expect(extractRanges(cve, { vendor: 'nodejs', product: 'node.js' })).toEqual([
      { startIncluding: '18.0.0-rc1', endIncluding: '18.0.0-rc1' },
      {},
    ]);
  });

  it('prefers CVSS v3.1 (primary), then v4.0, then v3.0', () => {
    const c = (metrics: Record<string, unknown>) => asCve(nvdCve('CVE-2023-0003', [], metrics));
    expect(
      selectCvss(
        c({
          cvssMetricV31: [...metric(7.5, 'Secondary'), ...metric(9.8)],
          cvssMetricV40: metric(9.3),
          cvssMetricV30: metric(5.0),
        }),
      ),
    ).toBe(9.8);
    expect(selectCvss(c({ cvssMetricV40: metric(9.3), cvssMetricV30: metric(5.0) }))).toBe(9.3);
    expect(selectCvss(c({ cvssMetricV30: metric(5.0, 'Secondary') }))).toBe(5.0);
    expect(selectCvss(c({}))).toBeNull();
  });
});

describe('RateLimiter', () => {
  it('allows N per window and sleeps until the oldest leaves the window', async () => {
    let clock = 0;
    const sleeps: number[] = [];
    const limiter = new RateLimiter(
      5,
      30_000,
      () => clock,
      async (ms) => {
        sleeps.push(ms);
        clock += ms;
      },
    );
    for (let i = 0; i < 5; i++) await limiter.acquire();
    expect(sleeps).toEqual([]);
    await limiter.acquire();
    expect(sleeps).toEqual([30_001]);
  });
});

async function seedAdvisory(cveId: string, product: string, createdAt = NOW) {
  await t.db.insert(schema.vulnerabilityAdvisories).values({
    cveId,
    product,
    kev: true,
    title: `${cveId} title`,
    createdAt,
    updatedAt: createdAt,
  });
}

const adv = async (cveId: string) =>
  (
    await t.db
      .select()
      .from(schema.vulnerabilityAdvisories)
      .where(eq(schema.vulnerabilityAdvisories.cveId, cveId))
      .orderBy(asc(schema.vulnerabilityAdvisories.product))
  )[0]!;

describe('syncNvd', () => {
  const nvdUrl = (id: string) => `${NVD_URL}?cveId=${id}`;

  it('stores ranges, cvss, published time and statuses for pending advisories', async () => {
    await seedAdvisory('CVE-2019-11043', 'php', later(-3 * HOUR));
    await seedAdvisory('CVE-2020-0002', 'nginx', later(-2 * HOUR));
    await seedAdvisory('CVE-2020-0003', 'redis', later(-1 * HOUR));
    const r = router({
      [nvdUrl('CVE-2019-11043')]: () =>
        json(
          nvdDoc(
            nvdCve(
              'CVE-2019-11043',
              [
                {
                  vulnerable: true,
                  criteria: cpe('php', 'php'),
                  versionStartIncluding: '7.3.0',
                  versionEndExcluding: '7.3.11',
                },
              ],
              { cvssMetricV31: metric(9.8) },
            ),
          ),
        ),
      // The KEV alias matched, but NVD lists another vendor's product: never matched to hosts.
      [nvdUrl('CVE-2020-0002')]: () =>
        json(nvdDoc(nvdCve('CVE-2020-0002', [{ vulnerable: true, criteria: cpe('acme', 'x') }]))),
      [nvdUrl('CVE-2020-0003')]: () => json(nvdDoc()),
    });
    expect(await syncNvd(t.db, NOW, deps(r.fetch, { nvdApiKey: 'k-123' }))).toBe('ok');
    expect(r.calls.map((c) => c.headers.apiKey)).toEqual(['k-123', 'k-123', 'k-123']);
    expect(await adv('CVE-2019-11043')).toMatchObject({
      nvdStatus: 'ok',
      ranges: [{ startIncluding: '7.3.0', endExcluding: '7.3.11' }],
      cvss: 9.8,
      publishedAt: new Date('2019-10-28T15:15:10.997Z'),
      nvdFetchedAt: NOW,
    });
    expect(await adv('CVE-2020-0002')).toMatchObject({ nvdStatus: 'no_product_match', ranges: [] });
    expect(await adv('CVE-2020-0003')).toMatchObject({ nvdStatus: 'not_found', ranges: [] });
    const status = await feedStatus(t.db);
    expect(status.feeds.find((f) => f.feed === 'nvd')).toMatchObject({
      items: 1,
      pending: 0,
      lastError: null,
    });
    // Nothing pending: no request.
    const idle = router({});
    expect(await syncNvd(t.db, later(HOUR), deps(idle.fetch))).toBe('skipped');
    expect(idle.calls).toHaveLength(0);
  });

  it('fetches a CVE once for several products and sends no apiKey without a key', async () => {
    await seedAdvisory('CVE-2022-1000', 'mysql');
    await seedAdvisory('CVE-2022-1000', 'mariadb');
    const r = router({
      [nvdUrl('CVE-2022-1000')]: () =>
        json(
          nvdDoc(
            nvdCve('CVE-2022-1000', [
              { vulnerable: true, criteria: cpe('oracle', 'mysql', '5.7.30') },
            ]),
          ),
        ),
    });
    await syncNvd(t.db, NOW, deps(r.fetch));
    expect(r.calls).toHaveLength(1);
    expect(r.calls[0]!.headers.apiKey).toBeUndefined();
    const rows = await t.db
      .select()
      .from(schema.vulnerabilityAdvisories)
      .orderBy(asc(schema.vulnerabilityAdvisories.product));
    expect(rows.map((a) => [a.product, a.nvdStatus, a.ranges])).toEqual([
      ['mariadb', 'no_product_match', []],
      ['mysql', 'ok', [{ startIncluding: '5.7.30', endIncluding: '5.7.30' }]],
    ]);
  });

  it('limits the batch to 5 without a key, oldest first, and keeps runs a window apart', async () => {
    for (let i = 0; i < 7; i++) {
      await seedAdvisory(`CVE-2024-000${i}`, 'php', later(i * 1000));
    }
    const r = router({}, (url) => json(nvdDoc(nvdCve(url.split('=')[1]!, []))));
    await syncNvd(t.db, NOW, deps(r.fetch));
    expect(r.calls.map((c) => c.url.split('=')[1])).toEqual([
      'CVE-2024-0000',
      'CVE-2024-0001',
      'CVE-2024-0002',
      'CVE-2024-0003',
      'CVE-2024-0004',
    ]);
    // A concurrent / immediate second run is refused by the feed claim.
    expect(await syncNvd(t.db, later(10_000), deps(r.fetch))).toBe('skipped');
    expect(r.calls).toHaveLength(5);
    await syncNvd(t.db, later(31_000), deps(r.fetch));
    expect(r.calls).toHaveLength(7);
  });

  it('honours the in-run rate limit when the batch exceeds it', async () => {
    for (let i = 0; i < 6; i++) await seedAdvisory(`CVE-2024-100${i}`, 'php', later(i * 1000));
    let clock = 0;
    const sleep = vi.fn(async (ms: number) => {
      clock += ms;
    });
    const r = router({}, (url) => json(nvdDoc(nvdCve(url.split('=')[1]!, []))));
    await syncNvd(t.db, NOW, deps(r.fetch, { nvdBatch: 6, clock: () => clock, sleep }));
    expect(r.calls).toHaveLength(6);
    expect(sleep).toHaveBeenCalledTimes(1);
  });

  it('backs off a failed lookup and retries it later; rate limiting stops the batch', async () => {
    await seedAdvisory('CVE-2024-2000', 'php', later(-2000));
    await seedAdvisory('CVE-2024-2001', 'php', later(-1000));
    const failing = router({
      [nvdUrl('CVE-2024-2000')]: () => new Response('<html>error</html>', { status: 500 }),
      [nvdUrl('CVE-2024-2001')]: () => json({ unexpected: true }),
    });
    expect(await syncNvd(t.db, NOW, deps(failing.fetch))).toBe('error:http_500');
    expect(await adv('CVE-2024-2000')).toMatchObject({ nvdStatus: 'error', nvdFetchedAt: null });
    expect(await adv('CVE-2024-2001')).toMatchObject({ nvdStatus: 'error', nvdFetchedAt: null });
    expect(await feedRow('nvd')).toMatchObject({ lastError: 'http_500', lastSuccessAt: null });
    expect((await feedStatus(t.db)).feeds.find((f) => f.feed === 'nvd')!.pending).toBe(2);

    // Within the back-off window nothing is retried.
    const idle = router({});
    expect(await syncNvd(t.db, later(HOUR), deps(idle.fetch))).toBe('skipped');
    expect(idle.calls).toHaveLength(0);

    // After it: retried. Rate limited → stop without penalising the CVE.
    const limited = router({}, () => new Response('', { status: 403 }));
    const after = later(NVD_RETRY_BACKOFF_MS + 60_000);
    expect(await syncNvd(t.db, after, deps(limited.fetch))).toBe('error:rate_limited');
    expect(limited.calls).toHaveLength(1);

    const ok = router({}, (url) => json(nvdDoc(nvdCve(url.split('=')[1]!, []))));
    expect(await syncNvd(t.db, later(NVD_RETRY_BACKOFF_MS + 2 * 60_000), deps(ok.fetch))).toBe(
      'ok',
    );
    expect(await adv('CVE-2024-2000')).toMatchObject({ nvdStatus: 'no_product_match' });
  });
});

describe('maintenance isolation', () => {
  it('runs every feed step and the rest of maintenance even when one feed fails', async () => {
    await seedAdvisory('CVE-2019-11043', 'php');
    const r = router({}, (url) => {
      if (url === KEV_URL) throw new TypeError('connection reset');
      if (url.startsWith(ENDOFLIFE_BASE)) return json(eolDoc([release('7.4', '2022-11-28', true)]));
      return json(
        nvdDoc(
          nvdCve('CVE-2019-11043', [
            { vulnerable: true, criteria: cpe('php', 'php'), versionEndExcluding: '7.3.11' },
          ]),
        ),
      );
    });
    const logger = createLogger({ test: true });
    const errors: unknown[] = [];
    vi.spyOn(logger, 'error').mockImplementation((m, f) => errors.push([m, f]));
    const info = vi.spyOn(logger, 'info');
    await runMaintenance(t.db, NOW, logger, { intel: deps(r.fetch) });

    const steps = info.mock.calls
      .filter(([m]) => m === 'maintenance_step')
      .map(([, f]) => (f as { step: string }).step);
    expect(steps).toEqual(
      expect.arrayContaining([
        'leases_reaped',
        'evaluate_pending_jobs',
        'intel_endoflife',
        'intel_cisa_kev',
        'intel_nvd',
      ]),
    );
    expect(await feedRow('cisa_kev')).toMatchObject({ lastError: 'network' });
    expect(await feedRow('endoflife')).toMatchObject({ lastError: null });
    expect(await adv('CVE-2019-11043')).toMatchObject({ nvdStatus: 'ok' });
    expect(errors).toEqual([]);
  });

  it('never fetches when no intel dependencies are given', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    await runMaintenance(t.db, NOW, createLogger({ test: true }));
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(await t.db.select().from(schema.intelFeeds)).toHaveLength(0);
  });
});
