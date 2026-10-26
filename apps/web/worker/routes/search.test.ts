// @vitest-environment node
// Global search (Milestone 13): every group, ordering, LIKE wildcard escaping, port / CVE / IP
// queries, permission-gated groups and asset-owner scoping. Synthetic data only; no network.
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { errorResponseSchema, searchResponseSchema, type Role } from '@exdomainvault/shared';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { cveQuery, ipQuery, portQuery } from '../services/search.ts';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const { assetIps, assets, domains, findings, intelFeeds, portObservations, scanJobs } = schema;

let t: TestDatabase;
const clock = new Date('2026-10-23T10:00:00.000Z');
const h = harness(
  () => t,
  () => clock,
);
const DAY = 86_400_000;
const at = (days: number) => new Date(clock.getTime() + days * DAY);

interface World {
  com: string;
  nets: string;
  www: string;
  api: string;
  mail: string;
}
let w: World;

beforeAll(async () => {
  t = await createTestDatabase();
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  w = await seed();
}, 30_000);
afterAll(async () => {
  vi.restoreAllMocks();
  await t?.close();
});

async function seed(): Promise<World> {
  const adminId = await ensureUser(t, 'admin');
  const ownerId = await ensureUser(t, 'asset_owner');
  const [com, nets] = await t.db
    .insert(domains)
    .values([{ fqdn: 'example.com' }, { fqdn: 'examples.net' }, { fqdn: 'shop-example.org' }])
    .returning();
  const approved = {
    verificationStatus: 'approved' as const,
    approvedBy: adminId,
    approvedAt: clock,
  };
  const [www, api, mail] = await t.db
    .insert(assets)
    .values([
      {
        domainId: com!.id,
        hostname: 'www.example.com',
        assetType: 'subdomain',
        discoverySource: 'manual',
        ownerUserId: ownerId,
        ...approved,
      },
      {
        domainId: com!.id,
        hostname: 'api.example.com',
        assetType: 'subdomain',
        discoverySource: 'manual',
        ...approved,
      },
      {
        domainId: nets!.id,
        hostname: 'mail.examples.net',
        assetType: 'subdomain',
        discoverySource: 'dns',
      },
    ])
    .returning();
  await t.db.insert(assetIps).values([
    { assetId: www!.id, ipAddress: '203.0.113.10', source: 'dns' },
    { assetId: api!.id, ipAddress: '203.0.113.10', source: 'dns' },
    { assetId: mail!.id, ipAddress: '203.0.113.25', source: 'dns' },
    { assetId: www!.id, ipAddress: '198.51.100.7', source: 'dns', isCurrent: false },
    { assetId: api!.id, ipAddress: '2001:db8::5', source: 'dns' },
  ]);

  const [job] = await t.db
    .insert(scanJobs)
    .values({
      jobType: 'scan',
      profile: 'quick',
      domainId: com!.id,
      status: 'succeeded',
      scopeSnapshot: {},
    })
    .returning();
  let n = 0;
  const port = (
    ip: string,
    p: number,
    state: string,
    observedAt: Date,
    service: string | null = 'https',
  ) => ({
    resultId: `search-port-${n++}`,
    scanJobId: job!.id,
    observedAt,
    checker: 'nmap',
    checkerVersion: '1',
    resultStatus: 'success' as const,
    ipAddress: ip,
    port: p,
    state,
    service,
  });
  await t.db.insert(portObservations).values([
    port('203.0.113.10', 443, 'open', at(-1)),
    // Was open, latest observation says closed → not listed.
    port('203.0.113.25', 443, 'open', at(-3)),
    port('203.0.113.25', 443, 'closed', at(-1)),
    // Open, but no asset currently resolves to it.
    port('203.0.113.99', 443, 'open', at(-1), null),
    port('203.0.113.10', 22, 'open', at(-1), 'ssh'),
  ]);

  await t.db.insert(intelFeeds).values({ feed: 'cisa_kev', lastSuccessAt: at(-1), items: 2 });
  await t.db.insert(schema.vulnerabilityAdvisories).values([
    {
      cveId: 'CVE-2019-11043',
      product: 'php',
      kev: true,
      title: 'PHP FPM buffer underflow',
      ranges: [{ startIncluding: '7.4.0', endExcluding: '7.4.4' }],
      nvdStatus: 'ok',
    },
    // Matches the id text but affects no reported version → not listed.
    {
      cveId: 'CVE-2019-99999',
      product: 'php',
      kev: true,
      title: 'Old PHP',
      ranges: [{ startIncluding: '5.0.0', endExcluding: '5.6.0' }],
      nvdStatus: 'ok',
    },
  ]);
  const inv = (assetId: string, hostname: string, product: string, version: string) => ({
    domainId: com!.id,
    assetId,
    hostname,
    source: 'http_header',
    product,
    version,
    banner: product,
    locationKey: `search-${n++}`,
    firstSeenAt: at(-1),
    lastSeenAt: at(-1),
  });
  await t.db
    .insert(schema.softwareInventory)
    .values([
      inv(www!.id, 'www.example.com', 'php', '7.4.3'),
      inv(api!.id, 'api.example.com', 'apache_httpd', '2.4.49'),
    ]);

  let f = 0;
  const finding = (domainId: string, assetId: string | null, title: string) => ({
    domainId,
    assetId,
    hostname: 'example.com',
    component: `c${f}`,
    category: 'http',
    ruleId: 'TST-S',
    ruleVersion: 1,
    fingerprint: `search-fp-${f++}`,
    title,
    description: 'Synthetic.',
    severity: 'medium' as const,
    confidence: 'high' as const,
    riskScore: 30,
    riskInputs: {},
    evidence: {},
    firstSeenAt: at(-1),
    lastSeenAt: at(-1),
  });
  await t.db
    .insert(findings)
    .values([
      finding(com!.id, www!.id, 'a_b header missing'),
      finding(com!.id, api!.id, 'aXbc header missing'),
      finding(com!.id, null, '100% coverage gap'),
      finding(com!.id, www!.id, 'Header missing'),
    ]);
  return { com: com!.id, nets: nets!.id, www: www!.id, api: api!.id, mail: mail!.id };
}

const search = async (role: Role, q: string) => {
  const res = await userCall(h, t, role, 'GET', `/search?q=${encodeURIComponent(q)}`);
  expect(res.status, await res.clone().text()).toBe(200);
  return searchResponseSchema.parse(await res.json());
};

describe('query classification', () => {
  it('recognises port, CVE and IP queries', () => {
    expect([
      portQuery('443'),
      portQuery('port:443'),
      portQuery('PORT 22'),
      portQuery('70000'),
    ]).toEqual([443, 443, 22, null]);
    expect(portQuery('443x')).toBeNull();
    expect([cveQuery('cve-2024-38475'), cveQuery('2024-384'), cveQuery('apache')]).toEqual([
      'CVE-2024-38475',
      '2024-384',
      null,
    ]);
    expect([ipQuery('203.0.'), ipQuery('2001:DB8'), ipQuery('cafe'), ipQuery('www')]).toEqual([
      '203.0.',
      '2001:db8',
      null,
      null,
    ]);
  });
});

describe('GET /search', () => {
  it('validates q', async () => {
    for (const q of ['', 'q=a', `q=${'a'.repeat(101)}`]) {
      const res = await userCall(h, t, 'viewer', 'GET', `/search?${q}`);
      expect(res.status).toBe(400);
      expect(errorResponseSchema.parse(await res.json()).error.code).toBe('validation_failed');
    }
  });

  it('searches domains and assets: exact first, then shortest, then alphabetical', async () => {
    const r = await search('viewer', 'Example');
    expect(r.q).toBe('Example');
    expect(r.domains.map((d) => d.fqdn)).toEqual([
      'example.com',
      'examples.net',
      'shop-example.org',
    ]);
    expect(r.assets.map((a) => a.hostname)).toEqual([
      'api.example.com',
      'www.example.com',
      'mail.examples.net',
    ]);
    expect(r.assets[2]!.domain).toEqual({ id: w.nets, fqdn: 'examples.net' });
    expect((await search('viewer', 'examples.net')).domains.map((d) => d.fqdn)).toEqual([
      'examples.net',
    ]);
    expect((await search('viewer', 'example.com')).domains[0]!.fqdn).toBe('example.com');
  });

  it('escapes LIKE wildcards in the query', async () => {
    expect((await search('viewer', 'a_b')).findings.map((f) => f.title)).toEqual([
      'a_b header missing',
    ]);
    expect((await search('viewer', '0%')).findings.map((f) => f.title)).toEqual([
      '100% coverage gap',
    ]);
    const none = await search('viewer', '%%');
    expect([none.domains, none.assets, none.findings, none.software]).toEqual([[], [], [], []]);
  });

  it('searches findings by title', async () => {
    const r = await search('analyst', 'header missing');
    expect(r.findings.map((f) => f.title)).toEqual([
      'Header missing',
      'a_b header missing',
      'aXbc header missing',
    ]);
    expect(r.findings[0]).toMatchObject({
      severity: 'medium',
      domain: { id: w.com, fqdn: 'example.com' },
    });
  });

  it('matches current IP addresses by prefix', async () => {
    const r = await search('viewer', '203.0.113');
    expect(r.ips).toEqual([
      {
        ipAddress: '203.0.113.10',
        assets: [
          { id: w.api, hostname: 'api.example.com' },
          { id: w.www, hostname: 'www.example.com' },
        ],
      },
      { ipAddress: '203.0.113.25', assets: [{ id: w.mail, hostname: 'mail.examples.net' }] },
    ]);
    expect((await search('viewer', '198.51')).ips).toEqual([]); // no longer current
    expect((await search('viewer', '2001:DB8')).ips.map((i) => i.ipAddress)).toEqual([
      '2001:db8::5',
    ]);
    // Prefix, not substring.
    expect((await search('viewer', '0.113')).ips).toEqual([]);
  });

  it('lists latest open ports for a port query', async () => {
    const expected = [
      { ipAddress: '203.0.113.10', port: 443, service: 'https', hostname: 'api.example.com' },
      { ipAddress: '203.0.113.99', port: 443, service: null, hostname: null },
    ];
    expect((await search('viewer', '443')).ports).toEqual(expected);
    expect((await search('viewer', 'port:443')).ports).toEqual(expected);
    expect((await search('viewer', 'header')).ports).toEqual([]);
  });

  it('searches software by product, catalogue label and version', async () => {
    const label = await search('viewer', 'apache http');
    expect(label.software).toEqual([
      {
        product: 'apache_httpd',
        productLabel: 'Apache HTTP Server',
        version: '2.4.49',
        hostname: 'api.example.com',
        domain: { id: w.com, fqdn: 'example.com' },
      },
    ]);
    expect((await search('viewer', '7.4')).software.map((s) => [s.product, s.version])).toEqual([
      ['php', '7.4.3'],
    ]);
    expect((await search('viewer', 'php')).software.map((s) => s.hostname)).toEqual([
      'www.example.com',
    ]);
  });

  it('lists CVEs that possibly affect a reported version', async () => {
    const expected = [{ cve: 'CVE-2019-11043', kev: true, affectedHosts: 1 }];
    expect((await search('viewer', 'CVE-2019')).vulnerabilities).toEqual(expected);
    expect((await search('viewer', '2019-110')).vulnerabilities).toEqual(expected);
    expect((await search('viewer', 'cve-2019-11043')).vulnerabilities).toEqual(expected);
    expect((await search('viewer', 'php')).vulnerabilities).toEqual([]); // not a CVE query
  });

  it('scopes asset owners and returns groups they may not read empty', async () => {
    const owner = await search('asset_owner', 'example');
    expect(owner.domains).toEqual([]); // no domains:read
    expect(owner.assets.map((a) => a.id)).toEqual([w.www]);
    expect((await search('asset_owner', '203.0.113')).ips).toEqual([
      { ipAddress: '203.0.113.10', assets: [{ id: w.www, hostname: 'www.example.com' }] },
    ]);
    expect((await search('asset_owner', '443')).ports).toEqual([
      { ipAddress: '203.0.113.10', port: 443, service: 'https', hostname: 'www.example.com' },
    ]);
    expect((await search('asset_owner', 'header missing')).findings.map((f) => f.title)).toEqual([
      'Header missing',
      'a_b header missing',
    ]);
    expect((await search('asset_owner', '0%')).findings).toEqual([]);
    expect((await search('asset_owner', 'apache')).software).toEqual([]);
    expect((await search('asset_owner', 'CVE-2019')).vulnerabilities).toHaveLength(1);
  });
});
