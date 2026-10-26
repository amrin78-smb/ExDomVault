// @vitest-environment node
// Overview dashboard (Milestone 13): stats, deltas and daily series, severity, trend, remediation
// order, certificate expiry, recent assets with roles, top software, asset-owner scoping and
// query validation. Synthetic data at fixed timestamps; no network.
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { dashboardResponseSchema, errorResponseSchema, type Role } from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const {
  assetIps,
  assets,
  auditLogs,
  domains,
  findings,
  intelFeeds,
  portObservations,
  scanJobs,
  scanProfiles,
  softwareEolCycles,
  softwareInventory,
  tlsObservations,
  vulnerabilityAdvisories,
} = schema;

let t: TestDatabase;
const clock = new Date('2026-10-23T10:00:00.000Z');
const h = harness(
  () => t,
  () => clock,
);
const DAY = 86_400_000;
const at = (days: number) => new Date(clock.getTime() + days * DAY);

beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});

beforeEach(async () => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  await t.db.delete(findings);
  await t.db.delete(softwareInventory);
  await t.db.delete(scanJobs);
  await t.db.delete(assets);
  await t.db.delete(domains);
  await t.db.delete(intelFeeds);
  await t.db.delete(softwareEolCycles);
  await t.db.delete(vulnerabilityAdvisories);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const call = (role: Role, path: string) => userCall(h, t, role, 'GET', path);
const get = async (role: Role, query = '') => {
  const res = await call(role, `/dashboard${query}`);
  expect(res.status, await res.clone().text()).toBe(200);
  return dashboardResponseSchema.parse(await res.json());
};

let seq = 0;
function finding(
  domainId: string,
  over: Partial<typeof findings.$inferInsert> & { firstSeenAt: Date },
): typeof findings.$inferInsert {
  seq++;
  return {
    domainId,
    hostname: 'example.com',
    component: `c${seq}`,
    category: 'dns',
    ruleId: 'TST-X',
    ruleVersion: 1,
    fingerprint: `fp-${seq}`,
    title: `Finding ${seq}`,
    description: 'Synthetic.',
    severity: 'low',
    confidence: 'high',
    riskScore: 10,
    riskInputs: {},
    evidence: {},
    lastSeenAt: over.firstSeenAt,
    ...over,
  };
}

interface World {
  com: string;
  net: string;
  org: string;
  www: string;
  api: string;
  mail: string;
  findings: Record<'f1' | 'f2' | 'f3' | 'f7', string>;
  jobs: { passive: string; discovery: string };
}

/**
 * Domains: example.org (created 40 days ago), example.com (20 days ago, monitored), example.net
 * (2026-10-20). Assets: www.example.com (approved 2026-10-18, owned by the asset owner),
 * api.example.com (pending), mail.example.net (approved 2026-10-22, port 25 open → mail role).
 */
async function seed(): Promise<World> {
  const adminId = await ensureUser(t, 'admin');
  const ownerId = await ensureUser(t, 'asset_owner');
  const [com, net, org] = await t.db
    .insert(domains)
    .values([
      { fqdn: 'example.com', monitoringEnabled: true, createdAt: at(-20) },
      { fqdn: 'example.net', createdAt: at(-3) },
      { fqdn: 'example.org', createdAt: at(-40) },
    ])
    .returning();
  const [www, api, mail] = await t.db
    .insert(assets)
    .values([
      {
        domainId: com!.id,
        hostname: 'www.example.com',
        assetType: 'subdomain',
        discoverySource: 'manual',
        ownerUserId: ownerId,
        verificationStatus: 'approved',
        approvedBy: adminId,
        approvedAt: at(-5),
        firstSeenAt: at(-10),
      },
      {
        domainId: com!.id,
        hostname: 'api.example.com',
        assetType: 'subdomain',
        discoverySource: 'certificate_transparency',
        firstSeenAt: at(-2),
      },
      {
        domainId: net!.id,
        hostname: 'mail.example.net',
        assetType: 'subdomain',
        discoverySource: 'dns',
        verificationStatus: 'approved',
        approvedBy: adminId,
        approvedAt: at(-1),
        firstSeenAt: at(-1),
      },
    ])
    .returning();

  const rows = await t.db
    .insert(findings)
    .values([
      // f1: open high, today.
      finding(com!.id, {
        assetId: www!.id,
        hostname: 'www.example.com',
        severity: 'high',
        riskScore: 70,
        firstSeenAt: new Date('2026-10-23T01:00:00Z'),
      }),
      // f2: acknowledged critical.
      finding(com!.id, {
        assetId: www!.id,
        hostname: 'www.example.com',
        severity: 'critical',
        riskScore: 90,
        status: 'acknowledged',
        firstSeenAt: new Date('2026-10-20T05:00:00Z'),
      }),
      // f3: domain-level SOFT-002 naming a CVE.
      finding(com!.id, {
        severity: 'medium',
        riskScore: 40,
        ruleId: 'SOFT-002',
        category: 'software',
        evidence: { cveId: 'CVE-2019-11043', product: 'php' },
        firstSeenAt: new Date('2026-10-01T12:00:00Z'),
      }),
      // f4: accepted risk with the highest score — counted as open, never a remediation item.
      finding(net!.id, {
        severity: 'low',
        riskScore: 95,
        status: 'accepted_risk',
        acceptedRiskReason: 'Compensating control',
        acceptedRiskApprovedBy: adminId,
        acceptedRiskReviewAt: at(30),
        firstSeenAt: new Date('2026-09-01T00:00:00Z'),
      }),
      // f5: resolved inside the range.
      finding(com!.id, {
        assetId: www!.id,
        hostname: 'www.example.com',
        severity: 'medium',
        status: 'resolved',
        firstSeenAt: new Date('2026-10-18T00:00:00Z'),
        resolvedAt: new Date('2026-10-22T00:00:00Z'),
      }),
      // f6: resolved before the 7-day range.
      finding(org!.id, {
        status: 'resolved',
        firstSeenAt: new Date('2026-10-10T00:00:00Z'),
        resolvedAt: new Date('2026-10-12T00:00:00Z'),
      }),
      // f7: open low on mail, same score as f1 (severity breaks the tie).
      finding(net!.id, {
        assetId: mail!.id,
        hostname: 'mail.example.net',
        severity: 'low',
        riskScore: 70,
        firstSeenAt: new Date('2026-10-19T08:00:00Z'),
      }),
    ])
    .returning();

  const [passive, discovery] = await t.db
    .insert(scanJobs)
    .values([
      {
        jobType: 'scan',
        profile: 'passive',
        domainId: com!.id,
        status: 'succeeded',
        scopeSnapshot: {},
        createdAt: at(-2),
        completedAt: at(-1 / 24),
      },
      {
        jobType: 'discovery',
        profile: 'discovery',
        domainId: net!.id,
        status: 'failed',
        scopeSnapshot: {},
        createdAt: at(-1),
        completedAt: at(-0.5),
      },
    ])
    .returning();

  // Mail role evidence: SMTP open on the current address.
  await t.db
    .insert(assetIps)
    .values({ assetId: mail!.id, ipAddress: '203.0.113.25', source: 'dns' });
  await t.db.insert(portObservations).values({
    resultId: 'dash-port-25',
    scanJobId: passive!.id,
    observedAt: at(-1),
    checker: 'nmap',
    checkerVersion: '1',
    resultStatus: 'success',
    ipAddress: '203.0.113.25',
    port: 25,
    state: 'open',
    service: 'smtp',
  });

  // Certificates: www (latest 25 days left), api (20), mail (expired 3 days ago), apex (200).
  let n = 0;
  const tls = (
    assetId: string | null,
    hostname: string,
    observedAt: Date,
    notAfter: Date,
  ): typeof tlsObservations.$inferInsert => ({
    resultId: `dash-tls-${n++}`,
    assetId,
    scanJobId: passive!.id,
    observedAt,
    checker: 'tls',
    checkerVersion: '1',
    resultStatus: 'success',
    hostname,
    port: 443,
    issuer: 'Test CA',
    notAfter,
  });
  await t.db
    .insert(tlsObservations)
    .values([
      tls(www!.id, 'www.example.com', at(-2), at(300)),
      tls(www!.id, 'www.example.com', at(-1), at(25)),
      tls(api!.id, 'api.example.com', at(-1), at(20)),
      tls(mail!.id, 'mail.example.net', at(-1), at(-3)),
      tls(null, 'example.com', at(-1), at(200)),
    ]);

  // Software inventory and intelligence.
  await t.db.insert(intelFeeds).values([{ feed: 'cisa_kev', lastSuccessAt: at(-1), items: 1 }]);
  await t.db.insert(softwareEolCycles).values([
    { product: 'php', cycle: '7.4', eolDate: '2022-11-28', latest: '7.4.33', fetchedAt: at(-1) },
    { product: 'php', cycle: '8.3', eolDate: '2027-12-31', latest: '8.3.12', fetchedAt: at(-1) },
    { product: 'nginx', cycle: '1.18', eolBoolean: true, latest: '1.18.0', fetchedAt: at(-1) },
  ]);
  await t.db.insert(vulnerabilityAdvisories).values({
    cveId: 'CVE-2019-11043',
    product: 'php',
    kev: true,
    title: 'PHP FPM buffer underflow',
    ranges: [{ startIncluding: '7.4.0', endExcluding: '7.4.4' }],
    nvdStatus: 'ok',
    nvdFetchedAt: at(-1),
  });
  const inv = (
    over: Partial<typeof softwareInventory.$inferInsert> & { product: string },
  ): typeof softwareInventory.$inferInsert => ({
    domainId: com!.id,
    source: 'http_header',
    banner: over.product,
    locationKey: `k-${n++}`,
    firstSeenAt: at(-1),
    lastSeenAt: at(-1),
    ...over,
  });
  await t.db.insert(softwareInventory).values([
    inv({ assetId: www!.id, hostname: 'www.example.com', product: 'nginx', version: '1.18.0' }),
    inv({ assetId: www!.id, hostname: 'www.example.com', product: 'php', version: '7.4.3' }),
    inv({ assetId: api!.id, hostname: 'api.example.com', product: 'php', version: '8.3.1' }),
    inv({
      source: 'service_identification',
      ipAddress: '203.0.113.10',
      port: 22,
      product: 'openssh',
      version: '8.2p1',
    }),
  ]);

  return {
    com: com!.id,
    net: net!.id,
    org: org!.id,
    www: www!.id,
    api: api!.id,
    mail: mail!.id,
    findings: { f1: rows[0]!.id, f2: rows[1]!.id, f3: rows[2]!.id, f7: rows[6]!.id },
    jobs: { passive: passive!.id, discovery: discovery!.id },
  };
}

describe('GET /dashboard', () => {
  it('is available to every role (sections are gated per permission)', async () => {
    for (const role of ['admin', 'analyst', 'asset_owner', 'viewer'] as Role[]) {
      expect((await call(role, '/dashboard')).status).toBe(200);
    }
  });

  it('rejects an unsupported range', async () => {
    for (const q of ['range=14', 'range=abc', 'range=0']) {
      const res = await call('viewer', `/dashboard?${q}`);
      expect(res.status).toBe(400);
      expect(errorResponseSchema.parse(await res.json()).error.code).toBe('validation_failed');
    }
  });

  it('returns a complete, empty dashboard without data; series have range + 1 points', async () => {
    const d = await get('viewer');
    expect(d.range).toBe(30);
    expect(d.lastScanAt).toBeNull();
    expect(d.stats.domains).toEqual({ value: 0, delta: 0, series: Array(31).fill(0), active: 0 });
    expect(d.stats.openFindings.series).toHaveLength(31);
    expect(d.stats.expiringCertificates).toEqual({ value: 0, delta: null, series: [] });
    expect(d.stats.eolSoftware).toEqual({ value: 0, delta: null, series: [], kev: 0 });
    expect(d.severity).toEqual({ informational: 0, low: 0, medium: 0, high: 0, critical: 0 });
    expect(d.trend).toHaveLength(31);
    expect(d.trend[0]!.date).toBe('2026-09-23');
    expect(d.trend[30]!.date).toBe('2026-10-23');
    for (const [range, points] of [
      [7, 8],
      [90, 91],
    ] as const) {
      const r = await get('viewer', `?range=${range}`);
      expect(r.range).toBe(range);
      expect(r.stats.assets.series).toHaveLength(points);
      expect(r.stats.criticalHigh.series).toHaveLength(points);
      expect(r.trend).toHaveLength(points);
    }
    expect([d.topRemediation, d.latestScans, d.certificateExpiry, d.recentAssets]).toEqual([
      [],
      [],
      [],
      [],
    ]);
    expect(d.topSoftware).toEqual([]);
  });

  it('aggregates the portfolio from stored data', async () => {
    const w = await seed();
    const d = await get('analyst', '?range=7');

    expect(d.generatedAt).toBe(clock.toISOString());
    expect(d.lastScanAt).toBe(at(-1 / 24).toISOString());

    // Days 2026-10-16 … 2026-10-23.
    expect(d.stats.domains).toEqual({
      value: 3,
      active: 1,
      delta: 1,
      series: [2, 2, 2, 2, 3, 3, 3, 3],
    });
    expect(d.stats.assets).toEqual({
      value: 2,
      pending: 1,
      delta: 2,
      series: [0, 0, 1, 1, 1, 1, 2, 2],
    });
    expect(d.stats.openFindings).toEqual({ value: 5, delta: 3, series: [2, 2, 3, 4, 5, 5, 4, 5] });
    expect(d.stats.criticalHigh).toEqual({
      value: 2,
      delta: 2,
      series: [0, 0, 0, 0, 1, 1, 1, 2],
    });
    expect(d.stats.expiringCertificates).toEqual({ value: 3, delta: null, series: [] });
    // nginx 1.18.0 and php 7.4.3 are end-of-life; php 7.4.3 is in a KEV range.
    expect(d.stats.eolSoftware).toEqual({ value: 2, delta: null, series: [], kev: 1 });

    expect(d.severity).toEqual({ informational: 0, low: 2, medium: 1, high: 1, critical: 1 });

    const day = (date: string) => d.trend.find((x) => x.date === date);
    expect(day('2026-10-18')).toMatchObject({ medium: 1, resolved: 0 });
    expect(day('2026-10-19')).toMatchObject({ low: 1 });
    expect(day('2026-10-20')).toMatchObject({ critical: 1 });
    expect(day('2026-10-22')).toMatchObject({ resolved: 1, medium: 0 });
    expect(day('2026-10-23')).toMatchObject({ high: 1 });
    expect(d.trend.reduce((n, x) => n + x.resolved, 0)).toBe(1);

    expect(
      d.topRemediation.map((r) => [r.findingId, r.riskScore, r.severity, r.cves, r.assetRole]),
    ).toEqual([
      [w.findings.f2, 90, 'critical', [], 'unclassified'],
      [w.findings.f1, 70, 'high', [], 'unclassified'],
      [w.findings.f7, 70, 'low', [], 'mail'],
      [w.findings.f3, 40, 'medium', ['CVE-2019-11043'], null],
    ]);
    expect(d.topRemediation[3]).toMatchObject({
      ruleId: 'SOFT-002',
      domain: { id: w.com, fqdn: 'example.com' },
      hostname: 'example.com',
    });

    const profiles = await t.db.select().from(scanProfiles);
    const names = Object.fromEntries(profiles.map((p) => [p.key, p.name]));
    expect(d.latestScans).toEqual([
      {
        id: w.jobs.discovery,
        jobType: 'discovery',
        domain: { id: w.net, fqdn: 'example.net' },
        profile: names.discovery,
        status: 'failed',
        createdAt: at(-1).toISOString(),
        completedAt: at(-0.5).toISOString(),
      },
      {
        id: w.jobs.passive,
        jobType: 'scan',
        domain: { id: w.com, fqdn: 'example.com' },
        profile: names.passive,
        status: 'succeeded',
        createdAt: at(-2).toISOString(),
        completedAt: at(-1 / 24).toISOString(),
      },
    ]);

    expect(d.certificateExpiry).toEqual([
      {
        hostname: 'mail.example.net',
        domain: { id: w.net, fqdn: 'example.net' },
        notAfter: at(-3).toISOString(),
        daysLeft: -3,
        issuer: 'Test CA',
      },
      {
        hostname: 'api.example.com',
        domain: { id: w.com, fqdn: 'example.com' },
        notAfter: at(20).toISOString(),
        daysLeft: 20,
        issuer: 'Test CA',
      },
      {
        hostname: 'www.example.com',
        domain: { id: w.com, fqdn: 'example.com' },
        notAfter: at(25).toISOString(),
        daysLeft: 25,
        issuer: 'Test CA',
      },
    ]);

    expect(d.recentAssets.map((a) => [a.hostname, a.status, a.source, a.role])).toEqual([
      ['mail.example.net', 'approved', 'dns', 'mail'],
      ['api.example.com', 'pending', 'certificate_transparency', 'unclassified'],
      ['www.example.com', 'approved', 'manual', 'unclassified'],
    ]);
    expect(d.recentAssets[0]).toMatchObject({
      id: w.mail,
      domain: { id: w.net, fqdn: 'example.net' },
      firstSeenAt: at(-1).toISOString(),
    });

    expect(d.topSoftware).toEqual([
      {
        product: 'php',
        productLabel: 'PHP',
        versions: ['7.4.3', '8.3.1'],
        hosts: 2,
        eolHosts: 1,
        kevCves: 1,
      },
      {
        product: 'nginx',
        productLabel: 'nginx',
        versions: ['1.18.0'],
        hosts: 1,
        eolHosts: 1,
        kevCves: 0,
      },
      {
        product: 'openssh',
        productLabel: 'OpenSSH',
        versions: ['8.2p1'],
        hosts: 1,
        eolHosts: 0,
        kevCves: 0,
      },
    ]);
  });

  it('scopes asset owners to their assets; domain counts and scans are empty', async () => {
    const w = await seed();
    const d = await get('asset_owner', '?range=7');

    expect(d.lastScanAt).toBeNull();
    expect(d.latestScans).toEqual([]);
    expect(d.stats.domains).toEqual({ value: 0, delta: null, series: [], active: 0 });
    expect(d.stats.assets).toMatchObject({ value: 1, pending: 0 });
    expect(d.stats.assets.series).toEqual([0, 0, 1, 1, 1, 1, 1, 1]);
    // Only f1, f2 (open) and f5 (resolved) are on www.
    expect(d.stats.openFindings).toMatchObject({ value: 2, series: [0, 0, 1, 1, 2, 2, 1, 2] });
    expect(d.severity).toEqual({ informational: 0, low: 0, medium: 0, high: 1, critical: 1 });
    expect(d.topRemediation.map((r) => r.findingId)).toEqual([w.findings.f2, w.findings.f1]);
    expect(d.certificateExpiry.map((c) => c.hostname)).toEqual(['www.example.com']);
    expect(d.stats.expiringCertificates.value).toBe(1);
    expect(d.recentAssets.map((a) => a.id)).toEqual([w.www]);
    expect(d.topSoftware.map((s) => [s.product, s.hosts])).toEqual([
      ['nginx', 1],
      ['php', 1],
    ]);
    expect(d.stats.eolSoftware).toMatchObject({ value: 2, kev: 1 });
  });
});
