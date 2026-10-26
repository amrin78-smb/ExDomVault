// @vitest-environment node
// Milestone 13 inventory views: GET /ports, /certificates, /vulnerabilities, /attack-surface and the
// role on the asset DTO, against PGlite with synthetic observations (reserved names/addresses).
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  ASSET_ROLES,
  DBIP_ATTRIBUTION,
  EXPORT_COLUMNS,
  assetDetailResponseSchema,
  assetListResponseSchema,
  attackSurfaceResponseSchema,
  certificatesResponseSchema,
  portsResponseSchema,
  vulnerabilitiesResponseSchema,
  type ExportResource,
  type Role,
} from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseCsv } from '../lib/csv.ts';
import { firstRow } from '../lib/db.ts';
import { seedDomain, seedJob, type Seed } from '../testing/findings-fixtures.ts';
import { ensureUser, harness, userCall, type Harness } from '../testing/harness.ts';

let t: TestDatabase;
const clock = new Date('2026-10-23T10:00:00.000Z');
const h = harness(
  () => t,
  () => clock,
);
/** Same app with a CSV export row cap of 2, to exercise truncation cheaply. */
const small = harness(
  () => t,
  () => clock,
  { exports: { maxRows: 2 } },
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
  await t.db.delete(schema.findings);
  await t.db.delete(schema.softwareInventory);
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
  await t.db.delete(schema.intelFeeds);
  await t.db.delete(schema.vulnerabilityAdvisories);
  await t.db.delete(schema.auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const DAY = 86_400_000;
const at = (hours: number) => new Date(Date.parse('2026-10-20T00:00:00.000Z') + hours * 3600_000);
const days = (n: number) => new Date(clock.getTime() + n * DAY);
let seq = 0;

const get = async (role: Role, path: string) => {
  const res = await userCall(h, t, role, 'GET', path);
  expect(res.status, path).toBe(200);
  return res.json();
};

/**
 * GET /exports/<resource>.csv for the inventory views (the encoding invariants — BOM, CRLF,
 * filename — are covered for every resource in exports.test.ts); returns the decoded rows.
 */
async function exportCsv(role: Role, resource: ExportResource, query = '', app: Harness = h) {
  const res = await userCall(app, t, role, 'GET', `/exports/${resource}.csv${query}`);
  expect(res.status, `${resource}${query}`).toBe(200);
  expect(res.headers.get('Content-Disposition')).toBe(
    `attachment; filename="exdomainvault-${resource}-20261023.csv"`,
  );
  const records = parseCsv(await res.text(), 100_000).map((r) => r.fields);
  const header = records[0]!;
  expect(header).toEqual([...EXPORT_COLUMNS[resource]]);
  return {
    res,
    rows: records.slice(1).map((r) => Object.fromEntries(header.map((c, i) => [c, r[i]!]))),
  };
}

const exportAudits = async () =>
  (await t.db.select().from(schema.auditLogs)).filter((a) => a.action === 'report.exported');

async function addAsset(
  s: Seed,
  hostname: string,
  over: Partial<typeof schema.assets.$inferInsert> = {},
): Promise<string> {
  const admin = await ensureUser(t, 'admin');
  return firstRow(
    await t.db
      .insert(schema.assets)
      .values({
        domainId: s.domainId,
        hostname,
        assetType: 'subdomain',
        discoverySource: 'manual',
        verificationStatus: 'approved',
        approvedBy: admin,
        approvedAt: at(0),
        ...over,
      })
      .returning(),
  ).id;
}

async function addIp(assetId: string, ip: string, countryCode: string | null, isCurrent = true) {
  await t.db
    .insert(schema.assetIps)
    .values({ assetId, ipAddress: ip, source: 'dns', isCurrent, countryCode });
}

interface PortSpec {
  ip: string;
  port: number;
  state: 'open' | 'closed' | 'filtered';
  service?: string;
  status?: 'success' | 'error';
}

async function addPorts(jobId: string, observedAt: Date, ports: PortSpec[]) {
  await t.db.insert(schema.portObservations).values(
    ports.map((p) => ({
      resultId: `inv-${seq++}`,
      scanJobId: jobId,
      observedAt,
      checker: 'port',
      checkerVersion: 'test',
      resultStatus: p.status ?? ('success' as const),
      ipAddress: p.ip,
      port: p.port,
      state: p.state,
      service: p.service ?? null,
    })),
  );
}

async function addFinding(
  s: Seed,
  over: Partial<typeof schema.findings.$inferInsert> & { ruleId: string; component: string },
) {
  await t.db.insert(schema.findings).values({
    domainId: s.domainId,
    hostname: s.fqdn,
    category: over.ruleId.startsWith('SOFT') ? 'software' : 'exposure',
    ruleVersion: 1,
    fingerprint: `fp-${seq++}`,
    title: 'Synthetic',
    description: 'Synthetic finding.',
    severity: 'high',
    confidence: 'high',
    riskScore: 50,
    riskInputs: {},
    evidence: {},
    firstSeenAt: at(1),
    lastSeenAt: at(2),
    ...over,
  });
}

interface World {
  owned: Seed;
  other: Seed;
  cdnAssetId: string;
}

/**
 * example.com (www owned by the asset owner) → 203.0.113.10 (NL); a stale 203.0.113.9.
 * example.org (www) → 198.51.100.20 (US) and 2001:db8::5 (no country); cdn.example.org (approved,
 * CloudFront, no addresses); pending.example.org (pending, excluded from the attack surface).
 */
async function world(): Promise<World> {
  const owned = await seedDomain(t, 'example.com', { owned: true });
  const other = await seedDomain(t, 'example.org');
  await addIp(owned.wwwAssetId, '203.0.113.10', 'NL');
  await addIp(owned.wwwAssetId, '203.0.113.9', 'NL', false);
  await addIp(other.wwwAssetId, '198.51.100.20', 'US');
  await addIp(other.wwwAssetId, '2001:db8::5', null);
  const cdnAssetId = await addAsset(other, 'cdn.example.org', {
    hostingHint: { provider: 'Amazon CloudFront', kind: 'cdn', matchedName: 'd1.cloudfront.net' },
  });
  const pending = await addAsset(other, 'pending.example.org', {
    verificationStatus: 'pending',
    approvedBy: null,
    approvedAt: null,
  });
  await addIp(pending, '192.0.2.50', 'FR');

  const j1 = await seedJob(t, owned.domainId, at(1), []);
  await addPorts(j1, at(1), [
    { ip: '203.0.113.10', port: 22, state: 'open', service: 'ssh' },
    { ip: '203.0.113.10', port: 443, state: 'open', service: 'https' },
    { ip: '203.0.113.10', port: 3306, state: 'closed' },
  ]);
  const j2 = await seedJob(t, owned.domainId, at(2), []);
  await addPorts(j2, at(2), [
    { ip: '203.0.113.10', port: 22, state: 'open', service: 'ssh' },
    { ip: '203.0.113.10', port: 443, state: 'filtered' },
  ]);
  const j3 = await seedJob(t, other.domainId, at(1), []);
  await addPorts(j3, at(1), [
    { ip: '198.51.100.20', port: 80, state: 'open', service: 'http' },
    { ip: '198.51.100.20', port: 22, state: 'open', service: 'ssh' },
    // Failed probe: never counted.
    { ip: '198.51.100.20', port: 25, state: 'open', status: 'error' },
  ]);
  await addFinding(owned, {
    ruleId: 'EXP-002',
    component: '203.0.113.10:22',
    assetId: null,
  });
  // A resolved EXP-002 is no violation.
  await addFinding(other, {
    ruleId: 'EXP-002',
    component: '198.51.100.20:22',
    status: 'resolved',
    resolvedAt: at(3),
  });
  return { owned, other, cdnAssetId };
}

// --- GET /ports ---------------------------------------------------------------------------------

describe('GET /ports', () => {
  const ports = async (role: Role, qs = '') =>
    portsResponseSchema.parse(await get(role, `/ports${qs}`));
  const keys = (r: { items: { ipAddress: string; port: number }[] }) =>
    r.items.map((i) => `${i.ipAddress}:${i.port}`);

  it('lists the latest state per address/port with hosts, country and policy violations', async () => {
    await world();
    const body = await ports('viewer');
    expect(keys(body)).toEqual(['198.51.100.20:22', '203.0.113.10:22', '198.51.100.20:80']);
    expect(body.total).toBe(3);
    expect(body.counts).toEqual({ open: 3, closed: 1, filtered: 1 });
    const ssh = body.items[1]!;
    expect(ssh).toMatchObject({
      protocol: 'tcp',
      state: 'open',
      service: 'ssh',
      hostnames: [{ hostname: 'www.example.com' }],
      domain: { fqdn: 'example.com' },
      country: 'NL',
      policyViolation: true,
      firstObservedAt: at(1).toISOString(),
      lastObservedAt: at(2).toISOString(),
    });
    expect(body.items[0]).toMatchObject({ country: 'US', policyViolation: false });
  });

  it('filters by state, port, domain and text; sorts and pages', async () => {
    const w = await world();
    const all = await ports('analyst', '?state=all&sort=ip');
    expect(all.total).toBe(5);
    expect(keys(all)).toEqual([
      '198.51.100.20:22',
      '198.51.100.20:80',
      '203.0.113.10:22',
      '203.0.113.10:443',
      '203.0.113.10:3306',
    ]);
    expect(all.items[3]).toMatchObject({ state: 'filtered', service: null });
    expect(keys(await ports('analyst', '?state=closed'))).toEqual(['203.0.113.10:3306']);
    expect((await ports('analyst', '?port=22')).total).toBe(2);
    const org = await ports('analyst', `?domainId=${w.other.domainId}`);
    expect(keys(org)).toEqual(['198.51.100.20:22', '198.51.100.20:80']);
    expect(org.counts).toEqual({ open: 2, closed: 0, filtered: 0 });
    expect((await ports('analyst', '?q=http')).total).toBe(1);
    expect((await ports('analyst', '?q=www.example.org')).total).toBe(2);
    expect((await ports('analyst', '?q=203.0.113')).total).toBe(1);
    expect(keys(await ports('analyst', '?state=all&sort=last_observed&pageSize=2'))).toEqual([
      '203.0.113.10:22',
      '203.0.113.10:443',
    ]);
    const page2 = await ports('analyst', '?pageSize=1&page=2');
    expect(page2).toMatchObject({ page: 2, pageSize: 1, total: 3 });
    expect(keys(page2)).toEqual(['203.0.113.10:22']);
    expect((await userCall(h, t, 'viewer', 'GET', '/ports?state=bogus')).status).toBe(400);
    expect((await userCall(h, t, 'viewer', 'GET', '/ports?pageSize=101')).status).toBe(400);
  });

  it('shows asset owners only addresses their assets resolve to', async () => {
    await world();
    const mine = await ports('asset_owner', '?state=all');
    expect(keys(mine)).toEqual(['203.0.113.10:22', '203.0.113.10:443', '203.0.113.10:3306']);
    expect(mine.counts).toEqual({ open: 1, closed: 1, filtered: 1 });
    expect(
      mine.items.every((i) => i.hostnames.every((x) => x.hostname === 'www.example.com')),
    ).toBe(true);
  });
  it('exports the same rows as CSV, with the list filters, visibility and an audit record', async () => {
    const w = await world();
    const { res, rows } = await exportCsv('viewer', 'ports', '?page=2&pageSize=1');
    expect(res.headers.get('X-Truncated')).toBeNull();
    expect(res.headers.get('X-Total-Rows')).toBe('3');
    expect(rows.map((r) => `${r.ip_address}:${r.port}`)).toEqual([
      '198.51.100.20:22',
      '203.0.113.10:22',
      '198.51.100.20:80',
    ]);
    expect(rows[1]).toEqual({
      ip_address: '203.0.113.10',
      port: '22',
      protocol: 'tcp',
      state: 'open',
      service: 'ssh',
      hostnames: 'www.example.com',
      domain: 'example.com',
      country: 'NL',
      policy_violation: 'true',
      first_observed_at: at(1).toISOString(),
      last_observed_at: at(2).toISOString(),
    });
    expect(rows[0]).toMatchObject({ country: 'US', policy_violation: 'false' });
    const viewerId = await ensureUser(t, 'viewer');
    const [audit] = await exportAudits();
    expect(audit).toMatchObject({
      actorUserId: viewerId,
      resourceType: 'report',
      resourceId: 'ports.csv',
      metadata: {
        resource: 'ports',
        filters: { state: 'open', sort: 'port' },
        rows: 3,
        truncated: false,
      },
    });

    const all = await exportCsv('analyst', 'ports', '?state=all&sort=ip');
    expect(all.rows).toHaveLength(5);
    expect(all.rows[3]).toMatchObject({ port: '443', state: 'filtered', service: '' });
    expect((await exportCsv('analyst', 'ports', '?state=closed')).rows).toHaveLength(1);
    expect((await exportCsv('analyst', 'ports', '?port=22')).rows).toHaveLength(2);
    const org = await exportCsv('analyst', 'ports', `?domainId=${w.other.domainId}`);
    expect(org.rows.map((r) => r.hostnames)).toEqual(['www.example.org', 'www.example.org']);

    const mine = await exportCsv('asset_owner', 'ports', '?state=all');
    expect(mine.rows.map((r) => `${r.ip_address}:${r.port}`)).toEqual([
      '203.0.113.10:22',
      '203.0.113.10:443',
      '203.0.113.10:3306',
    ]);
    // A filter naming another tenant's domain cannot widen visibility.
    const foreign = await exportCsv('asset_owner', 'ports', `?domainId=${w.other.domainId}`);
    expect(foreign.rows).toEqual([]);
    expect((await userCall(h, t, 'viewer', 'GET', '/exports/ports.csv?state=bogus')).status).toBe(
      400,
    );
  });

  it('neutralises formula-like service names and truncates at the cap', async () => {
    const w = await world();
    const job = await seedJob(t, w.owned.domainId, at(3), []);
    await addPorts(job, at(3), [
      { ip: '203.0.113.10', port: 8080, state: 'open', service: '=HYPERLINK("x")' },
    ]);
    const { rows } = await exportCsv('viewer', 'ports', '?port=8080');
    expect(rows[0]!.service).toBe(`'=HYPERLINK("x")`);

    const capped = await exportCsv('admin', 'ports', '?state=all', small);
    expect(capped.res.headers.get('X-Truncated')).toBe('true');
    expect(capped.res.headers.get('X-Total-Rows')).toBe('6');
    expect(capped.rows.map((r) => r.port)).toEqual(['22', '22']);
    const audits = await exportAudits();
    expect(audits.at(-1)!.metadata).toMatchObject({ resource: 'ports', rows: 2, truncated: true });
  });
});

// --- GET /certificates --------------------------------------------------------------------------

describe('GET /certificates', () => {
  interface TlsSpec {
    hostname: string;
    assetId?: string | null;
    port?: number;
    notAfter: Date | null;
    hostnameMatches?: boolean | null;
    trusted?: boolean;
    observedAt?: Date;
    status?: 'success' | 'error';
    issuer?: string;
  }
  async function addTls(jobId: string, specs: TlsSpec[]) {
    await t.db.insert(schema.tlsObservations).values(
      specs.map((s) => ({
        resultId: `inv-${seq++}`,
        scanJobId: jobId,
        assetId: s.assetId ?? null,
        observedAt: s.observedAt ?? at(1),
        checker: 'tls',
        checkerVersion: 'test',
        resultStatus: s.status ?? ('success' as const),
        evidence: {
          check: 'tls_certificate',
          ...(s.trusted !== undefined ? { trusted: s.trusted } : {}),
        },
        hostname: s.hostname,
        ipAddress: '203.0.113.10',
        port: s.port ?? 443,
        protocolVersion: 'TLSv1.3',
        notBefore: days(-300),
        notAfter: s.notAfter,
        issuer: s.issuer ?? 'Synthetic CA',
        subject: `CN=${s.hostname}`,
        subjectAltNames: [s.hostname],
        fingerprintSha256: 'ab'.repeat(32),
        hostnameMatches: s.hostnameMatches === undefined ? true : s.hostnameMatches,
      })),
    );
  }
  const certs = async (role: Role, qs = '') =>
    certificatesResponseSchema.parse(await get(role, `/certificates${qs}`));

  async function certWorld() {
    const w = await world();
    const j1 = await seedJob(t, w.owned.domainId, at(1), []);
    const j2 = await seedJob(t, w.other.domainId, at(1), []);
    await addTls(j1, [
      // Superseded by the newer observation below.
      {
        hostname: 'www.example.com',
        assetId: w.owned.wwwAssetId,
        notAfter: days(60),
        trusted: true,
      },
      {
        hostname: 'www.example.com',
        assetId: w.owned.wwwAssetId,
        notAfter: days(10),
        trusted: true,
        observedAt: at(2),
        issuer: 'Special Issuer',
      },
      // Failed observation: ignored.
      { hostname: 'www.example.com', notAfter: days(-5), observedAt: at(3), status: 'error' },
      { hostname: 'api.example.com', notAfter: days(-1) },
    ]);
    await addTls(j2, [
      // Expired AND mismatched: expired wins.
      {
        hostname: 'www.example.org',
        assetId: w.other.wwwAssetId,
        notAfter: days(-2),
        hostnameMatches: false,
      },
      { hostname: 'www.example.org', port: 8443, notAfter: days(60), hostnameMatches: false },
      { hostname: 'mail.example.org', notAfter: days(90), trusted: false },
      { hostname: 'ok.example.org', notAfter: days(200), hostnameMatches: null },
      // Outside the 90-day window.
      { hostname: 'old.example.org', notAfter: days(-200), observedAt: days(-100) },
    ]);
    return w;
  }

  it('lists the latest certificate per hostname/port with a primary status', async () => {
    await certWorld();
    const body = await certs('viewer');
    expect(body.items.map((i) => [`${i.hostname}:${i.port}`, i.status, i.daysLeft])).toEqual([
      ['www.example.org:443', 'expired', -2],
      ['api.example.com:443', 'expired', -1],
      ['www.example.com:443', 'expiring', 10],
      ['www.example.org:8443', 'mismatch', 60],
      ['mail.example.org:443', 'untrusted', 90],
      ['ok.example.org:443', 'valid', 200],
    ]);
    expect(body.total).toBe(6);
    expect(body.counts).toEqual({ expired: 2, expiring: 1, valid: 1, mismatch: 1, untrusted: 1 });
    expect(body.items[2]).toMatchObject({
      domain: { fqdn: 'example.com' },
      issuer: 'Special Issuer',
      trusted: true,
      hostnameMatches: true,
      ipAddress: '203.0.113.10',
      protocolVersion: 'TLSv1.3',
      subjectAltNames: ['www.example.com'],
      observedAt: at(2).toISOString(),
    });
    expect(body.items[1]).toMatchObject({ assetId: null, trusted: null });
  });

  it('filters by status, domain and text; sorts by hostname; pages', async () => {
    const w = await certWorld();
    const expired = await certs('analyst', '?status=expired');
    expect(expired.total).toBe(2);
    // Counts ignore the status filter.
    expect(expired.counts.valid).toBe(1);
    expect((await certs('analyst', `?domainId=${w.owned.domainId}`)).total).toBe(2);
    expect((await certs('analyst', '?q=special')).items.map((i) => i.hostname)).toEqual([
      'www.example.com',
    ]);
    const byName = await certs('analyst', '?sort=hostname&pageSize=2&page=2');
    expect(byName.items.map((i) => `${i.hostname}:${i.port}`)).toEqual([
      'ok.example.org:443',
      'www.example.com:443',
    ]);
    expect((await userCall(h, t, 'viewer', 'GET', '/certificates?status=bogus')).status).toBe(400);
  });

  it('shows asset owners only certificates of assets they own', async () => {
    await certWorld();
    const mine = await certs('asset_owner');
    expect(mine.items.map((i) => i.hostname)).toEqual(['www.example.com']);
    expect(mine.counts).toEqual({ expired: 0, expiring: 1, valid: 0, mismatch: 0, untrusted: 0 });
  });
  it('exports the same rows as CSV, with the list filters, visibility and an audit record', async () => {
    const w = await certWorld();
    const { res, rows } = await exportCsv('viewer', 'certificates', '?pageSize=1');
    expect(res.headers.get('X-Total-Rows')).toBe('6');
    expect(rows.map((r) => [`${r.hostname}:${r.port}`, r.status, r.days_left])).toEqual([
      ['www.example.org:443', 'expired', '-2'],
      ['api.example.com:443', 'expired', '-1'],
      ['www.example.com:443', 'expiring', '10'],
      ['www.example.org:8443', 'mismatch', '60'],
      ['mail.example.org:443', 'untrusted', '90'],
      ['ok.example.org:443', 'valid', '200'],
    ]);
    expect(rows[2]).toEqual({
      hostname: 'www.example.com',
      domain: 'example.com',
      ip_address: '203.0.113.10',
      port: '443',
      status: 'expiring',
      issuer: 'Special Issuer',
      subject: 'CN=www.example.com',
      subject_alt_names: 'www.example.com',
      not_before: days(-300).toISOString(),
      not_after: days(10).toISOString(),
      days_left: '10',
      hostname_matches: 'true',
      trusted: 'true',
      protocol_version: 'TLSv1.3',
      observed_at: at(2).toISOString(),
    });
    expect(rows[1]).toMatchObject({ trusted: '' });
    expect(rows[5]).toMatchObject({ hostname_matches: '' });
    const [audit] = await exportAudits();
    expect(audit).toMatchObject({
      resourceId: 'certificates.csv',
      metadata: {
        resource: 'certificates',
        filters: { sort: 'expiry' },
        rows: 6,
        truncated: false,
      },
    });

    expect((await exportCsv('analyst', 'certificates', '?status=expired')).rows).toHaveLength(2);
    const owned = await exportCsv('analyst', 'certificates', `?domainId=${w.owned.domainId}`);
    expect(owned.rows.map((r) => r.hostname)).toEqual(['api.example.com', 'www.example.com']);
    const byName = await exportCsv('analyst', 'certificates', '?sort=hostname&q=example.org');
    expect(byName.rows.map((r) => `${r.hostname}:${r.port}`)).toEqual([
      'mail.example.org:443',
      'ok.example.org:443',
      'www.example.org:443',
      'www.example.org:8443',
    ]);
    const mine = await exportCsv('asset_owner', 'certificates');
    expect(mine.rows.map((r) => r.hostname)).toEqual(['www.example.com']);
  });

  it('neutralises formula-like issuers and truncates at the cap', async () => {
    const w = await certWorld();
    const job = await seedJob(t, w.other.domainId, at(1), []);
    await addTls(job, [{ hostname: 'x.example.org', notAfter: days(300), issuer: '+SUM(1,2)' }]);
    const { rows } = await exportCsv('viewer', 'certificates', '?q=x.example.org');
    expect(rows.map((r) => r.issuer)).toEqual(["'+SUM(1,2)"]);

    const capped = await exportCsv('admin', 'certificates', '', small);
    expect(capped.res.headers.get('X-Truncated')).toBe('true');
    expect(capped.res.headers.get('X-Total-Rows')).toBe('7');
    expect(capped.rows.map((r) => r.hostname)).toEqual(['www.example.org', 'api.example.com']);
    // Exactly at the cap: not truncated.
    const exact = await exportCsv('admin', 'certificates', '?status=expired', small);
    expect(exact.res.headers.get('X-Truncated')).toBeNull();
    expect(exact.res.headers.get('X-Total-Rows')).toBe('2');
  });
});

// --- GET /vulnerabilities -----------------------------------------------------------------------

describe('GET /vulnerabilities', () => {
  async function vulnWorld() {
    const w = await world();
    const syncedAt = at(-1);
    await t.db.insert(schema.intelFeeds).values([
      { feed: 'cisa_kev', lastSuccessAt: syncedAt, items: 2 },
      { feed: 'nvd', lastSuccessAt: syncedAt, items: 2 },
    ]);
    await t.db.insert(schema.vulnerabilityAdvisories).values([
      {
        cveId: 'CVE-2019-11043',
        product: 'php',
        kev: true,
        ransomware: true,
        cvss: 9.8,
        kevDateAdded: '2022-03-25',
        title: 'PHP FPM buffer underflow',
        ranges: [{ startIncluding: '7.4.0', endExcluding: '7.4.4' }],
        nvdStatus: 'ok',
        nvdFetchedAt: syncedAt,
      },
      {
        cveId: 'CVE-2021-23017',
        product: 'nginx',
        kev: true,
        cvss: 7.7,
        title: 'nginx resolver off-by-one',
        ranges: [{ startIncluding: '0.6.18', endExcluding: '1.20.1' }],
        nvdStatus: 'ok',
        nvdFetchedAt: syncedAt,
      },
      // NVD not read yet: never matches.
      { cveId: 'CVE-2024-0001', product: 'php', kev: true, title: 'Pending' },
    ]);
    const inv = (
      s: Seed,
      hostname: string,
      product: string,
      version: string | null,
      assetId: string | null = null,
    ) => ({
      domainId: s.domainId,
      assetId,
      hostname,
      source: 'http_header',
      product,
      version,
      banner: `${product}/${version}`,
      locationKey: `http_header|${hostname}|||${product}`,
      firstSeenAt: at(1),
      lastSeenAt: at(1),
    });
    await t.db.insert(schema.softwareInventory).values([
      inv(w.owned, 'www.example.com', 'php', '7.4.3', w.owned.wwwAssetId),
      inv(w.other, 'shop.example.org', 'php', '7.4.2'),
      inv(w.other, 'new.example.org', 'php', '8.3.1'),
      inv(w.other, 'www.example.org', 'nginx', '1.18.0', w.other.wwwAssetId),
      // Too coarse to range-match (SOFT-002 ignores it), and hidden versions.
      inv(w.other, 'api.example.org', 'nginx', '1'),
      inv(w.other, 'hidden.example.org', 'nginx', null),
    ]);
    await addFinding(w.owned, {
      ruleId: 'SOFT-002',
      component: 'http_header:www.example.com:php:CVE-2019-11043',
      assetId: w.owned.wwwAssetId,
      evidence: { cveId: 'CVE-2019-11043' },
    });
    await addFinding(w.other, {
      ruleId: 'SOFT-002',
      component: 'http_header:shop.example.org:php:CVE-2019-11043',
      evidence: { cveId: 'CVE-2019-11043' },
    });
    await addFinding(w.other, {
      ruleId: 'SOFT-002',
      component: 'http_header:www.example.org:nginx:CVE-2021-23017',
      evidence: { cveId: 'CVE-2021-23017' },
      status: 'resolved',
      resolvedAt: at(3),
    });
    return w;
  }
  const vulns = async (role: Role, qs = '') =>
    vulnerabilitiesResponseSchema.parse(await get(role, `/vulnerabilities${qs}`));

  it('lists CVEs possibly affecting reported versions, matched like SOFT-002', async () => {
    await vulnWorld();
    const body = await vulns('viewer');
    expect(body.total).toBe(2);
    expect(body.items).toEqual([
      {
        cve: 'CVE-2019-11043',
        title: 'PHP FPM buffer underflow',
        cvss: expect.closeTo(9.8, 5),
        kev: true,
        knownRansomwareUse: true,
        products: [{ product: 'php', productLabel: 'PHP' }],
        affectedHosts: 2,
        affectedDomains: 2,
        openFindings: 2,
        kevDateAdded: '2022-03-25',
        kevDueDate: null,
      },
      expect.objectContaining({
        cve: 'CVE-2021-23017',
        affectedHosts: 1, // `nginx 1` is too coarse
        affectedDomains: 1,
        openFindings: 0,
        knownRansomwareUse: false,
      }),
    ]);
  });

  it('filters, sorts and pages', async () => {
    await vulnWorld();
    expect((await vulns('analyst', '?sort=cve')).items.map((i) => i.cve)).toEqual([
      'CVE-2019-11043',
      'CVE-2021-23017',
    ]);
    expect((await vulns('analyst', '?sort=cvss')).items[0]!.cve).toBe('CVE-2019-11043');
    expect((await vulns('analyst', '?q=nginx')).items.map((i) => i.cve)).toEqual([
      'CVE-2021-23017',
    ]);
    expect((await vulns('analyst', '?q=php')).total).toBe(1);
    expect((await vulns('analyst', '?kev=true')).total).toBe(2);
    expect((await vulns('analyst', '?kev=false')).total).toBe(0);
    const page2 = await vulns('analyst', '?pageSize=1&page=2');
    expect(page2).toMatchObject({ total: 2, page: 2 });
    expect(page2.items.map((i) => i.cve)).toEqual(['CVE-2021-23017']);
    expect((await userCall(h, t, 'viewer', 'GET', '/vulnerabilities?kev=yes')).status).toBe(400);
  });

  it('shows asset owners only their software and findings', async () => {
    await vulnWorld();
    const mine = await vulns('asset_owner');
    expect(mine.items.map((i) => [i.cve, i.affectedHosts, i.openFindings])).toEqual([
      ['CVE-2019-11043', 1, 1],
    ]);
  });

  it('is empty without intelligence', async () => {
    await world();
    expect(await vulns('viewer')).toEqual({ items: [], page: 1, pageSize: 25, total: 0 });
  });
  it('exports the same rows as CSV, with the list filters, visibility and an audit record', async () => {
    await vulnWorld();
    const { res, rows } = await exportCsv('viewer', 'vulnerabilities', '?pageSize=1&page=2');
    expect(res.headers.get('X-Total-Rows')).toBe('2');
    expect(rows).toEqual([
      {
        cve: 'CVE-2019-11043',
        title: 'PHP FPM buffer underflow',
        cvss: '9.8',
        kev: 'true',
        known_ransomware_use: 'true',
        products: 'php',
        affected_hosts: '2',
        affected_domains: '2',
        open_findings: '2',
        kev_date_added: '2022-03-25',
      },
      {
        cve: 'CVE-2021-23017',
        title: 'nginx resolver off-by-one',
        cvss: '7.7',
        kev: 'true',
        known_ransomware_use: 'false',
        products: 'nginx',
        affected_hosts: '1',
        affected_domains: '1',
        open_findings: '0',
        kev_date_added: '',
      },
    ]);
    const [audit] = await exportAudits();
    expect(audit).toMatchObject({
      resourceId: 'vulnerabilities.csv',
      metadata: {
        resource: 'vulnerabilities',
        filters: { sort: 'hosts' },
        rows: 2,
        truncated: false,
      },
    });

    const nginx = await exportCsv('analyst', 'vulnerabilities', '?q=nginx');
    expect(nginx.rows.map((r) => r.cve)).toEqual(['CVE-2021-23017']);
    const byCve = await exportCsv('analyst', 'vulnerabilities', '?sort=cve&kev=true');
    expect(byCve.rows.map((r) => r.cve)).toEqual(['CVE-2019-11043', 'CVE-2021-23017']);
    expect((await exportCsv('analyst', 'vulnerabilities', '?kev=false')).rows).toEqual([]);

    const mine = await exportCsv('asset_owner', 'vulnerabilities');
    expect(mine.rows.map((r) => [r.cve, r.affected_hosts, r.open_findings])).toEqual([
      ['CVE-2019-11043', '1', '1'],
    ]);
  });

  it('neutralises formula-like titles and truncates at the cap', async () => {
    await vulnWorld();
    await t.db.insert(schema.vulnerabilityAdvisories).values({
      cveId: 'CVE-2024-4577',
      product: 'php',
      kev: true,
      cvss: 9.8,
      title: '=cmd|calc',
      ranges: [{ startIncluding: '8.3.0', endExcluding: '8.3.8' }],
      nvdStatus: 'ok',
      nvdFetchedAt: at(-1),
    });
    const { rows } = await exportCsv('viewer', 'vulnerabilities', '?sort=cve');
    expect(rows.map((r) => [r.cve, r.title])).toEqual([
      ['CVE-2019-11043', 'PHP FPM buffer underflow'],
      ['CVE-2021-23017', 'nginx resolver off-by-one'],
      ['CVE-2024-4577', "'=cmd|calc"],
    ]);

    const capped = await exportCsv('admin', 'vulnerabilities', '?sort=cve', small);
    expect(capped.res.headers.get('X-Truncated')).toBe('true');
    expect(capped.res.headers.get('X-Total-Rows')).toBe('3');
    expect(capped.rows.map((r) => r.cve)).toEqual(['CVE-2019-11043', 'CVE-2021-23017']);
    const audits = await exportAudits();
    expect(audits.at(-1)!.metadata).toMatchObject({
      resource: 'vulnerabilities',
      filters: { sort: 'cve' },
      rows: 2,
      truncated: true,
    });
  });
});

// --- GET /attack-surface ------------------------------------------------------------------------

describe('GET /attack-surface', () => {
  const surface = async (role: Role) =>
    attackSurfaceResponseSchema.parse(await get(role, '/attack-surface'));

  it('summarises roles, hosting, geography and exposed services of approved assets', async () => {
    await world();
    const body = await surface('viewer');
    expect(body.totals).toEqual({
      approvedAssets: 3,
      currentIps: 3,
      openPorts: 3,
      thirdPartyHosted: 1,
    });
    expect(body.assetRoles.map((r) => r.role)).toEqual([...ASSET_ROLES]);
    const roles = Object.fromEntries(body.assetRoles.map((r) => [r.role, r.assets]));
    expect(roles).toMatchObject({ remote_access: 2, cloud_service: 1, mail: 0, unclassified: 0 });
    expect(body.hostingProviders).toEqual([
      { provider: null, kind: null, assets: 2 },
      { provider: 'Amazon CloudFront', kind: 'cdn', assets: 1 },
    ]);
    expect(body.countries).toEqual([
      { country: 'NL', assets: 1, ips: 1 },
      { country: 'US', assets: 1, ips: 1 },
    ]);
    expect(body.continents).toEqual([
      { continent: 'Europe', assets: 1, ips: 1 },
      { continent: 'North America', assets: 1, ips: 1 },
    ]);
    expect(body.unknownCountryIps).toBe(1);
    expect(body.geoAttribution).toBe(DBIP_ATTRIBUTION);
    expect(body.exposedServices).toEqual([
      { port: 22, service: 'ssh', ips: 2 },
      { port: 80, service: 'http', ips: 1 },
    ]);
  });

  it('is scoped to the asset owner’s assets', async () => {
    await world();
    const body = await surface('asset_owner');
    expect(body.totals).toEqual({
      approvedAssets: 1,
      currentIps: 1,
      openPorts: 1,
      thirdPartyHosted: 0,
    });
    expect(body.countries).toEqual([{ country: 'NL', assets: 1, ips: 1 }]);
    expect(body.exposedServices).toEqual([{ port: 22, service: 'ssh', ips: 1 }]);
  });

  it('returns zeros and no attribution for an empty inventory', async () => {
    const body = await surface('admin');
    expect(body.totals).toEqual({
      approvedAssets: 0,
      currentIps: 0,
      openPorts: 0,
      thirdPartyHosted: 0,
    });
    expect(body.assetRoles.every((r) => r.assets === 0)).toBe(true);
    expect(body.assetRoles).toHaveLength(ASSET_ROLES.length);
    expect(body).toMatchObject({
      hostingProviders: [],
      countries: [],
      continents: [],
      unknownCountryIps: 0,
      geoAttribution: null,
      exposedServices: [],
    });
  });
});

// --- Role on the asset DTO ----------------------------------------------------------------------

describe('asset role on GET /assets', () => {
  it('adds the primary role to list and detail responses and filters by role', async () => {
    const w = await world();
    const list = assetListResponseSchema.parse(await get('viewer', '/assets?pageSize=100'));
    expect(Object.fromEntries(list.items.map((a) => [a.hostname, a.role]))).toEqual({
      'cdn.example.org': 'cloud_service',
      'pending.example.org': 'unclassified',
      'www.example.com': 'remote_access',
      'www.example.org': 'remote_access',
    });
    const detail = assetDetailResponseSchema.parse(await get('viewer', `/assets/${w.cdnAssetId}`));
    expect(detail.asset.role).toBe('cloud_service');

    const remote = assetListResponseSchema.parse(
      await get('viewer', '/assets?role=remote_access&pageSize=1&page=2'),
    );
    expect(remote.total).toBe(2);
    expect(remote.items.map((a) => a.hostname)).toEqual(['www.example.org']);
    expect(assetListResponseSchema.parse(await get('viewer', '/assets?role=mail')).items).toEqual(
      [],
    );
    expect(
      assetListResponseSchema
        .parse(await get('viewer', `/domains/${w.other.domainId}/assets?role=cloud_service`))
        .items.map((a) => a.hostname),
    ).toEqual(['cdn.example.org']);
    expect((await userCall(h, t, 'viewer', 'GET', '/assets?role=bogus')).status).toBe(400);
  });

  it('keeps asset-owner scoping with the role filter', async () => {
    await world();
    const mine = assetListResponseSchema.parse(
      await get('asset_owner', '/assets?role=remote_access'),
    );
    expect(mine.items.map((a) => [a.hostname, a.role])).toEqual([
      ['www.example.com', 'remote_access'],
    ]);
    expect(mine.total).toBe(1);
    expect(
      assetListResponseSchema.parse(await get('asset_owner', '/assets?role=cloud_service')).total,
    ).toBe(0);
  });
});
