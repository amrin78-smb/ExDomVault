// @vitest-environment node
// CSV exports (GET /exports/<resource>.csv): columns, encoding, filters, visibility, permissions,
// truncation and the audit record, per resource. Synthetic data only.
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  EXPORT_COLUMNS,
  EXPORT_RESOURCES,
  errorResponseSchema,
  type ExportResource,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseCsv } from '../lib/csv.ts';
import { ensureUser, harness, userCall, type Harness } from '../testing/harness.ts';

const {
  advisories,
  assetIps,
  assets,
  auditLogs,
  domains,
  findings,
  intelFeeds,
  scanJobs,
  scanJobTargets,
  softwareEolCycles,
  softwareInventory,
  vulnerabilityAdvisories,
} = schema;

let t: TestDatabase;
const clock = new Date('2026-10-23T10:00:00.000Z');
const h = harness(
  () => t,
  () => clock,
);
/** Same app with a row cap of 2, to exercise truncation cheaply. */
const small = harness(
  () => t,
  () => clock,
  { exports: { maxRows: 2 } },
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

interface Csv {
  res: Response;
  header: string[];
  rows: Record<string, string>[];
  text: string;
}

/** Calls an export and decodes it, asserting the invariant encoding (BOM, CRLF, header row). */
async function exportCsv(
  role: Role,
  resource: ExportResource,
  query = '',
  app: Harness = h,
): Promise<Csv> {
  const res = await userCall(app, t, role, 'GET', `/exports/${resource}.csv${query}`);
  expect(res.status, `${resource}${query}`).toBe(200);
  expect(res.headers.get('Content-Type')).toBe('text/csv; charset=utf-8');
  expect(res.headers.get('Content-Disposition')).toBe(
    `attachment; filename="exdomainvault-${resource}-20261023.csv"`,
  );
  // Response.text() strips a leading BOM (UTF-8 decode), so check the raw bytes.
  const bytes = new Uint8Array(await res.clone().arrayBuffer());
  expect([...bytes.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
  const text = await res.text();
  expect(text.endsWith('\r\n')).toBe(true);
  expect(text.startsWith(`${EXPORT_COLUMNS[resource].join(',')}\r\n`)).toBe(true);
  const records = parseCsv(text, 100_000).map((r) => r.fields);
  const header = records[0]!;
  expect(header).toEqual([...EXPORT_COLUMNS[resource]]);
  return {
    res,
    header,
    text,
    rows: records.slice(1).map((r) => Object.fromEntries(header.map((c, i) => [c, r[i]!]))),
  };
}

const forbidden = async (role: Role, resource: ExportResource) => {
  const res = await userCall(h, t, role, 'GET', `/exports/${resource}.csv`);
  expect(res.status, `${role} ${resource}`).toBe(403);
  expect(errorResponseSchema.parse(await res.json()).error.code).toBe('forbidden');
};

const exportAudits = async () =>
  (await t.db.select().from(auditLogs)).filter((a) => a.action === 'report.exported');

let seq = 0;
function finding(
  domainId: string,
  over: Partial<typeof findings.$inferInsert>,
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
    firstSeenAt: at(-5),
    lastSeenAt: at(-1),
    ...over,
  };
}

interface World {
  com: string;
  net: string;
  idn: string;
  www: string;
  api: string;
  mail: string;
  adminId: string;
  analystId: string;
  ownerId: string;
}

/**
 * example.com (high, verified by DNS, monitored): www (owned by the asset owner, approved, two IPs,
 * CDN hint), api (pending). example.net (admin attestation, owner "=cmd"): mail (approved).
 * xn--bcher-kva.com (bücher.com).
 */
async function seed(): Promise<World> {
  const adminId = await ensureUser(t, 'admin');
  const analystId = await ensureUser(t, 'analyst');
  const ownerId = await ensureUser(t, 'asset_owner');
  await ensureUser(t, 'viewer');
  const [com, net, idn] = await t.db
    .insert(domains)
    .values([
      {
        fqdn: 'example.com',
        criticality: 'high',
        businessOwner: 'Payments, EU',
        verificationStatus: 'verified',
        verifiedAt: at(-30),
        verificationMethod: 'dns_txt',
        monitoringEnabled: true,
        registrar: 'Example Registrar',
        expiresAt: new Date('2027-01-31T00:00:00.000Z'),
        createdAt: at(-3),
      },
      {
        fqdn: 'example.net',
        criticality: 'low',
        businessOwner: '=cmd|calc',
        verificationStatus: 'verified',
        verifiedAt: at(-10),
        verificationMethod: 'admin_attestation',
        verificationExpiresAt: new Date('2027-06-30T00:00:00.000Z'),
        createdAt: at(-2),
      },
      { fqdn: 'xn--bcher-kva.com', createdAt: at(-1) },
    ])
    .returning();
  const approved = {
    verificationStatus: 'approved' as const,
    approvedBy: adminId,
    approvedAt: at(-4),
    decidedBy: adminId,
    decidedAt: at(-4),
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
        hostingHint: { provider: 'Cloudflare', kind: 'cdn', matchedName: 'www.example.com.cdn' },
        decisionReason: 'Owned, "verified"',
        firstSeenAt: at(-6),
        lastSeenAt: at(-1),
        ...approved,
      },
      {
        domainId: com!.id,
        hostname: 'api.example.com',
        assetType: 'subdomain',
        discoverySource: 'certificate_transparency',
        firstSeenAt: at(-6),
        lastSeenAt: at(-2),
      },
      {
        domainId: net!.id,
        hostname: 'mail.example.net',
        assetType: 'subdomain',
        discoverySource: 'manual',
        firstSeenAt: at(-6),
        lastSeenAt: at(-3),
        ...approved,
      },
    ])
    .returning();
  await t.db.insert(assetIps).values([
    { assetId: www!.id, ipAddress: '192.0.2.2', source: 'dns' },
    { assetId: www!.id, ipAddress: '192.0.2.1', source: 'dns' },
    { assetId: www!.id, ipAddress: '192.0.2.9', source: 'dns', isCurrent: false },
  ]);
  return {
    com: com!.id,
    net: net!.id,
    idn: idn!.id,
    www: www!.id,
    api: api!.id,
    mail: mail!.id,
    adminId,
    analystId,
    ownerId,
  };
}

describe('permissions', () => {
  it('follows each list endpoint’s permission', async () => {
    for (const r of ['domains', 'scans', 'users', 'audit-logs'] as const) {
      await forbidden('asset_owner', r);
    }
    for (const r of ['users', 'audit-logs'] as const) {
      await forbidden('analyst', r);
      await forbidden('viewer', r);
    }
    // Every role allowed by the list may export (an empty export is still a CSV with a header).
    for (const r of EXPORT_RESOURCES) await exportCsv('admin', r);
    for (const r of ['assets', 'advisories', 'software'] as const)
      await exportCsv('asset_owner', r);
    for (const r of ['domains', 'assets', 'advisories', 'software', 'scans'] as const) {
      await exportCsv('viewer', r);
    }
  });

  it('validates filters like the list and ignores paging', async () => {
    const res = await userCall(h, t, 'admin', 'GET', '/exports/domains.csv?criticality=ultra');
    expect(res.status).toBe(400);
    expect(errorResponseSchema.parse(await res.json()).error.code).toBe('validation_failed');
    await seed();
    const { rows } = await exportCsv('admin', 'domains', '?page=3&pageSize=1');
    expect(rows).toHaveLength(3);
  });
});

describe('GET /exports/domains.csv', () => {
  it('exports every column, escapes cells and audits the export', async () => {
    const w = await seed();
    await t.db
      .insert(findings)
      .values([
        finding(w.com, {}),
        finding(w.com, {}),
        finding(w.com, { status: 'resolved', resolvedAt: at(-1) }),
      ]);
    const { res, rows, text } = await exportCsv('analyst', 'domains');
    expect(res.headers.get('X-Truncated')).toBeNull();
    expect(res.headers.get('X-Total-Rows')).toBe('3');
    expect(rows.map((r) => r.domain)).toEqual(['example.com', 'example.net', 'xn--bcher-kva.com']);
    expect(rows[0]).toEqual({
      domain: 'example.com',
      unicode_name: 'example.com',
      verification_status: 'verified',
      verification_method: 'dns_txt',
      verification_expires_at: '',
      criticality: 'high',
      business_owner: 'Payments, EU',
      monitoring: 'true',
      registrar: 'Example Registrar',
      registration_expires_at: '2027-01-31T00:00:00.000Z',
      open_findings: '2',
      created_at: at(-3).toISOString(),
    });
    expect(text).toContain('"Payments, EU"');
    expect(rows[1]).toMatchObject({
      verification_method: 'admin_attestation',
      verification_expires_at: '2027-06-30T00:00:00.000Z',
      business_owner: "'=cmd|calc",
      monitoring: 'false',
      open_findings: '0',
    });
    expect(rows[2]!.unicode_name).toBe('bücher.com');

    const audits = await exportAudits();
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      actorType: 'user',
      actorUserId: w.analystId,
      resourceType: 'report',
      resourceId: 'domains.csv',
      metadata: { resource: 'domains', filters: { sort: 'fqdn' }, rows: 3, truncated: false },
    });
    expect(audits[0]!.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('applies the list filters and sort', async () => {
    await seed();
    const high = await exportCsv('viewer', 'domains', '?criticality=high');
    expect(high.rows.map((r) => r.domain)).toEqual(['example.com']);
    const sorted = await exportCsv('viewer', 'domains', '?sort=-createdAt&monitoring=false');
    expect(sorted.rows.map((r) => r.domain)).toEqual(['xn--bcher-kva.com', 'example.net']);
    const search = await exportCsv('viewer', 'domains', '?q=bücher.com');
    expect(search.rows.map((r) => r.domain)).toEqual(['xn--bcher-kva.com']);
    const audits = await exportAudits();
    expect(audits).toHaveLength(3);
    expect(audits.map((a) => a.metadata)).toContainEqual({
      resource: 'domains',
      filters: { q: 'bücher.com', sort: 'fqdn' },
      rows: 1,
      truncated: false,
    });
  });
});

describe('GET /exports/assets.csv', () => {
  it('exports assets with lists joined and owner visibility', async () => {
    const w = await seed();
    await t.db.insert(findings).values(finding(w.com, { hostname: 'www.example.com' }));
    const all = await exportCsv('analyst', 'assets');
    expect(all.rows.map((r) => r.hostname)).toEqual([
      'api.example.com',
      'mail.example.net',
      'www.example.com',
    ]);
    expect(all.rows[2]).toEqual({
      hostname: 'www.example.com',
      domain: 'example.com',
      asset_type: 'subdomain',
      status: 'approved',
      source: 'manual',
      current_ips: '192.0.2.1; 192.0.2.2',
      hosting_provider: 'Cloudflare',
      wildcard_only: 'false',
      owner: 'asset_owner@example.com',
      decided_by: 'admin@example.com',
      decided_at: at(-4).toISOString(),
      decision_reason: 'Owned, "verified"',
      first_seen_at: at(-6).toISOString(),
      last_seen_at: at(-1).toISOString(),
      active_findings: '1',
    });
    expect(all.text).toContain('"Owned, ""verified"""');

    const owner = await exportCsv('asset_owner', 'assets');
    expect(owner.rows.map((r) => r.hostname)).toEqual(['www.example.com']);
    expect(owner.res.headers.get('X-Total-Rows')).toBe('1');
    // Filters naming another tenant's domain cannot widen visibility.
    const foreign = await exportCsv('asset_owner', 'assets', `?domainId=${w.net}`);
    expect(foreign.rows).toEqual([]);

    const pending = await exportCsv('viewer', 'assets', '?status=pending');
    expect(pending.rows.map((r) => r.hostname)).toEqual(['api.example.com']);
    const recent = await exportCsv('viewer', 'assets', '?sort=-lastSeenAt&thirdParty=false');
    expect(recent.rows.map((r) => r.hostname)).toEqual(['api.example.com', 'mail.example.net']);
  });
});

describe('GET /exports/advisories.csv', () => {
  async function seedAdvisories(w: World) {
    const [f1, f2, f3] = await t.db
      .insert(findings)
      .values([
        finding(w.com, {
          assetId: w.www,
          hostname: 'www.example.com',
          severity: 'high',
          riskScore: 80,
          ruleId: 'DNS-001',
        }),
        finding(w.com, { assetId: w.api, hostname: 'api.example.com', riskScore: 20 }),
        finding(w.com, {
          assetId: w.www,
          hostname: 'www.example.com',
          riskScore: 50,
          status: 'resolved',
          resolvedAt: at(-1),
        }),
      ])
      .returning();
    await t.db.insert(advisories).values(
      [f1!, f2!, f3!].map((f, i) => ({
        findingId: f.id,
        title: `Advisory ${i + 1}`,
        summary: i === 0 ? '@SUM(1)' : 'Summary',
        businessImpact: 'Impact',
        recommendedActions: i === 0 ? ['-Rotate keys', 'Patch, then verify'] : ['Fix'],
        referenceLinks: i === 0 ? ['https://a.example/x', 'https://b.example/y'] : [],
      })),
    );
    return [f1!, f2!, f3!];
  }

  it('exports active advisories by risk, with lists joined and injection neutralised', async () => {
    const w = await seed();
    const [f1] = await seedAdvisories(w);
    const { rows, text } = await exportCsv('viewer', 'advisories');
    expect(rows.map((r) => r.advisory_title)).toEqual(['Advisory 1', 'Advisory 2']);
    expect(rows[0]).toEqual({
      finding_id: f1!.id,
      rule_id: 'DNS-001',
      severity: 'high',
      risk_score: '80',
      finding_status: 'open',
      domain: 'example.com',
      hostname: 'www.example.com',
      advisory_title: 'Advisory 1',
      summary: "'@SUM(1)",
      business_impact: 'Impact',
      recommended_actions: "'-Rotate keys; Patch, then verify",
      references: 'https://a.example/x; https://b.example/y',
    });
    expect(text).toContain(`"'-Rotate keys; Patch, then verify"`);

    const all = await exportCsv('viewer', 'advisories', '?status=all');
    expect(all.rows.map((r) => r.advisory_title)).toEqual([
      'Advisory 1',
      'Advisory 3',
      'Advisory 2',
    ]);
  });

  it('shows asset owners only advisories on their assets', async () => {
    const w = await seed();
    await seedAdvisories(w);
    const owner = await exportCsv('asset_owner', 'advisories', '?status=all');
    expect(owner.rows.map((r) => r.hostname)).toEqual(['www.example.com', 'www.example.com']);
    const [audit] = await exportAudits();
    expect(audit).toMatchObject({
      actorUserId: w.ownerId,
      resourceId: 'advisories.csv',
      metadata: { resource: 'advisories', filters: { status: 'all' }, rows: 2, truncated: false },
    });
  });
});

describe('GET /exports/software.csv', () => {
  async function seedSoftware(w: World) {
    const synced = at(-1);
    await t.db.insert(intelFeeds).values([
      { feed: 'endoflife', lastSuccessAt: synced, items: 2 },
      { feed: 'cisa_kev', lastSuccessAt: synced, items: 1 },
      { feed: 'nvd', lastSuccessAt: synced, items: 1 },
    ]);
    await t.db.insert(softwareEolCycles).values([
      { product: 'php', cycle: '7.4', eolDate: '2022-11-28', latest: '7.4.33', fetchedAt: synced },
      { product: 'php', cycle: '8.3', eolDate: '2027-12-31', latest: '8.3.12', fetchedAt: synced },
    ]);
    await t.db.insert(vulnerabilityAdvisories).values({
      cveId: 'CVE-2019-11043',
      product: 'php',
      kev: true,
      cvss: 9.8,
      title: 'PHP FPM buffer underflow',
      ranges: [{ startIncluding: '7.4.0', endExcluding: '7.4.4' }],
      nvdStatus: 'ok',
      nvdFetchedAt: synced,
    });
    const row = (over: Partial<typeof softwareInventory.$inferInsert>) => ({
      domainId: w.com,
      source: 'http_header',
      product: 'php',
      banner: 'x',
      locationKey: `k${seq++}`,
      firstSeenAt: at(-5),
      lastSeenAt: at(-1),
      ...over,
    });
    await t.db.insert(softwareInventory).values([
      row({
        assetId: w.www,
        hostname: 'www.example.com',
        version: '7.4.3',
        banner: '=PHP/7.4.3',
      }),
      row({ assetId: w.api, hostname: 'api.example.com', version: '8.3.1', banner: 'PHP/8.3.1' }),
      row({
        source: 'service_identification',
        ipAddress: '203.0.113.10',
        port: 22,
        product: 'openssh',
        version: '8.2p1',
        backportDistribution: 'Ubuntu',
        banner: 'OpenSSH_8.2p1 Ubuntu',
      }),
      row({
        domainId: w.net,
        assetId: w.mail,
        hostname: 'mail.example.net',
        version: '7.4.1',
        banner: 'PHP/7.4.1',
      }),
    ]);
  }

  it('computes end-of-life and known-exploited status per row', async () => {
    const w = await seed();
    await seedSoftware(w);
    const { rows } = await exportCsv('analyst', 'software');
    expect(rows.map((r) => [r.domain, r.hostname, r.product])).toEqual([
      ['example.com', '', 'openssh'],
      ['example.com', 'api.example.com', 'php'],
      ['example.com', 'www.example.com', 'php'],
      ['example.net', 'mail.example.net', 'php'],
    ]);
    expect(rows[2]).toEqual({
      domain: 'example.com',
      hostname: 'www.example.com',
      ip_address: '',
      port: '',
      source: 'http_header',
      product: 'php',
      version: '7.4.3',
      eol_cycle: '7.4',
      eol_date: '2022-11-28',
      is_eol: 'true',
      known_exploited_cves: 'CVE-2019-11043',
      backport_distribution: '',
      banner: "'=PHP/7.4.3",
      first_seen_at: at(-5).toISOString(),
      last_seen_at: at(-1).toISOString(),
    });
    expect(rows[1]).toMatchObject({ eol_cycle: '8.3', is_eol: 'false', known_exploited_cves: '' });
    expect(rows[0]).toMatchObject({
      ip_address: '203.0.113.10',
      port: '22',
      source: 'service_identification',
      eol_cycle: '',
      is_eol: '',
      backport_distribution: 'Ubuntu',
    });
  });

  it('applies the status filters, other filters and owner visibility', async () => {
    const w = await seed();
    await seedSoftware(w);
    const eol = await exportCsv('viewer', 'software', '?status=eol');
    expect(eol.rows.map((r) => r.hostname)).toEqual(['www.example.com', 'mail.example.net']);
    expect(eol.res.headers.get('X-Total-Rows')).toBe('2');
    const kev = await exportCsv('viewer', 'software', `?status=kev&domainId=${w.com}`);
    expect(kev.rows.map((r) => r.hostname)).toEqual(['www.example.com']);
    const product = await exportCsv('viewer', 'software', '?product=openssh');
    expect(product.rows.map((r) => r.product)).toEqual(['openssh']);

    const owner = await exportCsv('asset_owner', 'software');
    expect(owner.rows.map((r) => r.hostname)).toEqual(['www.example.com']);
    const ownerEol = await exportCsv('asset_owner', 'software', '?status=eol');
    expect(ownerEol.rows.map((r) => r.hostname)).toEqual(['www.example.com']);
  });

  it('truncates a status-filtered export at the cap and reports the matching total', async () => {
    const w = await seed();
    await seedSoftware(w);
    await t.db.insert(softwareInventory).values({
      domainId: w.net,
      hostname: 'old.example.net',
      source: 'http_header',
      product: 'php',
      version: '7.4.2',
      banner: 'PHP/7.4.2',
      locationKey: 'old',
      firstSeenAt: at(-5),
      lastSeenAt: at(-1),
    });
    const { res, rows } = await exportCsv('admin', 'software', '?status=eol', small);
    expect(res.headers.get('X-Truncated')).toBe('true');
    expect(res.headers.get('X-Total-Rows')).toBe('3');
    expect(rows.map((r) => r.hostname)).toEqual(['www.example.com', 'mail.example.net']);
    const [audit] = await exportAudits();
    expect(audit!.metadata).toMatchObject({ resource: 'software', rows: 2, truncated: true });
  });
});

describe('GET /exports/scans.csv', () => {
  it('exports jobs newest first with duration and target counts', async () => {
    const w = await seed();
    const [done, failed] = await t.db
      .insert(scanJobs)
      .values([
        {
          jobType: 'scan',
          profile: 'passive',
          domainId: w.com,
          status: 'succeeded',
          requestedBy: w.analystId,
          scopeSnapshot: { trigger: 'manual' },
          createdAt: at(-2),
          startedAt: new Date(at(-2).getTime() + 1000),
          completedAt: new Date(at(-2).getTime() + 91_400),
          attempts: 1,
        },
        {
          jobType: 'scan',
          profile: 'passive',
          domainId: w.net,
          status: 'failed',
          scopeSnapshot: { trigger: 'schedule' },
          createdAt: at(-1),
          attempts: 3,
          errorCode: '-timeout',
        },
      ])
      .returning();
    await t.db.insert(scanJobTargets).values([
      { scanJobId: done!.id, targetHostname: 'a.example.com', status: 'succeeded' },
      { scanJobId: done!.id, targetHostname: 'b.example.com', status: 'succeeded' },
      { scanJobId: done!.id, targetHostname: 'c.example.com', status: 'failed' },
    ]);
    const { rows } = await exportCsv('viewer', 'scans');
    expect(rows.map((r) => r.scan_id)).toEqual([failed!.id, done!.id]);
    expect(rows[1]).toEqual({
      scan_id: done!.id,
      job_type: 'scan',
      domain: 'example.com',
      profile: 'passive',
      trigger: 'manual',
      status: 'succeeded',
      requested_by: 'analyst@example.com',
      created_at: at(-2).toISOString(),
      started_at: new Date(at(-2).getTime() + 1000).toISOString(),
      completed_at: new Date(at(-2).getTime() + 91_400).toISOString(),
      duration_seconds: '90',
      targets: '3',
      targets_failed: '1',
      attempt: '1',
      error_code: '',
    });
    expect(rows[0]).toMatchObject({
      trigger: 'schedule',
      requested_by: '',
      started_at: '',
      duration_seconds: '',
      targets: '0',
      attempt: '3',
      error_code: "'-timeout",
    });

    const onlyFailed = await exportCsv('viewer', 'scans', '?status=failed');
    expect(onlyFailed.rows.map((r) => r.scan_id)).toEqual([failed!.id]);
    const byDomain = await exportCsv('viewer', 'scans', `?domainId=${w.com}`);
    expect(byDomain.rows.map((r) => r.scan_id)).toEqual([done!.id]);
  });
});

describe('GET /exports/users.csv', () => {
  it('exports users by email with the list filters', async () => {
    await seed();
    await t.db.insert(schema.users).values({
      email: 'pending@example.com',
      displayName: '+Pending, User',
      role: 'viewer',
      authProvider: 'dev',
      isActive: false,
    });
    const { rows } = await exportCsv('admin', 'users');
    expect(rows.map((r) => r.email)).toEqual([
      'admin@example.com',
      'analyst@example.com',
      'asset_owner@example.com',
      'pending@example.com',
      'viewer@example.com',
    ]);
    expect(rows[3]).toEqual({
      email: 'pending@example.com',
      display_name: "'+Pending, User",
      role: 'viewer',
      active: 'false',
      signed_in: 'false',
      last_login_at: '',
      created_at: rows[3]!.created_at,
    });
    expect(rows[0]).toMatchObject({ active: 'true', signed_in: 'true' });
    expect(new Date(rows[3]!.created_at!).toISOString()).toBe(rows[3]!.created_at);

    const viewers = await exportCsv('admin', 'users', '?role=viewer&active=true');
    expect(viewers.rows.map((r) => r.email)).toEqual(['viewer@example.com']);
    await t.db.delete(schema.users).where(eq(schema.users.email, 'pending@example.com'));
  });
});

describe('GET /exports/audit-logs.csv', () => {
  it('exports entries newest first with JSON metadata, filtered', async () => {
    const w = await seed();
    await t.db.insert(auditLogs).values([
      {
        actorType: 'user',
        actorUserId: w.adminId,
        action: 'domain.created',
        resourceType: 'domain',
        resourceId: w.com,
        requestId: 'req-1',
        metadata: { fqdn: 'example.com', note: 'a, "b"' },
        createdAt: at(-2),
      },
      {
        actorType: 'system',
        action: 'finding.status_changed',
        resourceType: 'finding',
        metadata: {},
        createdAt: at(-1),
      },
    ]);
    const { rows } = await exportCsv('admin', 'audit-logs');
    expect(rows.map((r) => r.action)).toEqual(['finding.status_changed', 'domain.created']);
    expect(rows[1]).toEqual({
      created_at: at(-2).toISOString(),
      actor_type: 'user',
      actor: 'admin@example.com',
      action: 'domain.created',
      resource_type: 'domain',
      resource_id: w.com,
      request_id: 'req-1',
      metadata: '{"fqdn":"example.com","note":"a, \\"b\\""}',
    });
    expect(rows[0]).toMatchObject({ actor_type: 'system', actor: '', metadata: '{}' });

    const prefix = await exportCsv('admin', 'audit-logs', '?action=domain.');
    expect(prefix.rows.map((r) => r.action)).toEqual(['domain.created']);
    // The first export's own audit record is visible to later exports.
    const exported = await exportCsv('admin', 'audit-logs', '?action=report.exported');
    expect(exported.rows).toHaveLength(2);
    expect(exported.rows.every((r) => r.resource_type === 'report')).toBe(true);
  });
});

describe('truncation', () => {
  it('caps every export at the row limit and reports the total', async () => {
    await seed();
    const d = await exportCsv('admin', 'domains', '', small);
    expect(d.res.headers.get('X-Truncated')).toBe('true');
    expect(d.res.headers.get('X-Total-Rows')).toBe('3');
    expect(d.rows.map((r) => r.domain)).toEqual(['example.com', 'example.net']);
    const a = await exportCsv('admin', 'assets', '', small);
    expect(a.res.headers.get('X-Total-Rows')).toBe('3');
    expect(a.rows).toHaveLength(2);
    const u = await exportCsv('admin', 'users', '', small);
    expect(u.res.headers.get('X-Truncated')).toBe('true');
    expect(u.rows).toHaveLength(2);

    // At the limit exactly: not truncated.
    const exact = await exportCsv('admin', 'domains', '?monitoring=false', small);
    expect(exact.res.headers.get('X-Truncated')).toBeNull();
    expect(exact.res.headers.get('X-Total-Rows')).toBe('2');

    const audits = await exportAudits();
    expect(audits.map((x) => [x.resourceId, x.metadata.rows, x.metadata.truncated])).toEqual(
      expect.arrayContaining([
        ['domains.csv', 2, true],
        ['assets.csv', 2, true],
        ['users.csv', 2, true],
        ['domains.csv', 2, false],
      ]),
    );
  });
});
