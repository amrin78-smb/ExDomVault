// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  REPORT_CSV_COLUMNS,
  REPORT_CSV_MAX_ROWS,
  errorResponseSchema,
  reportSummaryResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseCsv } from '../lib/csv.ts';
import { csvCell } from '../services/reports.ts';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const { assets, auditLogs, domains, findings, scanJobs, tlsObservations } = schema;

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
  await t.db.delete(scanJobs);
  await t.db.delete(assets);
  await t.db.delete(domains);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const call = (role: Role, path: string) => userCall(h, t, role, 'GET', path);

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
  a: string;
  b: string;
  c: string;
  www: string;
  api: string;
  mail: string;
  adminId: string;
  ownerId: string;
}

/**
 * example.com (high, Payments, verified, monitored, registration expires in 10 days),
 * example.net (low, Payments, registration expired 2 days ago),
 * example.org (no business owner, monitored, expires in 100 days).
 */
async function seed(): Promise<World> {
  const adminId = await ensureUser(t, 'admin');
  const ownerId = await ensureUser(t, 'asset_owner');
  const [a, b, c] = await t.db
    .insert(domains)
    .values([
      {
        fqdn: 'example.com',
        criticality: 'high',
        businessOwner: 'Payments',
        verificationStatus: 'verified',
        verifiedAt: at(-30),
        verificationMethod: 'dns_txt',
        monitoringEnabled: true,
        expiresAt: at(10),
      },
      { fqdn: 'example.net', criticality: 'low', businessOwner: 'Payments', expiresAt: at(-2) },
      { fqdn: 'example.org', monitoringEnabled: true, expiresAt: at(100) },
    ])
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
        domainId: a!.id,
        hostname: 'www.example.com',
        assetType: 'subdomain',
        discoverySource: 'manual',
        ownerUserId: ownerId,
        ...approved,
      },
      {
        domainId: a!.id,
        hostname: 'api.example.com',
        assetType: 'subdomain',
        discoverySource: 'manual',
      },
      {
        domainId: b!.id,
        hostname: 'mail.example.net',
        assetType: 'subdomain',
        discoverySource: 'manual',
        ...approved,
      },
    ])
    .returning();
  return {
    a: a!.id,
    b: b!.id,
    c: c!.id,
    www: www!.id,
    api: api!.id,
    mail: mail!.id,
    adminId,
    ownerId,
  };
}

async function seedFindings(w: World) {
  await t.db.insert(findings).values([
    // 1-3: example.com, open/acknowledged.
    finding(w.a, {
      assetId: w.www,
      hostname: 'www.example.com',
      severity: 'high',
      riskScore: 70,
      firstSeenAt: new Date('2026-10-23T01:00:00Z'),
    }),
    finding(w.a, {
      assetId: w.www,
      hostname: 'www.example.com',
      severity: 'critical',
      riskScore: 90,
      status: 'acknowledged',
      category: 'tls',
      firstSeenAt: new Date('2026-10-20T05:00:00Z'),
    }),
    finding(w.a, {
      severity: 'medium',
      riskScore: 40,
      category: 'email',
      firstSeenAt: new Date('2026-10-01T12:00:00Z'),
    }),
    // 4-5: example.net, accepted risks (one due for review, one not).
    finding(w.b, {
      assetId: w.mail,
      hostname: 'mail.example.net',
      severity: 'low',
      riskScore: 10,
      status: 'accepted_risk',
      acceptedRiskReason: 'Compensating control',
      acceptedRiskApprovedBy: w.adminId,
      acceptedRiskReviewAt: at(5),
      title: 'Due risk',
      firstSeenAt: new Date('2026-09-01T00:00:00Z'),
    }),
    finding(w.b, {
      hostname: 'example.net',
      severity: 'high',
      riskScore: 60,
      status: 'accepted_risk',
      acceptedRiskReason: 'Later',
      acceptedRiskApprovedBy: w.adminId,
      acceptedRiskReviewAt: at(40),
      firstSeenAt: new Date('2026-09-01T00:00:00Z'),
    }),
    // 6-8: resolved (4 days, 2 days, and one outside the 90-day window).
    finding(w.a, {
      assetId: w.www,
      hostname: 'www.example.com',
      severity: 'medium',
      riskScore: 50,
      status: 'resolved',
      firstSeenAt: new Date('2026-10-18T00:00:00Z'),
      resolvedAt: new Date('2026-10-22T00:00:00Z'),
    }),
    finding(w.c, {
      hostname: 'example.org',
      riskScore: 20,
      status: 'resolved',
      firstSeenAt: new Date('2026-10-10T00:00:00Z'),
      resolvedAt: new Date('2026-10-12T00:00:00Z'),
    }),
    finding(w.c, {
      hostname: 'example.org',
      severity: 'informational',
      riskScore: 5,
      status: 'resolved',
      firstSeenAt: new Date('2026-01-01T00:00:00Z'),
      resolvedAt: new Date('2026-05-01T00:00:00Z'),
    }),
  ]);
}

async function seedScans(w: World) {
  const [ok, , old] = await t.db
    .insert(scanJobs)
    .values([
      {
        jobType: 'scan',
        profile: 'passive',
        domainId: w.a,
        status: 'succeeded',
        scopeSnapshot: {},
        completedAt: at(-1 / 24),
      },
      {
        jobType: 'scan',
        profile: 'quick',
        domainId: w.a,
        status: 'failed',
        scopeSnapshot: {},
        completedAt: clock,
      },
      {
        jobType: 'scan',
        profile: 'passive',
        domainId: w.c,
        status: 'succeeded',
        scopeSnapshot: {},
        completedAt: at(-100),
      },
    ])
    .returning();
  let n = 0;
  const tls = (
    scanJobId: string,
    assetId: string | null,
    hostname: string,
    observedAt: Date,
    over: Partial<typeof tlsObservations.$inferInsert> = {},
  ): typeof tlsObservations.$inferInsert => ({
    resultId: `tls-${n++}`,
    assetId,
    scanJobId,
    observedAt,
    checker: 'tls',
    checkerVersion: '1',
    resultStatus: 'success',
    hostname,
    port: 443,
    issuer: 'Test CA',
    ...over,
  });
  await t.db.insert(tlsObservations).values([
    // www: the latest observation (25 days left) wins over the older one (300 days).
    tls(ok!.id, w.www, 'www.example.com', at(-2), { notAfter: at(300) }),
    tls(ok!.id, w.www, 'www.example.com', at(-1), { notAfter: at(25) }),
    // api: a later failed check is ignored.
    tls(ok!.id, w.api, 'api.example.com', at(-1), { notAfter: at(20), issuer: null }),
    tls(ok!.id, w.api, 'api.example.com', at(0), { resultStatus: 'error', notAfter: null }),
    // mail: already expired.
    tls(ok!.id, w.mail, 'mail.example.net', at(-1), { notAfter: at(-3) }),
    // Not expiring soon, and an observation outside the look-back window.
    tls(ok!.id, null, 'example.com', at(-1), { notAfter: at(200) }),
    tls(old!.id, null, 'old.example.org', at(-100), { notAfter: at(1) }),
  ]);
}

const summary = async (role: Role) => {
  const res = await call(role, '/reports/summary');
  expect(res.status).toBe(200);
  return reportSummaryResponseSchema.parse(await res.json());
};

describe('GET /reports/summary', () => {
  it('is available to every role with reports:read', async () => {
    for (const role of ['admin', 'analyst', 'asset_owner', 'viewer'] as Role[]) {
      expect((await call(role, '/reports/summary')).status).toBe(200);
    }
  });

  it('returns an empty but complete summary without data', async () => {
    const s = await summary('viewer');
    expect(s.findings).toMatchObject({ open: 0, meanDaysToResolve: null });
    expect(s.trend).toHaveLength(30);
    expect(s.trend.every((d) => d.created === 0 && d.resolved === 0)).toBe(true);
    expect(s.coverage.lastScanAt).toBeNull();
  });

  it('summarises the whole portfolio from stored data', async () => {
    const w = await seed();
    await seedFindings(w);
    await seedScans(w);
    const s = await summary('analyst');

    expect(s.generatedAt).toBe(clock.toISOString());
    expect(s.coverage).toEqual({
      domains: 3,
      monitoredDomains: 2,
      verifiedDomains: 1,
      approvedAssets: 2,
      pendingAssets: 1,
      lastScanAt: at(-1 / 24).toISOString(),
    });
    expect(s.findings).toEqual({
      open: 5,
      bySeverity: { informational: 0, low: 1, medium: 1, high: 2, critical: 1 },
      byStatus: {
        open: 2,
        acknowledged: 1,
        remediation_in_progress: 0,
        resolved: 3,
        accepted_risk: 2,
      },
      byCategory: {
        dns: 3,
        email: 1,
        tls: 1,
        http: 0,
        exposure: 0,
        registration: 0,
        asset: 0,
        software: 0,
      },
      meanDaysToResolve: 3,
    });

    expect(s.trendDays).toBe(30);
    expect(s.trend).toHaveLength(30);
    expect(s.trend[0]!.date).toBe('2026-09-24');
    expect(s.trend[29]!.date).toBe('2026-10-23');
    const day = (d: string) => s.trend.find((x) => x.date === d);
    expect(day('2026-10-23')).toEqual({ date: '2026-10-23', created: 1, resolved: 0 });
    expect(day('2026-10-22')).toEqual({ date: '2026-10-22', created: 0, resolved: 1 });
    expect(day('2026-10-12')).toEqual({ date: '2026-10-12', created: 0, resolved: 1 });
    expect(s.trend.reduce((n, d) => n + d.created, 0)).toBe(5);
    expect(s.trend.reduce((n, d) => n + d.resolved, 0)).toBe(2);

    expect(s.topDomains).toEqual([
      {
        domain: { id: w.a, fqdn: 'example.com' },
        criticality: 'high',
        openFindings: 3,
        riskTotal: 200,
        highestSeverity: 'critical',
      },
      {
        domain: { id: w.b, fqdn: 'example.net' },
        criticality: 'low',
        openFindings: 2,
        riskTotal: 70,
        highestSeverity: 'high',
      },
    ]);
    expect(s.byBusinessOwner).toEqual([
      { businessOwner: 'Payments', domains: 2, openFindings: 5, highOrCritical: 3 },
      { businessOwner: null, domains: 1, openFindings: 0, highOrCritical: 0 },
    ]);
    expect(s.expiringRegistrations).toEqual([
      { domain: { id: w.b, fqdn: 'example.net' }, expiresAt: at(-2).toISOString(), daysLeft: -2 },
      { domain: { id: w.a, fqdn: 'example.com' }, expiresAt: at(10).toISOString(), daysLeft: 10 },
    ]);
    expect(s.expiringCertificates).toEqual([
      {
        domain: { id: w.b, fqdn: 'example.net' },
        hostname: 'mail.example.net',
        notAfter: at(-3).toISOString(),
        daysLeft: -3,
        issuer: 'Test CA',
      },
      {
        domain: { id: w.a, fqdn: 'example.com' },
        hostname: 'api.example.com',
        notAfter: at(20).toISOString(),
        daysLeft: 20,
        issuer: null,
      },
      {
        domain: { id: w.a, fqdn: 'example.com' },
        hostname: 'www.example.com',
        notAfter: at(25).toISOString(),
        daysLeft: 25,
        issuer: 'Test CA',
      },
    ]);
    expect(s.acceptedRisksDue).toEqual([
      {
        findingId: expect.any(String),
        title: 'Due risk',
        domain: { id: w.b, fqdn: 'example.net' },
        reviewAt: at(5).toISOString(),
      },
    ]);
  });

  it('scopes an asset owner to the findings and assets they own', async () => {
    const w = await seed();
    await seedFindings(w);
    await seedScans(w);
    const s = await summary('asset_owner');

    expect(s.coverage).toEqual({
      domains: 0,
      monitoredDomains: 0,
      verifiedDomains: 0,
      approvedAssets: 1,
      pendingAssets: 0,
      lastScanAt: null,
    });
    expect(s.findings).toMatchObject({
      open: 2,
      bySeverity: { informational: 0, low: 0, medium: 0, high: 1, critical: 1 },
      byStatus: { open: 1, acknowledged: 1, resolved: 1, accepted_risk: 0 },
      meanDaysToResolve: 4,
    });
    expect(s.trend.reduce((n, d) => n + d.created, 0)).toBe(3);
    expect(s.trend.reduce((n, d) => n + d.resolved, 0)).toBe(1);
    expect(s.topDomains).toEqual([]);
    expect(s.byBusinessOwner).toEqual([]);
    expect(s.expiringRegistrations).toEqual([]);
    expect(s.expiringCertificates.map((c) => c.hostname)).toEqual(['www.example.com']);
    expect(s.acceptedRisksDue).toEqual([]);

    // Ownership drives it: without assets the owner sees nothing.
    await t.db.update(assets).set({ ownerUserId: null });
    const none = await summary('asset_owner');
    expect(none.findings.open).toBe(0);
    expect(none.expiringCertificates).toEqual([]);
  });
});

describe('csvCell', () => {
  it('neutralises formulas and applies RFC 4180 quoting', () => {
    expect(csvCell('plain')).toBe('plain');
    expect(csvCell(null)).toBe('');
    expect(csvCell(42)).toBe('42');
    expect(csvCell('=1+1')).toBe("'=1+1");
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('-1')).toBe("'-1");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell('\tx')).toBe("'\tx");
    expect(csvCell('\rx')).toBe('"\'\rx"');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('=HYPERLINK("http://x.test","y")')).toBe(
      '"\'=HYPERLINK(""http://x.test"",""y"")"',
    );
    expect(csvCell('line\nbreak')).toBe('"line\nbreak"');
  });
});

describe('GET /reports/findings.csv', () => {
  it('requires reports:generate', async () => {
    for (const role of ['asset_owner', 'viewer'] as Role[]) {
      const res = await call(role, '/reports/findings.csv');
      expect(res.status).toBe(403);
      expect(errorResponseSchema.parse(await res.json()).error.code).toBe('forbidden');
    }
    expect((await call('analyst', '/reports/findings.csv')).status).toBe(200);
  });

  it('exports the filtered findings with fixed columns, escaping and an audit row', async () => {
    const w = await seed();
    await seedFindings(w);
    const analystId = await ensureUser(t, 'analyst');
    await t.db.insert(findings).values(
      finding(w.a, {
        hostname: 'www.example.com',
        severity: 'high',
        riskScore: 99,
        title: '=HYPERLINK("http://evil.test","click"), really',
        component: '-cmd',
        assignedTo: analystId,
        firstSeenAt: new Date('2026-10-21T00:00:00Z'),
      }),
    );

    const res = await call('analyst', '/reports/findings.csv?severity=high');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('text/csv; charset=utf-8');
    expect(res.headers.get('Content-Disposition')).toBe(
      'attachment; filename="findings-20261023.csv"',
    );
    expect(res.headers.get('X-Truncated')).toBeNull();
    const text = await res.text();
    expect(text.endsWith('\r\n')).toBe(true);
    const records = parseCsv(text, 100).map((r) => r.fields);
    expect(records[0]).toEqual([...REPORT_CSV_COLUMNS]);
    // Active high findings (an accepted risk is active too), highest risk first.
    expect(records.slice(1).map((r) => r[3])).toEqual(['99', '70', '60']);
    const row = Object.fromEntries(REPORT_CSV_COLUMNS.map((c, i) => [c, records[1]![i]]));
    expect(row).toMatchObject({
      rule_id: 'TST-X',
      severity: 'high',
      status: 'open',
      domain: 'example.com',
      hostname: 'www.example.com',
      component: "'-cmd",
      title: '\'=HYPERLINK("http://evil.test","click"), really',
      first_seen_at: '2026-10-21T00:00:00.000Z',
      resolved_at: '',
      assignee: 'analyst@example.com',
      business_owner: 'Payments',
    });

    const audit = await t.db.select().from(auditLogs);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      action: 'report.exported',
      actorUserId: analystId,
      resourceType: 'report',
      resourceId: 'findings.csv',
      metadata: {
        report: 'findings',
        format: 'csv',
        rows: 3,
        truncated: false,
        filters: { status: 'active', severity: 'high', sort: '-riskScore' },
      },
    });

    const resolved = await call('admin', `/reports/findings.csv?status=resolved&domainId=${w.c}`);
    const rows = parseCsv(await resolved.text(), 100);
    expect(rows).toHaveLength(3);
    expect(rows[1]!.fields[12]).toBe('');
    await expect(call('admin', '/reports/findings.csv?severity=bad')).resolves.toMatchObject({
      status: 400,
    });
  });

  it(`caps the export at ${REPORT_CSV_MAX_ROWS} rows and flags truncation`, async () => {
    const [d] = await t.db.insert(domains).values({ fqdn: 'example.com' }).returning();
    const rows = Array.from({ length: REPORT_CSV_MAX_ROWS + 1 }, () =>
      finding(d!.id, { firstSeenAt: clock }),
    );
    for (let i = 0; i < rows.length; i += 1000) {
      await t.db.insert(findings).values(rows.slice(i, i + 1000));
    }
    const res = await call('admin', '/reports/findings.csv');
    expect(res.status).toBe(200);
    expect(res.headers.get('X-Truncated')).toBe('true');
    const records = parseCsv(await res.text(), REPORT_CSV_MAX_ROWS + 10);
    expect(records).toHaveLength(REPORT_CSV_MAX_ROWS + 1);
    const [audit] = await t.db.select().from(auditLogs);
    expect(audit!.metadata).toMatchObject({ rows: REPORT_CSV_MAX_ROWS, truncated: true });
  }, 60_000);
});
