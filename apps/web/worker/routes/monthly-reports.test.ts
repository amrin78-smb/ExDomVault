// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import type { Rule } from '@exdomainvault/rules';
import {
  errorResponseSchema,
  monthlyReportListResponseSchema,
  monthlyReportResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { and, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateJob } from '../services/evaluation.ts';
import { buildMonthlyReport, generateDueMonthlyReport } from '../services/monthly-reports.ts';
import {
  dmarcRule,
  dnsFor,
  hostRule,
  seedDomain,
  seedJob,
  type Seed,
} from '../testing/findings-fixtures.ts';
import { harness, userCall } from '../testing/harness.ts';

const { assets, auditLogs, domainScoreSnapshots, domains, findings, monthlyReports, scanJobs } =
  schema;

let t: TestDatabase;
let clock = new Date('2026-11-03T06:00:00.000Z');
const h = harness(
  () => t,
  () => clock,
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
  clock = new Date('2026-11-03T06:00:00.000Z');
  await t.db.delete(monthlyReports);
  await t.db.delete(domainScoreSnapshots);
  await t.db.delete(findings);
  await t.db.delete(scanJobs);
  await t.db.delete(assets);
  await t.db.delete(domains);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const RULES: readonly Rule[] = [dmarcRule, hostRule];
const d = (s: string) => new Date(`${s}T12:00:00.000Z`);
const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function scan(s: Seed, when: string, opts: Parameters<typeof dnsFor>[1]) {
  const job = await seedJob(t, s.domainId, d(when), dnsFor(s.fqdn, opts));
  expect((await evaluateJob(t.db, job, clock, RULES)).status).toBe('evaluated');
}

/**
 * b.example (since September): DMARC missing since 09-10 (medium; due date forced into October so
 * it is overdue at month end). a.example (Payments, October): DMARC missing + apex and www hosts
 * from 10-05; the apex host resolved 10-15 (10 days, within SLA); www resolved only on 11-02.
 */
async function world() {
  const b = await seedDomain(t, 'b.example', { criticality: 'low' });
  const a = await seedDomain(t, 'a.example');
  await t.db
    .update(domains)
    .set({ createdAt: d('2026-09-01'), businessOwner: 'Payments' })
    .where(eq(domains.id, a.domainId));
  await t.db
    .update(domains)
    .set({ createdAt: d('2026-08-01') })
    .where(eq(domains.id, b.domainId));
  await t.db
    .update(assets)
    .set({ createdAt: d('2026-08-01') })
    .where(eq(assets.domainId, b.domainId));
  await t.db
    .update(assets)
    .set({ createdAt: d('2026-10-02') })
    .where(eq(assets.domainId, a.domainId));

  await scan(b, '2026-09-10', {});
  await scan(a, '2026-10-05', { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] });
  await scan(a, '2026-10-15', { apexA: [], wwwA: ['192.0.2.2'] });
  await scan(a, '2026-11-02', { apexA: [], wwwA: [] });
  await t.db
    .update(findings)
    .set({ dueAt: d('2026-10-20') })
    .where(and(eq(findings.domainId, b.domainId), eq(findings.ruleId, 'TST-DMARC')));

  await t.db.insert(domainScoreSnapshots).values([
    { domainId: a.domainId, day: '2026-09-30', score: 60, grade: 'D' },
    { domainId: a.domainId, day: '2026-10-30', score: 70, grade: 'C' },
    { domainId: a.domainId, day: '2026-10-31', score: 76, grade: 'C' },
    { domainId: b.domainId, day: '2026-10-31', score: 96, grade: 'A' },
    { domainId: b.domainId, day: '2026-11-02', score: 10, grade: 'F' }, // after the month
  ]);
  return { a, b };
}

describe('buildMonthlyReport', () => {
  it('aggregates the month as a point-in-time snapshot', async () => {
    const { a, b } = await world();
    const r = await buildMonthlyReport(t.db, '2026-10', clock);
    expect(r).toMatchObject({
      version: 1,
      period: '2026-10',
      periodStart: '2026-10-01T00:00:00.000Z',
      periodEnd: '2026-11-01T00:00:00.000Z',
      generatedAt: clock.toISOString(),
      totals: { domains: 2, monitoredDomains: 0, assets: 2, approvedAssets: 2, newAssets: 1 },
    });
    expect(r.findings).toMatchObject({
      opened: { high: 2, medium: 1, low: 0, critical: 0, informational: 0 },
      openedTotal: 3,
      reopened: 0,
      resolved: { high: 1 },
      resolvedTotal: 1,
      // www host (still open at month end), both DMARC findings.
      openAtEnd: { high: 1, medium: 2 },
      openAtEndTotal: 3,
      acceptedRiskAtEnd: 0,
      overdueAtEnd: 1,
      overdueAtEndBySeverity: { medium: 1 },
    });
    expect(r.sla).toMatchObject({
      resolvedWithSla: 1,
      resolvedWithinSla: 1,
      compliancePercent: 100,
      meanDaysToResolve: 10,
    });
    expect(r.sla.meanDaysToResolveBySeverity.high).toBe(10);
    expect(r.topFindings.map((f) => [f.ruleId, f.hostname])).toEqual([
      ['TST-HOST', 'www.a.example'],
      ['TST-DMARC', 'a.example'],
      ['TST-DMARC', 'b.example'],
    ]);
    expect(r.topFindings[2]?.overdue).toBe(true);
    expect(r.topDomains.map((x) => [x.domain.id, x.openFindings, x.grade])).toEqual([
      [a.domainId, 2, 'C'],
      [b.domainId, 1, 'A'],
    ]);
    expect(r.securityScore).toMatchObject({
      scoredDomains: 2,
      averageScore: 86,
      grades: { A: 1, B: 0, C: 1, D: 0, F: 0 },
      previousAverageScore: 60,
      change: 26,
    });
    expect(r.securityScore.best[0]).toMatchObject({ domain: { fqdn: 'b.example' }, score: 96 });
    expect(r.securityScore.worst[0]).toMatchObject({ domain: { fqdn: 'a.example' }, score: 76 });
    expect(r.exposure).toEqual({
      certificatesExpiring30d: 0,
      endOfLifeSoftware: 0,
      knownExploitedSoftware: 0,
    });
  });
});

describe('cron generation', () => {
  it('generates the previous month once, audited as a system action', async () => {
    await world();
    expect(await generateDueMonthlyReport(t.db, clock)).toBe(1);
    expect(await generateDueMonthlyReport(t.db, new Date(clock.getTime() + 3600_000))).toBe(0);
    const rows = await t.db.select().from(monthlyReports);
    expect(rows.map((r) => r.period)).toEqual(['2026-10-01']);
    const audit = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'report.monthly_generated'));
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ actorType: 'system', resourceId: '2026-10' });
  });

  it('skips months before any domain existed', async () => {
    expect(await generateDueMonthlyReport(t.db, clock)).toBe(0);
    expect(await t.db.select().from(monthlyReports)).toEqual([]);
  });
});

describe('monthly report API', () => {
  it('lists and reads reports; asset owners are refused', async () => {
    await world();
    await generateDueMonthlyReport(t.db, clock);
    for (const role of ['admin', 'analyst', 'viewer'] as const) {
      const res = await call(role, 'GET', '/reports/monthly');
      expect(res.status).toBe(200);
      const list = monthlyReportListResponseSchema.parse(await res.json());
      expect(list.items).toEqual([
        {
          period: '2026-10',
          generatedAt: clock.toISOString(),
          openAtEndTotal: 3,
          overdueAtEnd: 1,
          averageScore: 86,
        },
      ]);
    }
    const res = await call('viewer', 'GET', '/reports/monthly/2026-10');
    expect(res.status).toBe(200);
    expect(monthlyReportResponseSchema.parse(await res.json()).report.period).toBe('2026-10');

    expect((await call('asset_owner', 'GET', '/reports/monthly')).status).toBe(403);
    expect((await call('asset_owner', 'GET', '/reports/monthly/2026-10')).status).toBe(403);
    expect((await call('viewer', 'GET', '/reports/monthly/2026-09')).status).toBe(404);
    const bad = await call('viewer', 'GET', '/reports/monthly/2026-13');
    expect(bad.status).toBe(400);
    expect(errorResponseSchema.parse(await bad.json()).error.code).toBe('validation_failed');
  });

  it('lets administrators (re)generate a month, audited; refuses future months', async () => {
    await world();
    for (const role of ['analyst', 'viewer', 'asset_owner'] as const) {
      expect((await call(role, 'POST', '/reports/monthly/generate', {})).status).toBe(403);
    }
    let res = await call('admin', 'POST', '/reports/monthly/generate', {});
    expect(res.status).toBe(201);
    expect(monthlyReportResponseSchema.parse(await res.json()).report.period).toBe('2026-10');

    clock = new Date('2026-11-04T08:00:00.000Z');
    res = await call('admin', 'POST', '/reports/monthly/generate', { period: '2026-10' });
    expect(res.status).toBe(201);
    const rows = await t.db.select().from(monthlyReports);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.generatedAt.toISOString()).toBe(clock.toISOString());

    // The current (partial) month is allowed; a future month is not.
    res = await call('admin', 'POST', '/reports/monthly/generate', { period: '2026-11' });
    expect(res.status).toBe(201);
    res = await call('admin', 'POST', '/reports/monthly/generate', { period: '2026-12' });
    expect(res.status).toBe(400);
    res = await call('admin', 'POST', '/reports/monthly/generate', { period: 'october' });
    expect(res.status).toBe(400);

    const audit = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'report.monthly_generated'));
    expect(audit.map((a) => a.metadata)).toEqual(
      expect.arrayContaining([
        { period: '2026-10', trigger: 'manual', regenerated: false },
        { period: '2026-10', trigger: 'manual', regenerated: true },
        { period: '2026-11', trigger: 'manual', regenerated: false },
      ]),
    );
  });
});
