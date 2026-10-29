// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import type { Rule } from '@exdomainvault/rules';
import {
  DEFAULT_SLA_POLICY,
  errorResponseSchema,
  findingListResponseSchema,
  findingDetailResponseSchema,
  reportSummaryResponseSchema,
  slaPolicyResponseSchema,
  slaPolicyUpdateResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { and, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateJob } from '../services/evaluation.ts';
import { expireAcceptedRisks } from '../services/finding-lifecycle.ts';
import { runMaintenance } from '../services/maintenance.ts';
import { backfillDueDates } from '../services/sla.ts';
import { createLogger } from '../lib/logger.ts';
import {
  FAKE_RULES,
  dmarcRule,
  dnsFor,
  hostRule,
  seedDomain,
  seedJob,
  type Seed,
} from '../testing/findings-fixtures.ts';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const { applicationSettings, auditLogs, domains, findingStatusHistory, findings, scanJobs } =
  schema;

let t: TestDatabase;
let clock = new Date('2026-10-22T10:00:00.000Z');
const h = harness(
  () => t,
  () => clock,
  { rules: FAKE_RULES },
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
  vi.spyOn(console, 'error').mockImplementation(() => {});
  clock = new Date('2026-10-22T10:00:00.000Z');
  await t.db.delete(findings);
  await t.db.delete(scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(domains);
  await t.db.delete(auditLogs);
  // Back to the seeded default policy.
  await t.db
    .update(applicationSettings)
    .set({ value: DEFAULT_SLA_POLICY, updatedBy: null })
    .where(eq(applicationSettings.key, 'sla_policy'));
});
afterEach(() => vi.restoreAllMocks());

const DAY = 86_400_000;
const T0 = new Date('2026-10-01T00:00:00.000Z');
const at = (days: number) => new Date(T0.getTime() + days * DAY);

const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function row(ruleId: string, hostname: string) {
  const [r] = await t.db
    .select()
    .from(findings)
    .where(and(eq(findings.ruleId, ruleId), eq(findings.hostname, hostname)));
  if (!r) throw new Error(`no finding ${ruleId} ${hostname}`);
  return r;
}

/** DMARC (medium) and host (high) rules: no change-detection findings in the way. */
const RULES: readonly Rule[] = [dmarcRule, hostRule];

async function scan(s: Seed, day: number, opts: Parameters<typeof dnsFor>[1], rules = RULES) {
  const job = await seedJob(t, s.domainId, at(day), dnsFor(s.fqdn, opts));
  const res = await evaluateJob(t.db, job, clock, rules);
  expect(res.status).toBe('evaluated');
}

describe('due dates on findings', () => {
  it('sets due_at from first seen when a finding is created', async () => {
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'] });
    // TST-HOST is high (30 days), TST-DMARC medium (90 days).
    expect((await row('TST-HOST', s.fqdn)).dueAt?.toISOString()).toBe(at(30).toISOString());
    expect((await row('TST-DMARC', s.fqdn)).dueAt?.toISOString()).toBe(at(90).toISOString());
  });

  it('keeps the due date on refresh and restarts the clock on recurrence', async () => {
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'] });
    await scan(s, 5, { apexA: ['192.0.2.1'] });
    expect((await row('TST-HOST', s.fqdn)).dueAt?.toISOString()).toBe(at(30).toISOString());

    await scan(s, 10, { apexA: [] }); // checked and absent → resolved
    const resolved = await row('TST-HOST', s.fqdn);
    expect(resolved.status).toBe('resolved');
    expect(resolved.dueAt?.toISOString()).toBe(at(30).toISOString()); // kept for compliance

    await scan(s, 40, { apexA: ['192.0.2.1'] }); // recurrence
    const reopened = await row('TST-HOST', s.fqdn);
    expect(reopened.status).toBe('open');
    expect(reopened.recurrenceCount).toBe(1);
    expect(reopened.dueAt?.toISOString()).toBe(at(70).toISOString());
  });

  it('recomputes the due date when re-evaluation changes the severity', async () => {
    // Same fingerprint as TST-HOST, but critical while the host has two addresses.
    const variable: Rule = {
      ...hostRule,
      evaluate(input) {
        const out = hostRule.evaluate(input);
        return {
          ...out,
          findings: out.findings.map((f) => ({
            ...f,
            severity: (f.evidence.values as string[]).length > 1 ? 'critical' : 'high',
          })),
        };
      },
    };
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'] }, [variable]);
    expect((await row('TST-HOST', s.fqdn)).dueAt?.toISOString()).toBe(at(30).toISOString());
    await scan(s, 3, { apexA: ['192.0.2.1', '192.0.2.2'] }, [variable]);
    const f = await row('TST-HOST', s.fqdn);
    expect(f.severity).toBe('critical');
    expect(f.dueAt?.toISOString()).toBe(at(7).toISOString()); // still from first seen
  });

  it('restarts the clock when an accepted risk lapses', async () => {
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'] });
    const f = await row('TST-HOST', s.fqdn);
    const admin = await ensureUser(t, 'admin');
    await t.db
      .update(findings)
      .set({
        status: 'accepted_risk',
        acceptedRiskReason: 'Compensating control in place',
        acceptedRiskApprovedBy: admin,
        acceptedRiskReviewAt: at(50),
      })
      .where(eq(findings.id, f.id));
    expect(await expireAcceptedRisks(t.db, at(51))).toBe(1);
    const after = await row('TST-HOST', s.fqdn);
    expect(after.status).toBe('open');
    expect(after.dueAt?.toISOString()).toBe(at(81).toISOString());
  });

  it('restarts the clock when a user moves an accepted risk back to work', async () => {
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'] });
    const f = await row('TST-HOST', s.fqdn);
    clock = at(1);
    let res = await call('analyst', 'PATCH', `/findings/${f.id}`, {
      expectedStatus: 'open',
      status: 'accepted_risk',
      reason: 'Compensating control in place',
      acceptedRiskReviewAt: at(60).toISOString(),
    });
    expect(res.status).toBe(200);
    clock = at(20);
    res = await call('analyst', 'PATCH', `/findings/${f.id}`, {
      expectedStatus: 'accepted_risk',
      status: 'open',
      reason: 'Control was removed',
    });
    expect(res.status).toBe(200);
    const after = await row('TST-HOST', s.fqdn);
    expect(after.dueAt?.toISOString()).toBe(at(50).toISOString());
    // acknowledged → open does not restart it
    clock = at(25);
    await call('analyst', 'PATCH', `/findings/${f.id}`, {
      expectedStatus: 'open',
      status: 'acknowledged',
    });
    await call('analyst', 'PATCH', `/findings/${f.id}`, {
      expectedStatus: 'acknowledged',
      status: 'open',
      reason: 'Back to the queue',
    });
    expect((await row('TST-HOST', s.fqdn)).dueAt?.toISOString()).toBe(at(50).toISOString());
  });

  it('backfills missing due dates idempotently (cron step)', async () => {
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'] });
    await scan(s, 10, { apexA: [] }); // TST-HOST resolved
    await t.db.update(findings).set({ dueAt: null });
    expect(await backfillDueDates(t.db)).toBe(2); // resolved findings included
    expect((await row('TST-HOST', s.fqdn)).dueAt?.toISOString()).toBe(at(30).toISOString());
    expect((await row('TST-DMARC', s.fqdn)).dueAt?.toISOString()).toBe(at(90).toISOString());
    expect(await backfillDueDates(t.db)).toBe(0);

    await t.db.update(findings).set({ dueAt: null });
    await runMaintenance(t.db, clock, createLogger({ requestId: 'test' }));
    expect((await row('TST-DMARC', s.fqdn)).dueAt).not.toBeNull();
  });
});

describe('GET/PUT /settings/sla', () => {
  it('returns the policy to finding readers', async () => {
    for (const role of ['admin', 'analyst', 'viewer', 'asset_owner'] as const) {
      const res = await call(role, 'GET', '/settings/sla');
      expect(res.status).toBe(200);
      expect(slaPolicyResponseSchema.parse(await res.json()).policy).toEqual(DEFAULT_SLA_POLICY);
    }
  });

  it('lets only administrators change it', async () => {
    for (const role of ['analyst', 'viewer', 'asset_owner'] as const) {
      const res = await call(role, 'PUT', '/settings/sla', { ...DEFAULT_SLA_POLICY, high: 14 });
      expect(res.status).toBe(403);
    }
  });

  it.each([
    { ...DEFAULT_SLA_POLICY, high: 0 },
    { ...DEFAULT_SLA_POLICY, high: 3651 },
    { ...DEFAULT_SLA_POLICY, high: 2.5 },
    { critical: 7 },
    { ...DEFAULT_SLA_POLICY, extra: 1 },
  ])('rejects an invalid policy %#', async (body) => {
    const res = await call('admin', 'PUT', '/settings/sla', body);
    expect(res.status).toBe(400);
    expect(errorResponseSchema.parse(await res.json()).error.code).toBe('validation_failed');
  });

  it('recomputes non-resolved findings, keeps resolved ones, and audits', async () => {
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] });
    await scan(s, 10, { apexA: [], wwwA: ['192.0.2.2'] }); // apex host resolved
    clock = at(11);
    const res = await call('admin', 'PUT', '/settings/sla', {
      ...DEFAULT_SLA_POLICY,
      high: 14,
      medium: null,
    });
    expect(res.status).toBe(200);
    const body = slaPolicyUpdateResponseSchema.parse(await res.json());
    expect(body.policy.high).toBe(14);
    expect(body.updatedBy?.email).toBe('admin@example.com');
    expect(body.recomputed).toBe(2); // www host + DMARC

    expect((await row('TST-HOST', `www.${s.fqdn}`)).dueAt?.toISOString()).toBe(
      at(14).toISOString(),
    );
    expect((await row('TST-DMARC', s.fqdn)).dueAt).toBeNull();
    expect((await row('TST-HOST', s.fqdn)).dueAt?.toISOString()).toBe(at(30).toISOString());

    const [audit] = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'settings.sla_updated'));
    expect(audit?.metadata).toMatchObject({
      before: DEFAULT_SLA_POLICY,
      after: { high: 14, medium: null },
      recomputed: 2,
    });

    // Saving the same policy again changes nothing.
    const again = slaPolicyUpdateResponseSchema.parse(
      await (
        await call('admin', 'PUT', '/settings/sla', {
          ...DEFAULT_SLA_POLICY,
          high: 14,
          medium: null,
        })
      ).json(),
    );
    expect(again.recomputed).toBe(0);
  });
});

describe('overdue in the findings API', () => {
  async function world() {
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'] }); // host high due day 30, DMARC due day 90
    await scan(s, 20, { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] }); // www host due day 50
    return s;
  }

  it('marks overdue findings and filters and sorts on due dates', async () => {
    const s = await world();
    clock = at(40);
    let res = await call('analyst', 'GET', '/findings?sort=dueAt');
    const list = findingListResponseSchema.parse(await res.json());
    expect(list.items.map((f) => [f.hostname, f.ruleId, f.overdue])).toEqual([
      [s.fqdn, 'TST-HOST', true],
      [`www.${s.fqdn}`, 'TST-HOST', false],
      [s.fqdn, 'TST-DMARC', false],
    ]);
    expect(list.items[0]?.dueAt).toBe(at(30).toISOString());

    res = await call('analyst', 'GET', '/findings?overdue=true');
    expect(findingListResponseSchema.parse(await res.json()).items.map((f) => f.hostname)).toEqual([
      s.fqdn,
    ]);
    res = await call('analyst', 'GET', '/findings?overdue=false');
    expect(findingListResponseSchema.parse(await res.json()).total).toBe(2);
    res = await call(
      'analyst',
      'GET',
      `/findings?dueBefore=${encodeURIComponent(at(60).toISOString())}`,
    );
    expect(findingListResponseSchema.parse(await res.json()).total).toBe(2);
    res = await call('analyst', 'GET', '/findings?overdue=maybe');
    expect(res.status).toBe(400);

    const host = await row('TST-HOST', s.fqdn);
    res = await call('analyst', 'GET', `/findings/${host.id}`);
    const detail = findingDetailResponseSchema.parse(await res.json());
    expect(detail.finding).toMatchObject({ overdue: true, dueAt: at(30).toISOString() });
  });

  it('never reports accepted risk as overdue', async () => {
    const s = await world();
    const host = await row('TST-HOST', s.fqdn);
    clock = at(40);
    await call('analyst', 'PATCH', `/findings/${host.id}`, {
      expectedStatus: 'open',
      status: 'accepted_risk',
      reason: 'Compensating control in place',
      acceptedRiskReviewAt: at(80).toISOString(),
    });
    const res = await call('analyst', 'GET', '/findings?overdue=true');
    expect(findingListResponseSchema.parse(await res.json()).total).toBe(0);
  });
});

describe('SLA section of GET /reports/summary', () => {
  it('reports overdue, compliance and mean days to resolve', async () => {
    const s = await seedDomain(t, 'a.example');
    await scan(s, 0, { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] }); // two hosts due day 30
    await scan(s, 10, { apexA: [], wwwA: ['192.0.2.2'] }); // apex resolved within SLA (10 d)
    clock = at(35);
    // www host overdue now; resolve it late on day 36
    await scan(s, 36, { apexA: [], wwwA: [] });
    await scan(s, 37, { apexA: ['192.0.2.1'], wwwA: [] }); // apex recurs, due day 67
    clock = at(70);
    const res = await call('viewer', 'GET', '/reports/summary');
    expect(res.status).toBe(200);
    const { sla } = reportSummaryResponseSchema.parse(await res.json());
    expect(sla.policy).toEqual(DEFAULT_SLA_POLICY);
    expect(sla.overdue).toBe(1); // the recurring apex host (due day 67)
    expect(sla.overdueBySeverity.high).toBe(1);
    // Still-resolved findings in the window: www (late).
    expect(sla.resolvedWithSla).toBe(1);
    expect(sla.resolvedWithinSla).toBe(0);
    expect(sla.compliancePercent).toBe(0);
    expect(sla.meanDaysToResolveBySeverity.high).toBe(36);
    expect(sla.meanDaysToResolveBySeverity.critical).toBeNull();
  });
});

// Status history entries exist for every recurrence (used for the SLA clock).
it('records the recurrence used as the SLA clock start', async () => {
  const s = await seedDomain(t, 'a.example');
  await scan(s, 0, { apexA: ['192.0.2.1'] });
  await scan(s, 1, { apexA: [] });
  await scan(s, 2, { apexA: ['192.0.2.1'] });
  const f = await row('TST-HOST', s.fqdn);
  const hist = await t.db
    .select()
    .from(findingStatusHistory)
    .where(eq(findingStatusHistory.findingId, f.id));
  expect(hist.map((x) => x.reason).sort()).toEqual(['condition_absent', 'detected', 'recurrence']);
});
