// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  advisoryListResponseSchema,
  bulkMonitoringResponseSchema,
  errorResponseSchema,
  findingDetailResponseSchema,
  findingListResponseSchema,
  findingSummaryResponseSchema,
  ruleCatalogueResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { and, asc, eq, inArray } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateJob } from '../services/evaluation.ts';
import {
  FAKE_RULES,
  dnsFor,
  seedDomain,
  seedJob,
  type Seed,
} from '../testing/findings-fixtures.ts';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

let t: TestDatabase;
let clock: Date;
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
  clock = new Date('2026-10-22T10:00:00.000Z');
  await t.db.delete(schema.findings);
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
  await t.db.delete(schema.auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function expectError(res: Response, status: number, code: string) {
  expect(res.status).toBe(status);
  expect(errorResponseSchema.parse(await res.json()).error.code).toBe(code);
}

const at = (hours: number) => new Date(Date.parse('2026-10-20T00:00:00.000Z') + hours * 3600_000);

/**
 * a.example (high criticality, www owned by the asset owner): DMARC missing (email, medium, domain
 * level), host findings for apex and www (exposure, high). b.example (low criticality): DMARC fixed
 * after first scan (resolved), an apex host finding and an A-record change (dns, low).
 * Active: 5, all: 6.
 */
async function seedFindings(): Promise<{ a: Seed; b: Seed }> {
  const a = await seedDomain(t, 'a.example', { owned: true, criticality: 'high' });
  const b = await seedDomain(t, 'b.example', { criticality: 'low' });
  await evaluateJob(
    t.db,
    await seedJob(
      t,
      a.domainId,
      at(1),
      dnsFor(a.fqdn, { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] }),
    ),
    clock,
    FAKE_RULES,
  );
  await evaluateJob(t.db, await seedJob(t, b.domainId, at(1), dnsFor(b.fqdn)), clock, FAKE_RULES);
  await evaluateJob(
    t.db,
    await seedJob(t, b.domainId, at(2), dnsFor(b.fqdn, { dmarc: true, apexA: ['198.51.100.1'] })),
    clock,
    FAKE_RULES,
  );
  return { a, b };
}

const list = async (role: Role, qs = '') => {
  const res = await call(role, 'GET', `/findings${qs}`);
  expect(res.status).toBe(200);
  return findingListResponseSchema.parse(await res.json());
};

describe('GET /findings', () => {
  it('lists active findings by risk for viewers, with filters', async () => {
    const { a, b } = await seedFindings();
    const all = await list('viewer');
    expect(all.total).toBe(5);
    // Highest risk first: exposure/high on the high-criticality domain (75×1.1×1.0 = 83).
    expect(all.items[0]).toMatchObject({ ruleId: 'TST-HOST', riskScore: 83 });
    expect(all.items.every((f) => f.status !== 'resolved')).toBe(true);
    const scores = all.items.map((f) => f.riskScore);
    expect(scores).toEqual([...scores].sort((x, y) => y - x));

    expect((await list('viewer', '?status=all')).total).toBe(6);
    expect((await list('viewer', '?status=resolved')).items).toMatchObject([
      { ruleId: 'TST-DMARC', domain: { id: b.domainId, fqdn: 'b.example' } },
    ]);
    expect((await list('viewer', '?severity=medium')).items.map((f) => f.hostname)).toEqual([
      'a.example',
    ]);
    expect((await list('viewer', '?category=exposure')).total).toBe(3);
    expect((await list('viewer', `?domainId=${a.domainId}`)).total).toBe(3);
    expect((await list('viewer', '?ruleId=TST-DMARC')).total).toBe(1);
    expect((await list('viewer', '?q=WWW.A')).items.map((f) => f.hostname)).toEqual([
      'www.a.example',
    ]);
    expect((await list('viewer', '?q=dmarc')).total).toBe(1); // title match
    // LIKE wildcards are escaped: a literal % matches nothing.
    expect((await list('viewer', '?q=%25')).total).toBe(0);
  });

  it('sorts and paginates', async () => {
    await seedFindings();
    const asc = await list('analyst', '?sort=riskScore');
    const scores = asc.items.map((f) => f.riskScore);
    expect(scores).toEqual([...scores].sort((x, y) => x - y));
    const bySeverity = await list('analyst', '?sort=-severity');
    expect(bySeverity.items.map((f) => f.severity)).toEqual([
      'high',
      'high',
      'high',
      'medium',
      'low',
    ]);

    const p1 = await list('analyst', '?pageSize=3&page=1');
    const p2 = await list('analyst', '?pageSize=3&page=2');
    expect([p1.items.length, p2.items.length, p1.total]).toEqual([3, 2, 5]);
    expect(new Set([...p1.items, ...p2.items].map((f) => f.id)).size).toBe(5);
  });

  it('rejects invalid queries', async () => {
    await expectError(await call('viewer', 'GET', '/findings?sort=evil'), 400, 'validation_failed');
    await expectError(
      await call('viewer', 'GET', '/findings?status=unknown'),
      400,
      'validation_failed',
    );
    await expectError(
      await call('viewer', 'GET', '/findings?pageSize=1000'),
      400,
      'validation_failed',
    );
  });

  it('scopes asset owners to findings on their own assets', async () => {
    const { a } = await seedFindings();
    const own = await list('asset_owner', '?status=all');
    expect(own.items.map((f) => [f.hostname, f.assetId])).toEqual([
      ['www.a.example', a.wwwAssetId],
    ]);

    // Domain-level and other findings are invisible, including by id.
    const domainLevel = (await list('admin')).items.find((f) => f.ruleId === 'TST-DMARC')!;
    await expectError(
      await call('asset_owner', 'GET', `/findings/${domainLevel.id}`),
      404,
      'not_found',
    );
    const ownId = own.items[0]!.id;
    expect((await call('asset_owner', 'GET', `/findings/${ownId}`)).status).toBe(200);

    const summary = findingSummaryResponseSchema.parse(
      await (await call('asset_owner', 'GET', '/findings/summary')).json(),
    );
    expect(summary.total).toBe(1);

    const adv = advisoryListResponseSchema.parse(
      await (await call('asset_owner', 'GET', '/advisories')).json(),
    );
    expect(adv.items.map((x) => x.findingId)).toEqual([ownId]);
  });
});

describe('GET /findings/summary', () => {
  it('counts active findings by severity and category, optionally per domain', async () => {
    const { b } = await seedFindings();
    const res = await call('viewer', 'GET', '/findings/summary');
    const s = findingSummaryResponseSchema.parse(await res.json());
    expect(s.total).toBe(5);
    expect(s.bySeverity).toEqual({ informational: 0, low: 1, medium: 1, high: 3, critical: 0 });
    expect(s.byCategory).toEqual({
      dns: 1,
      email: 1,
      tls: 0,
      http: 0,
      exposure: 3,
      registration: 0,
      asset: 0,
    });

    const perDomain = findingSummaryResponseSchema.parse(
      await (await call('viewer', 'GET', `/findings/summary?domainId=${b.domainId}`)).json(),
    );
    expect(perDomain.total).toBe(2); // DMARC resolved; host and A-change findings active
    await expectError(
      await call('viewer', 'GET', '/findings/summary?domainId=nope'),
      400,
      'validation_failed',
    );
  });
});

describe('GET /findings/:id', () => {
  it('returns the finding with advisory, history and rule documentation', async () => {
    const { b } = await seedFindings();
    const [row] = await t.db
      .select()
      .from(schema.findings)
      .where(
        and(eq(schema.findings.domainId, b.domainId), eq(schema.findings.ruleId, 'TST-DMARC')),
      );
    // A user-made transition shows who made it.
    const analyst = await ensureUser(t, 'analyst');
    await t.db.insert(schema.findingStatusHistory).values({
      findingId: row!.id,
      fromStatus: 'resolved',
      toStatus: 'resolved',
      changedBy: analyst,
      reason: 'note',
      note: 'Checked manually',
      createdAt: new Date('2026-10-23T00:00:00Z'),
    });

    const res = await call('viewer', 'GET', `/findings/${row!.id}`);
    expect(res.status).toBe(200);
    const body = findingDetailResponseSchema.parse(await res.json());
    expect(body.finding).toMatchObject({
      id: row!.id,
      status: 'resolved',
      category: 'email',
      component: 'dmarc',
      domain: { id: b.domainId, fqdn: 'b.example' },
      assetId: null,
    });
    expect(body.advisory).toMatchObject({
      findingId: row!.id,
      title: 'Fix: No DMARC policy published',
      references: ['https://example.com/reference'],
    });
    expect(body.history.map((x) => [x.reason, x.changedBy?.email ?? null])).toEqual([
      ['detected', null],
      ['condition_absent', null],
      ['note', 'analyst@example.com'],
    ]);
    expect(body.rule).toEqual({
      id: 'TST-DMARC',
      version: 1,
      detection: 'Synthetic detection.',
      resolution: 'Synthetic resolution.',
      evidenceRequirements: 'Successful DNS observations.',
    });
  });

  it('returns 404 for unknown or malformed ids', async () => {
    await expectError(
      await call('viewer', 'GET', '/findings/00000000-0000-4000-8000-000000000000'),
      404,
      'not_found',
    );
    await expectError(await call('viewer', 'GET', '/findings/not-a-uuid'), 404, 'not_found');
  });
});

describe('GET /advisories', () => {
  it('lists advisories of active findings by default, all on request', async () => {
    await seedFindings();
    const active = advisoryListResponseSchema.parse(
      await (await call('viewer', 'GET', '/advisories')).json(),
    );
    expect(active.total).toBe(5);
    expect(active.items[0]!.finding).toMatchObject({ ruleId: 'TST-HOST', riskScore: 83 });
    const all = advisoryListResponseSchema.parse(
      await (await call('viewer', 'GET', '/advisories?status=all&pageSize=2&page=3')).json(),
    );
    expect([all.total, all.items.length]).toEqual([6, 2]);
  });
});

describe('GET /rules', () => {
  it('returns the rule catalogue', async () => {
    const res = await call('viewer', 'GET', '/rules');
    expect(res.status).toBe(200);
    const body = ruleCatalogueResponseSchema.parse(await res.json());
    expect(body.items.map((r) => r.id)).toEqual(['TST-DMARC', 'TST-ACHANGE', 'TST-HOST']);
    expect(body.items[2]).toMatchObject({
      version: 2,
      category: 'exposure',
      defaultSeverity: 'high',
      requires: ['dns'],
    });
  });
});

describe('POST /domains/monitoring', () => {
  const monitoring = async (ids: string[]) =>
    (
      await t.db
        .select({ fqdn: schema.domains.fqdn, on: schema.domains.monitoringEnabled })
        .from(schema.domains)
        .where(inArray(schema.domains.id, ids))
        .orderBy(asc(schema.domains.fqdn))
    ).map((r) => [r.fqdn, r.on]);

  it('turns monitoring on for listed domains, auditing each change', async () => {
    const a = await seedDomain(t, 'a.example');
    const b = await seedDomain(t, 'b.example');
    const c = await seedDomain(t, 'c.example');
    const res = await call('admin', 'POST', '/domains/monitoring', {
      domainIds: [a.domainId, b.domainId],
      enabled: true,
    });
    expect(res.status).toBe(200);
    expect(bulkMonitoringResponseSchema.parse(await res.json())).toEqual({ updated: 2 });
    expect(await monitoring([a.domainId, b.domainId, c.domainId])).toEqual([
      ['a.example', true],
      ['b.example', true],
      ['c.example', false],
    ]);
    const audit = await t.db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'domain.monitoring_enabled'));
    expect(audit.map((x) => x.resourceId).sort()).toEqual([a.domainId, b.domainId].sort());
    expect(audit[0]!.metadata).toMatchObject({ bulk: true });
    expect(audit[0]!.actorUserId).toBe(await ensureUser(t, 'admin'));

    // Unchanged domains are neither updated nor audited again.
    const again = await call('admin', 'POST', '/domains/monitoring', {
      domainIds: [a.domainId],
      enabled: true,
    });
    expect(await again.json()).toEqual({ updated: 0 });
  });

  it('applies to every domain with all: true', async () => {
    const a = await seedDomain(t, 'a.example');
    const b = await seedDomain(t, 'b.example');
    await call('admin', 'POST', '/domains/monitoring', { all: true, enabled: true });
    const off = await call('admin', 'POST', '/domains/monitoring', { all: true, enabled: false });
    expect(await off.json()).toEqual({ updated: 2 });
    expect(await monitoring([a.domainId, b.domainId])).toEqual([
      ['a.example', false],
      ['b.example', false],
    ]);
    const disabled = await t.db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'domain.monitoring_disabled'));
    expect(disabled).toHaveLength(2);
  });

  it('requires domains:write and a valid request', async () => {
    const a = await seedDomain(t, 'a.example');
    for (const role of ['viewer', 'analyst', 'asset_owner'] as const) {
      await expectError(
        await call(role, 'POST', '/domains/monitoring', { all: true, enabled: true }),
        403,
        'forbidden',
      );
    }
    expect(await monitoring([a.domainId])).toEqual([['a.example', false]]);
    for (const body of [
      { domainIds: [], enabled: true },
      { domainIds: ['not-a-uuid'], enabled: true },
      { domainIds: Array.from({ length: 501 }, () => a.domainId), enabled: true },
      { all: false, enabled: true },
      { all: true },
      { domainIds: [a.domainId], all: true, enabled: true },
    ]) {
      await expectError(
        await call('admin', 'POST', '/domains/monitoring', body),
        400,
        'validation_failed',
      );
    }
  });
});
