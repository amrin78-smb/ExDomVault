// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import type { Rule } from '@exdomainvault/rules';
import {
  domainDetailResponseSchema,
  domainListResponseSchema,
  domainScoreResponseSchema,
  reportSummaryResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateJob } from '../services/evaluation.ts';
import { snapshotSecurityScores } from '../services/security-score.ts';
import {
  dmarcRule,
  dnsFor,
  hostRule,
  seedDomain,
  seedJob,
  type Seed,
} from '../testing/findings-fixtures.ts';
import { harness, userCall } from '../testing/harness.ts';

const { auditLogs, domainScoreSnapshots, domains, findings, scanJobs } = schema;

let t: TestDatabase;
let clock = new Date('2026-10-22T10:00:00.000Z');
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
  clock = new Date('2026-10-22T10:00:00.000Z');
  await t.db.delete(domainScoreSnapshots);
  await t.db.delete(findings);
  await t.db.delete(scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(domains);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const RULES: readonly Rule[] = [dmarcRule, hostRule];
const DAY = 86_400_000;
const call = (role: Role, path: string) => userCall(h, t, role, 'GET', path);

async function scan(s: Seed, when: Date, opts: Parameters<typeof dnsFor>[1]) {
  const job = await seedJob(t, s.domainId, when, dnsFor(s.fqdn, opts));
  expect((await evaluateJob(t.db, job, clock, RULES)).status).toBe('evaluated');
}

async function snapshots(domainId: string) {
  return t.db
    .select()
    .from(domainScoreSnapshots)
    .where(eq(domainScoreSnapshots.domainId, domainId))
    .orderBy(domainScoreSnapshots.day);
}

/**
 * a.example: DMARC missing (email, medium 4) + apex and www hosts (exposure, high 10 each) → 76 C.
 * b.example: DMARC published, no hosts → 100 A. c.example: never scanned → unscored.
 */
async function world() {
  const a = await seedDomain(t, 'a.example');
  const b = await seedDomain(t, 'b.example');
  const c = await seedDomain(t, 'c.example');
  await t.db.update(domains).set({ businessOwner: 'Payments' }).where(eq(domains.id, a.domainId));
  await t.db.update(domains).set({ businessOwner: 'Payments' }).where(eq(domains.id, b.domainId));
  const day1 = new Date(clock.getTime() - DAY);
  await scan(a, day1, { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] });
  await scan(b, day1, { dmarc: true });
  return { a, b, c };
}

describe('daily snapshots (cron)', () => {
  it('writes one row per scored domain per day, refreshed at most hourly', async () => {
    const { a, b, c } = await world();
    expect(await snapshotSecurityScores(t.db, clock)).toBe(2);
    const [snap] = await snapshots(a.domainId);
    expect(snap).toMatchObject({ day: '2026-10-22', score: 76, grade: 'C' });
    expect(snap?.inputs).toMatchObject({ version: 1 });
    expect((await snapshots(b.domainId))[0]).toMatchObject({ score: 100, grade: 'A' });
    expect(await snapshots(c.domainId)).toEqual([]);

    // Within the hour: nothing to do.
    expect(await snapshotSecurityScores(t.db, new Date(clock.getTime() + 30 * 60_000))).toBe(0);

    // Later the same day, after a change: the day's row is updated in place.
    await t.db
      .update(findings)
      .set({ status: 'resolved', resolvedAt: clock })
      .where(eq(findings.ruleId, 'TST-DMARC'));
    const later = new Date(clock.getTime() + 2 * 3600_000);
    expect(await snapshotSecurityScores(t.db, later)).toBe(2);
    const rows = await snapshots(a.domainId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ score: 80, grade: 'B' });

    // Next day: a new row.
    expect(await snapshotSecurityScores(t.db, new Date(clock.getTime() + DAY))).toBe(2);
    expect((await snapshots(a.domainId)).map((r) => r.day)).toEqual(['2026-10-22', '2026-10-23']);
  });

  it('counts overdue findings with the overdue penalty', async () => {
    const { a } = await world();
    // Push the clock past the 30-day high SLA: both hosts overdue (15 each), DMARC not (90 days).
    clock = new Date(clock.getTime() + 40 * DAY);
    await snapshotSecurityScores(t.db, clock);
    const rows = await snapshots(a.domainId);
    expect(rows.at(-1)).toMatchObject({ score: 66, grade: 'D' });
  });
});

describe('domain DTO and list', () => {
  it('shows the latest score and grade, filters and sorts by them', async () => {
    const { a, b, c } = await world();
    await snapshotSecurityScores(t.db, clock);

    let res = await call('viewer', '/domains?sort=score');
    let list = domainListResponseSchema.parse(await res.json());
    expect(list.items.map((d) => [d.fqdn, d.score, d.grade])).toEqual([
      ['a.example', 76, 'C'],
      ['b.example', 100, 'A'],
      ['c.example', null, null],
    ]);
    res = await call('viewer', '/domains?sort=-score');
    list = domainListResponseSchema.parse(await res.json());
    expect(list.items.map((d) => d.fqdn)).toEqual(['b.example', 'a.example', 'c.example']);

    res = await call('viewer', '/domains?grade=C');
    expect(domainListResponseSchema.parse(await res.json()).items.map((d) => d.id)).toEqual([
      a.domainId,
    ]);
    res = await call('viewer', '/domains?grade=none');
    expect(domainListResponseSchema.parse(await res.json()).items.map((d) => d.id)).toEqual([
      c.domainId,
    ]);
    expect((await call('viewer', '/domains?grade=E')).status).toBe(400);

    res = await call('viewer', `/domains/${b.domainId}`);
    expect(domainDetailResponseSchema.parse(await res.json()).domain).toMatchObject({
      score: 100,
      grade: 'A',
    });
  });
});

describe('GET /domains/:id/score', () => {
  it('explains the current score and writes a missing snapshot on demand', async () => {
    const { a } = await world();
    const res = await call('analyst', `/domains/${a.domainId}/score`);
    expect(res.status).toBe(200);
    const body = domainScoreResponseSchema.parse(await res.json());
    expect(body.current).toMatchObject({ score: 76, grade: 'C' });
    expect(body.current?.deductions.map((d) => [d.category, d.points])).toEqual([
      ['exposure', 20],
      ['email', 4],
    ]);
    expect(body.trend).toEqual([{ day: '2026-10-22', score: 76, grade: 'C' }]);
    expect(await snapshots(a.domainId)).toHaveLength(1);
  });

  it('returns the 90-day trend oldest first with today live', async () => {
    const { a } = await world();
    await t.db.insert(domainScoreSnapshots).values([
      { domainId: a.domainId, day: '2026-07-01', score: 10, grade: 'F' }, // older than 90 days
      { domainId: a.domainId, day: '2026-10-01', score: 50, grade: 'F' },
      { domainId: a.domainId, day: '2026-10-22', score: 99, grade: 'A' }, // stale today
    ]);
    const body = domainScoreResponseSchema.parse(
      await (await call('viewer', `/domains/${a.domainId}/score`)).json(),
    );
    expect(body.trendDays).toBe(90);
    expect(body.trend).toEqual([
      { day: '2026-10-01', score: 50, grade: 'F' },
      { day: '2026-10-22', score: 76, grade: 'C' },
    ]);
  });

  it('has no score for a domain that was never scanned', async () => {
    const { c } = await world();
    const body = domainScoreResponseSchema.parse(
      await (await call('viewer', `/domains/${c.domainId}/score`)).json(),
    );
    expect(body.current).toBeNull();
    expect(body.trend).toEqual([]);
    expect(await snapshots(c.domainId)).toEqual([]);
  });

  it('404s for an unknown domain and refuses asset owners', async () => {
    expect((await call('viewer', `/domains/${crypto.randomUUID()}/score`)).status).toBe(404);
    const { a } = await world();
    expect((await call('asset_owner', `/domains/${a.domainId}/score`)).status).toBe(403);
  });
});

describe('business owner aggregation in GET /reports/summary', () => {
  it('reports average score and grade distribution per business owner', async () => {
    await world();
    await snapshotSecurityScores(t.db, clock);
    const body = reportSummaryResponseSchema.parse(
      await (await call('viewer', '/reports/summary')).json(),
    );
    const payments = body.byBusinessOwner.find((r) => r.businessOwner === 'Payments');
    expect(payments).toMatchObject({
      domains: 2,
      averageScore: 88,
      grade: 'B',
      grades: { A: 1, B: 0, C: 1, D: 0, F: 0 },
      overdue: 0,
    });
    const none = body.byBusinessOwner.find((r) => r.businessOwner === null);
    expect(none).toMatchObject({ averageScore: null, grade: null });
  });
});
