// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { claimResponseSchema, workerCredentialCreatedResponseSchema } from '@exdomainvault/shared';
import { asc, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.ts';
import { createLogger } from '../lib/logger.ts';
import { evaluateJob, evaluatePendingJobs } from '../services/evaluation.ts';
import { runMaintenance } from '../services/maintenance.ts';
import {
  FAKE_RULES,
  aChangeRule,
  dmarcRule,
  dnsFor,
  hostRule,
  seedDomain,
  seedJob,
} from '../testing/findings-fixtures.ts';
import {
  ensureUser,
  generateWorkerKey,
  harness,
  signedHeaders,
  userCall,
  workerCall,
} from '../testing/harness.ts';

let t: TestDatabase;
let clock: Date;
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
  await t.db.delete(schema.findings);
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
  await t.db.delete(schema.workerRegistry);
});
afterEach(() => vi.restoreAllMocks());

const at = (hours: number) => new Date(Date.parse('2026-10-20T00:00:00.000Z') + hours * 3600_000);

const allFindings = () => t.db.select().from(schema.findings).orderBy(asc(schema.findings.ruleId));
const historyOf = (findingId: string) =>
  t.db
    .select()
    .from(schema.findingStatusHistory)
    .where(eq(schema.findingStatusHistory.findingId, findingId))
    .orderBy(asc(schema.findingStatusHistory.createdAt));
const jobRow = async (id: string) =>
  (await t.db.select().from(schema.scanJobs).where(eq(schema.scanJobs.id, id)))[0]!;

describe('evaluateJob', () => {
  it('creates a finding with history and advisory for a succeeded job', async () => {
    const s = await seedDomain(t, 'example.com');
    const job = await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn));
    const r = await evaluateJob(t.db, job, clock, [dmarcRule]);
    expect(r).toMatchObject({ status: 'evaluated', created: 1, resolved: 0 });

    const [f] = await allFindings();
    expect(f).toMatchObject({
      ruleId: 'TST-DMARC',
      ruleVersion: 1,
      domainId: s.domainId,
      assetId: null, // domain-level finding
      hostname: 'example.com',
      component: 'dmarc',
      category: 'email',
      status: 'open',
      severity: 'medium',
      fingerprint: `TST-DMARC|${s.domainId}|example.com|dmarc`,
      recurrenceCount: 0,
    });
    expect(f!.firstSeenAt).toEqual(at(1));
    expect(f!.lastSeenAt).toEqual(at(1));
    // Risk v1: 50 × 0.8 (public record) × 1.0 (high criticality) = 40, inputs stored.
    expect(f!.riskScore).toBe(40);
    expect(f!.riskInputs).toMatchObject({ model: 'v1', exposure: 'public_record' });

    expect(await historyOf(f!.id)).toMatchObject([
      { fromStatus: null, toStatus: 'open', reason: 'detected', scanJobId: job, changedBy: null },
    ]);
    const adv = await t.db
      .select()
      .from(schema.advisories)
      .where(eq(schema.advisories.findingId, f!.id));
    expect(adv).toHaveLength(1);
    expect(adv[0]!.title).toBe('Fix: No DMARC policy published');
    expect((await jobRow(job)).rulesEvaluatedAt).toEqual(clock);
  });

  it('evaluates a job only once', async () => {
    const s = await seedDomain(t, 'example.com');
    const job = await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn));
    await evaluateJob(t.db, job, clock, [dmarcRule]);
    const again = await evaluateJob(t.db, job, new Date(clock.getTime() + 60_000), [dmarcRule]);
    expect(again.status).toBe('not_eligible');
    const rows = await allFindings();
    expect(rows).toHaveLength(1);
    expect(await historyOf(rows[0]!.id)).toHaveLength(1);
    expect((await jobRow(job)).rulesEvaluatedAt).toEqual(clock);
  });

  it('refreshes the same finding when a later job sees the same condition', async () => {
    const s = await seedDomain(t, 'example.com');
    await evaluateJob(t.db, await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn)), clock, [
      dmarcRule,
    ]);
    const job2 = await seedJob(t, s.domainId, at(2), dnsFor(s.fqdn));
    const r = await evaluateJob(t.db, job2, clock, [dmarcRule]);
    expect(r).toMatchObject({ created: 0, refreshed: 1 });
    const rows = await allFindings();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.firstSeenAt).toEqual(at(1));
    expect(rows[0]!.lastSeenAt).toEqual(at(2));
    expect(await historyOf(rows[0]!.id)).toHaveLength(1);
  });

  it('resolves a finding when a successful check shows the condition is gone', async () => {
    const s = await seedDomain(t, 'example.com');
    await evaluateJob(t.db, await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn)), clock, [
      dmarcRule,
    ]);
    const job2 = await seedJob(t, s.domainId, at(2), dnsFor(s.fqdn, { dmarc: true }));
    const r = await evaluateJob(t.db, job2, clock, [dmarcRule]);
    expect(r).toMatchObject({ resolved: 1 });
    const [f] = await allFindings();
    expect(f).toMatchObject({ status: 'resolved', resolvedAt: at(2), lastSeenAt: at(1) });
    expect((await historyOf(f!.id)).map((x) => [x.fromStatus, x.toStatus, x.reason])).toEqual([
      [null, 'open', 'detected'],
      ['open', 'resolved', 'condition_absent'],
    ]);
  });

  it('never evaluates failed or cancelled jobs, so they cannot resolve findings', async () => {
    const s = await seedDomain(t, 'example.com');
    await evaluateJob(t.db, await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn)), clock, [
      dmarcRule,
    ]);
    // Both carry evidence that DMARC exists, but the jobs did not succeed.
    const failed = await seedJob(t, s.domainId, at(2), dnsFor(s.fqdn, { dmarc: true }), 'failed');
    const cancelled = await seedJob(
      t,
      s.domainId,
      at(3),
      dnsFor(s.fqdn, { dmarc: true }),
      'cancelled',
    );
    expect((await evaluateJob(t.db, failed, clock, [dmarcRule])).status).toBe('not_eligible');
    expect((await evaluateJob(t.db, cancelled, clock, [dmarcRule])).status).toBe('not_eligible');
    expect(await evaluatePendingJobs(t.db, clock, { rules: [dmarcRule] })).toBe(0);
    expect((await allFindings())[0]!.status).toBe('open');
    expect((await jobRow(failed)).rulesEvaluatedAt).toBeNull();
  });

  it('leaves an existing finding untouched when the rule lacks successful evidence', async () => {
    const s = await seedDomain(t, 'example.com');
    await evaluateJob(t.db, await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn)), clock, [
      dmarcRule,
    ]);
    // The DMARC lookup timed out and no other DNS observation succeeded: the rule is skipped.
    const job2 = await seedJob(t, s.domainId, at(2), [
      { hostname: `_dmarc.${s.fqdn}`, recordType: 'TXT', values: [], status: 'timeout' },
    ]);
    const r = await evaluateJob(t.db, job2, clock, [dmarcRule]);
    expect(r).toMatchObject({ status: 'evaluated', skippedRules: 1, resolved: 0, refreshed: 0 });
    const [f] = await allFindings();
    expect(f).toMatchObject({ status: 'open', lastSeenAt: at(1) });

    // Partial evidence for DMARC while other DNS succeeded: the rule runs but neither raises nor
    // resolves (it does not list the component as checked).
    const job3 = await seedJob(t, s.domainId, at(3), dnsFor(s.fqdn, { dmarcStatus: 'partial' }));
    const r3 = await evaluateJob(t.db, job3, clock, [dmarcRule]);
    expect(r3).toMatchObject({ skippedRules: 0, resolved: 0, refreshed: 0 });
    expect((await allFindings())[0]).toMatchObject({ status: 'open', lastSeenAt: at(1) });
  });

  it('reopens the same finding on recurrence', async () => {
    const s = await seedDomain(t, 'example.com');
    const rules = [dmarcRule];
    await evaluateJob(t.db, await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn)), clock, rules);
    await evaluateJob(
      t.db,
      await seedJob(t, s.domainId, at(2), dnsFor(s.fqdn, { dmarc: true })),
      clock,
      rules,
    );
    const job3 = await seedJob(t, s.domainId, at(3), dnsFor(s.fqdn));
    const r = await evaluateJob(t.db, job3, new Date(clock.getTime() + 1000), rules);
    expect(r).toMatchObject({ reopened: 1, created: 0 });
    const rows = await allFindings();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      status: 'open',
      resolvedAt: null,
      recurrenceCount: 1,
      firstSeenAt: at(1),
      lastSeenAt: at(3),
    });
    const history = await historyOf(rows[0]!.id);
    expect(history.map((x) => x.reason)).toEqual(['detected', 'condition_absent', 'recurrence']);
    expect(history[2]).toMatchObject({ fromStatus: 'resolved', toStatus: 'open', scanJobId: job3 });
  });

  it('keeps triage status (accepted risk) when refreshing, and resolves it when the condition is gone', async () => {
    const s = await seedDomain(t, 'example.com');
    const admin = await ensureUser(t, 'admin');
    await evaluateJob(t.db, await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn)), clock, [
      dmarcRule,
    ]);
    await t.db.update(schema.findings).set({
      status: 'accepted_risk',
      acceptedRiskReason: 'Mail is not used on this domain',
      acceptedRiskApprovedBy: admin,
      acceptedRiskReviewAt: new Date('2027-01-01T00:00:00Z'),
    });
    await evaluateJob(t.db, await seedJob(t, s.domainId, at(2), dnsFor(s.fqdn)), clock, [
      dmarcRule,
    ]);
    expect((await allFindings())[0]).toMatchObject({ status: 'accepted_risk', lastSeenAt: at(2) });

    await evaluateJob(
      t.db,
      await seedJob(t, s.domainId, at(3), dnsFor(s.fqdn, { dmarc: true })),
      clock,
      [dmarcRule],
    );
    const [f] = await allFindings();
    expect(f!.status).toBe('resolved');
    expect((await historyOf(f!.id)).at(-1)).toMatchObject({
      fromStatus: 'accepted_risk',
      toStatus: 'resolved',
      reason: 'condition_absent',
    });
  });

  it('links findings to the asset whose hostname they concern', async () => {
    const s = await seedDomain(t, 'example.com');
    await evaluateJob(
      t.db,
      await seedJob(
        t,
        s.domainId,
        at(1),
        dnsFor(s.fqdn, { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] }),
      ),
      clock,
      [hostRule],
    );
    const rows = await t.db.select().from(schema.findings).orderBy(asc(schema.findings.hostname));
    expect(rows.map((r) => [r.hostname, r.assetId, r.category])).toEqual([
      ['example.com', null, 'exposure'],
      ['www.example.com', s.wwwAssetId, 'exposure'],
    ]);
  });

  it('builds the previous set from the latest successful observation of earlier jobs', async () => {
    const s = await seedDomain(t, 'example.com');
    const a = (values: string[], status: 'success' | 'error' = 'success') => [
      { hostname: s.fqdn, recordType: 'A', values, status },
      { hostname: `_dmarc.${s.fqdn}`, recordType: 'TXT', values: [] },
    ];
    const job1 = await seedJob(t, s.domainId, at(1), a(['192.0.2.1']));
    await seedJob(t, s.domainId, at(2), a([], 'error')); // failed lookup: not a known-good state
    const job3 = await seedJob(t, s.domainId, at(3), a(['192.0.2.3']));
    const job4 = await seedJob(t, s.domainId, at(4), a(['192.0.2.4'])); // later: never "previous"

    // Oldest first: job1 has no previous (no finding), job2 has no successful A, job3 compares with
    // job1 (the latest earlier SUCCESS), then job4 compares with job3.
    expect(await evaluatePendingJobs(t.db, clock, { limit: 3, rules: [aChangeRule] })).toBe(3);
    let [f] = await allFindings();
    expect(f!.evidence).toEqual({
      previous: ['192.0.2.1'],
      current: ['192.0.2.3'],
      previousJob: job1,
    });

    expect(await evaluatePendingJobs(t.db, clock, { rules: [aChangeRule] })).toBe(1);
    [f] = await allFindings();
    expect(f!.evidence).toMatchObject({ previous: ['192.0.2.3'], current: ['192.0.2.4'] });
    expect((await jobRow(job4)).rulesEvaluatedAt).not.toBeNull();
    expect((await jobRow(job3)).rulesEvaluatedAt).not.toBeNull();
  });

  it('defers a job while an earlier succeeded job of the domain is unevaluated', async () => {
    const s = await seedDomain(t, 'example.com');
    const job1 = await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn));
    const job2 = await seedJob(t, s.domainId, at(2), dnsFor(s.fqdn, { dmarc: true }));
    expect((await evaluateJob(t.db, job2, clock, FAKE_RULES)).status).toBe('deferred');
    expect((await jobRow(job2)).rulesEvaluatedAt).toBeNull();
    expect(await allFindings()).toHaveLength(0);

    // Other domains are independent.
    const other = await seedDomain(t, 'example.net');
    const otherJob = await seedJob(t, other.domainId, at(5), dnsFor(other.fqdn));
    expect((await evaluateJob(t.db, otherJob, clock, FAKE_RULES)).status).toBe('evaluated');

    expect(await evaluatePendingJobs(t.db, clock, { rules: FAKE_RULES })).toBe(2);
    expect((await jobRow(job1)).rulesEvaluatedAt).not.toBeNull();
    const dmarc = (await allFindings()).find((f) => f.domainId === s.domainId);
    expect(dmarc).toMatchObject({ ruleId: 'TST-DMARC', status: 'resolved' });
  });

  it('runs as a maintenance step', async () => {
    const s = await seedDomain(t, 'example.com');
    const job = await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn));
    await runMaintenance(t.db, clock, createLogger({ test: true }));
    expect((await jobRow(job)).rulesEvaluatedAt).toEqual(clock);
  });
});

describe('evaluation after a results submission', () => {
  it('evaluates the job in waitUntil on a separate connection when it succeeds', async () => {
    const [d] = await t.db.insert(schema.domains).values({ fqdn: 'example.com' }).returning();
    const key = await generateWorkerKey();
    const reg = await userCall(h, t, 'admin', 'POST', '/workers', {
      name: 'eval-worker',
      publicKey: key.publicKey,
    });
    const keyId = workerCredentialCreatedResponseSchema.parse(await reg.json()).credentialId;
    const w = { key, keyId };
    expect(
      (
        await userCall(h, t, 'analyst', 'POST', `/domains/${d!.id}/scans`, {
          profile: 'passive',
        })
      ).status,
    ).toBe(202);
    const claim = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock });
    const job = claimResponseSchema.parse(await claim.json()).job!;

    const path = '/api/v1/internal/worker/results';
    const body = JSON.stringify({
      jobId: job.id,
      attempt: job.attempt,
      resultId: 'result-final',
      targets: job.targets.map((x) => ({ targetId: x.id, status: 'succeeded' })),
      observations: [],
      complete: true,
    });
    const pending: Promise<unknown>[] = [];
    let connections = 0;
    const app = createApp({
      ...h.deps,
      connect: async () => {
        connections++;
        return { db: t.db, close: async () => {} };
      },
    });
    const res = await app.request(
      path,
      {
        method: 'POST',
        headers: await signedHeaders(w.key, w.keyId, 'POST', path, body, { now: clock }),
        body,
      },
      h.env('viewer') as unknown as Env,
      {
        waitUntil: (p: Promise<unknown>) => void pending.push(p),
        passThroughOnException: () => {},
        props: {},
      } as unknown as ExecutionContext,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ accepted: true, status: 'succeeded' });
    await Promise.all(pending);
    expect(connections).toBe(2); // the request's own connection plus the evaluation's
    expect((await jobRow(job.id)).rulesEvaluatedAt).toEqual(clock);
  });
});
