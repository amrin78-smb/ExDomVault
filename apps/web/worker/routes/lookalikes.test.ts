// @vitest-environment node
// Milestone 15: lookalike-domain (brand) monitoring — API, scheduling, ingest, LOOK-001 lifecycle.
// Synthetic names only (example.com and its generated variants); nothing is resolved here.
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  claimResponseSchema,
  domainDetailResponseSchema,
  errorResponseSchema,
  generateLookalikes,
  lookalikeCheckResponseSchema,
  lookalikeListResponseSchema,
  scopeSnapshotSchema,
  workerCredentialCreatedResponseSchema,
  type ClaimedJob,
  type Role,
} from '@exdomainvault/shared';
import { and, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateJob } from '../services/evaluation.ts';
import { BRAND_PRIORITY, scheduleBrandMonitoring } from '../services/lookalikes.ts';
import {
  generateWorkerKey,
  harness,
  userCall,
  workerCall,
  type TestWorkerKey,
} from '../testing/harness.ts';

const { auditLogs, domains, findings, lookalikeObservations, scanJobs } = schema;

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
  await t.db.delete(findings);
  await t.db.delete(scanJobs);
  await t.db.delete(domains);
  await t.db.delete(schema.workerRegistry);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function expectError(res: Response, status: number, code: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
  return body.error;
}

const iso = (offsetSeconds = 0) => new Date(clock.getTime() + offsetSeconds * 1000).toISOString();

async function addDomain(fqdn = 'example.com', brandMonitoring = true): Promise<string> {
  const [d] = await t.db.insert(domains).values({ fqdn, brandMonitoring }).returning();
  return d!.id;
}

let workerSeq = 0;
async function registerWorker() {
  const key = await generateWorkerKey();
  const reg = await call('admin', 'POST', '/workers', {
    name: `brand-${workerSeq++}`,
    publicKey: key.publicKey,
  });
  expect(reg.status).toBe(201);
  return { key, keyId: workerCredentialCreatedResponseSchema.parse(await reg.json()).credentialId };
}

interface Run {
  w: { key: TestWorkerKey; keyId: string };
  job: ClaimedJob;
  apex: string;
}

async function requestAndClaim(domainId: string, w?: Run['w']): Promise<Run> {
  const worker = w ?? (await registerWorker());
  const res = await call('analyst', 'POST', `/domains/${domainId}/lookalikes/check`);
  expect(res.status).toBe(201);
  const claimed = await workerCall(h, worker.key, worker.keyId, 'claim', {}, { now: clock });
  const job = claimResponseSchema.parse(await claimed.json()).job!;
  expect(job.profile).toBe('brand');
  return { w: worker, job, apex: job.targets[0]!.id };
}

const look = (
  targetId: string,
  candidate: string,
  technique: string,
  over: Partial<{ registered: boolean; resultStatus: string; records: unknown }> = {},
) => ({
  kind: 'lookalike',
  targetId,
  observedAt: iso(),
  checkerVersion: '0.1.0',
  resultStatus: 'success',
  evidence: { queries: 4 },
  candidate,
  technique,
  registered: true,
  records: { NS: ['ns1.parking.example.net.'], MX: ['10 mx.example.org.'] },
  ...over,
});

const submit = (
  r: Run,
  resultId: string,
  observations: unknown[],
  opts: { complete?: boolean; targetStatus?: string; errorCode?: string } = {},
) =>
  workerCall(
    h,
    r.w.key,
    r.w.keyId,
    'results',
    {
      jobId: r.job.id,
      attempt: r.job.attempt,
      resultId,
      targets: opts.targetStatus
        ? [
            {
              targetId: r.apex,
              status: opts.targetStatus,
              ...(opts.errorCode ? { errorCode: opts.errorCode } : {}),
            },
          ]
        : [],
      observations,
      complete: opts.complete ?? false,
    },
    { now: clock },
  );

const listLookalikes = async (query = '') => {
  const res = await call('viewer', 'GET', `/lookalikes${query}`);
  expect(res.status).toBe(200);
  return lookalikeListResponseSchema.parse(await res.json());
};

describe('brand monitoring switch', () => {
  it('is off by default, admin-only to change, and audited', async () => {
    const [d] = await t.db.insert(domains).values({ fqdn: 'example.com' }).returning();
    const get = await call('viewer', 'GET', `/domains/${d!.id}`);
    expect(domainDetailResponseSchema.parse(await get.json()).domain.brandMonitoring).toBe(false);

    await expectError(
      await call('analyst', 'PATCH', `/domains/${d!.id}`, { brandMonitoring: true }),
      403,
      'forbidden',
    );
    const on = await call('admin', 'PATCH', `/domains/${d!.id}`, { brandMonitoring: true });
    expect(on.status).toBe(200);
    expect(domainDetailResponseSchema.parse(await on.json()).domain.brandMonitoring).toBe(true);
    const audits = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'domain.brand_monitoring_enabled'));
    expect(audits).toHaveLength(1);
    expect(audits[0]!.metadata).toMatchObject({ fqdn: 'example.com' });

    await call('admin', 'PATCH', `/domains/${d!.id}`, { brandMonitoring: false });
    const off = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'domain.brand_monitoring_disabled'));
    expect(off).toHaveLength(1);
  });
});

describe('POST /domains/:id/lookalikes/check', () => {
  it('refuses while brand monitoring is off', async () => {
    const id = await addDomain('example.com', false);
    await expectError(
      await call('analyst', 'POST', `/domains/${id}/lookalikes/check`),
      409,
      'conflict',
    );
    await expectError(
      await call('analyst', 'POST', `/domains/${crypto.randomUUID()}/lookalikes/check`),
      404,
      'not_found',
    );
  });

  it('queues one passive brand job with the server-generated candidates, excluding our own domains', async () => {
    const id = await addDomain('example.com');
    await addDomain('example.net', false); // ours: never a lookalike candidate
    const res = await call('analyst', 'POST', `/domains/${id}/lookalikes/check`);
    expect(res.status).toBe(201);
    const body = lookalikeCheckResponseSchema.parse(await res.json());
    expect(body.created).toBe(true);

    const [job] = await t.db.select().from(scanJobs).where(eq(scanJobs.id, body.scanJobId));
    expect(job).toMatchObject({ profile: 'brand', jobType: 'scan', status: 'queued' });
    const snap = scopeSnapshotSchema.parse(job!.scopeSnapshot);
    expect(snap.profile.config).toMatchObject({ active: false, checks: ['lookalike'] });
    expect(snap.targets).toEqual([{ assetId: null, hostname: 'example.com' }]);
    const names = snap.lookalike!.candidates.map((c) => c.candidate);
    expect(names).toContain('exmple.com');
    expect(names).not.toContain('example.net');
    expect(snap.lookalike!.candidates).toEqual(
      generateLookalikes('example.com', { suffix: 'com', exclude: ['example.com', 'example.net'] }),
    );

    // A second request returns the queued job.
    const again = await call('analyst', 'POST', `/domains/${id}/lookalikes/check`);
    expect(again.status).toBe(200);
    expect(lookalikeCheckResponseSchema.parse(await again.json())).toEqual({
      scanJobId: body.scanJobId,
      created: false,
    });
    const audit = await t.db
      .select()
      .from(auditLogs)
      .where(and(eq(auditLogs.action, 'scan.requested'), eq(auditLogs.resourceId, body.scanJobId)));
    expect(audit[0]!.metadata).toMatchObject({ profile: 'brand', active: false });
  });

  it('the brand profile cannot be requested as an ordinary scan', async () => {
    const id = await addDomain('example.com');
    await expectError(
      await call('analyst', 'POST', `/domains/${id}/scans`, { profile: 'brand' }),
      400,
      'validation_failed',
    );
  });
});

describe('weekly scheduler', () => {
  it('schedules only domains with brand monitoring on, staggered, idempotent', async () => {
    const on = await addDomain('example.com', true);
    await addDomain('example.org', false);
    // Run at many points of the week, ending at the last second of a weekly cycle (every slot is
    // due by then): the domain gets exactly one job, when its slot comes.
    const WEEK_S = 7 * 86_400;
    const start = Date.parse('2026-10-22T10:00:00.000Z');
    const cycleEnd = (Math.floor(start / 1000 / WEEK_S) + 1) * WEEK_S - 1;
    const times = [
      ...Array.from({ length: 7 }, (_, day) => start + day * 86_400_000),
      cycleEnd * 1000,
    ].sort((a, b) => a - b);
    let created = 0;
    for (const at of times) {
      clock = new Date(at);
      created += await scheduleBrandMonitoring(t.db, clock);
    }
    expect(created).toBe(1);
    const jobs = await t.db.select().from(scanJobs);
    expect(jobs).toHaveLength(1);
    expect(jobs[0]).toMatchObject({ domainId: on, profile: 'brand', priority: BRAND_PRIORITY });
    expect(
      scopeSnapshotSchema.parse(jobs[0]!.scopeSnapshot).lookalike!.candidates.length,
    ).toBeGreaterThan(100);
    // Queued already: nothing more.
    expect(await scheduleBrandMonitoring(t.db, clock)).toBe(0);
  });

  it('does nothing when the brand profile is disabled', async () => {
    await addDomain('example.com', true);
    await t.db
      .update(schema.scanProfiles)
      .set({ enabled: false })
      .where(eq(schema.scanProfiles.key, 'brand'));
    try {
      clock = new Date('2026-10-30T10:00:00.000Z');
      expect(await scheduleBrandMonitoring(t.db, clock)).toBe(0);
    } finally {
      await t.db
        .update(schema.scanProfiles)
        .set({ enabled: true })
        .where(eq(schema.scanProfiles.key, 'brand'));
    }
  });
});

describe('lookalike ingestion', () => {
  it('stores candidates from the job list with the listed technique', async () => {
    const id = await addDomain();
    const r = await requestAndClaim(id);
    const res = await submit(r, 'result-0001', [look(r.apex, 'exmple.com', 'omission')]);
    expect(res.status).toBe(200);
    const rows = await t.db.select().from(lookalikeObservations);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      domainId: id,
      candidate: 'exmple.com',
      technique: 'omission',
      registered: true,
      checker: 'lookalike',
      records: { NS: ['ns1.parking.example.net.'], MX: ['10 mx.example.org.'] },
    });
  });

  it.each([
    ['a name not in the job list', 'not-listed.example.org', 'omission', 'candidate'],
    ['a wrong technique', 'exmple.com', 'homoglyph', 'technique'],
    ['the job domain itself', 'www.example.com', 'omission', 'candidate'],
  ])('rejects %s', async (_label, candidate, technique, field) => {
    const id = await addDomain();
    const r = await requestAndClaim(id);
    const err = await expectError(
      await submit(r, 'result-0001', [look(r.apex, candidate, technique)]),
      400,
      'validation_failed',
    );
    expect(err.details?.[0]?.path).toBe(`observations.0.${field}`);
    expect(await t.db.select().from(lookalikeObservations)).toHaveLength(0);
  });

  it('rejects a candidate that has since become one of our monitored domains', async () => {
    const id = await addDomain();
    const r = await requestAndClaim(id);
    await addDomain('exmple.com', false); // added after the job was created
    const err = await expectError(
      await submit(r, 'result-0001', [look(r.apex, 'exmple.com', 'omission')]),
      400,
      'validation_failed',
    );
    expect(err.details?.[0]?.message).toMatch(/our monitored domains/);
  });

  it('rejects lookalike observations from a non-brand job', async () => {
    const id = await addDomain();
    const w = await registerWorker();
    await call('analyst', 'POST', `/domains/${id}/scans`, { profile: 'passive' });
    const claimed = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock });
    const job = claimResponseSchema.parse(await claimed.json()).job!;
    const r: Run = { w, job, apex: job.targets[0]!.id };
    await expectError(
      await submit(r, 'result-0001', [look(r.apex, 'exmple.com', 'omission')]),
      400,
      'validation_failed',
    );
  });
});

describe('LOOK-001 lifecycle and GET /lookalikes', () => {
  async function completeRun(
    domainId: string,
    obs: (apex: string) => unknown[],
    targetStatus = 'succeeded',
    w?: Run['w'],
  ) {
    const r = await requestAndClaim(domainId, w);
    const res = await submit(r, `r-${r.job.id}`, obs(r.apex), {
      complete: true,
      targetStatus,
      ...(targetStatus === 'failed' ? { errorCode: 'target_timeout' } : {}),
    });
    expect(res.status).toBe(200);
    const ev = await evaluateJob(t.db, r.job.id, clock);
    expect(ev.status).toBe('evaluated');
    return r;
  }

  const look001 = () => t.db.select().from(findings).where(eq(findings.ruleId, 'LOOK-001'));

  it('raises, keeps through incomplete runs, and resolves only on a complete run', async () => {
    const id = await addDomain();
    const first = await completeRun(id, (apex) => [
      look(apex, 'exmple.com', 'omission'),
      look(apex, 'exampel.com', 'transposition', { records: { NS: ['ns.example.net.'] } }),
    ]);
    let rows = await look001();
    expect(rows.map((f) => [f.component, f.severity, f.status]).sort()).toEqual([
      ['exampel.com', 'informational', 'open'],
      ['exmple.com', 'medium', 'open'],
    ]);
    expect(rows[0]!.hostname).toBe('example.com');
    expect(rows[0]!.category).toBe('asset');

    let list = await listLookalikes();
    expect(list.summary).toMatchObject({
      domainsMonitored: 1,
      registered: 2,
      withMail: 1,
      newThisWeek: 2,
    });
    expect(list.summary.candidatesChecked).toBeGreaterThan(100);
    expect(list.items[0]).toMatchObject({
      candidate: 'exmple.com',
      state: 'registered',
      hasMail: true,
      finding: { severity: 'medium', status: 'open' },
    });

    // Incomplete run (time budget exhausted) that no longer sees exmple.com: nothing resolves.
    clock = new Date(clock.getTime() + 7 * 86_400_000);
    await completeRun(
      id,
      (apex) => [look(apex, 'exampel.com', 'transposition')],
      'failed',
      first.w,
    );
    rows = await look001();
    expect(rows.every((f) => f.status === 'open')).toBe(true);
    list = await listLookalikes();
    expect(list.items.find((i) => i.candidate === 'exmple.com')?.state).toBe('registered');

    // Complete run where exmple.com failed to resolve: still not resolved.
    clock = new Date(clock.getTime() + 7 * 86_400_000);
    await completeRun(
      id,
      (apex) => [
        look(apex, 'exampel.com', 'transposition'),
        look(apex, 'exmple.com', 'omission', {
          registered: false,
          resultStatus: 'error',
          records: {},
        }),
      ],
      'succeeded',
      first.w,
    );
    expect((await look001()).every((f) => f.status === 'open')).toBe(true);

    // Complete run without it: resolved; the list shows it as gone.
    clock = new Date(clock.getTime() + 7 * 86_400_000);
    await completeRun(
      id,
      (apex) => [look(apex, 'exampel.com', 'transposition')],
      'succeeded',
      first.w,
    );
    rows = await look001();
    expect(rows.find((f) => f.component === 'exmple.com')?.status).toBe('resolved');
    expect(rows.find((f) => f.component === 'exampel.com')?.status).toBe('open');

    list = await listLookalikes();
    expect(list.summary.registered).toBe(1);
    expect(list.summary.newThisWeek).toBe(0);
    const gone = await listLookalikes('?registered=false');
    expect(gone.items.map((i) => [i.candidate, i.state])).toEqual([['exmple.com', 'gone']]);
    expect(gone.items[0]!.finding?.status).toBe('resolved');
    const filtered = await listLookalikes('?q=exampel&technique=transposition');
    expect(filtered.items.map((i) => i.candidate)).toEqual(['exampel.com']);
    expect(filtered.items[0]!.firstSeenAt).toBe('2026-10-22T10:00:00.000Z');
  });

  it('is not visible to asset owners', async () => {
    const res = await call('asset_owner', 'GET', '/lookalikes');
    expect(res.status).toBe(403);
  });
});
