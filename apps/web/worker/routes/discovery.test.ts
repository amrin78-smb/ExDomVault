// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  claimResponseSchema,
  discoveryRequestResponseSchema,
  errorResponseSchema,
  scanJobDetailResponseSchema,
  scanProfileListResponseSchema,
  workerCredentialCreatedResponseSchema,
  type ClaimedJob,
  type Role,
} from '@exdomainvault/shared';
import { and, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateJob } from '../services/evaluation.ts';
import {
  DISCOVERY_PRIORITY,
  DISCOVERY_SCHEDULE_BATCH,
  scheduleDiscovery,
} from '../services/maintenance.ts';
import {
  generateWorkerKey,
  harness,
  userCall,
  workerCall,
  type TestWorkerKey,
} from '../testing/harness.ts';

const { assetIps, assets, auditLogs, discoveryObservations, domains, findings, scanJobs } = schema;

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
  await t.db.delete(assets);
  await t.db.delete(domains);
  await t.db.delete(schema.workerRegistry);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function expectError(res: Response, status: number, code: string, path?: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
  if (path) expect(body.error.details?.[0]?.path).toBe(path);
  return body.error;
}

const iso = (offsetSeconds = 0) => new Date(clock.getTime() + offsetSeconds * 1000).toISOString();

let workerSeq = 0;
async function registerWorker() {
  const key = await generateWorkerKey();
  const reg = await call('admin', 'POST', '/workers', {
    name: `disc-${workerSeq++}`,
    publicKey: key.publicKey,
  });
  expect(reg.status).toBe(201);
  return { key, keyId: workerCredentialCreatedResponseSchema.parse(await reg.json()).credentialId };
}

interface Setup {
  w: { key: TestWorkerKey; keyId: string };
  domainId: string;
  job: ClaimedJob;
  apex: string;
}

async function addDomain(fqdn = 'example.com'): Promise<string> {
  const [d] = await t.db.insert(domains).values({ fqdn, monitoringEnabled: true }).returning();
  return d!.id;
}

/** example.com; a discovery job requested through the API and claimed by a fresh worker. */
async function setup(): Promise<Setup> {
  const domainId = await addDomain();
  const w = await registerWorker();
  const res = await call('analyst', 'POST', `/domains/${domainId}/discovery`);
  expect(res.status).toBe(201);
  discoveryRequestResponseSchema.parse(await res.json());
  const claimed = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock });
  const job = claimResponseSchema.parse(await claimed.json()).job!;
  expect(job.profile).toBe('discovery');
  expect(job.targets).toHaveLength(1);
  return { w, domainId, job, apex: job.targets[0]!.id };
}

const disc = (
  targetId: string,
  hostname: string,
  over: Partial<{ wildcard: boolean; resultStatus: string; observedAt: string }> = {},
) => ({
  kind: 'discovery',
  targetId,
  observedAt: iso(),
  checkerVersion: '0.1.0',
  resultStatus: 'success',
  evidence: { provider: 'crt.sh', certificates: 1 },
  hostname,
  source: 'certificate_transparency',
  wildcard: false,
  ...over,
});

const dns = (
  targetId: string,
  hostname: string,
  recordType: string,
  values: string[],
  over: Partial<{ resultStatus: string; observedAt: string }> = {},
) => ({
  kind: 'dns',
  targetId,
  observedAt: iso(),
  checkerVersion: '0.1.0',
  resultStatus: 'success',
  evidence: {},
  hostname,
  recordType,
  ttl: 300,
  values,
  ...over,
});

const submit = (
  s: Pick<Setup, 'w' | 'job'>,
  resultId: string,
  observations: unknown[],
  complete = false,
) =>
  workerCall(
    h,
    s.w.key,
    s.w.keyId,
    'results',
    { jobId: s.job.id, attempt: s.job.attempt, resultId, targets: [], observations, complete },
    { now: clock },
  );

const assetRows = async () =>
  (await t.db.select().from(assets)).sort((a, b) => (a.hostname < b.hostname ? -1 : 1));

describe('discovery ingestion', () => {
  it('stores candidates as pending assets, deduplicated, and records each sighting', async () => {
    const s = await setup();
    const res = await submit(s, 'result-0001', [
      disc(s.apex, 'www.example.com'),
      disc(s.apex, 'www.example.com', { observedAt: iso(30) }),
      disc(s.apex, 'api.example.com', { wildcard: true }),
      disc(s.apex, 'example.com'),
    ]);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: true, status: 'running' });

    const rows = await assetRows();
    expect(
      rows.map((a) => [a.hostname, a.assetType, a.verificationStatus, a.wildcardOnly]),
    ).toEqual([
      ['api.example.com', 'subdomain', 'pending', true],
      ['example.com', 'apex', 'pending', false],
      ['www.example.com', 'subdomain', 'pending', false],
    ]);
    const www = rows.find((a) => a.hostname === 'www.example.com')!;
    expect(www).toMatchObject({
      discoverySource: 'certificate_transparency',
      monitoringEnabled: false,
      firstSeenAt: clock,
      lastSeenAt: new Date(iso(30)),
    });
    const sightings = await t.db.select().from(discoveryObservations);
    expect(sightings).toHaveLength(4);
    expect(sightings.filter((o) => o.assetId === www.id)).toHaveLength(2);
    expect(sightings.every((o) => o.domainId === s.domainId && o.checker === 'discovery')).toBe(
      true,
    );

    // A duplicate delivery changes nothing.
    const again = await submit(s, 'result-0001', [disc(s.apex, 'new.example.com')]);
    expect(await again.json()).toEqual({ accepted: false, status: 'running' });
    expect(await assetRows()).toHaveLength(3);
  });

  it('only advances last seen and narrows wildcard-only; never changes the approval status', async () => {
    const s = await setup();
    const admin = (await t.db.select().from(schema.users))[0]!.id;
    await t.db.insert(assets).values([
      {
        domainId: s.domainId,
        hostname: 'old.example.com',
        assetType: 'subdomain',
        discoverySource: 'manual',
        verificationStatus: 'rejected',
        firstSeenAt: new Date('2026-01-01T00:00:00Z'),
        lastSeenAt: new Date('2026-10-23T00:00:00Z'), // later than this sighting
      },
      {
        domainId: s.domainId,
        hostname: 'app.example.com',
        assetType: 'subdomain',
        discoverySource: 'dns',
        verificationStatus: 'approved',
        approvedBy: admin,
        approvedAt: clock,
        monitoringEnabled: true,
        wildcardOnly: true,
        firstSeenAt: new Date('2026-01-01T00:00:00Z'),
        lastSeenAt: new Date('2026-01-01T00:00:00Z'),
      },
    ]);
    await submit(s, 'result-0001', [
      disc(s.apex, 'old.example.com'),
      disc(s.apex, 'app.example.com', { wildcard: true }),
    ]);
    let rows = await assetRows();
    expect(
      rows.map((a) => [a.hostname, a.verificationStatus, a.wildcardOnly, a.discoverySource]),
    ).toEqual([
      ['app.example.com', 'approved', true, 'dns'],
      ['old.example.com', 'rejected', false, 'manual'],
    ]);
    expect(rows[0]!.lastSeenAt).toEqual(clock);
    expect(rows[0]!.firstSeenAt).toEqual(new Date('2026-01-01T00:00:00Z'));
    expect(rows[1]!.lastSeenAt).toEqual(new Date('2026-10-23T00:00:00Z')); // never moves back
    expect(rows[0]!.monitoringEnabled).toBe(true);

    // A non-wildcard sighting clears wildcard-only for good.
    await submit(s, 'result-0002', [disc(s.apex, 'app.example.com', { wildcard: false })]);
    await submit(s, 'result-0003', [disc(s.apex, 'app.example.com', { wildcard: true })]);
    rows = await assetRows();
    expect(rows[0]!.wildcardOnly).toBe(false);
  });

  it('stores failed or partial runs as evidence only', async () => {
    const s = await setup();
    const res = await submit(
      s,
      'result-0001',
      [
        disc(s.apex, 'example.com', { resultStatus: 'error' }),
        disc(s.apex, 'partial.example.com', { resultStatus: 'partial' }),
      ],
      true,
    );
    expect(res.status).toBe(200);
    expect(await assetRows()).toHaveLength(0);
    const stored = await t.db.select().from(discoveryObservations);
    expect(stored.map((o) => [o.hostname, o.resultStatus, o.assetId])).toEqual(
      expect.arrayContaining([
        ['example.com', 'error', null],
        ['partial.example.com', 'partial', null],
      ]),
    );
  });

  it.each([
    'evil-example.com',
    'example.com.evil.net',
    'wwwexample.com',
    'example.co',
    'xn--exmple-cua.com',
  ])('rejects %s (outside the label boundary) and stores nothing', async (hostname) => {
    const s = await setup();
    const res = await submit(s, 'result-0001', [
      disc(s.apex, 'ok.example.com'),
      disc(s.apex, hostname),
    ]);
    await expectError(res, 400, 'validation_failed', 'observations.1.hostname');
    expect(await assetRows()).toHaveLength(0);
    expect(await t.db.select().from(discoveryObservations)).toHaveLength(0);
  });

  it('rejects malformed hostnames by schema', async () => {
    const s = await setup();
    const malformed = [
      '*.example.com',
      'Example.com',
      'www.example.com.',
      '-a.example.com',
      'a..example.com',
    ];
    for (const [n, bad] of malformed.entries()) {
      const res = await submit(s, `result-bad-${n}`, [disc(s.apex, bad)]);
      await expectError(res, 400, 'validation_failed', 'observations.0.hostname');
    }
    expect(await assetRows()).toHaveLength(0);
  });

  it('refuses discovery observations for jobs that are not discovery jobs', async () => {
    const domainId = await addDomain();
    const w = await registerWorker();
    const res = await call('analyst', 'POST', `/domains/${domainId}/scans`, { profile: 'passive' });
    expect(res.status).toBe(202);
    const claimed = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock });
    const job = claimResponseSchema.parse(await claimed.json()).job!;
    const out = await submit({ w, job }, 'result-0001', [
      disc(job.targets[0]!.id, 'www.example.com'),
    ]);
    await expectError(out, 400, 'validation_failed', 'observations.0.kind');
    expect(await assetRows()).toHaveLength(0);
  });
});

describe('DNS observations update the inventory', () => {
  it('keeps the latest answer current per address family and clears on an empty answer', async () => {
    const s = await setup();
    await submit(s, 'result-0001', [
      disc(s.apex, 'www.example.com'),
      dns(s.apex, 'www.example.com', 'A', ['192.0.2.10', '192.0.2.11']),
      dns(s.apex, 'www.example.com', 'AAAA', ['2001:db8::1']),
      // Not an asset: ignored.
      dns(s.apex, 'other.example.com', 'A', ['192.0.2.99']),
    ]);
    const ipsOf = async () =>
      (await t.db.select().from(assetIps))
        .map((r) => [r.ipAddress, r.isCurrent, r.source] as const)
        .sort((a, b) => (a[0] < b[0] ? -1 : 1));
    expect(await ipsOf()).toEqual([
      ['192.0.2.10', true, 'dns'],
      ['192.0.2.11', true, 'dns'],
      ['2001:db8::1', true, 'dns'],
    ]);

    // A newer A answer replaces the IPv4 set; IPv6 is untouched.
    await submit(s, 'result-0002', [
      dns(s.apex, 'www.example.com', 'A', ['192.0.2.11', '192.0.2.12'], { observedAt: iso(60) }),
    ]);
    expect(await ipsOf()).toEqual([
      ['192.0.2.10', false, 'dns'],
      ['192.0.2.11', true, 'dns'],
      ['192.0.2.12', true, 'dns'],
      ['2001:db8::1', true, 'dns'],
    ]);

    // An older, out-of-order answer revives nothing.
    await submit(s, 'result-0003', [
      dns(s.apex, 'www.example.com', 'A', ['192.0.2.10'], { observedAt: iso(10) }),
    ]);
    expect((await ipsOf())[0]).toEqual(['192.0.2.10', false, 'dns']);

    // Failed lookups change nothing; an empty successful answer leaves none current.
    await submit(s, 'result-0004', [
      dns(s.apex, 'www.example.com', 'AAAA', [], { resultStatus: 'error', observedAt: iso(120) }),
      dns(s.apex, 'www.example.com', 'A', [], { observedAt: iso(120) }),
    ]);
    expect((await ipsOf()).filter((r) => r[1])).toEqual([['2001:db8::1', true, 'dns']]);
  });

  it('derives the hosting hint from CNAME answers', async () => {
    const s = await setup();
    await submit(s, 'result-0001', [
      disc(s.apex, 'cdn.example.com'),
      disc(s.apex, 'plain.example.com'),
      dns(s.apex, 'cdn.example.com', 'CNAME', ['d111.cloudfront.net.']),
      dns(s.apex, 'plain.example.com', 'CNAME', ['host.example.org.']),
    ]);
    const hint = async (h: string) =>
      (await t.db.select().from(assets).where(eq(assets.hostname, h)))[0]!.hostingHint;
    expect(await hint('cdn.example.com')).toEqual({
      provider: 'Amazon CloudFront',
      kind: 'cdn',
      matchedName: 'd111.cloudfront.net',
    });
    expect(await hint('plain.example.com')).toBeNull();

    // No CNAME observation: unchanged. Empty CNAME answer: cleared.
    await submit(s, 'result-0002', [dns(s.apex, 'cdn.example.com', 'A', ['192.0.2.1'])]);
    expect(await hint('cdn.example.com')).not.toBeNull();
    await submit(s, 'result-0003', [dns(s.apex, 'cdn.example.com', 'CNAME', [])]);
    expect(await hint('cdn.example.com')).toBeNull();
  });
});

describe('POST /domains/:id/discovery', () => {
  it('queues one passive discovery job for the apex and reuses it while queued', async () => {
    const domainId = await addDomain();
    const first = await call('analyst', 'POST', `/domains/${domainId}/discovery`);
    expect(first.status).toBe(201);
    const body = discoveryRequestResponseSchema.parse(await first.json());
    expect(body.created).toBe(true);
    const detail = scanJobDetailResponseSchema.parse(
      await (await call('viewer', 'GET', `/scans/${body.scanJobId}`)).json(),
    );
    expect(detail.job).toMatchObject({ jobType: 'discovery', profile: 'discovery' });
    expect(detail.targets.map((x) => [x.hostname, x.assetId])).toEqual([['example.com', null]]);
    expect(detail.scopeSnapshot.profile.config.active).toBe(false);

    const second = await call('admin', 'POST', `/domains/${domainId}/discovery`);
    expect(second.status).toBe(200);
    expect(discoveryRequestResponseSchema.parse(await second.json())).toEqual({
      scanJobId: body.scanJobId,
      created: false,
    });
    const audit = await t.db.select().from(auditLogs).where(eq(auditLogs.action, 'scan.requested'));
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({ jobType: 'discovery', profile: 'discovery' });
  });

  it('needs scans:request and an existing domain', async () => {
    const domainId = await addDomain();
    for (const role of ['viewer', 'asset_owner'] as const) {
      await expectError(
        await call(role, 'POST', `/domains/${domainId}/discovery`),
        403,
        'forbidden',
      );
    }
    await expectError(
      await call('analyst', 'POST', '/domains/00000000-0000-4000-8000-000000000000/discovery'),
      404,
      'not_found',
    );
  });

  it('is refused by the scans endpoint and not listed as a scan profile', async () => {
    const domainId = await addDomain();
    await expectError(
      await call('analyst', 'POST', `/domains/${domainId}/scans`, { profile: 'discovery' }),
      400,
      'validation_failed',
      'profile',
    );
    const profiles = scanProfileListResponseSchema.parse(
      await (await call('viewer', 'GET', '/scan-profiles')).json(),
    );
    expect(profiles.items.map((p) => p.key)).not.toContain('discovery');
  });
});

describe('weekly discovery scheduling', () => {
  it('schedules due monitored domains at low priority, at most weekly, without duplicates', async () => {
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) ids.push(await addDomain(`d${i}.example.com`));
    await t.db.insert(domains).values({ fqdn: 'off.example.com', monitoringEnabled: false });
    const week = 7 * 86_400_000;
    const oldAt = new Date(clock.getTime() - week - 60_000);
    // Without history, a domain waits for its slot in the week: a full sweep over a week schedules
    // each exactly once.
    let total = 0;
    const start = clock;
    for (let hour = 0; hour < 7 * 24; hour++) {
      clock = new Date(start.getTime() + hour * 3600_000);
      total += await scheduleDiscovery(t.db, clock);
    }
    expect(total).toBe(5);
    const jobs = await t.db.select().from(scanJobs);
    expect(jobs).toHaveLength(5);
    expect(new Set(jobs.map((j) => j.domainId))).toEqual(new Set(ids));
    expect(jobs.every((j) => j.jobType === 'discovery' && j.priority === DISCOVERY_PRIORITY)).toBe(
      true,
    );
    // Spread out: not all created in the same hour (5 independent slots over a week).
    expect(new Set(jobs.map((j) => j.createdAt.getTime())).size).toBeGreaterThan(1);

    // Finished jobs recur after a week, not before.
    await t.db.update(scanJobs).set({ status: 'succeeded', completedAt: clock, createdAt: oldAt });
    clock = new Date(start.getTime());
    expect(await scheduleDiscovery(t.db, clock)).toBe(5);
    expect(await scheduleDiscovery(t.db, clock)).toBe(0); // queued: no duplicate
    await t.db
      .update(scanJobs)
      .set({ status: 'succeeded', completedAt: clock })
      .where(eq(scanJobs.status, 'queued'));
    clock = new Date(start.getTime() + 6 * 86_400_000);
    expect(await scheduleDiscovery(t.db, clock)).toBe(0); // within the week
  });

  it('caps the number of jobs per run', async () => {
    const week = 7 * 86_400_000;
    const n = DISCOVERY_SCHEDULE_BATCH + 5;
    const rows = await t.db
      .insert(domains)
      .values(
        Array.from({ length: n }, (_, i) => ({
          fqdn: `c${i}.example.com`,
          monitoringEnabled: true,
        })),
      )
      .returning({ id: domains.id, fqdn: domains.fqdn });
    // Each has an old finished discovery job, so all are due now regardless of slot.
    const snapshot = { version: 1 };
    await t.db.insert(scanJobs).values(
      rows.map((d) => ({
        jobType: 'discovery' as const,
        profile: 'discovery',
        domainId: d.id,
        status: 'succeeded' as const,
        scopeSnapshot: snapshot,
        createdAt: new Date(clock.getTime() - week - 1000),
        completedAt: new Date(clock.getTime() - week),
      })),
    );
    expect(await scheduleDiscovery(t.db, clock)).toBe(DISCOVERY_SCHEDULE_BATCH);
    expect(await scheduleDiscovery(t.db, clock)).toBe(5);
    expect(await scheduleDiscovery(t.db, clock)).toBe(0);
    const queued = await t.db
      .select()
      .from(scanJobs)
      .where(and(eq(scanJobs.status, 'queued'), eq(scanJobs.jobType, 'discovery')));
    expect(queued).toHaveLength(n);
    const targets = await t.db.select().from(schema.scanJobTargets);
    expect(targets.every((x) => x.assetId === null)).toBe(true);
  });
});

describe('end to end', () => {
  it('a discovery run produces ASSET-001 findings for pending candidates only', async () => {
    const s = await setup();
    const admin = (await t.db.select().from(schema.users))[0]!.id;
    await t.db.insert(assets).values({
      domainId: s.domainId,
      hostname: 'known.example.com',
      assetType: 'subdomain',
      discoverySource: 'manual',
      verificationStatus: 'approved',
      approvedBy: admin,
      approvedAt: clock,
    });
    const res = await submit(
      s,
      'result-0001',
      [disc(s.apex, 'new.example.com'), disc(s.apex, 'known.example.com')],
      true,
    );
    expect(await res.json()).toEqual({ accepted: true, status: 'succeeded' });
    clock = new Date(clock.getTime() + 1000);
    const r = await evaluateJob(t.db, s.job.id, clock);
    expect(r.status).toBe('evaluated');
    const rows = await t.db.select().from(findings);
    expect(rows.map((f) => [f.ruleId, f.hostname, f.status])).toEqual([
      ['ASSET-001', 'new.example.com', 'open'],
    ]);
    const candidate = (await assetRows()).find((a) => a.hostname === 'new.example.com')!;
    expect(rows[0]!.assetId).toBe(candidate.id);
    expect(candidate.verificationStatus).toBe('pending');
  });
});
