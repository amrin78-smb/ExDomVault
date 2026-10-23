// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { RETENTION_POLICY } from '@exdomainvault/shared';
import { eq, inArray } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createLogger } from '../lib/logger.ts';
import { readOpsState } from './ops.ts';
import { RETENTION_INTERVAL_MS, runRetention } from './retention.ts';

const {
  auditLogs,
  dnsObservations,
  domains,
  findingComments,
  findingStatusHistory,
  findings,
  httpObservations,
  registrationObservations,
  scanJobResults,
  scanJobTargets,
  scanJobs,
  softwareInventory,
} = schema;

const DAY = 86_400_000;
const NOW = new Date('2027-06-01T00:00:00.000Z');
const ago = (days: number) => new Date(NOW.getTime() - days * DAY);
const logger = createLogger({ test: true });

let t: TestDatabase;
let domainId: string;
let seq = 0;

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
  await t.db.delete(findings);
  await t.db.delete(scanJobs);
  await t.db.delete(domains);
  await t.db.delete(schema.applicationSettings);
  await t.db.delete(auditLogs);
  const [d] = await t.db.insert(domains).values({ fqdn: 'retention.example' }).returning();
  domainId = d!.id;
});
afterEach(() => vi.restoreAllMocks());

async function job(
  opts: {
    ageDays?: number;
    status?: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
    evaluated?: boolean;
    profile?: string;
  } = {},
) {
  const created = ago(opts.ageDays ?? 400);
  const status = opts.status ?? 'succeeded';
  const finished = !['queued', 'running'].includes(status);
  const [row] = await t.db
    .insert(scanJobs)
    .values({
      jobType: 'scan',
      profile: opts.profile ?? 'passive',
      domainId,
      status,
      scopeSnapshot: { version: 1, trigger: 'schedule' },
      createdAt: created,
      scheduledAt: created,
      startedAt: finished ? created : null,
      completedAt: finished ? new Date(created.getTime() + 60_000) : null,
      ...(status === 'running'
        ? { leaseExpiresAt: NOW, workerId: await workerId(), attempts: 1 }
        : {}),
      rulesEvaluatedAt: status === 'succeeded' && opts.evaluated !== false ? created : null,
    })
    .returning({ id: scanJobs.id });
  return row!.id;
}

async function workerId() {
  const [w] = await t.db
    .insert(schema.workerRegistry)
    .values({ name: `w-${seq++}` })
    .returning({ id: schema.workerRegistry.id });
  return w!.id;
}

async function dns(
  jobId: string,
  hostname: string,
  ageDays: number,
  resultStatus: 'success' | 'error' = 'success',
) {
  const [row] = await t.db
    .insert(dnsObservations)
    .values({
      resultId: `r-${seq++}`,
      scanJobId: jobId,
      observedAt: ago(ageDays),
      checker: 'dns',
      checkerVersion: '1',
      resultStatus,
      hostname,
      recordType: 'A',
      recordValues: ['192.0.2.1'],
    })
    .returning({ id: dnsObservations.id });
  return row!.id;
}

/** Literal SQL text of a Drizzle SQL object (template strings and raw fragments). */
function textOf(q: unknown): string {
  if (!q || typeof q !== 'object') return '';
  const o = q as { value?: unknown; queryChunks?: unknown[] };
  if (Array.isArray(o.value)) return o.value.join('');
  if (Array.isArray(o.queryChunks)) return o.queryChunks.map(textOf).join(' ');
  return '';
}

const dnsIds = async () =>
  new Set((await t.db.select({ id: dnsObservations.id }).from(dnsObservations)).map((r) => r.id));
const jobIds = async () =>
  new Set((await t.db.select({ id: scanJobs.id }).from(scanJobs)).map((r) => r.id));

describe('observation retention', () => {
  it('deletes old observations but keeps the latest successful one per key', async () => {
    const j = await job({ ageDays: 10 });
    const aOld = await dns(j, 'a.retention.example', 300);
    const aOlder = await dns(j, 'a.retention.example', 400);
    const aLatest = await dns(j, 'a.retention.example', 200);
    // Only observation of its key, very old: it is the latest, so it survives.
    const bOnly = await dns(j, 'b.retention.example', 500);
    // Latest overall is a (recent-ish but past cutoff) error; the latest success is older.
    const cSuccess = await dns(j, 'c.retention.example', 300);
    const cOldError = await dns(j, 'c.retention.example', 280, 'error');
    const cLatestError = await dns(j, 'c.retention.example', 250, 'error');
    // Recent observations are never touched, whatever their rank.
    const dRecent1 = await dns(j, 'd.retention.example', 5);
    const dRecent2 = await dns(j, 'd.retention.example', 3);

    const res = await runRetention(t.db, NOW, logger, { force: true });
    expect(res.ran).toBe(true);
    const left = await dnsIds();
    for (const kept of [aLatest, bOnly, cSuccess, cLatestError, dRecent1, dRecent2]) {
      expect(left.has(kept)).toBe(true);
    }
    for (const gone of [aOld, aOlder, cOldError]) expect(left.has(gone)).toBe(false);
    expect(res.byTable.dns_observations).toBe(3);
  });

  it('keys observations by domain: the same name under two domains keeps one each', async () => {
    const [other] = await t.db.insert(domains).values({ fqdn: 'other.example' }).returning();
    const j1 = await job({ ageDays: 10 });
    const [j2row] = await t.db
      .insert(scanJobs)
      .values({
        jobType: 'scan',
        profile: 'passive',
        domainId: other!.id,
        status: 'succeeded',
        scopeSnapshot: {},
        completedAt: ago(9),
        rulesEvaluatedAt: ago(9),
      })
      .returning({ id: scanJobs.id });
    const mine = await dns(j1, 'shared.example', 300);
    const theirs = await dns(j2row!.id, 'shared.example', 200);
    await runRetention(t.db, NOW, logger, { force: true });
    const left = await dnsIds();
    expect(left.has(mine)).toBe(true);
    expect(left.has(theirs)).toBe(true);
  });

  it('applies the per-key rule to registration and HTTP observations', async () => {
    const j = await job({ ageDays: 10 });
    const reg = (ageDays: number) =>
      t.db
        .insert(registrationObservations)
        .values({
          resultId: `r-${seq++}`,
          scanJobId: j,
          domainId,
          observedAt: ago(ageDays),
          checker: 'rdap',
          checkerVersion: '1',
          resultStatus: 'success',
          dataStatus: 'available',
        })
        .returning({ id: registrationObservations.id });
    const [oldReg] = await reg(400);
    const [newerReg] = await reg(300);
    const http = (url: string, ageDays: number) =>
      t.db
        .insert(httpObservations)
        .values({
          resultId: `r-${seq++}`,
          scanJobId: j,
          observedAt: ago(ageDays),
          checker: 'http',
          checkerVersion: '1',
          resultStatus: 'success',
          url,
        })
        .returning({ id: httpObservations.id });
    const [h1] = await http('https://www.retention.example/', 400);
    const [h2] = await http('https://www.retention.example/', 190);
    const [h3] = await http('http://www.retention.example/', 400);

    const res = await runRetention(t.db, NOW, logger, { force: true });
    const regs = (await t.db.select().from(registrationObservations)).map((r) => r.id);
    expect(regs).toEqual([newerReg!.id]);
    const https = (await t.db.select().from(httpObservations)).map((r) => r.id).sort();
    expect(https).toEqual([h2!.id, h3!.id].sort());
    expect(oldReg).toBeDefined();
    expect(h1).toBeDefined();
    expect(res.byTable.registration_observations).toBe(1);
    expect(res.byTable.http_observations).toBe(1);
  });

  it('deletes in bounded batches and continues on the next tick while a backlog remains', async () => {
    const j = await job({ ageDays: 10 });
    for (let i = 0; i < 4; i++) await dns(j, 'a.retention.example', 300 + i);
    const latest = await dns(j, 'a.retention.example', 200);

    const first = await runRetention(t.db, NOW, logger, { force: true, batch: 2 });
    expect(first.byTable.dns_observations).toBe(2);
    expect((await readOpsState(t.db)).retention.more).toBe(true);
    // Within the hourly interval, but the backlog flag makes the next tick run.
    const second = await runRetention(t.db, new Date(NOW.getTime() + 300_000), logger, {
      batch: 2,
    });
    expect(second.ran).toBe(true);
    expect(second.byTable.dns_observations).toBe(2);
    expect([...(await dnsIds())]).toEqual([latest]);
  });
});

describe('scan job retention', () => {
  it('deletes old finished jobs with their targets and results, keeps everything else', async () => {
    const oldDone = await job({ ageDays: RETENTION_POLICY.scanJobDays + 10 });
    const oldFailed = await job({ ageDays: 400, status: 'failed' });
    const oldCancelled = await job({ ageDays: 400, status: 'cancelled' });
    const recentDone = await job({ ageDays: 30 });
    const oldQueued = await job({ ageDays: 400, status: 'queued' });
    const oldRunning = await job({ ageDays: 400, status: 'running', profile: 'quick' });
    const oldUnevaluated = await job({ ageDays: 400, evaluated: false });
    // A job still holding its key's latest observation must stay (observations cascade).
    const oldWithLatest = await job({ ageDays: 400 });
    const latestObs = await dns(oldWithLatest, 'only.retention.example', 399);
    // A job referenced by a finding's status history stays.
    const oldInHistory = await job({ ageDays: 400 });

    await t.db
      .insert(scanJobTargets)
      .values({ scanJobId: oldDone, targetHostname: 'retention.example' });
    await t.db.insert(scanJobResults).values({ scanJobId: oldDone, resultId: 'x', attempt: 1 });
    const [finding] = await t.db
      .insert(findings)
      .values({
        domainId,
        hostname: 'retention.example',
        component: 'dmarc',
        category: 'email',
        ruleId: 'DNS-003',
        ruleVersion: 1,
        fingerprint: 'fp-retention',
        title: 't',
        description: 'd',
        severity: 'medium',
        confidence: 'high',
        riskScore: 40,
        riskInputs: {},
        evidence: {},
        firstSeenAt: ago(400),
        lastSeenAt: ago(400),
      })
      .returning({ id: findings.id });
    await t.db
      .insert(findingStatusHistory)
      .values([
        { findingId: finding!.id, toStatus: 'open', reason: 'detected', scanJobId: oldInHistory },
      ]);
    await t.db.insert(findingComments).values({ findingId: finding!.id, body: 'note' });
    await t.db.insert(softwareInventory).values({
      domainId,
      source: 'http_header',
      product: 'nginx',
      banner: 'nginx',
      locationKey: 'k',
      firstSeenAt: ago(400),
      lastSeenAt: ago(400),
      lastScanJobId: oldFailed,
    });
    await t.db.insert(auditLogs).values({
      actorType: 'system',
      action: 'scan.scheduled',
      resourceType: 'scan_job',
      createdAt: ago(1000),
    });

    const res = await runRetention(t.db, NOW, logger, { force: true });
    const left = await jobIds();
    for (const gone of [oldDone, oldFailed, oldCancelled]) expect(left.has(gone)).toBe(false);
    for (const kept of [
      recentDone,
      oldQueued,
      oldRunning,
      oldUnevaluated,
      oldWithLatest,
      oldInHistory,
    ]) {
      expect(left.has(kept)).toBe(true);
    }
    expect(res.byTable.scan_jobs).toBe(3);
    expect((await dnsIds()).has(latestObs)).toBe(true);
    expect(
      await t.db.select().from(scanJobTargets).where(eq(scanJobTargets.scanJobId, oldDone)),
    ).toHaveLength(0);
    expect(await t.db.select().from(scanJobResults)).toHaveLength(0);
    const [inv] = await t.db.select().from(softwareInventory);
    expect(inv!.lastScanJobId).toBeNull();
    // Never touched: findings, history, comments, audit logs.
    expect(await t.db.select().from(findings)).toHaveLength(1);
    expect(await t.db.select().from(findingStatusHistory)).toHaveLength(1);
    expect(await t.db.select().from(findingComments)).toHaveLength(1);
    expect(await t.db.select().from(auditLogs)).toHaveLength(1);
  });

  it('records the run in ops_state and runs at most hourly', async () => {
    await job({ ageDays: 400 });
    const res = await runRetention(t.db, NOW, logger);
    expect(res).toMatchObject({ ran: true, deleted: 1 });
    const state = await readOpsState(t.db);
    expect(state.retention).toMatchObject({
      lastRunAt: NOW.toISOString(),
      deletedLastRun: 1,
      more: false,
    });

    await job({ ageDays: 400 });
    const soon = await runRetention(
      t.db,
      new Date(NOW.getTime() + RETENTION_INTERVAL_MS - 1),
      logger,
    );
    expect(soon.ran).toBe(false);
    const later = await runRetention(t.db, new Date(NOW.getTime() + RETENTION_INTERVAL_MS), logger);
    expect(later).toMatchObject({ ran: true, deleted: 1 });
  });

  it('isolates a failing table step and still records the others', async () => {
    const old = await job({ ageDays: 400 });
    const realExecute = t.db.execute.bind(t.db);
    const spy = vi.spyOn(t.db, 'execute').mockImplementation(((
      q: Parameters<typeof t.db.execute>[0],
    ) => {
      const text = textOf(q);
      if (text.includes('tls_observations') && text.includes('row_number'))
        return Promise.reject(new Error('boom'));
      return realExecute(q);
    }) as typeof t.db.execute);
    const res = await runRetention(t.db, NOW, logger, { force: true });
    spy.mockRestore();
    expect(res.failed).toEqual(['tls_observations']);
    expect((await jobIds()).has(old)).toBe(false);
    expect((await readOpsState(t.db)).retention.failed).toEqual(['tls_observations']);
    expect(
      await t.db
        .select()
        .from(scanJobs)
        .where(inArray(scanJobs.id, [old])),
    ).toHaveLength(0);
  });
});
