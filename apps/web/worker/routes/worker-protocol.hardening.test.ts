// @vitest-environment node
/**
 * Hardening: worker request authentication, job leases/retries and finding idempotency — the gaps
 * left by scans.test.ts, redteam.test.ts, evaluation.test.ts and finding-lifecycle.test.ts.
 * Every test asserts the SAFE behaviour.
 */
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  WORKER_HEADERS,
  claimResponseSchema,
  errorResponseSchema,
  workerCredentialCreatedResponseSchema,
  workerSigningString,
  type ClaimedJob,
} from '@exdomainvault/shared';
import { and, asc, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.ts';
import { decodeBase64, encodeBase64, sha256HexBytes } from '../lib/ed25519.ts';
import { createLogger } from '../lib/logger.ts';
import { evaluateJob, evaluatePendingJobs } from '../services/evaluation.ts';
import { LEASE_SECONDS, backoffSeconds } from '../services/job-lifecycle.ts';
import { runMaintenance } from '../services/maintenance.ts';
import { dmarcRule, dnsFor, hostRule, seedDomain, seedJob } from '../testing/findings-fixtures.ts';
import {
  generateWorkerKey,
  harness,
  signedHeaders,
  userCall,
  workerCall,
  type TestWorkerKey,
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
  vi.spyOn(console, 'error').mockImplementation(() => {});
  clock = new Date('2026-10-22T10:00:00.000Z');
  await t.db.delete(schema.findings);
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
  await t.db.delete(schema.workerRegistry);
});
afterEach(() => vi.restoreAllMocks());

const advance = (seconds: number) => {
  clock = new Date(clock.getTime() + seconds * 1000);
};
const nowSeconds = () => Math.floor(clock.getTime() / 1000);

async function expectError(res: Response, status: number, code: string) {
  const text = await res.text();
  expect(res.status, text).toBe(status);
  expect(errorResponseSchema.parse(JSON.parse(text)).error.code).toBe(code);
}
const deny = (res: Response) => expectError(res, 401, 'unauthenticated');

interface W {
  key: TestWorkerKey;
  keyId: string;
  workerId: string;
}
let seq = 0;
async function registerWorker(): Promise<W> {
  const key = await generateWorkerKey();
  const res = await userCall(h, t, 'admin', 'POST', '/workers', {
    name: `hw-${seq++}`,
    publicKey: key.publicKey,
  });
  expect(res.status).toBe(201);
  const body = workerCredentialCreatedResponseSchema.parse(await res.json());
  return { key, keyId: body.credentialId, workerId: body.worker.id };
}

async function addDomain(fqdn: string) {
  const [d] = await t.db.insert(schema.domains).values({ fqdn }).returning();
  return d!;
}
async function requestScan(domainId: string) {
  const res = await userCall(h, t, 'analyst', 'POST', `/domains/${domainId}/scans`, {
    profile: 'passive',
  });
  expect(res.status).toBe(202);
  return ((await res.json()) as { job: { id: string } }).job;
}
async function claim(w: W): Promise<ClaimedJob | null> {
  const res = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock });
  expect(res.status).toBe(200);
  return claimResponseSchema.parse(await res.json()).job;
}
const jobRow = async (id: string) =>
  (await t.db.select().from(schema.scanJobs).where(eq(schema.scanJobs.id, id)))[0]!;

/** Sends a raw request to the worker API with the given headers and body. */
const rawWorker = (path: string, headers: Record<string, string>, body: string) =>
  createApp(h.deps).request(
    path,
    { method: 'POST', headers, body },
    h.env('viewer') as unknown as Env,
  );

const CLAIM = '/api/v1/internal/worker/claim';
const HEARTBEAT = '/api/v1/internal/worker/heartbeat';

// ================================================================================================

describe('worker signatures: binding to method, path, query and body', () => {
  it('a signature for /claim is not valid for /heartbeat', async () => {
    const w = await registerWorker();
    const body = '{}';
    const headers = await signedHeaders(w.key, w.keyId, 'POST', CLAIM, body, { now: clock });
    await deny(await rawWorker(HEARTBEAT, headers, body));
  });

  it('a signature over another method is refused', async () => {
    const w = await registerWorker();
    const headers = await signedHeaders(w.key, w.keyId, 'GET', CLAIM, '{}', { now: clock });
    await deny(await rawWorker(CLAIM, headers, '{}'));
  });

  it('a query string added or removed after signing is refused', async () => {
    const w = await registerWorker();
    const plain = await signedHeaders(w.key, w.keyId, 'POST', CLAIM, '{}', { now: clock });
    await deny(await rawWorker(`${CLAIM}?profiles=deep`, plain, '{}'));
    const withQuery = await signedHeaders(w.key, w.keyId, 'POST', `${CLAIM}?a=1`, '{}', {
      now: clock,
    });
    await deny(await rawWorker(CLAIM, withQuery, '{}'));
  });

  it('a whitespace-only change to the signed body is refused', async () => {
    const w = await registerWorker();
    const headers = await signedHeaders(w.key, w.keyId, 'POST', CLAIM, '{}', { now: clock });
    await deny(await rawWorker(CLAIM, headers, '{ }'));
    await deny(await rawWorker(CLAIM, headers, '{}\n'));
  });

  it('a non-canonical (malleated, S + L) signature is refused', async () => {
    const w = await registerWorker();
    const headers = await signedHeaders(w.key, w.keyId, 'POST', CLAIM, '{}', { now: clock });
    const sig = decodeBase64(headers[WORKER_HEADERS.signature]!)!;
    // L = 2^252 + 27742317777372353535851937790883648493 (little endian).
    const L = Buffer.from(
      'edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010',
      'hex',
    );
    const s = sig.slice(32);
    let carry = 0;
    const sum = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      const v = s[i]! + L[i]! + carry;
      sum[i] = v & 0xff;
      carry = v >> 8;
    }
    const malleated = new Uint8Array([...sig.slice(0, 32), ...sum]);
    await deny(
      await rawWorker(
        CLAIM,
        { ...headers, [WORKER_HEADERS.signature]: encodeBase64(malleated) },
        '{}',
      ),
    );
  });

  it.each([
    ['empty', ''],
    ['short', 'AAAA'],
    ['not base64', '!!!!'],
    ['129 bytes', encodeBase64(new Uint8Array(129))],
    ['all zero', encodeBase64(new Uint8Array(64))],
  ])('a malformed signature (%s) is refused', async (_l, value) => {
    const w = await registerWorker();
    const headers = await signedHeaders(w.key, w.keyId, 'POST', CLAIM, '{}', { now: clock });
    await deny(await rawWorker(CLAIM, { ...headers, [WORKER_HEADERS.signature]: value }, '{}'));
  });

  it.each([
    ['key id not a UUID', { [WORKER_HEADERS.keyId]: 'worker-1' }],
    ['timestamp with fraction', { [WORKER_HEADERS.timestamp]: '1792000000.5' }],
    ['negative timestamp', { [WORKER_HEADERS.timestamp]: '-1' }],
    ['huge timestamp', { [WORKER_HEADERS.timestamp]: '9'.repeat(40) }],
    ['short nonce', { [WORKER_HEADERS.nonce]: 'abc' }],
    ['nonce with separator', { [WORKER_HEADERS.nonce]: 'abcdefgh\nijklmnopq' }],
  ])('malformed auth headers (%s) are refused', async (_l, over) => {
    const w = await registerWorker();
    const headers = await signedHeaders(w.key, w.keyId, 'POST', CLAIM, '{}', { now: clock });
    let res: Response;
    try {
      res = await rawWorker(CLAIM, { ...headers, ...over }, '{}');
    } catch {
      return; // the Request constructor itself refused the header value
    }
    await deny(res);
  });
});

describe('worker signatures: time window and replay', () => {
  it('accepts timestamps just inside ±5 minutes, refuses just outside (both directions)', async () => {
    const w = await registerWorker();
    for (const [offset, ok] of [
      [-299, true],
      [299, true],
      [-301, false],
      [301, false],
    ] as const) {
      const res = await workerCall(
        h,
        w.key,
        w.keyId,
        'claim',
        {},
        { now: clock, timestamp: nowSeconds() + offset },
      );
      if (ok) expect(res.status, `offset ${offset}`).toBe(200);
      else await deny(res);
    }
  });

  it('a captured request cannot be replayed later (nonce, then timestamp)', async () => {
    const w = await registerWorker();
    const headers = await signedHeaders(w.key, w.keyId, 'POST', CLAIM, '{}', { now: clock });
    expect((await rawWorker(CLAIM, headers, '{}')).status).toBe(200);
    await deny(await rawWorker(CLAIM, headers, '{}'));
    // After the nonce table is pruned the timestamp window still refuses it.
    advance(LEASE_SECONDS + 400);
    await runMaintenance(t.db, clock, createLogger({}));
    await deny(await rawWorker(CLAIM, headers, '{}'));
  });

  it('a used nonce cannot be reused with a new signature over a different body', async () => {
    const w = await registerWorker();
    const nonce = 'fixed-nonce-0123456789';
    expect((await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock, nonce })).status).toBe(
      200,
    );
    await deny(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'claim',
        { profiles: ['passive'] },
        { now: clock, nonce },
      ),
    );
  });

  it('a forged request does not burn the nonce of a later legitimate request', async () => {
    const w = await registerWorker();
    const attacker = await generateWorkerKey();
    const nonce = 'victim-nonce-0123456789';
    await deny(await workerCall(h, attacker, w.keyId, 'claim', {}, { now: clock, nonce }));
    expect((await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock, nonce })).status).toBe(
      200,
    );
  });

  it('nonces are per credential: one worker cannot block another by guessing nonces', async () => {
    const a = await registerWorker();
    const b = await registerWorker();
    const nonce = 'shared-nonce-0123456789';
    expect((await workerCall(h, a.key, a.keyId, 'claim', {}, { now: clock, nonce })).status).toBe(
      200,
    );
    expect((await workerCall(h, b.key, b.keyId, 'claim', {}, { now: clock, nonce })).status).toBe(
      200,
    );
  });
});

describe('worker keys', () => {
  const SMALL_ORDER = [
    `01${'00'.repeat(31)}`, // identity point
    '00'.repeat(32),
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', // order 8
    `ec${'ff'.repeat(30)}ff7f`,
  ];

  it.each(SMALL_ORDER)('registering small-order key %s is refused', async (hex) => {
    const publicKey = encodeBase64(Buffer.from(hex, 'hex'));
    const res = await userCall(h, t, 'admin', 'POST', '/workers', {
      name: `so-${seq++}`,
      publicKey,
    });
    expect(res.status).toBe(400);
  });

  it.each(SMALL_ORDER)(
    'a small-order key smuggled into the database never verifies a forged signature (%s)',
    async (hex) => {
      const [w] = await t.db
        .insert(schema.workerRegistry)
        .values({ name: `smuggled-${seq++}` })
        .returning();
      const [cred] = await t.db
        .insert(schema.workerCredentials)
        .values({
          workerId: w!.id,
          publicKey: encodeBase64(Buffer.from(hex, 'hex')),
          createdAt: clock,
          expiresAt: new Date(clock.getTime() + 86_400_000),
        })
        .returning();
      const timestamp = String(nowSeconds());
      const nonce = `smuggle-${seq++}-0123456789`;
      // R = identity, S = 0 verifies for every message under a small-order key on lax verifiers.
      const forged = new Uint8Array(64);
      forged[0] = 1;
      void workerSigningString('POST', CLAIM, timestamp, nonce, await sha256HexBytes('{}'));
      await deny(
        await rawWorker(
          CLAIM,
          {
            'Content-Type': 'application/json',
            [WORKER_HEADERS.keyId]: cred!.id,
            [WORKER_HEADERS.timestamp]: timestamp,
            [WORKER_HEADERS.nonce]: nonce,
            [WORKER_HEADERS.signature]: encodeBase64(forged),
          },
          '{}',
        ),
      );
    },
  );

  it('a credential revoked while its worker holds a job stops it immediately', async () => {
    const w = await registerWorker();
    const d = await addDomain('revoked.example');
    const job = await requestScan(d.id);
    expect((await claim(w))?.id).toBe(job.id);
    const res = await userCall(
      h,
      t,
      'admin',
      'POST',
      `/workers/${w.workerId}/credentials/${w.keyId}/revoke`,
    );
    expect(res.status).toBe(200);
    await deny(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'heartbeat',
        { jobId: job.id, attempt: 1 },
        { now: clock },
      ),
    );
  });
});

// ================================================================================================

describe('leases and retries', () => {
  it('concurrent claims by many workers hand each job to exactly one worker', async () => {
    const workers = await Promise.all(Array.from({ length: 6 }, () => registerWorker()));
    const jobs: string[] = [];
    for (const name of ['a.example', 'b.example', 'c.example']) {
      jobs.push((await requestScan((await addDomain(name)).id)).id);
    }
    // Two rounds of simultaneous claims from every worker.
    const results = (
      await Promise.all([...workers, ...workers].map((w) => claim(w).then((j) => ({ w, j }))))
    ).filter((r) => r.j !== null);
    const claimedIds = results.map((r) => r.j!.id);
    expect(claimedIds.sort()).toEqual([...jobs].sort());
    expect(new Set(claimedIds).size).toBe(claimedIds.length);
    for (const r of results) {
      const row = await jobRow(r.j!.id);
      expect(row).toMatchObject({ status: 'claimed', attempts: 1, workerId: r.w.workerId });
    }
  });

  it('backoff grows and is bounded', () => {
    const values = Array.from({ length: 12 }, (_, i) => backoffSeconds(i + 1));
    for (let i = 1; i < values.length; i++)
      expect(values[i]!).toBeGreaterThanOrEqual(values[i - 1]!);
    expect(values[0]!).toBeGreaterThan(0);
    expect(Math.max(...values)).toBeLessThanOrEqual(30 * 60);
    expect(backoffSeconds(1_000)).toBe(30 * 60);
  });

  it('a lease that expires on the last attempt fails the job for good', async () => {
    const w = await registerWorker();
    const d = await addDomain('ceiling.example');
    const job = await requestScan(d.id);
    for (let attempt = 1; attempt <= 3; attempt++) {
      const claimed = await claim(w);
      expect(claimed?.attempt).toBe(attempt);
      advance(LEASE_SECONDS + 1);
      await runMaintenance(t.db, clock, createLogger({}));
      advance(backoffSeconds(attempt));
    }
    expect(await jobRow(job.id)).toMatchObject({
      status: 'failed',
      attempts: 3,
      errorCode: 'lease_expired',
    });
    advance(3600);
    expect(await claim(w)).toBeNull();
  });

  it('after reaping, the old attempt is fenced and the new holder proceeds', async () => {
    const a = await registerWorker();
    const b = await registerWorker();
    const d = await addDomain('fence.example');
    const job = await requestScan(d.id);
    const first = await claim(a);
    advance(LEASE_SECONDS + 1);
    await runMaintenance(t.db, clock, createLogger({}));
    advance(backoffSeconds(1));
    const second = await claim(b);
    expect(second).toMatchObject({ id: job.id, attempt: 2 });

    const targetId = first!.targets[0]!.id;
    const stale = {
      jobId: job.id,
      attempt: 1,
      resultId: 'stale-result-0001',
      targets: [{ targetId, status: 'succeeded' }],
      complete: true,
    };
    await expectError(
      await workerCall(h, a.key, a.keyId, 'results', stale, { now: clock }),
      409,
      'conflict',
    );
    // Even claiming the current attempt number does not help a worker that does not hold it.
    await expectError(
      await workerCall(h, a.key, a.keyId, 'results', { ...stale, attempt: 2 }, { now: clock }),
      409,
      'conflict',
    );
    await expectError(
      await workerCall(
        h,
        a.key,
        a.keyId,
        'failures',
        { jobId: job.id, attempt: 1, errorCode: 'x_err', errorSummary: 'late', retryable: false },
        { now: clock },
      ),
      409,
      'conflict',
    );
    expect(await jobRow(job.id)).toMatchObject({ status: 'claimed', workerId: b.workerId });

    const ok = await workerCall(
      h,
      b.key,
      b.keyId,
      'results',
      { ...stale, attempt: 2, resultId: 'fresh-result-0001' },
      { now: clock },
    );
    expect(await ok.json()).toEqual({ accepted: true, status: 'succeeded' });
  });

  it('resubmitting results is idempotent, and nothing changes a finished job', async () => {
    const w = await registerWorker();
    const d = await addDomain('idem.example');
    const job = await requestScan(d.id);
    const claimed = await claim(w);
    const result = {
      jobId: job.id,
      attempt: 1,
      resultId: 'idem-result-0001',
      targets: [{ targetId: claimed!.targets[0]!.id, status: 'succeeded' }],
      complete: true,
    };
    const send = () => workerCall(h, w.key, w.keyId, 'results', result, { now: clock });
    // Concurrent duplicate deliveries.
    const responses = await Promise.all([send(), send(), send()]);
    const bodies = await Promise.all(responses.map((r) => r.json()));
    expect(bodies.filter((b) => (b as { accepted: boolean }).accepted)).toHaveLength(1);
    expect(
      await t.db
        .select()
        .from(schema.scanJobResults)
        .where(eq(schema.scanJobResults.scanJobId, job.id)),
    ).toHaveLength(1);

    // A different result id or a failure report after completion is refused; status stays.
    await expectError(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'results',
        { ...result, resultId: 'idem-result-0002' },
        { now: clock },
      ),
      409,
      'conflict',
    );
    await expectError(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'failures',
        { jobId: job.id, attempt: 1, errorCode: 'late_err', errorSummary: 'x', retryable: true },
        { now: clock },
      ),
      409,
      'conflict',
    );
    expect(await jobRow(job.id)).toMatchObject({ status: 'succeeded', attempts: 1 });
  });

  it('reaping is idempotent under concurrent maintenance runs', async () => {
    const w = await registerWorker();
    const d = await addDomain('reap.example');
    const job = await requestScan(d.id);
    await claim(w);
    advance(LEASE_SECONDS + 1);
    await Promise.all([
      runMaintenance(t.db, clock, createLogger({})),
      runMaintenance(t.db, clock, createLogger({})),
    ]);
    const row = await jobRow(job.id);
    expect(row).toMatchObject({ status: 'queued', attempts: 1, workerId: null });
    expect(row.scheduledAt.getTime()).toBe(clock.getTime() + backoffSeconds(1) * 1000);
  });
});

// ================================================================================================

const at = (hours: number) => new Date(Date.parse('2026-10-20T00:00:00.000Z') + hours * 3600_000);
const findingsOf = (domainId: string) =>
  t.db
    .select()
    .from(schema.findings)
    .where(eq(schema.findings.domainId, domainId))
    .orderBy(asc(schema.findings.fingerprint));
const historyOf = (findingId: string) =>
  t.db
    .select()
    .from(schema.findingStatusHistory)
    .where(eq(schema.findingStatusHistory.findingId, findingId))
    .orderBy(asc(schema.findingStatusHistory.createdAt));

describe('finding idempotency', () => {
  it('a partially successful job resolves only the components it checked', async () => {
    const s = await seedDomain(t, 'partial.example');
    const first = await seedJob(t, s.domainId, at(1), [
      ...dnsFor(s.fqdn, { apexA: ['192.0.2.1'], wwwA: ['192.0.2.2'] }),
    ]);
    await evaluateJob(t.db, first, clock, [dmarcRule, hostRule]);
    const before = await findingsOf(s.domainId);
    expect(before.map((f) => [f.ruleId, f.hostname, f.status])).toEqual([
      ['TST-DMARC', 'partial.example', 'open'],
      ['TST-HOST', 'partial.example', 'open'],
      ['TST-HOST', 'www.partial.example', 'open'],
    ]);

    // Second job: apex A checked successfully and empty (condition gone); www A timed out; the
    // DMARC lookup errored. Only the apex host finding may resolve.
    const second = await seedJob(t, s.domainId, at(2), [
      { hostname: `_dmarc.${s.fqdn}`, recordType: 'TXT', values: [], status: 'error' },
      { hostname: s.fqdn, recordType: 'A', values: [] },
      { hostname: `www.${s.fqdn}`, recordType: 'A', values: [], status: 'timeout' },
    ]);
    const r = await evaluateJob(t.db, second, clock, [dmarcRule, hostRule]);
    expect(r).toMatchObject({ status: 'evaluated', resolved: 1 });
    const after = await findingsOf(s.domainId);
    expect(after.map((f) => [f.ruleId, f.hostname, f.status])).toEqual([
      ['TST-DMARC', 'partial.example', 'open'],
      ['TST-HOST', 'partial.example', 'resolved'],
      ['TST-HOST', 'www.partial.example', 'open'],
    ]);
  });

  it('a failed or cancelled job with "success" evidence never resolves, even via the pending sweep', async () => {
    const s = await seedDomain(t, 'failed.example');
    await evaluateJob(t.db, await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn)), clock, [
      dmarcRule,
    ]);
    for (const status of ['failed', 'cancelled'] as const) {
      await seedJob(t, s.domainId, at(2), dnsFor(s.fqdn, { dmarc: true }), status);
    }
    await Promise.all([
      evaluatePendingJobs(t.db, clock, { rules: [dmarcRule] }),
      evaluatePendingJobs(t.db, clock, { rules: [dmarcRule] }),
    ]);
    const [f] = await findingsOf(s.domainId);
    expect(f).toMatchObject({ status: 'open' });
    expect(await historyOf(f!.id)).toHaveLength(1);
  });

  it('two jobs of one domain evaluated concurrently apply in completion order, once each', async () => {
    const s = await seedDomain(t, 'race.example');
    const raise = await seedJob(t, s.domainId, at(1), dnsFor(s.fqdn, { apexA: ['192.0.2.9'] }));
    const clear = await seedJob(t, s.domainId, at(2), dnsFor(s.fqdn, { dmarc: true }));
    // Later job first, both repeatedly and concurrently, then the sweep picks up deferrals.
    await Promise.all([
      evaluateJob(t.db, clear, clock, [dmarcRule, hostRule]),
      evaluateJob(t.db, raise, clock, [dmarcRule, hostRule]),
      evaluateJob(t.db, clear, clock, [dmarcRule, hostRule]),
      evaluateJob(t.db, raise, clock, [dmarcRule, hostRule]),
    ]);
    await evaluatePendingJobs(t.db, clock, { rules: [dmarcRule, hostRule] });
    await evaluatePendingJobs(t.db, clock, { rules: [dmarcRule, hostRule] });

    const rows = await findingsOf(s.domainId);
    const fps = rows.map((r) => r.fingerprint);
    expect(new Set(fps).size).toBe(fps.length);
    const dmarc = rows.find((r) => r.ruleId === 'TST-DMARC')!;
    const host = rows.find((r) => r.ruleId === 'TST-HOST')!;
    // DMARC raised by the first job, resolved by the second; the host finding resolved because the
    // second job saw the apex with no A records.
    expect(dmarc.status).toBe('resolved');
    expect(host.status).toBe('resolved');
    expect((await historyOf(dmarc.id)).map((x) => [x.toStatus, x.reason])).toEqual([
      ['open', 'detected'],
      ['resolved', 'condition_absent'],
    ]);
    for (const id of [raise, clear]) expect((await jobRow(id)).rulesEvaluatedAt).not.toBeNull();
  });

  it('duplicate result submissions through the API lead to one finding per fingerprint', async () => {
    const w = await registerWorker();
    const s = await seedDomain(t, 'dup.example');
    const job = await requestScan(s.domainId);
    const claimed = await claim(w);
    const target = claimed!.targets.find((x) => x.hostname === s.fqdn)!;
    const submission = {
      jobId: job.id,
      attempt: 1,
      resultId: 'dup-result-0001',
      targets: claimed!.targets.map((x) => ({ targetId: x.id, status: 'succeeded' })),
      observations: [
        {
          kind: 'dns',
          targetId: target.id,
          hostname: `_dmarc.${s.fqdn}`,
          observedAt: clock.toISOString(),
          checkerVersion: '1',
          evidence: {},
          resultStatus: 'success',
          recordType: 'TXT',
          ttl: 300,
          values: [],
        },
      ],
      complete: true,
    };
    const responses = await Promise.all(
      [1, 2, 3].map(() => workerCall(h, w.key, w.keyId, 'results', submission, { now: clock })),
    );
    for (const r of responses) expect(r.status, await r.clone().text()).toBe(200);
    await Promise.all([
      evaluatePendingJobs(t.db, clock, { rules: [dmarcRule] }),
      evaluatePendingJobs(t.db, clock, { rules: [dmarcRule] }),
    ]);
    const rows = await t.db
      .select()
      .from(schema.findings)
      .where(
        and(eq(schema.findings.domainId, s.domainId), eq(schema.findings.ruleId, 'TST-DMARC')),
      );
    expect(rows).toHaveLength(1);
    expect(await historyOf(rows[0]!.id)).toHaveLength(1);
    expect(
      await t.db
        .select()
        .from(schema.dnsObservations)
        .where(eq(schema.dnsObservations.scanJobId, job.id)),
    ).toHaveLength(1);
  });
});
