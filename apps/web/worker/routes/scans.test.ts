// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  claimResponseSchema,
  errorResponseSchema,
  scanJobDetailResponseSchema,
  scanJobListResponseSchema,
  scanProfileListResponseSchema,
  workerCredentialCreatedResponseSchema,
  type ClaimedJob,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.ts';
import { createLogger } from '../lib/logger.ts';
import { WORKER_RATE_LIMIT_PER_MINUTE } from '../middleware/worker-auth.ts';
import { LEASE_SECONDS, backoffSeconds } from '../services/job-lifecycle.ts';
import { pruneNonces, runMaintenance, schedulePassiveMonitoring } from '../services/maintenance.ts';
import {
  generateWorkerKey,
  harness,
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
const ACTIVE_ON = { ACTIVE_SCANNING_ENABLED: 'true' };

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
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
  await t.db.delete(schema.workerRegistry);
  await t.db.delete(schema.auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const call = (
  role: Role,
  method: string,
  path: string,
  body?: unknown,
  env?: Record<string, string>,
) => userCall(h, t, role, method, path, body, env);

async function expectError(res: Response, status: number, code: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
  return body.error;
}

const auditActions = async () =>
  (await t.db.select().from(schema.auditLogs).orderBy(schema.auditLogs.createdAt)).map(
    (a) => a.action,
  );

async function addDomain(fqdn: string, opts: { verified?: boolean; monitoring?: boolean } = {}) {
  const [d] = await t.db
    .insert(schema.domains)
    .values({
      fqdn,
      monitoringEnabled: opts.monitoring ?? false,
      ...(opts.verified
        ? {
            verificationStatus: 'verified' as const,
            verifiedAt: clock,
            verificationMethod: 'dns_txt' as const,
          }
        : {}),
    })
    .returning();
  if (!d) throw new Error('domain');
  return d;
}

async function requestScan(domainId: string, profile = 'passive', env?: Record<string, string>) {
  const res = await call('analyst', 'POST', `/domains/${domainId}/scans`, { profile }, env);
  expect(res.status).toBe(202);
  return scanJobDetailResponseSchema.parse(await res.json());
}

async function registerWorker(
  name = 'home-1',
): Promise<{ key: TestWorkerKey; keyId: string; workerId: string }> {
  const key = await generateWorkerKey();
  const res = await call('admin', 'POST', '/workers', { name, publicKey: key.publicKey });
  expect(res.status).toBe(201);
  const body = workerCredentialCreatedResponseSchema.parse(await res.json());
  return { key, keyId: body.credentialId, workerId: body.worker.id };
}

async function claim(
  w: { key: TestWorkerKey; keyId: string },
  env?: Record<string, string>,
): Promise<ClaimedJob | null> {
  const res = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock, envExtra: env });
  expect(res.status).toBe(200);
  return claimResponseSchema.parse(await res.json()).job;
}

const advance = (seconds: number) => {
  clock = new Date(clock.getTime() + seconds * 1000);
};

describe('scan profiles', () => {
  it('lists the seeded profiles and whether active scanning is enabled', async () => {
    const body = scanProfileListResponseSchema.parse(
      await (await call('viewer', 'GET', '/scan-profiles')).json(),
    );
    expect(body.items.map((p) => [p.key, p.config.active])).toEqual([
      ['passive', false],
      ['quick', true],
      ['standard', true],
      ['deep', true],
    ]);
    expect(body.activeScanningEnabled).toBe(false);
    const standard = body.items.find((p) => p.key === 'standard');
    expect(standard?.config.tcpPorts).toContain(443);
    expect(standard?.config.checks).toContain('tcp_ports');
  });
});

describe('creating scans', () => {
  it('creates a passive scan for an unverified domain with an immutable snapshot, and returns 202', async () => {
    const d = await addDomain('example.com');
    const { job, targets, scopeSnapshot } = await requestScan(d.id);
    expect(job).toMatchObject({
      status: 'queued',
      profile: 'passive',
      trigger: 'manual',
      domain: { id: d.id, fqdn: 'example.com' },
      requestedBy: { email: 'analyst@example.com' },
      attempts: 0,
      maxAttempts: 3,
      targetCounts: { pending: 1, running: 0, succeeded: 0, failed: 0, skipped: 0 },
    });
    expect(targets.map((x) => [x.hostname, x.assetId])).toEqual([['example.com', null]]);
    expect(scopeSnapshot).toMatchObject({
      version: 1,
      domain: { fqdn: 'example.com', verificationStatus: 'unverified' },
      profile: { key: 'passive', config: { active: false, checks: ['dns', 'rdap'] } },
    });
    expect(await auditActions()).toEqual(['scan.requested']);
  });

  it('refuses a second queued or active job for the same domain and profile', async () => {
    const d = await addDomain('example.com');
    await requestScan(d.id);
    await expectError(
      await call('analyst', 'POST', `/domains/${d.id}/scans`, { profile: 'passive' }),
      409,
      'conflict',
    );
  });

  it('refuses active profiles while active scanning is disabled', async () => {
    const d = await addDomain('example.com', { verified: true });
    const err = await expectError(
      await call('admin', 'POST', `/domains/${d.id}/scans`, { profile: 'quick' }),
      409,
      'conflict',
    );
    expect(err.message).toContain('Active scanning is disabled');
    expect(await t.db.select().from(schema.scanJobs)).toEqual([]);
  });

  it('requires a verified, unexpired domain for active profiles', async () => {
    const unverified = await addDomain('unverified.com');
    await expectError(
      await call(
        'admin',
        'POST',
        `/domains/${unverified.id}/scans`,
        { profile: 'quick' },
        ACTIVE_ON,
      ),
      409,
      'conflict',
    );
    const [lapsed] = await t.db
      .insert(schema.domains)
      .values({
        fqdn: 'lapsed.com',
        verificationStatus: 'verified',
        verifiedAt: clock,
        verificationMethod: 'admin_attestation',
        verificationExpiresAt: new Date(clock.getTime() - 1000),
      })
      .returning();
    await expectError(
      await call('admin', 'POST', `/domains/${lapsed!.id}/scans`, { profile: 'quick' }, ACTIVE_ON),
      409,
      'conflict',
    );
  });

  it('approves the apex of a verified domain as an asset and snapshots approved targets only', async () => {
    const d = await addDomain('example.com', { verified: true });
    const [pending] = await t.db
      .insert(schema.assets)
      .values({
        domainId: d.id,
        hostname: 'pending.example.com',
        assetType: 'subdomain',
        discoverySource: 'dns',
      })
      .returning();
    const { targets, scopeSnapshot } = await requestScan(d.id, 'standard', ACTIVE_ON);
    expect(targets.map((x) => x.hostname)).toEqual(['example.com']);
    expect(targets[0]?.assetId).not.toBeNull();
    expect(scopeSnapshot.targets.map((x) => x.hostname)).toEqual(['example.com']);
    const assetRows = await t.db
      .select()
      .from(schema.assets)
      .where(eq(schema.assets.domainId, d.id));
    expect(assetRows.find((a) => a.hostname === 'example.com')?.verificationStatus).toBe(
      'approved',
    );
    expect(assetRows.find((a) => a.id === pending!.id)?.verificationStatus).toBe('pending');
    expect(await auditActions()).toEqual(['asset.approved', 'scan.requested']);
  });

  it('never implicitly re-approves a rejected apex', async () => {
    const d = await addDomain('example.com', { verified: true });
    await t.db.insert(schema.assets).values({
      domainId: d.id,
      hostname: 'example.com',
      assetType: 'apex',
      discoverySource: 'manual',
      verificationStatus: 'rejected',
    });
    await expectError(
      await call('admin', 'POST', `/domains/${d.id}/scans`, { profile: 'quick' }, ACTIVE_ON),
      409,
      'conflict',
    );
  });

  it('enforces permissions and validates the profile', async () => {
    const d = await addDomain('example.com');
    await expectError(
      await call('viewer', 'POST', `/domains/${d.id}/scans`, { profile: 'passive' }),
      403,
      'forbidden',
    );
    await expectError(await call('asset_owner', 'GET', '/scans'), 403, 'forbidden');
    const err = await expectError(
      await call('admin', 'POST', `/domains/${d.id}/scans`, { profile: 'nmap -sS' }),
      400,
      'validation_failed',
    );
    expect(err.details?.[0]?.path).toBe('profile');
    await expectError(
      await call('admin', 'POST', `/domains/${d.id}/scans`, { profile: 'passive', args: '-p-' }),
      400,
      'validation_failed',
    );
  });

  it('lists and filters scans', async () => {
    const a = await addDomain('alpha.com');
    const b = await addDomain('bravo.com');
    await requestScan(a.id);
    await requestScan(b.id);
    const all = scanJobListResponseSchema.parse(
      await (await call('viewer', 'GET', '/scans')).json(),
    );
    expect(all.total).toBe(2);
    const filtered = scanJobListResponseSchema.parse(
      await (await call('viewer', 'GET', `/scans?domainId=${b.id}`)).json(),
    );
    expect(filtered.items.map((j) => j.domain?.fqdn)).toEqual(['bravo.com']);
  });
});

describe('worker authentication', () => {
  it('accepts a correctly signed request and records last use', async () => {
    const w = await registerWorker();
    expect(await claim(w)).toBeNull();
    const [worker] = await t.db.select().from(schema.workerRegistry);
    expect(worker).toMatchObject({ lastSeenAt: clock, version: '0.1.0-test' });
  });

  it('rejects unsigned, tampered, stale, replayed and wrongly keyed requests', async () => {
    const w = await registerWorker();
    const other = await generateWorkerKey();
    const deny = async (res: Response) => expectError(res, 401, 'unauthenticated');

    // No signature headers at all.
    await deny(
      await createApp(h.deps).request(
        '/api/v1/internal/worker/claim',
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
        h.env('viewer') as unknown as Env,
      ),
    );
    // Body differs from what was signed.
    await deny(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'claim',
        { profiles: ['deep'] },
        { now: clock, signedBody: '{}' },
      ),
    );
    // Signed by a different key.
    await deny(await workerCall(h, other, w.keyId, 'claim', {}, { now: clock }));
    // Timestamp outside the ±5 minute window.
    await deny(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'claim',
        {},
        { timestamp: Math.floor(clock.getTime() / 1000) - 301 },
      ),
    );
    // Unknown key id.
    await deny(await workerCall(h, w.key, crypto.randomUUID(), 'claim', {}, { now: clock }));
    // Replay: the same nonce twice.
    const nonce = 'replay-nonce-0123456789';
    expect((await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock, nonce })).status).toBe(
      200,
    );
    await deny(await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock, nonce }));
  });

  it('rejects revoked and expired credentials and disabled workers', async () => {
    const w = await registerWorker();
    expect(
      (await call('admin', 'PATCH', `/workers/${w.workerId}`, { status: 'disabled' })).status,
    ).toBe(200);
    await expectError(
      await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock }),
      401,
      'unauthenticated',
    );
    await call('admin', 'PATCH', `/workers/${w.workerId}`, { status: 'active' });
    expect((await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock })).status).toBe(200);

    expect(
      (await call('admin', 'POST', `/workers/${w.workerId}/credentials/${w.keyId}/revoke`)).status,
    ).toBe(200);
    await expectError(
      await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock }),
      401,
      'unauthenticated',
    );

    const fresh = await generateWorkerKey();
    const added = workerCredentialCreatedResponseSchema.parse(
      await (
        await call('admin', 'POST', `/workers/${w.workerId}/credentials`, {
          publicKey: fresh.publicKey,
          expiresInDays: 1,
        })
      ).json(),
    );
    expect(
      (await workerCall(h, fresh, added.credentialId, 'claim', {}, { now: clock })).status,
    ).toBe(200);
    advance(86_400 + 1);
    await expectError(
      await workerCall(h, fresh, added.credentialId, 'claim', {}, { now: clock }),
      401,
      'unauthenticated',
    );
  });

  it('rate-limits each credential', async () => {
    const w = await registerWorker();
    await t.db.insert(schema.workerRequestNonces).values(
      Array.from({ length: WORKER_RATE_LIMIT_PER_MINUTE }, (_, i) => ({
        credentialId: w.keyId,
        nonce: `prefill-nonce-${String(i).padStart(4, '0')}`,
        createdAt: new Date(clock.getTime() - 30_000),
      })),
    );
    await expectError(
      await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock }),
      429,
      'rate_limited',
    );
    advance(31);
    expect((await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock })).status).toBe(200);
  });

  it('never accepts user sessions on the worker API', async () => {
    await expectError(
      await call('admin', 'POST', '/internal/worker/claim', {}),
      401,
      'unauthenticated',
    );
  });
});

describe('worker administration', () => {
  it('registers workers with validated public keys, admin only', async () => {
    const key = await generateWorkerKey();
    await expectError(
      await call('analyst', 'POST', '/workers', { name: 'home-1', publicKey: key.publicKey }),
      403,
      'forbidden',
    );
    await expectError(
      await call('admin', 'POST', '/workers', { name: 'home-1', publicKey: 'A'.repeat(43) + '=' }),
      400,
      'validation_failed',
    );
    await expectError(
      await call('admin', 'POST', '/workers', { name: 'Home 1', publicKey: key.publicKey }),
      400,
      'validation_failed',
    );
    const w = await registerWorker('home-1');
    await expectError(
      await call('admin', 'POST', '/workers', {
        name: 'home-1',
        publicKey: (await generateWorkerKey()).publicKey,
      }),
      409,
      'conflict',
    );
    const list = (await (await call('admin', 'GET', '/workers')).json()) as {
      items: { credentials: { fingerprint: string }[] }[];
    };
    expect(list.items[0]?.credentials[0]?.fingerprint).toMatch(/^([0-9a-f]{2}:){7}[0-9a-f]{2}$/);
    expect(JSON.stringify(list)).not.toContain(w.key.publicKey);
    expect(await auditActions()).toContain('worker.registered');
  });
});

describe('job lifecycle', () => {
  it('claims atomically: one job goes to exactly one worker', async () => {
    const a = await registerWorker('home-a');
    const b = await registerWorker('home-b');
    const d = await addDomain('example.com');
    await requestScan(d.id);
    const [ja, jb] = await Promise.all([claim(a), claim(b)]);
    const claimed = [ja, jb].filter(Boolean);
    expect(claimed).toHaveLength(1);
    expect(claimed[0]).toMatchObject({
      attempt: 1,
      profile: 'passive',
      leaseSeconds: LEASE_SECONDS,
    });
    expect(claimed[0]?.targets.map((x) => x.hostname)).toEqual(['example.com']);
    const [row] = await t.db.select().from(schema.scanJobs);
    expect(row).toMatchObject({ status: 'claimed', attempts: 1 });
  });

  it('runs heartbeat → results → complete, and treats duplicate result deliveries as no-ops', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com');
    const { job } = await requestScan(d.id);
    const claimed = await claim(w);
    const ref = { jobId: job.id, attempt: 1 };

    const hb = await workerCall(
      h,
      w.key,
      w.keyId,
      'heartbeat',
      { ...ref, progress: { completedTargets: 0, totalTargets: 1 } },
      { now: clock },
    );
    expect(await hb.json()).toMatchObject({ cancelRequested: false });

    const result = {
      ...ref,
      resultId: 'result-0001',
      targets: [{ targetId: claimed!.targets[0]!.id, status: 'succeeded' }],
      complete: true,
    };
    const first = await workerCall(h, w.key, w.keyId, 'results', result, { now: clock });
    expect(await first.json()).toEqual({ accepted: true, status: 'succeeded' });
    // Same result again (network retry): accepted false, nothing changes.
    const again = await workerCall(h, w.key, w.keyId, 'results', result, { now: clock });
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ accepted: false, status: 'succeeded' });

    const detail = scanJobDetailResponseSchema.parse(
      await (await call('viewer', 'GET', `/scans/${job.id}`)).json(),
    );
    expect(detail.job).toMatchObject({
      status: 'succeeded',
      progress: { completedTargets: 0, totalTargets: 1 },
    });
    expect(detail.targets[0]).toMatchObject({ status: 'succeeded' });
    expect(await t.db.select().from(schema.scanJobResults)).toHaveLength(1);
  });

  it('rejects results for targets outside the job snapshot and from a stale attempt', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com');
    const { job } = await requestScan(d.id);
    await claim(w);
    await expectError(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'results',
        {
          jobId: job.id,
          attempt: 1,
          resultId: 'result-0001',
          targets: [{ targetId: crypto.randomUUID(), status: 'succeeded' }],
          complete: false,
        },
        { now: clock },
      ),
      400,
      'validation_failed',
    );
    await expectError(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'heartbeat',
        { jobId: job.id, attempt: 2 },
        { now: clock },
      ),
      409,
      'conflict',
    );
  });

  it('requeues an expired lease with backoff, then fences out the old attempt', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com');
    const { job } = await requestScan(d.id);
    await claim(w);

    advance(LEASE_SECONDS + 1);
    await runMaintenance(t.db, clock, createLogger({}));
    let [row] = await t.db.select().from(schema.scanJobs);
    expect(row).toMatchObject({
      status: 'queued',
      errorCode: 'lease_expired',
      workerId: null,
      attempts: 1,
    });
    expect(row!.scheduledAt.getTime()).toBe(clock.getTime() + backoffSeconds(1) * 1000);

    expect(await claim(w)).toBeNull(); // still backing off
    advance(backoffSeconds(1));
    const second = await claim(w);
    expect(second?.attempt).toBe(2);

    // The first attempt's late heartbeat is refused.
    await expectError(
      await workerCall(
        h,
        w.key,
        w.keyId,
        'heartbeat',
        { jobId: job.id, attempt: 1 },
        { now: clock },
      ),
      409,
      'conflict',
    );
    [row] = await t.db.select().from(schema.scanJobs);
    expect(row?.attempts).toBe(2);
  });

  it('stops retrying at the attempt ceiling', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com');
    const { job } = await requestScan(d.id);
    for (let attempt = 1; attempt <= 3; attempt++) {
      const claimed = await claim(w);
      expect(claimed?.attempt).toBe(attempt);
      const res = await workerCall(
        h,
        w.key,
        w.keyId,
        'failures',
        {
          jobId: job.id,
          attempt,
          errorCode: 'dns_timeout',
          errorSummary: 'Resolver timed out',
          retryable: true,
        },
        { now: clock },
      );
      const body = (await res.json()) as { status: string; retryAt: string | null };
      expect(body.status).toBe(attempt < 3 ? 'queued' : 'failed');
      advance(backoffSeconds(attempt));
    }
    expect(await claim(w)).toBeNull();
    const detail = scanJobDetailResponseSchema.parse(
      await (await call('viewer', 'GET', `/scans/${job.id}`)).json(),
    );
    expect(detail.job).toMatchObject({ status: 'failed', attempts: 3, errorCode: 'dns_timeout' });
    expect(detail.targets[0]).toMatchObject({ status: 'failed', errorCode: 'dns_timeout' });
  });

  it('fails immediately on a non-retryable error', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com');
    const { job } = await requestScan(d.id);
    await claim(w);
    const res = await workerCall(
      h,
      w.key,
      w.keyId,
      'failures',
      {
        jobId: job.id,
        attempt: 1,
        errorCode: 'scope_rejected',
        errorSummary: 'Target resolved to a private address',
        retryable: false,
      },
      { now: clock },
    );
    expect(await res.json()).toEqual({ status: 'failed', retryAt: null });
  });

  it('cancels queued jobs immediately and running jobs via the heartbeat', async () => {
    const w = await registerWorker();
    const a = await addDomain('alpha.com');
    const b = await addDomain('bravo.com');
    const queued = (await requestScan(a.id)).job;
    const cancelled = scanJobDetailResponseSchema.parse(
      await (await call('analyst', 'POST', `/scans/${queued.id}/cancel`)).json(),
    );
    expect(cancelled.job.status).toBe('cancelled');
    expect(cancelled.targets[0]?.status).toBe('skipped');
    await expectError(await call('analyst', 'POST', `/scans/${queued.id}/cancel`), 409, 'conflict');

    const running = (await requestScan(b.id)).job;
    await claim(w);
    const flagged = scanJobDetailResponseSchema.parse(
      await (await call('analyst', 'POST', `/scans/${running.id}/cancel`)).json(),
    );
    expect(flagged.job).toMatchObject({ status: 'claimed' });
    expect(flagged.job.cancelRequestedAt).not.toBeNull();

    const hb = await workerCall(
      h,
      w.key,
      w.keyId,
      'heartbeat',
      { jobId: running.id, attempt: 1 },
      { now: clock },
    );
    expect(await hb.json()).toMatchObject({ cancelRequested: true });
    const res = await workerCall(
      h,
      w.key,
      w.keyId,
      'failures',
      {
        jobId: running.id,
        attempt: 1,
        errorCode: 'cancelled',
        errorSummary: 'Stopped on request',
        retryable: true,
      },
      { now: clock },
    );
    expect(await res.json()).toEqual({ status: 'cancelled', retryAt: null });
    expect(await auditActions()).toEqual(
      expect.arrayContaining(['scan.cancelled', 'scan.cancel_requested']),
    );
  });

  it('refuses at claim time an active job whose domain is no longer authorised', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com', { verified: true });
    const { job } = await requestScan(d.id, 'quick', ACTIVE_ON);
    await t.db
      .update(schema.domains)
      .set({ verificationStatus: 'revoked', verifiedAt: null, verificationMethod: null })
      .where(eq(schema.domains.id, d.id));
    expect(await claim(w, ACTIVE_ON)).toBeNull();
    const [row] = await t.db.select().from(schema.scanJobs).where(eq(schema.scanJobs.id, job.id));
    expect(row).toMatchObject({ status: 'cancelled', errorCode: 'domain_not_authorised' });
    expect(await auditActions()).toContain('scan.refused');
    const targets = await t.db.select().from(schema.scanJobTargets);
    expect(targets.map((x) => x.status)).toEqual(['skipped']);
  });

  it('does not hand out active jobs when active scanning is switched off after creation', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com', { verified: true });
    await requestScan(d.id, 'quick', ACTIVE_ON);
    expect(await claim(w)).toBeNull();
    const [row] = await t.db.select().from(schema.scanJobs);
    expect(row?.errorCode).toBe('active_scanning_disabled');
  });
});

describe('lifecycle edge cases', () => {
  it('refuses a scheduled job when monitoring was turned off while it waited', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com', { monitoring: true });
    await schedulePassiveMonitoring(t.db, clock);
    await t.db.update(schema.domains).set({ monitoringEnabled: false }).where(eq(schema.domains.id, d.id));
    expect(await claim(w)).toBeNull();
    const [row] = await t.db.select().from(schema.scanJobs);
    expect(row).toMatchObject({ status: 'cancelled', errorCode: 'monitoring_disabled' });
  });

  it('does not reveal another worker\'s job through a replayed result id', async () => {
    const a = await registerWorker('home-a');
    const b = await registerWorker('home-b');
    const d = await addDomain('example.com');
    const { job } = await requestScan(d.id);
    const claimed = await claim(a);
    const result = {
      jobId: job.id,
      attempt: 1,
      resultId: 'result-0001',
      targets: [{ targetId: claimed!.targets[0]!.id, status: 'succeeded' }],
      complete: false,
    };
    expect((await workerCall(h, a.key, a.keyId, 'results', result, { now: clock })).status).toBe(200);
    await expectError(await workerCall(h, b.key, b.keyId, 'results', result, { now: clock }), 409, 'conflict');
  });

  it('never moves a target out of a final status', async () => {
    const w = await registerWorker();
    const d = await addDomain('example.com');
    const { job } = await requestScan(d.id);
    const claimed = await claim(w);
    const targetId = claimed!.targets[0]!.id;
    const send = (resultId: string, status: string) =>
      workerCall(h, w.key, w.keyId, 'results', {
        jobId: job.id,
        attempt: 1,
        resultId,
        targets: [{ targetId, status }],
        complete: false,
      }, { now: clock });
    await send('result-0001', 'succeeded');
    await send('result-0002', 'running');
    const [target] = await t.db.select().from(schema.scanJobTargets);
    expect(target?.status).toBe('succeeded');
  });
});

describe('maintenance', () => {
  it('schedules one passive job per monitored domain per day, without duplicates', async () => {
    await addDomain('alpha.com', { monitoring: true });
    await addDomain('bravo.com', { monitoring: true });
    await addDomain('quiet.com');
    expect(await schedulePassiveMonitoring(t.db, clock)).toBe(2);
    expect(await schedulePassiveMonitoring(t.db, clock)).toBe(0);

    const jobs = await t.db.select().from(schema.scanJobs);
    expect(jobs.every((j) => j.profile === 'passive' && j.priority === 200)).toBe(true);
    expect(jobs.every((j) => (j.scopeSnapshot as { trigger: string }).trigger === 'schedule')).toBe(
      true,
    );
    expect(await t.db.select().from(schema.scanJobTargets)).toHaveLength(2);

    // Completed today: nothing new until the interval has passed.
    await t.db.update(schema.scanJobs).set({ status: 'succeeded', completedAt: clock });
    advance(3600);
    expect(await schedulePassiveMonitoring(t.db, clock)).toBe(0);
    advance(23 * 3600);
    expect(await schedulePassiveMonitoring(t.db, clock)).toBe(2);
    expect(await auditActions()).toEqual(['scan.scheduled', 'scan.scheduled']);
  });

  it('prunes nonces older than the signature window', async () => {
    const w = await registerWorker();
    await t.db.insert(schema.workerRequestNonces).values([
      {
        credentialId: w.keyId,
        nonce: 'old-nonce-0000000001',
        createdAt: new Date(clock.getTime() - 3_600_000),
      },
      { credentialId: w.keyId, nonce: 'new-nonce-0000000001', createdAt: clock },
    ]);
    expect(await pruneNonces(t.db, clock)).toBe(1);
  });
});
