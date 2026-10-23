// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  DEFAULT_SCAN_SCHEDULE,
  RETENTION_POLICY,
  SCAN_SCHEDULE_SETTING_KEY,
  errorResponseSchema,
  opsAlertsResponseSchema,
  opsHealthResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createLogger } from '../lib/logger.ts';
import { runMaintenance } from '../services/maintenance.ts';
import { OPS_STATE_KEY, checkWorkerOutage, mergeOpsState } from '../services/ops.ts';
import { harness, userCall } from '../testing/harness.ts';

const { applicationSettings, domains, intelFeeds, scanJobTargets, scanJobs, workerRegistry } =
  schema;

const MIN = 60_000;
let t: TestDatabase;
let clock: Date;
const h = harness(
  () => t,
  () => clock,
);
const call = (role: Role, path: string, env?: Record<string, string>) =>
  userCall(h, t, role, 'GET', path, undefined, env);

let logs: { level: string; message: string; [k: string]: unknown }[] = [];

beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});
beforeEach(async () => {
  logs = [];
  const capture = (line: unknown) => {
    try {
      logs.push(JSON.parse(String(line)));
    } catch {
      // not a structured line
    }
  };
  vi.spyOn(console, 'log').mockImplementation(capture);
  vi.spyOn(console, 'warn').mockImplementation(capture);
  vi.spyOn(console, 'error').mockImplementation(capture);
  clock = new Date('2026-10-23T12:00:00.000Z');
  await t.db.delete(scanJobs);
  await t.db.delete(domains);
  await t.db.delete(workerRegistry);
  await t.db.delete(applicationSettings);
  await t.db.delete(intelFeeds);
});
afterEach(() => vi.restoreAllMocks());

const ago = (ms: number) => new Date(clock.getTime() - ms);

async function domain(fqdn = 'ops.example') {
  const [d] = await t.db.insert(domains).values({ fqdn }).returning();
  return d!.id;
}

async function worker(
  name: string,
  lastSeenAt: Date | null,
  status: 'active' | 'disabled' = 'active',
) {
  const [w] = await t.db
    .insert(workerRegistry)
    .values({ name, lastSeenAt, status, version: lastSeenAt ? '1.2.3' : null })
    .returning({ id: workerRegistry.id });
  return w!.id;
}

async function job(
  domainId: string | null,
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled',
  opts: {
    profile?: string;
    createdAgo?: number;
    runSeconds?: number;
    completedAgo?: number;
    errorCode?: string;
    workerId?: string;
  } = {},
) {
  const created = ago(opts.createdAgo ?? 2 * MIN);
  const finished = ['succeeded', 'failed', 'cancelled'].includes(status);
  const completed = finished ? ago(opts.completedAgo ?? MIN) : null;
  const started =
    completed && opts.runSeconds !== undefined
      ? new Date(completed.getTime() - opts.runSeconds * 1000)
      : status === 'running'
        ? created
        : null;
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
      startedAt: started,
      completedAt: completed,
      errorCode: opts.errorCode ?? null,
      ...(status === 'running'
        ? { workerId: opts.workerId, leaseExpiresAt: new Date(clock.getTime() + MIN), attempts: 1 }
        : {}),
    })
    .returning({ id: scanJobs.id });
  return row!.id;
}

describe('GET /ops/health', () => {
  it('requires settings:manage', async () => {
    for (const role of ['analyst', 'viewer', 'asset_owner'] as const) {
      const res = await call(role, '/ops/health');
      expect(res.status).toBe(403);
      expect(errorResponseSchema.parse(await res.json()).error.code).toBe('forbidden');
    }
  });

  it('reports workers, queue, scan rates, durations, failures and retention from stored state', async () => {
    const w1 = await worker('home-1', ago(MIN));
    await worker('home-2', ago(10 * MIN));
    await worker('home-3', ago(3 * 3600_000));
    await worker('spare', null);
    const d1 = await domain('a.example');
    const d2 = await domain('b.example');
    const d3 = await domain('c.example');

    await job(d1, 'queued', { createdAgo: 30 * MIN });
    await job(d2, 'queued', { createdAgo: 5 * MIN, profile: 'quick' });
    await job(d3, 'running', { workerId: w1 });
    // Last 24 h: 4 succeeded (10, 20, 30, 40 s), 1 failed, 1 cancelled.
    for (const [i, s] of [10, 20, 30, 40].entries()) {
      await job(null, 'succeeded', { runSeconds: s, completedAgo: (i + 1) * 3600_000 });
    }
    const failed = await job(null, 'failed', { errorCode: 'dns_timeout', completedAgo: 2 * MIN });
    await t.db.insert(scanJobTargets).values([
      {
        scanJobId: failed,
        targetHostname: 'x.a.example',
        status: 'failed',
        errorCode: 'dns_timeout',
        completedAt: ago(MIN),
      },
      {
        scanJobId: failed,
        targetHostname: 'y.a.example',
        status: 'failed',
        errorCode: 'tls_refused',
        completedAt: ago(MIN),
      },
    ]);
    await job(null, 'cancelled');
    // Older than 24 h, inside 7 days.
    await job(null, 'succeeded', { runSeconds: 100, completedAgo: 3 * 86_400_000 });
    await job(null, 'failed', { errorCode: 'old_error', completedAgo: 3 * 86_400_000 });
    await mergeOpsState(
      t.db,
      { retention: { lastRunAt: ago(MIN).toISOString(), deletedLastRun: 42 } },
      clock,
    );

    const res = await call('admin', '/ops/health');
    expect(res.status).toBe(200);
    const body = opsHealthResponseSchema.parse(await res.json());
    expect(body.generatedAt).toBe(clock.toISOString());
    expect(body.workers.map((w) => [w.name, w.status])).toEqual([
      ['home-1', 'online'],
      ['home-2', 'stale'],
      ['home-3', 'offline'],
      ['spare', 'never_seen'],
    ]);
    expect(body.queue).toEqual({
      queued: 2,
      running: 1,
      oldestQueuedAgeSeconds: 30 * 60,
      byProfile: [
        { profile: 'passive', queued: 1, running: 1 },
        { profile: 'quick', queued: 1, running: 0 },
      ],
    });
    expect(body.outage).toEqual({ active: false, since: null, queuedJobs: 2 });
    expect(body.scans.last24h).toEqual({
      succeeded: 4,
      failed: 1,
      cancelled: 1,
      successRate: 0.8,
      p50DurationSeconds: 25,
      p95DurationSeconds: 38.5,
    });
    expect(body.scans.last7d).toMatchObject({ succeeded: 5, failed: 2, cancelled: 1 });
    expect(body.failuresByCode).toEqual([
      { code: 'dns_timeout', count: 2 },
      { code: 'tls_refused', count: 1 },
    ]);
    expect(body.database.ok).toBe(true);
    expect(body.database.latencyMs).toBeGreaterThanOrEqual(0);
    expect(body.feeds.map((f) => f.feed)).toEqual(['endoflife', 'cisa_kev', 'nvd']);
    expect(body.retention).toEqual({
      lastRunAt: ago(MIN).toISOString(),
      deletedLastRun: 42,
      policy: RETENTION_POLICY,
    });
  });

  it('answers with empty statistics on an empty system', async () => {
    const body = opsHealthResponseSchema.parse(await (await call('admin', '/ops/health')).json());
    expect(body.scans.last24h).toEqual({
      succeeded: 0,
      failed: 0,
      cancelled: 0,
      successRate: null,
      p50DurationSeconds: null,
      p95DurationSeconds: null,
    });
    expect(body.queue.oldestQueuedAgeSeconds).toBeNull();
    expect(body.retention.lastRunAt).toBeNull();
  });
});

describe('worker outage', () => {
  const logger = createLogger({ test: true });
  const outageLogs = () => logs.filter((l) => String(l.message).startsWith('worker_outage_'));

  it('is not an outage when nothing is queued, even with no worker', async () => {
    await worker('home', ago(3 * 3600_000));
    expect(await checkWorkerOutage(t.db, clock, logger)).toBe(0);
    const body = opsHealthResponseSchema.parse(await (await call('admin', '/ops/health')).json());
    expect(body.outage.active).toBe(false);
  });

  it('logs started and ended exactly once per transition and exposes it in health and alerts', async () => {
    const w = await worker('home', ago(45 * MIN));
    await worker('disabled-but-fresh', ago(MIN), 'disabled');
    await job(await domain(), 'queued', { createdAgo: 60 * MIN });

    expect(await checkWorkerOutage(t.db, clock, logger)).toBe(1);
    expect(await checkWorkerOutage(t.db, clock, logger)).toBe(0);
    await runMaintenance(t.db, clock, logger);
    const started = outageLogs();
    expect(started).toHaveLength(1);
    expect(started[0]).toMatchObject({
      level: 'error',
      message: 'worker_outage_started',
      queuedJobs: 1,
      // last seen 45 min ago + 30 min threshold = 15 min ago (later than the oldest queued job)
      since: ago(15 * MIN).toISOString(),
    });

    const health = opsHealthResponseSchema.parse(await (await call('admin', '/ops/health')).json());
    expect(health.outage).toEqual({
      active: true,
      since: ago(15 * MIN).toISOString(),
      queuedJobs: 1,
    });
    const adminAlerts = opsAlertsResponseSchema.parse(
      await (await call('admin', '/ops/alerts')).json(),
    );
    expect(adminAlerts.alerts).toEqual([
      expect.objectContaining({
        kind: 'worker_outage',
        severity: 'critical',
        since: ago(15 * MIN).toISOString(),
      }),
    ]);
    expect(adminAlerts.alerts[0]!.message).toMatch(/1 job\(s\) are queued/);
    const viewerAlerts = opsAlertsResponseSchema.parse(
      await (await call('viewer', '/ops/alerts')).json(),
    );
    expect(viewerAlerts.alerts[0]!.message).toBe(
      'Scans are delayed. Administrators have been alerted.',
    );

    // The worker comes back.
    await t.db.update(workerRegistry).set({ lastSeenAt: clock }).where(eq(workerRegistry.id, w));
    clock = new Date(clock.getTime() + 5 * MIN);
    expect(await checkWorkerOutage(t.db, clock, logger)).toBe(1);
    expect(await checkWorkerOutage(t.db, clock, logger)).toBe(0);
    const all = outageLogs();
    expect(all).toHaveLength(2);
    expect(all[1]).toMatchObject({
      level: 'info',
      message: 'worker_outage_ended',
      durationSeconds: 20 * 60,
    });
    const [state] = await t.db
      .select()
      .from(applicationSettings)
      .where(eq(applicationSettings.key, OPS_STATE_KEY));
    expect((state!.value as { outageSince: string | null }).outageSince).toBeNull();
  });

  it('treats a never-seen worker as offline', async () => {
    await worker('new', null);
    await job(await domain(), 'queued', { createdAgo: 5 * MIN });
    expect(await checkWorkerOutage(t.db, clock, logger)).toBe(1);
    expect(outageLogs()[0]).toMatchObject({ since: ago(5 * MIN).toISOString() });
  });
});

describe('GET /ops/alerts', () => {
  it('is empty when everything is healthy, for every role', async () => {
    for (const role of ['admin', 'analyst', 'viewer', 'asset_owner'] as const) {
      const res = await call(role, '/ops/alerts');
      expect(res.status).toBe(200);
      expect(opsAlertsResponseSchema.parse(await res.json())).toEqual({ alerts: [] });
    }
  });

  it('raises feeds_stale for feeds without a success in 3 days (NVD only with pending work)', async () => {
    await t.db.insert(intelFeeds).values([
      {
        feed: 'endoflife',
        lastSuccessAt: ago(4 * 86_400_000),
        lastAttemptAt: ago(MIN),
        lastError: 'http_503',
      },
      { feed: 'cisa_kev', lastSuccessAt: ago(86_400_000), lastAttemptAt: ago(86_400_000) },
      // Idle NVD (nothing pending) is not stale.
      { feed: 'nvd', lastSuccessAt: ago(30 * 86_400_000), lastAttemptAt: ago(30 * 86_400_000) },
    ]);
    const admin = opsAlertsResponseSchema.parse(await (await call('admin', '/ops/alerts')).json());
    expect(admin.alerts).toEqual([
      {
        kind: 'feeds_stale',
        severity: 'warning',
        message: expect.stringContaining('endoflife (http_503)'),
        since: ago(86_400_000).toISOString(),
      },
    ]);
    expect(admin.alerts[0]!.message).not.toContain('nvd');
    const viewer = opsAlertsResponseSchema.parse(
      await (await call('viewer', '/ops/alerts')).json(),
    );
    expect(viewer.alerts[0]!.message).toBe('Vulnerability intelligence may be out of date.');
    expect(viewer.alerts[0]!.message).not.toContain('endoflife');
  });

  it('does not alert on feeds that were never attempted (fresh install)', async () => {
    const res = opsAlertsResponseSchema.parse(await (await call('admin', '/ops/alerts')).json());
    expect(res.alerts).toEqual([]);
  });

  it('raises active_scanning_disabled only when a schedule is enabled while the switch is off', async () => {
    await t.db.insert(applicationSettings).values({
      key: SCAN_SCHEDULE_SETTING_KEY,
      value: { ...DEFAULT_SCAN_SCHEDULE, enabled: true },
    });
    const off = opsAlertsResponseSchema.parse(await (await call('admin', '/ops/alerts')).json());
    expect(off.alerts.map((a) => a.kind)).toEqual(['active_scanning_disabled']);
    expect(off.alerts[0]!.message).toContain('ACTIVE_SCANNING_ENABLED');
    const viewer = opsAlertsResponseSchema.parse(
      await (await call('viewer', '/ops/alerts')).json(),
    );
    expect(viewer.alerts[0]!.message).toBe('Scheduled active scans are paused.');

    const on = opsAlertsResponseSchema.parse(
      await (await call('admin', '/ops/alerts', { ACTIVE_SCANNING_ENABLED: 'true' })).json(),
    );
    expect(on.alerts).toEqual([]);
  });
});
