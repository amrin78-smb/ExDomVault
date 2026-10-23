// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  DEFAULT_SCAN_SCHEDULE,
  SCAN_SCHEDULE_SETTING_KEY,
  claimResponseSchema,
  errorResponseSchema,
  scanScheduleResponseSchema,
  workerCredentialCreatedResponseSchema,
  type Role,
  type ScanSchedule,
  type ScopeSnapshot,
} from '@exdomainvault/shared';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createLogger } from '../lib/logger.ts';
import { runMaintenance } from '../services/maintenance.ts';
import {
  ACTIVE_SCHEDULE_BATCH,
  ACTIVE_SCHEDULE_PRIORITY,
  scheduleActiveScans,
} from '../services/scan-schedule.ts';
import {
  ensureUser,
  generateWorkerKey,
  harness,
  userCall,
  workerCall,
} from '../testing/harness.ts';

const { applicationSettings, approvedNetworks, assets, auditLogs, domains, scanJobs } = schema;

let t: TestDatabase;
let clock: Date;
const h = harness(
  () => t,
  () => clock,
);
const ACTIVE_ON = { ACTIVE_SCANNING_ENABLED: 'true' };
const ON = { activeScanningEnabled: true };
const DAY = 86_400_000;

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
  await t.db.delete(scanJobs);
  await t.db.delete(assets);
  await t.db.delete(domains);
  await t.db.delete(approvedNetworks);
  await t.db.delete(applicationSettings);
  await t.db.delete(schema.workerRegistry);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const call = (
  role: Role,
  method: string,
  path: string,
  body?: unknown,
  env?: Record<string, string>,
) => userCall(h, t, role, method, path, body, env);

type Auth = 'dns' | 'admin' | 'lapsed' | 'revoked' | 'none';

async function addDomain(fqdn: string, opts: { auth?: Auth; monitoring?: boolean } = {}) {
  const auth = opts.auth ?? 'dns';
  const verified =
    auth === 'dns'
      ? {
          verificationStatus: 'verified' as const,
          verifiedAt: clock,
          verificationMethod: 'dns_txt' as const,
        }
      : auth === 'admin' || auth === 'lapsed'
        ? {
            verificationStatus: 'verified' as const,
            verifiedAt: clock,
            verificationMethod: 'admin_attestation' as const,
            verificationExpiresAt: new Date(clock.getTime() + (auth === 'admin' ? 30 : -1) * DAY),
          }
        : auth === 'revoked'
          ? { verificationStatus: 'revoked' as const }
          : {};
  const [d] = await t.db
    .insert(domains)
    .values({ fqdn, monitoringEnabled: opts.monitoring ?? true, ...verified })
    .returning();
  if (!d) throw new Error('domain');
  return d;
}

/** Enables the schedule as the admin user (the accountable approver for implicit apex approval). */
async function setSchedule(s: Partial<ScanSchedule>, by: 'admin' | null = 'admin') {
  const value = { ...DEFAULT_SCAN_SCHEDULE, enabled: true, ...s };
  const updatedBy = by ? await ensureUser(t, by) : null;
  await t.db
    .insert(applicationSettings)
    .values({ key: SCAN_SCHEDULE_SETTING_KEY, value, updatedBy })
    .onConflictDoUpdate({ target: applicationSettings.key, set: { value, updatedBy } });
}

/** A finished job of the profile created `ageMs` ago, so the domain is due regardless of its slot. */
async function pastJob(domainId: string, ageMs: number, profile = 'quick') {
  await t.db.insert(scanJobs).values({
    jobType: 'scan',
    profile,
    domainId,
    status: 'succeeded',
    scopeSnapshot: { version: 1, trigger: 'manual' },
    createdAt: new Date(clock.getTime() - ageMs),
    completedAt: new Date(clock.getTime() - ageMs + 60_000),
  });
}

const queued = () => t.db.select().from(scanJobs).where(eq(scanJobs.status, 'queued'));

describe('scheduled active scans', () => {
  it('is disabled by default', async () => {
    const d = await addDomain('example.com');
    await pastJob(d.id, 2 * DAY);
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(0);
    await runMaintenance(t.db, clock, createLogger({}), { activeScanningEnabled: true });
    expect((await queued()).filter((j) => j.profile === 'quick')).toHaveLength(0);
  });

  it('schedules nothing while the server switch is off', async () => {
    const d = await addDomain('example.com');
    await pastJob(d.id, 2 * DAY);
    await setSchedule({});
    expect(await scheduleActiveScans(t.db, clock, { activeScanningEnabled: false })).toBe(0);
    // runMaintenance without the option fails closed.
    await runMaintenance(t.db, clock, createLogger({}));
    expect((await queued()).filter((j) => j.profile === 'quick')).toHaveLength(0);
    await runMaintenance(t.db, clock, createLogger({}), { activeScanningEnabled: true });
    expect((await queued()).filter((j) => j.profile === 'quick')).toHaveLength(1);
  });

  it('only schedules monitored domains currently authorised for active scanning', async () => {
    const ok = await addDomain('dns.example.com');
    const admin = await addDomain('admin.example.com', { auth: 'admin' });
    const others = [
      await addDomain('lapsed.example.com', { auth: 'lapsed' }),
      await addDomain('revoked.example.com', { auth: 'revoked' }),
      await addDomain('unverified.example.com', { auth: 'none' }),
      await addDomain('unmonitored.example.com', { monitoring: false }),
    ];
    for (const d of [ok, admin, ...others]) await pastJob(d.id, 2 * DAY);
    await setSchedule({});
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(2);
    expect(new Set((await queued()).map((j) => j.domainId))).toEqual(new Set([ok.id, admin.id]));
  });

  it('snapshots approved targets and networks like a user-requested active scan', async () => {
    const d = await addDomain('example.com');
    await pastJob(d.id, 2 * DAY, 'standard');
    await t.db.insert(assets).values([
      {
        domainId: d.id,
        hostname: 'www.example.com',
        assetType: 'subdomain',
        discoverySource: 'manual',
        verificationStatus: 'approved',
        approvedBy: await ensureUser(t, 'admin'),
        approvedAt: clock,
      },
      {
        domainId: d.id,
        hostname: 'dev.example.com',
        assetType: 'subdomain',
        discoverySource: 'certificate_transparency',
        verificationStatus: 'pending',
      },
    ]);
    await t.db.insert(approvedNetworks).values({
      cidr: '198.51.100.0/24',
      label: 'Origin',
      reason: 'Owned range',
      createdAt: clock,
      expiresAt: new Date(clock.getTime() + 30 * DAY),
    });
    await setSchedule({ profile: 'standard' });
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(1);

    const [job] = await queued();
    expect(job).toMatchObject({
      jobType: 'scan',
      profile: 'standard',
      priority: ACTIVE_SCHEDULE_PRIORITY,
      reason: 'Scheduled standard scan',
      requestedBy: null,
    });
    const snapshot = job?.scopeSnapshot as ScopeSnapshot;
    expect(snapshot.trigger).toBe('schedule');
    expect(snapshot.requestedBy).toBeNull();
    expect(snapshot.profile.config.active).toBe(true);
    expect(snapshot.approvedNetworks).toEqual(['198.51.100.0/24']);
    expect(snapshot.targets.map((x) => x.hostname).sort()).toEqual([
      'example.com',
      'www.example.com',
    ]);
    const targets = await t.db
      .select()
      .from(schema.scanJobTargets)
      .where(eq(schema.scanJobTargets.scanJobId, job?.id ?? ''));
    expect(targets.map((x) => x.targetHostname).sort()).toEqual(['example.com', 'www.example.com']);
    expect(targets.every((x) => x.assetId !== null)).toBe(true);

    // The apex was approved implicitly by the system, audited; then one run-level audit row.
    const audit = await t.db.select().from(auditLogs).orderBy(auditLogs.createdAt);
    const apex = audit.find((a) => a.action === 'asset.approved');
    const adminId = await ensureUser(t, 'admin');
    expect(apex).toMatchObject({ actorType: 'system', actorUserId: null });
    expect(apex?.metadata).toMatchObject({
      basis: 'domain_verification',
      hostname: 'example.com',
      trigger: 'schedule',
      onBehalfOf: adminId,
    });
    const [apexRow] = await t.db.select().from(assets).where(eq(assets.hostname, 'example.com'));
    expect(apexRow).toMatchObject({ verificationStatus: 'approved', approvedBy: adminId });
    const runs = audit.filter((a) => a.action === 'scan.scheduled');
    expect(runs).toHaveLength(1);
    expect(runs[0]?.metadata).toMatchObject({ profile: 'standard', jobs: 1, jobIds: [job?.id] });
  });

  it('is re-checked at claim time like any active job', async () => {
    const key = await generateWorkerKey();
    const reg = workerCredentialCreatedResponseSchema.parse(
      await (
        await call('admin', 'POST', '/workers', { name: 'home-1', publicKey: key.publicKey })
      ).json(),
    );
    const d = await addDomain('example.com');
    await pastJob(d.id, 2 * DAY);
    await setSchedule({});
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(1);
    await t.db
      .update(domains)
      .set({ verificationStatus: 'revoked', verifiedAt: null, verificationMethod: null })
      .where(eq(domains.id, d.id));
    const res = await workerCall(
      h,
      key,
      reg.credentialId,
      'claim',
      {},
      {
        now: clock,
        envExtra: ACTIVE_ON,
      },
    );
    expect(claimResponseSchema.parse(await res.json()).job).toBeNull();
    const [row] = await t.db
      .select()
      .from(scanJobs)
      .where(eq(scanJobs.reason, 'Scheduled quick scan'));
    expect(row).toMatchObject({ status: 'cancelled', errorCode: 'domain_not_authorised' });
  });

  it('honours the interval, counts manual jobs and never duplicates', async () => {
    const d = await addDomain('example.com');
    await pastJob(d.id, 2 * DAY); // a manual run two days ago
    await setSchedule({ intervalDays: 3 });
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(0); // within the interval

    clock = new Date(clock.getTime() + DAY + 60_000);
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(1);
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(0); // queued: no duplicate
    await t.db
      .update(scanJobs)
      .set({ status: 'succeeded', completedAt: clock })
      .where(eq(scanJobs.status, 'queued'));
    clock = new Date(clock.getTime() + 2 * DAY);
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(0); // finished, but within 3 days
    clock = new Date(clock.getTime() + DAY);
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(1);
    expect(await t.db.select().from(scanJobs)).toHaveLength(3);
  });

  it('does not queue behind a running job of the profile (one active job per domain)', async () => {
    const d = await addDomain('example.com');
    await pastJob(d.id, 2 * DAY);
    const res = await call(
      'analyst',
      'POST',
      `/domains/${d.id}/scans`,
      { profile: 'quick' },
      ACTIVE_ON,
    );
    expect(res.status).toBe(202);
    await t.db
      .update(scanJobs)
      .set({ createdAt: new Date(clock.getTime() - 2 * DAY) })
      .where(eq(scanJobs.status, 'queued'));
    await setSchedule({});
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(0);
    expect(await queued()).toHaveLength(1);
  });

  it('staggers domains without history across the interval by their slot', async () => {
    const ids: string[] = [];
    for (let i = 0; i < 6; i++) ids.push((await addDomain(`d${i}.example.com`)).id);
    await setSchedule({ intervalDays: 1 });
    const slots = new Map<string, number>(
      (
        await t.db
          .select({
            id: domains.id,
            slot: sql<number>`(abs(hashtext(${domains.id}::text)::bigint) % 86400)::int`,
          })
          .from(domains)
      ).map((r) => [r.id, Number(r.slot)]),
    );
    const start = new Date('2026-10-22T00:00:00.000Z').getTime();
    const ticks: number[] = [];
    for (let m = 0; m < 24 * 60; m += 30) {
      clock = new Date(start + m * 60_000);
      ticks.push(clock.getTime());
      await scheduleActiveScans(t.db, clock, ON);
    }
    const jobs = await t.db.select().from(scanJobs);
    // Each domain was queued exactly once, at the first tick at or after its slot.
    for (const id of ids) {
      const slot = slots.get(id) ?? 0;
      const expected = ticks.find((ms) => (ms - start) / 1000 >= slot);
      const mine = jobs.filter((j) => j.domainId === id);
      expect(mine.map((j) => j.createdAt.getTime())).toEqual(expected ? [expected] : []);
    }
  });

  it('caps the jobs per run, least recently scanned first', async () => {
    const n = ACTIVE_SCHEDULE_BATCH + 5;
    const rows = await t.db
      .insert(domains)
      .values(
        Array.from({ length: n }, (_, i) => ({
          fqdn: `c${String(i).padStart(2, '0')}.example.com`,
          monitoringEnabled: true,
          verificationStatus: 'verified' as const,
          verifiedAt: clock,
          verificationMethod: 'dns_txt' as const,
        })),
      )
      .returning({ id: domains.id, fqdn: domains.fqdn });
    // The last domain has the most recent previous job: it is left for the next run.
    for (const [i, d] of rows.entries()) await pastJob(d.id, (10 - i / 10) * DAY);
    await setSchedule({});
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(ACTIVE_SCHEDULE_BATCH);
    const first = new Set((await queued()).map((j) => j.domainId));
    expect(first.has(rows[n - 1]?.id ?? '')).toBe(false);
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(5);
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(0);
    expect(await queued()).toHaveLength(n);
    const runs = await t.db.select().from(auditLogs).where(eq(auditLogs.action, 'scan.scheduled'));
    expect(runs).toHaveLength(2);
  });

  it('a failing domain does not stop the others', async () => {
    const a = await addDomain('a.example.com');
    const b = await addDomain('b.example.com');
    for (const d of [a, b]) await pastJob(d.id, 2 * DAY);
    // a's apex was explicitly rejected and it has no other approved asset: no targets.
    await t.db.insert(assets).values({
      domainId: a.id,
      hostname: 'a.example.com',
      assetType: 'apex',
      discoverySource: 'manual',
      verificationStatus: 'rejected',
    });
    await setSchedule({});
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(1);
    expect((await queued()).map((j) => j.domainId)).toEqual([b.id]);
    const [run] = await t.db.select().from(auditLogs).where(eq(auditLogs.action, 'scan.scheduled'));
    expect(run?.metadata).toMatchObject({ jobs: 1, skipped: { no_targets: 1 }, failed: 0 });
  });
  it('never approves the apex implicitly without an accountable administrator', async () => {
    const d = await addDomain('example.com');
    await pastJob(d.id, 2 * DAY);
    await setSchedule({}, null); // e.g. the administrator who enabled it was deleted
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(0);
    expect(await t.db.select().from(assets)).toHaveLength(0);
    const [run] = await t.db.select().from(auditLogs).where(eq(auditLogs.action, 'scan.scheduled'));
    expect(run?.metadata).toMatchObject({ jobs: 0, skipped: { no_targets: 1 } });
  });
});

describe('GET/PUT /settings/scan-schedule', () => {
  it('returns the default schedule and live counts', async () => {
    const d = await addDomain('example.com');
    await addDomain('other.example.com', { auth: 'none' });
    await addDomain('off.example.com', { monitoring: false });
    const res = await call('viewer', 'GET', '/settings/scan-schedule');
    expect(res.status).toBe(200);
    expect(scanScheduleResponseSchema.parse(await res.json())).toEqual({
      schedule: DEFAULT_SCAN_SCHEDULE,
      updatedAt: null,
      updatedBy: null,
      eligibleDomains: 1,
      activeScanningEnabled: false,
      scheduledLast24h: 0,
    });

    await pastJob(d.id, 2 * DAY);
    await setSchedule({});
    await scheduleActiveScans(t.db, clock, ON);
    const body = scanScheduleResponseSchema.parse(
      await (await call('analyst', 'GET', '/settings/scan-schedule', undefined, ACTIVE_ON)).json(),
    );
    expect(body).toMatchObject({ activeScanningEnabled: true, scheduledLast24h: 1 });
    expect(body.schedule.enabled).toBe(true);
  });

  it('enforces permissions per role', async () => {
    const put = { enabled: true, profile: 'quick', intervalDays: 2 };
    expect((await call('asset_owner', 'GET', '/settings/scan-schedule')).status).toBe(403);
    for (const role of ['viewer', 'analyst', 'asset_owner'] as const) {
      const res = await call(role, 'PUT', '/settings/scan-schedule', put);
      expect(res.status).toBe(403);
      expect(errorResponseSchema.parse(await res.json()).error.code).toBe('forbidden');
    }
    expect(await t.db.select().from(applicationSettings)).toHaveLength(0);
    expect((await call('admin', 'PUT', '/settings/scan-schedule', put)).status).toBe(200);
  });

  it('validates the body', async () => {
    for (const bad of [
      { enabled: true, profile: 'deep', intervalDays: 1 },
      { enabled: true, profile: 'passive', intervalDays: 1 },
      { enabled: true, profile: 'quick', intervalDays: 0 },
      { enabled: true, profile: 'quick', intervalDays: 31 },
      { enabled: true, profile: 'quick', intervalDays: 1.5 },
      { enabled: 'yes', profile: 'quick', intervalDays: 1 },
      { enabled: true, profile: 'quick' },
      { enabled: true, profile: 'quick', intervalDays: 1, extra: 1 },
    ]) {
      const res = await call('admin', 'PUT', '/settings/scan-schedule', bad);
      expect(res.status).toBe(400);
      expect(errorResponseSchema.parse(await res.json()).error.code).toBe('validation_failed');
    }
    expect(await t.db.select().from(applicationSettings)).toHaveLength(0);
  });

  it('saves while the server switch is off, audits before/after and reports who changed it', async () => {
    const first = { enabled: true, profile: 'standard', intervalDays: 7 } as const;
    const res = await call('admin', 'PUT', '/settings/scan-schedule', first);
    expect(res.status).toBe(200);
    const body = scanScheduleResponseSchema.parse(await res.json());
    expect(body.schedule).toEqual(first);
    expect(body.activeScanningEnabled).toBe(false);
    expect(body.updatedBy?.email).toBe('admin@example.com');
    expect(body.updatedAt).toBe(clock.toISOString());

    // Nothing is scheduled while the switch is off, even though the schedule is enabled.
    const d = await addDomain('example.com');
    await pastJob(d.id, 30 * DAY, 'standard');
    await runMaintenance(t.db, clock, createLogger({}));
    expect((await queued()).filter((j) => j.profile === 'standard')).toHaveLength(0);

    const second = { enabled: false, profile: 'quick', intervalDays: 1 } as const;
    expect((await call('admin', 'PUT', '/settings/scan-schedule', second)).status).toBe(200);
    const [row] = await t.db
      .select()
      .from(applicationSettings)
      .where(eq(applicationSettings.key, SCAN_SCHEDULE_SETTING_KEY));
    expect(row?.value).toEqual(second);
    const audits = await t.db
      .select()
      .from(auditLogs)
      .where(and(eq(auditLogs.action, 'settings.scan_schedule_updated')))
      .orderBy(auditLogs.createdAt);
    expect(audits.map((a) => a.metadata)).toEqual([
      { key: SCAN_SCHEDULE_SETTING_KEY, before: null, after: first },
      { key: SCAN_SCHEDULE_SETTING_KEY, before: first, after: second },
    ]);
    expect(
      audits.every((a) => a.actorType === 'user' && a.actorUserId === body.updatedBy?.id),
    ).toBe(true);
  });

  it('treats an invalid stored value as disabled', async () => {
    await t.db
      .insert(applicationSettings)
      .values({ key: SCAN_SCHEDULE_SETTING_KEY, value: { enabled: true, profile: 'deep' } });
    const d = await addDomain('example.com');
    await pastJob(d.id, 2 * DAY);
    expect(await scheduleActiveScans(t.db, clock, ON)).toBe(0);
    const body = scanScheduleResponseSchema.parse(
      await (await call('viewer', 'GET', '/settings/scan-schedule')).json(),
    );
    expect(body.schedule.enabled).toBe(false);
  });
});
