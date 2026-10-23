// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { RATE_LIMITS, errorResponseSchema, type Role } from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const { domains, scanJobs } = schema;
const HOUR = 3600_000;
const ACTIVE_ON = { ACTIVE_SCANNING_ENABLED: 'true' };

let t: TestDatabase;
let clock: Date;
const h = harness(
  () => t,
  () => clock,
);
const call = (
  role: Role,
  method: string,
  path: string,
  body?: unknown,
  env?: Record<string, string>,
) => userCall(h, t, role, method, path, body, env);

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
  clock = new Date('2026-10-23T12:00:00.000Z');
  await t.db.delete(scanJobs);
  await t.db.delete(domains);
});
afterEach(() => vi.restoreAllMocks());

async function domain(fqdn: string) {
  const [d] = await t.db
    .insert(domains)
    .values({
      fqdn,
      verificationStatus: 'verified',
      verificationMethod: 'dns_txt',
      verifiedAt: clock,
    })
    .returning();
  return d!.id;
}

/** Finished past jobs (they do not block new ones via the one-active-job index). */
async function pastJobs(
  n: number,
  opts: {
    userId?: string | null;
    domainId?: string | null;
    ageMs?: number;
    jobType?: 'scan' | 'discovery';
    profile?: string;
    active?: boolean;
    trigger?: 'manual' | 'schedule';
  },
) {
  if (n === 0) return;
  const created = new Date(clock.getTime() - (opts.ageMs ?? 10 * 60_000));
  await t.db.insert(scanJobs).values(
    Array.from({ length: n }, (_, i) => ({
      jobType: opts.jobType ?? ('scan' as const),
      profile: opts.profile ?? 'passive',
      domainId: opts.domainId ?? null,
      status: 'succeeded' as const,
      requestedBy: opts.userId ?? null,
      scopeSnapshot: {
        version: 1,
        trigger: opts.trigger ?? 'manual',
        profile: { key: opts.profile ?? 'passive', config: { active: opts.active ?? false } },
      },
      // Spread one second apart, newest first.
      createdAt: new Date(created.getTime() - i * 1000),
      completedAt: created,
    })),
  );
}

const scan = (role: Role, domainId: string, profile = 'passive', env?: Record<string, string>) =>
  call(role, 'POST', `/domains/${domainId}/scans`, { profile }, env);

async function expectRateLimited(res: Response) {
  expect(res.status).toBe(429);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe('rate_limited');
  const retry = Number(res.headers.get('Retry-After'));
  expect(Number.isInteger(retry)).toBe(true);
  expect(retry).toBeGreaterThanOrEqual(1);
  return { retry, message: body.error.message };
}

describe('scan quota per user per hour', () => {
  it('refuses the request over the limit with an exact Retry-After, then allows it later', async () => {
    const analyst = await ensureUser(t, 'analyst');
    const d1 = await domain('quota-a.example');
    const d2 = await domain('quota-b.example');
    // limit - 1 earlier requests, 50 min old and older (one second apart).
    await pastJobs(RATE_LIMITS.scanRequestsPerUserPerHour - 1, {
      userId: analyst,
      ageMs: 50 * 60_000,
    });

    expect((await scan('analyst', d1)).status).toBe(202);
    const { retry, message } = await expectRateLimited(await scan('analyst', d2));
    expect(message).toContain(`${RATE_LIMITS.scanRequestsPerUserPerHour} scans per hour`);
    // Exact: the oldest counted job (50 min + 58 s old) leaves the one-hour window in 542 s.
    expect(retry).toBe(3600 - 50 * 60 - (RATE_LIMITS.scanRequestsPerUserPerHour - 2));
    // No job was created for the refused request.
    expect(await t.db.select().from(scanJobs).where(eq(scanJobs.domainId, d2))).toHaveLength(0);

    clock = new Date(clock.getTime() + retry * 1000);
    expect((await scan('analyst', d2)).status).toBe(202);
  });

  it('counts per user: another user is not affected', async () => {
    const analyst = await ensureUser(t, 'analyst');
    await pastJobs(RATE_LIMITS.scanRequestsPerUserPerHour, { userId: analyst });
    const d = await domain('quota-c.example');
    await expectRateLimited(await scan('analyst', d));
    expect((await scan('admin', d)).status).toBe(202);
  });

  it('does not count scheduled jobs or jobs older than an hour', async () => {
    const analyst = await ensureUser(t, 'analyst');
    await pastJobs(100, { userId: null, trigger: 'schedule' });
    await pastJobs(RATE_LIMITS.scanRequestsPerUserPerHour, { userId: analyst, ageMs: HOUR + 1000 });
    const d = await domain('quota-d.example');
    expect((await scan('analyst', d)).status).toBe(202);
  });

  it('counts discovery requests too', async () => {
    const analyst = await ensureUser(t, 'analyst');
    await pastJobs(RATE_LIMITS.scanRequestsPerUserPerHour, {
      userId: analyst,
      jobType: 'discovery',
      profile: 'discovery',
    });
    const d = await domain('quota-e.example');
    await expectRateLimited(await call('analyst', 'POST', `/domains/${d}/discovery`));
  });
});

describe('active scans per domain per day', () => {
  it('limits requested active scans per domain across users; passive scans stay allowed', async () => {
    const d = await domain('quota-active.example');
    const other = await domain('quota-other.example');
    const users = await Promise.all((['admin', 'analyst'] as const).map((r) => ensureUser(t, r)));
    // Spread across users; a day window.
    await pastJobs(RATE_LIMITS.activeScansPerDomainPerDay / 2, {
      userId: users[0]!,
      domainId: d,
      profile: 'quick',
      active: true,
      ageMs: 20 * HOUR,
    });
    await pastJobs(RATE_LIMITS.activeScansPerDomainPerDay / 2, {
      userId: users[1]!,
      domainId: d,
      profile: 'standard',
      active: true,
      ageMs: 2 * HOUR,
    });
    // Scheduled active scans do not count against the requested quota.
    await pastJobs(10, { domainId: other, profile: 'quick', active: true, trigger: 'schedule' });

    const { retry } = await expectRateLimited(await scan('admin', d, 'quick', ACTIVE_ON));
    // The oldest counted job (20 h old, newest-first spacing) leaves the window in ~4 h.
    expect(retry).toBeGreaterThan(3.9 * 3600);
    expect(retry).toBeLessThanOrEqual(4 * 3600 + 60);
    expect((await scan('admin', d, 'passive', ACTIVE_ON)).status).toBe(202);
    // Another domain is under its quota (it has no approved active targets, hence 409, not 429).
    expect((await scan('admin', other, 'quick', ACTIVE_ON)).status).not.toBe(429);
  });
});

describe('discovery per domain per day', () => {
  it('limits discovery requests per domain; an already queued job is returned without counting', async () => {
    const d = await domain('quota-disc.example');
    const analyst = await ensureUser(t, 'analyst');
    await pastJobs(RATE_LIMITS.discoveryPerDomainPerDay - 1, {
      userId: analyst,
      domainId: d,
      jobType: 'discovery',
      profile: 'discovery',
    });
    expect((await call('analyst', 'POST', `/domains/${d}/discovery`)).status).toBe(201);
    // Queued already: returned (200), not a new job, no quota error.
    expect((await call('analyst', 'POST', `/domains/${d}/discovery`)).status).toBe(200);
    await t.db
      .update(scanJobs)
      .set({ status: 'cancelled', completedAt: clock })
      .where(eq(scanJobs.status, 'queued'));
    await expectRateLimited(await call('admin', 'POST', `/domains/${d}/discovery`));
  });
});
