// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { auditListResponseSchema, errorResponseSchema, type Role } from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const { auditLogs } = schema;

let t: TestDatabase;
const clock = new Date('2026-10-23T10:00:00.000Z');
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

let analystId: string;

beforeEach(async () => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  await t.db.delete(auditLogs);
  analystId = await ensureUser(t, 'analyst');
  const at = (minute: number) => new Date(`2026-10-20T10:${String(minute).padStart(2, '0')}:00Z`);
  await t.db.insert(auditLogs).values([
    {
      actorType: 'user',
      actorUserId: analystId,
      action: 'finding.status_changed',
      resourceType: 'finding',
      resourceId: 'f-1',
      requestId: 'req-1',
      metadata: { from: 'open', to: 'acknowledged' },
      createdAt: at(1),
    },
    {
      actorType: 'user',
      actorUserId: analystId,
      action: 'finding.assigned',
      resourceType: 'finding',
      resourceId: 'f-2',
      createdAt: at(2),
    },
    {
      actorType: 'system',
      action: 'finding.status_changed',
      resourceType: 'finding',
      resourceId: 'f-1',
      createdAt: at(3),
    },
    {
      actorType: 'worker',
      action: 'scan.completed',
      resourceType: 'scan_job',
      resourceId: 'j-1',
      createdAt: at(4),
    },
    // `_` must not act as a LIKE wildcard in the prefix filter.
    { actorType: 'system', action: 'scanXjob.created', resourceType: 'scan_job', createdAt: at(5) },
  ]);
});
afterEach(() => vi.restoreAllMocks());

const list = async (qs = '') => {
  const res = await userCall(h, t, 'admin', 'GET', `/audit-logs${qs}`);
  expect(res.status).toBe(200);
  return auditListResponseSchema.parse(await res.json());
};

describe('GET /audit-logs', () => {
  it('requires audit:read (administrators only)', async () => {
    for (const role of ['analyst', 'asset_owner', 'viewer'] as Role[]) {
      const res = await userCall(h, t, role, 'GET', '/audit-logs');
      expect(res.status).toBe(403);
      expect(errorResponseSchema.parse(await res.json()).error.code).toBe('forbidden');
    }
  });

  it('lists newest first with the actor email', async () => {
    const res = await list();
    expect(res.total).toBe(5);
    expect(res.items.map((e) => e.action)).toEqual([
      'scanXjob.created',
      'scan.completed',
      'finding.status_changed',
      'finding.assigned',
      'finding.status_changed',
    ]);
    const first = res.items[4]!;
    expect(first).toMatchObject({
      actorType: 'user',
      actor: { id: analystId, email: 'analyst@example.com' },
      resourceType: 'finding',
      resourceId: 'f-1',
      requestId: 'req-1',
      metadata: { from: 'open', to: 'acknowledged' },
      createdAt: '2026-10-20T10:01:00.000Z',
    });
    expect(res.items[0]!.actor).toBeNull();
  });

  it('filters by exact action, action prefix, resource, actor and time range', async () => {
    expect((await list('?action=finding.status_changed')).total).toBe(2);
    expect((await list('?action=finding.')).items.map((e) => e.action)).toEqual([
      'finding.status_changed',
      'finding.assigned',
      'finding.status_changed',
    ]);
    expect((await list('?action=finding')).total).toBe(0);
    expect((await list('?action=scan_job.')).total).toBe(0);
    expect((await list('?resourceType=finding&resourceId=f-1')).total).toBe(2);
    expect((await list(`?actorUserId=${analystId}`)).total).toBe(2);
    expect((await list('?actorType=worker')).items.map((e) => e.action)).toEqual([
      'scan.completed',
    ]);
    const range = await list('?from=2026-10-20T10:02:00Z&to=2026-10-20T10:03:00Z');
    expect(range.items.map((e) => e.createdAt)).toEqual([
      '2026-10-20T10:03:00.000Z',
      '2026-10-20T10:02:00.000Z',
    ]);
    const page = await list('?pageSize=2&page=2');
    expect(page).toMatchObject({ total: 5, page: 2, pageSize: 2 });
    expect(page.items).toHaveLength(2);
  });

  it('validates the query', async () => {
    for (const qs of ['?action=DROP%20TABLE', '?actorUserId=nope', '?from=yesterday']) {
      const res = await userCall(h, t, 'admin', 'GET', `/audit-logs${qs}`);
      expect(res.status).toBe(400);
      expect(errorResponseSchema.parse(await res.json()).error.code).toBe('validation_failed');
    }
  });
});
