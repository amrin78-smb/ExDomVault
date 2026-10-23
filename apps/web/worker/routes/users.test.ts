// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  auditListResponseSchema,
  errorResponseSchema,
  userListResponseSchema,
  userResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.ts';
import { updateUser } from '../services/user-admin.ts';
import { ORIGIN, ensureUser, harness, userCall } from '../testing/harness.ts';

const { auditLogs, users } = schema;

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
  clock = new Date('2026-10-23T10:00:00.000Z');
  await t.db.delete(auditLogs);
  await t.db.delete(users);
});
afterEach(() => vi.restoreAllMocks());

const ROLES: readonly Role[] = ['admin', 'analyst', 'asset_owner', 'viewer'];
const MISSING = '00000000-0000-4000-8000-000000000000';

const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function expectError(res: Response, status: number, code: string, path?: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
  if (path) expect(body.error.details?.[0]?.path).toBe(path);
  return body.error;
}

/** Inserts a user directly (signed in unless `subject` is null). */
async function addUser(
  email: string,
  role: Role,
  over: Partial<typeof users.$inferInsert> = {},
): Promise<string> {
  const [row] = await t.db
    .insert(users)
    .values({
      email,
      role,
      authProvider: 'dev',
      authProviderSubject: `dev:${email}`,
      ...over,
    })
    .returning({ id: users.id });
  return row!.id;
}

const actions = async () =>
  (await t.db.select().from(auditLogs)).map((a) => ({ action: a.action, metadata: a.metadata }));

describe('permissions', () => {
  it('allows only administrators to manage users', async () => {
    const id = await addUser('someone@example.com', 'viewer');
    for (const role of ROLES) {
      const list = await call(role, 'GET', '/users');
      const get = await call(role, 'GET', `/users/${id}`);
      const create = await call(role, 'POST', '/users', {
        email: `n-${role}@x.test`,
        role: 'viewer',
      });
      const patch = await call(role, 'PATCH', `/users/${id}`, { displayName: 'X' });
      if (role === 'admin') {
        expect([list.status, get.status, create.status, patch.status]).toEqual([
          200, 200, 201, 200,
        ]);
      } else {
        for (const res of [list, get, create, patch]) await expectError(res, 403, 'forbidden');
      }
    }
  });

  it('keeps the assignee picker on findings:assign', async () => {
    expect((await call('analyst', 'GET', '/users/assignable')).status).toBe(200);
    await expectError(await call('viewer', 'GET', '/users/assignable'), 403, 'forbidden');
  });
});

describe('GET /users', () => {
  it('lists, filters and pages users', async () => {
    await addUser('bob@example.com', 'analyst', { displayName: 'Bob Builder' });
    await addUser('carol@example.com', 'viewer', { isActive: false, authProviderSubject: null });
    const all = userListResponseSchema.parse(await (await call('admin', 'GET', '/users')).json());
    expect(all.items.map((u) => u.email)).toEqual([
      'admin@example.com',
      'bob@example.com',
      'carol@example.com',
    ]);
    const carol = all.items.find((u) => u.email === 'carol@example.com')!;
    expect(carol).toMatchObject({ isActive: false, signedIn: false, lastLoginAt: null });

    const q = async (qs: string) =>
      userListResponseSchema.parse(await (await call('admin', 'GET', `/users?${qs}`)).json());
    expect((await q('q=builder')).items.map((u) => u.email)).toEqual(['bob@example.com']);
    expect((await q('role=analyst')).total).toBe(1);
    expect((await q('active=false')).items.map((u) => u.email)).toEqual(['carol@example.com']);
    const page = await q('pageSize=1&page=2');
    expect(page).toMatchObject({ total: 3, page: 2, pageSize: 1 });
    expect(page.items[0]!.email).toBe('bob@example.com');
    await expectError(await call('admin', 'GET', '/users?role=root'), 400, 'validation_failed');
  });

  it('returns one user, 404 for unknown or malformed ids', async () => {
    const id = await addUser('bob@example.com', 'analyst');
    const res = userResponseSchema.parse(await (await call('admin', 'GET', `/users/${id}`)).json());
    expect(res.user).toMatchObject({ id, email: 'bob@example.com', role: 'analyst' });
    await expectError(await call('admin', 'GET', `/users/${MISSING}`), 404, 'not_found');
    await expectError(await call('admin', 'GET', '/users/nope'), 404, 'not_found');
  });
});

describe('POST /users', () => {
  it('pre-provisions a user with a lowercased email, audited', async () => {
    const res = await call('admin', 'POST', '/users', {
      email: 'New.Person@Example.COM',
      displayName: 'New Person',
      role: 'asset_owner',
    });
    expect(res.status).toBe(201);
    const { user } = userResponseSchema.parse(await res.json());
    expect(user).toMatchObject({
      email: 'new.person@example.com',
      displayName: 'New Person',
      role: 'asset_owner',
      isActive: true,
      signedIn: false,
    });
    const [row] = await t.db.select().from(users).where(eq(users.id, user.id));
    expect(row).toMatchObject({ authProvider: 'dev', authProviderSubject: null });
    expect(await actions()).toEqual([
      {
        action: 'user.created',
        metadata: {
          email: 'new.person@example.com',
          role: 'asset_owner',
          displayName: 'New Person',
        },
      },
    ]);
  });

  it('rejects duplicates (case-insensitive) with 409 on email, without an audit row', async () => {
    await addUser('bob@example.com', 'viewer');
    await expectError(
      await call('admin', 'POST', '/users', { email: 'BOB@example.com', role: 'viewer' }),
      409,
      'conflict',
      'email',
    );
    expect(await actions()).toEqual([]);
  });

  it('validates the body', async () => {
    await expectError(
      await call('admin', 'POST', '/users', { email: 'not-an-email', role: 'viewer' }),
      400,
      'validation_failed',
      'email',
    );
    await expectError(
      await call('admin', 'POST', '/users', { email: 'a@b.test', role: 'root' }),
      400,
      'validation_failed',
      'role',
    );
    await expectError(
      await call('admin', 'POST', '/users', { email: 'a@b.test', role: 'viewer', isActive: false }),
      400,
      'validation_failed',
    );
  });
});

describe('PATCH /users/:id', () => {
  it('changes role, active flag and display name, auditing each change', async () => {
    const id = await addUser('bob@example.com', 'viewer');
    clock = new Date('2026-10-23T11:00:00.000Z');
    const res = await call('admin', 'PATCH', `/users/${id}`, {
      role: 'analyst',
      isActive: false,
      displayName: 'Bob',
    });
    expect(res.status).toBe(200);
    const { user } = userResponseSchema.parse(await res.json());
    expect(user).toMatchObject({
      role: 'analyst',
      isActive: false,
      displayName: 'Bob',
      updatedAt: clock.toISOString(),
    });
    expect(await actions()).toEqual(
      expect.arrayContaining([
        {
          action: 'user.role_changed',
          metadata: { email: 'bob@example.com', from: 'viewer', to: 'analyst' },
        },
        { action: 'user.deactivated', metadata: { email: 'bob@example.com' } },
        {
          action: 'user.updated',
          metadata: { email: 'bob@example.com', displayName: { from: null, to: 'Bob' } },
        },
      ]),
    );
    expect(await actions()).toHaveLength(3);

    await call('admin', 'PATCH', `/users/${id}`, { isActive: true });
    expect((await actions()).map((a) => a.action)).toContain('user.activated');
  });

  it('is a no-op without audit when nothing changes', async () => {
    const id = await addUser('bob@example.com', 'viewer', { displayName: 'Bob' });
    const res = await call('admin', 'PATCH', `/users/${id}`, {
      role: 'viewer',
      isActive: true,
      displayName: 'Bob',
    });
    expect(res.status).toBe(200);
    expect(await actions()).toEqual([]);
  });

  it('rejects an empty or unknown-field body and unknown users', async () => {
    const id = await addUser('bob@example.com', 'viewer');
    await expectError(await call('admin', 'PATCH', `/users/${id}`, {}), 400, 'validation_failed');
    await expectError(
      await call('admin', 'PATCH', `/users/${id}`, { email: 'x@y.test' }),
      400,
      'validation_failed',
    );
    await expectError(
      await call('admin', 'PATCH', `/users/${MISSING}`, { role: 'viewer' }),
      404,
      'not_found',
    );
  });

  it('refuses changing your own role or deactivating yourself', async () => {
    const self = await ensureUser(t, 'admin');
    await addUser('other-admin@example.com', 'admin');
    await expectError(
      await call('admin', 'PATCH', `/users/${self}`, { role: 'viewer' }),
      409,
      'conflict',
      'role',
    );
    await expectError(
      await call('admin', 'PATCH', `/users/${self}`, { isActive: false }),
      409,
      'conflict',
      'isActive',
    );
    // Unchanged role and own display name are allowed.
    const ok = await call('admin', 'PATCH', `/users/${self}`, { role: 'admin', displayName: 'Me' });
    expect(ok.status).toBe(200);
    expect((await actions()).map((a) => a.action)).toEqual(['user.updated']);
  });

  it('never demotes or deactivates the last active administrator', async () => {
    // Through the API the caller is always an active admin, so a lone target admin can only be
    // reached concurrently; the service guard itself is checked with an arbitrary actor.
    const only = await addUser('only@example.com', 'admin');
    await addUser('former@example.com', 'admin', { isActive: false });
    const actor = { userId: await addUser('ops@example.com', 'viewer'), requestId: 'req-1' };
    await expect(updateUser(t.db, only, { role: 'analyst' }, actor, clock)).rejects.toMatchObject({
      status: 409,
      code: 'conflict',
      details: [{ path: 'role' }],
    });
    await expect(updateUser(t.db, only, { isActive: false }, actor, clock)).rejects.toMatchObject({
      status: 409,
      details: [{ path: 'isActive' }],
    });
    // Renaming and re-asserting the role stay allowed.
    await expect(
      updateUser(t.db, only, { role: 'admin', displayName: 'Only' }, actor, clock),
    ).resolves.toMatchObject({ role: 'admin', displayName: 'Only' });
    const [row] = await t.db.select().from(users).where(eq(users.id, only));
    expect(row).toMatchObject({ role: 'admin', isActive: true });
    expect((await actions()).map((a) => a.action)).toEqual(['user.updated']);
  });

  it('lets only one of two concurrent cross-demotions succeed', async () => {
    const a = await ensureUser(t, 'admin');
    const b = await addUser('b-admin@example.com', 'admin');
    const asB = (path: string, body: unknown) =>
      createApp(h.deps).request(
        `/api/v1${path}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
          body: JSON.stringify(body),
        },
        h.env('admin', { DEV_AUTH_EMAIL: 'b-admin@example.com' }) as unknown as Env,
      );
    const [r1, r2] = await Promise.all([
      call('admin', 'PATCH', `/users/${b}`, { role: 'viewer' }),
      asB(`/users/${a}`, { role: 'viewer' }),
    ]);
    const statuses = [r1.status, r2.status].sort();
    expect(statuses).toEqual([200, 409]);
    const loser = r1.status === 409 ? r1 : r2;
    await expectError(loser, 409, 'conflict', 'role');
    const admins = await t.db.select().from(users).where(eq(users.role, 'admin'));
    expect(admins).toHaveLength(1);
    expect((await actions()).map((x) => x.action)).toEqual(['user.role_changed']);
  });

  it('lets only one of two concurrent cross-deactivations succeed', async () => {
    const a = await ensureUser(t, 'admin');
    const b = await addUser('b-admin@example.com', 'admin');
    const asB = (path: string, body: unknown) =>
      createApp(h.deps).request(
        `/api/v1${path}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
          body: JSON.stringify(body),
        },
        h.env('admin', { DEV_AUTH_EMAIL: 'b-admin@example.com' }) as unknown as Env,
      );
    const [r1, r2] = await Promise.all([
      call('admin', 'PATCH', `/users/${b}`, { isActive: false }),
      asB(`/users/${a}`, { isActive: false }),
    ]);
    expect([r1.status, r2.status].sort()).toEqual([200, 409]);
    const active = await t.db.select().from(users).where(eq(users.isActive, true));
    expect(active.filter((u) => u.role === 'admin')).toHaveLength(1);
  });
});

describe('deactivated users', () => {
  it('are refused at authentication (403) and can be reactivated', async () => {
    const id = await ensureUser(t, 'analyst');
    expect((await call('admin', 'PATCH', `/users/${id}`, { isActive: false })).status).toBe(200);
    const denied = await expectError(await call('analyst', 'GET', '/me'), 403, 'forbidden');
    expect(denied.message).toMatch(/deactivated/);
    expect((await call('admin', 'PATCH', `/users/${id}`, { isActive: true })).status).toBe(200);
    expect((await call('analyst', 'GET', '/me')).status).toBe(200);
  });

  it('a pre-provisioned user binds on first sign-in and then shows as signed in', async () => {
    const res = await call('admin', 'POST', '/users', {
      email: 'viewer@example.com',
      role: 'viewer',
    });
    const { user } = userResponseSchema.parse(await res.json());
    expect(user.signedIn).toBe(false);
    // userCall would upsert the row; sign in directly with the dev identity instead.
    const me = await createApp(h.deps).request('/api/v1/me', {}, h.env('viewer') as unknown as Env);
    expect(me.status).toBe(200);
    const after = userResponseSchema.parse(
      await (await call('admin', 'GET', `/users/${user.id}`)).json(),
    );
    expect(after.user).toMatchObject({ signedIn: true, role: 'viewer' });
    expect(after.user.lastLoginAt).not.toBeNull();
  });
});

describe('audit trail', () => {
  it('is readable through GET /audit-logs', async () => {
    await call('admin', 'POST', '/users', { email: 'z@example.com', role: 'viewer' });
    const log = auditListResponseSchema.parse(
      await (await call('admin', 'GET', '/audit-logs?action=user.')).json(),
    );
    expect(log.items.map((e) => e.action)).toEqual(['user.created']);
    expect(log.items[0]!.actor?.email).toBe('admin@example.com');
  });
});
