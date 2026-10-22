// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { eq } from 'drizzle-orm';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Identity } from '../auth/types.ts';
import { resolveUser } from './users.ts';

let t: TestDatabase;
beforeEach(async () => {
  t = await createTestDatabase();
}, 30_000);
afterEach(async () => {
  await t.close();
});

const identity = (over: Partial<Identity> = {}): Identity => ({
  provider: 'cloudflare_access',
  subject: 'sub-1',
  email: 'alice@example.com',
  name: 'Alice',
  ...over,
});
const opts = (admins: string[] = []) => ({
  bootstrapAdminEmails: new Set(admins),
  requestId: 'req-1',
});

describe('resolveUser', () => {
  it('denies authenticated identities that are not provisioned', async () => {
    expect(await resolveUser(t.db, identity(), opts())).toEqual({
      ok: false,
      reason: 'not_provisioned',
    });
    expect(await t.db.select().from(schema.users)).toHaveLength(0);
  });

  it('bootstraps a listed email as administrator, once, with an audit record', async () => {
    const first = await resolveUser(t.db, identity(), opts(['alice@example.com']));
    expect(first).toMatchObject({ ok: true, created: true, user: { role: 'admin', email: 'alice@example.com' } });

    const second = await resolveUser(t.db, identity(), opts(['alice@example.com']));
    expect(second).toMatchObject({ ok: true, created: false });

    const audit = await t.db.select().from(schema.auditLogs);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ action: 'user.bootstrap_admin', actorType: 'system', requestId: 'req-1' });
  });

  it('binds a pre-provisioned user on first sign-in and keeps their role', async () => {
    await t.db.insert(schema.users).values({
      email: 'alice@example.com',
      role: 'analyst',
      authProvider: 'cloudflare_access',
    });
    const result = await resolveUser(t.db, identity(), opts());
    expect(result).toMatchObject({ ok: true, user: { role: 'analyst' } });

    const [row] = await t.db.select().from(schema.users);
    expect(row).toMatchObject({ authProviderSubject: 'sub-1', displayName: 'Alice' });
    expect(row!.lastLoginAt).toBeInstanceOf(Date);
  });

  it('refuses to re-bind an email already linked to another identity', async () => {
    await t.db.insert(schema.users).values({
      email: 'alice@example.com',
      authProvider: 'cloudflare_access',
      authProviderSubject: 'original-sub',
    });
    expect(await resolveUser(t.db, identity({ subject: 'attacker-sub' }), opts(['alice@example.com']))).toEqual({
      ok: false,
      reason: 'identity_conflict',
    });
  });

  it('denies deactivated users', async () => {
    await t.db.insert(schema.users).values({
      email: 'alice@example.com',
      authProvider: 'cloudflare_access',
      authProviderSubject: 'sub-1',
      isActive: false,
    });
    expect(await resolveUser(t.db, identity(), opts())).toEqual({ ok: false, reason: 'inactive' });
  });

  it('only refreshes last_login_at periodically', async () => {
    await resolveUser(t.db, identity(), { ...opts(['alice@example.com']), now: new Date('2026-10-22T00:00:00Z') });
    await resolveUser(t.db, identity(), { ...opts(), now: new Date('2026-10-22T00:05:00Z') });
    const [row] = await t.db.select().from(schema.users).where(eq(schema.users.email, 'alice@example.com'));
    expect(row!.lastLoginAt?.toISOString()).toBe('2026-10-22T00:00:00.000Z');
  });
});
