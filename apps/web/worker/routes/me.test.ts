// @vitest-environment node
// GET /me (Milestone 13): the organisation label from the optional ORG_NAME binding.
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { meResponseSchema } from '@exdomainvault/shared';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { harness, userCall } from '../testing/harness.ts';

let t: TestDatabase;
const clock = new Date('2026-10-23T10:00:00.000Z');
const h = harness(
  () => t,
  () => clock,
);

beforeAll(async () => {
  t = await createTestDatabase();
  vi.spyOn(console, 'log').mockImplementation(() => {});
}, 30_000);
afterAll(async () => {
  vi.restoreAllMocks();
  await t?.close();
});

const me = async (env: Record<string, string> = {}) => {
  const res = await userCall(h, t, 'viewer', 'GET', '/me', undefined, env);
  expect(res.status).toBe(200);
  return meResponseSchema.parse(await res.json());
};

describe('GET /me organisation', () => {
  it('is null when ORG_NAME is unset or blank', async () => {
    expect((await me()).organisation).toBeNull();
    expect((await me({ ORG_NAME: '  ' })).organisation).toBeNull();
  });

  it('returns the trimmed, length-capped ORG_NAME', async () => {
    const body = await me({ ORG_NAME: '  Example Org Ltd ' });
    expect(body.organisation).toBe('Example Org Ltd');
    expect(body.user.role).toBe('viewer');
    expect((await me({ ORG_NAME: 'o'.repeat(150) })).organisation).toBe('o'.repeat(100));
  });
});
