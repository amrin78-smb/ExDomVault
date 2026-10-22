// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  approvedNetworkListResponseSchema,
  approvedNetworkSchema,
  claimResponseSchema,
  errorResponseSchema,
  scanJobDetailResponseSchema,
  workerCredentialCreatedResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateWorkerKey, harness, userCall, workerCall } from '../testing/harness.ts';

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
  await t.db.delete(schema.approvedNetworks);
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

const valid = {
  cidr: '8.8.8.0/24',
  label: 'Primary hosting',
  reason: 'Our own servers in the colocation rack',
  reference: 'CHG-1234',
  reviewBy: '2027-06-30',
};

async function approve(over: Record<string, unknown> = {}) {
  const res = await call('admin', 'POST', '/approved-networks', { ...valid, ...over });
  expect(res.status).toBe(201);
  return approvedNetworkSchema.parse(await res.json());
}

const revoke = (id: string, reason = 'Servers decommissioned') =>
  call('admin', 'POST', `/approved-networks/${id}/revoke`, { reason });

const auditActions = async () =>
  (await t.db.select().from(schema.auditLogs).orderBy(schema.auditLogs.createdAt)).map(
    (a) => a.action,
  );

async function verifiedDomain(fqdn = 'example.com') {
  const [d] = await t.db
    .insert(schema.domains)
    .values({
      fqdn,
      verificationStatus: 'verified',
      verifiedAt: clock,
      verificationMethod: 'dns_txt',
    })
    .returning();
  return d!;
}

async function requestScan(domainId: string, profile: string) {
  const res = await call('analyst', 'POST', `/domains/${domainId}/scans`, { profile }, ACTIVE_ON);
  expect(res.status).toBe(202);
  return scanJobDetailResponseSchema.parse(await res.json());
}

async function registerWorker() {
  const key = await generateWorkerKey();
  const res = await call('admin', 'POST', '/workers', { name: 'net-1', publicKey: key.publicKey });
  expect(res.status).toBe(201);
  return { key, keyId: workerCredentialCreatedResponseSchema.parse(await res.json()).credentialId };
}

describe('approved networks API', () => {
  it('approves a canonicalised network, lists it and audits the approval', async () => {
    const created = await approve({ cidr: ' 8.8.8.77/24 ' });
    expect(created).toMatchObject({
      cidr: '8.8.8.0/24',
      label: 'Primary hosting',
      reference: 'CHG-1234',
      expiresAt: '2027-06-30T23:59:59.999Z',
      revokedAt: null,
      revokeReason: null,
      createdBy: { email: 'admin@example.com' },
    });
    const v6 = await approve({ cidr: '2606:4700:ABCD::1/48', reference: '' });
    expect(v6).toMatchObject({ cidr: '2606:4700:abcd::/48', reference: null });
    const single = await approve({ cidr: '9.9.9.9' });
    expect(single.cidr).toBe('9.9.9.9/32');

    const list = approvedNetworkListResponseSchema.parse(
      await (await call('admin', 'GET', '/approved-networks')).json(),
    );
    expect(list.items.map((n) => n.cidr).sort()).toEqual([
      '2606:4700:abcd::/48',
      '8.8.8.0/24',
      '9.9.9.9/32',
    ]);
    expect(await auditActions()).toEqual([
      'network.approved',
      'network.approved',
      'network.approved',
    ]);
    const [audit] = await t.db.select().from(schema.auditLogs).limit(1);
    expect(audit).toMatchObject({ resourceType: 'approved_network', actorType: 'user' });
    expect(audit!.metadata).toMatchObject({ reason: valid.reason });
  });

  it.each([
    ['private', '10.1.0.0/24'],
    ['CGNAT', '100.64.0.0/16'],
    ['loopback', '127.0.0.1'],
    ['documentation', '203.0.113.0/24'],
    ['public network address covering a special range', '192.0.0.0/16'],
    ['multicast', '224.0.0.0/16'],
    ['IPv6 ULA', 'fd00::/48'],
    ['IPv4-mapped', '::ffff:8.8.8.0/120'],
    ['6to4', '2002:808:808::/48'],
    ['IPv6 documentation', '2001:db8::/32'],
    ['too broad IPv4', '8.0.0.0/15'],
    ['too broad IPv6', '2606::/31'],
    ['alternative encoding', '0x08.8.8.0/24'],
    ['leading zeros', '008.8.8.0/24'],
    ['garbage', 'not-a-network'],
    ['prefix out of range', '8.8.8.0/33'],
  ])('rejects a %s network (%s)', async (_label, cidr) => {
    const err = await expectError(
      await call('admin', 'POST', '/approved-networks', { ...valid, cidr }),
      400,
      'validation_failed',
    );
    expect(err.details?.[0]?.path).toBe('cidr');
    expect(await t.db.select().from(schema.approvedNetworks)).toHaveLength(0);
  });

  it('accepts the broadest allowed networks', async () => {
    await approve({ cidr: '8.8.0.0/16' });
    await approve({ cidr: '2606:4700::/32' });
  });

  it.each([
    ['in the past', '2026-10-21'],
    ['beyond 24 months', '2028-10-23'],
  ])('rejects a review date %s', async (_label, reviewBy) => {
    const err = await expectError(
      await call('admin', 'POST', '/approved-networks', { ...valid, reviewBy }),
      400,
      'validation_failed',
    );
    expect(err.details?.[0]?.path).toBe('reviewBy');
  });

  it('validates the body schema', async () => {
    await expectError(
      await call('admin', 'POST', '/approved-networks', { ...valid, reason: 'short' }),
      400,
      'validation_failed',
    );
    await expectError(
      await call('admin', 'POST', '/approved-networks', { ...valid, extra: true }),
      400,
      'validation_failed',
    );
  });

  it('refuses duplicate and overlapping active approvals', async () => {
    await approve();
    await expectError(await call('admin', 'POST', '/approved-networks', valid), 409, 'conflict');
    await expectError(
      await call('admin', 'POST', '/approved-networks', { ...valid, cidr: '8.8.8.128/25' }),
      409,
      'conflict',
    );
    await expectError(
      await call('admin', 'POST', '/approved-networks', { ...valid, cidr: '8.8.0.0/16' }),
      409,
      'conflict',
    );
    await approve({ cidr: '8.8.9.0/24' });
  });

  it('revokes an approval, audits it, and allows re-approval afterwards', async () => {
    const n = await approve();
    const res = await revoke(n.id);
    expect(res.status).toBe(200);
    expect(approvedNetworkSchema.parse(await res.json())).toMatchObject({
      revokedAt: clock.toISOString(),
      revokeReason: 'Servers decommissioned',
    });
    await expectError(await revoke(n.id), 409, 'conflict');
    await expectError(await revoke(crypto.randomUUID()), 404, 'not_found');
    await expectError(await revoke(n.id, 'short'), 400, 'validation_failed');
    expect(await auditActions()).toEqual(['network.approved', 'network.revoked']);
    const [row] = await t.db.select().from(schema.approvedNetworks);
    expect(row!.revokedBy).not.toBeNull();

    await approve();
  });

  it('treats an expired approval as inactive and lets it be re-approved', async () => {
    const old = await approve({ reviewBy: '2026-10-23' });
    clock = new Date('2026-10-24T00:00:00.000Z');
    const renewed = await approve();
    expect(renewed.id).not.toBe(old.id);
    const list = approvedNetworkListResponseSchema.parse(
      await (await call('admin', 'GET', '/approved-networks')).json(),
    );
    expect(list.items.find((n) => n.id === old.id)).toMatchObject({
      revokedAt: '2026-10-23T23:59:59.999Z',
      revokeReason: 'Expired (review date passed).',
    });
  });

  it.each<Role>(['analyst', 'viewer', 'asset_owner'])('forbids %s', async (role) => {
    const n = await approve();
    await expectError(await call(role, 'GET', '/approved-networks'), 403, 'forbidden');
    await expectError(
      await call(role, 'POST', '/approved-networks', { ...valid, cidr: '9.9.9.0/24' }),
      403,
      'forbidden',
    );
    await expectError(
      await call(role, 'POST', `/approved-networks/${n.id}/revoke`, { reason: 'Not ours anymore' }),
      403,
      'forbidden',
    );
  });
});

describe('approved networks in job scope', () => {
  it('snapshots active networks for active profiles only', async () => {
    const d = await verifiedDomain();
    await approve({ cidr: '8.8.8.0/24' });
    await approve({ cidr: '2606:4700::/32' });
    const revoked = await approve({ cidr: '9.9.9.0/24' });
    await revoke(revoked.id);
    await approve({ cidr: '1.1.1.0/24', reviewBy: '2026-10-22' }); // lapses tonight
    clock = new Date('2026-10-23T08:00:00.000Z');

    const standard = await requestScan(d.id, 'standard');
    expect(standard.scopeSnapshot.approvedNetworks).toEqual(['2606:4700::/32', '8.8.8.0/24']);
    const passive = await requestScan(d.id, 'passive');
    expect(passive.scopeSnapshot.approvedNetworks).toEqual([]);
    const [audit] = (await t.db.select().from(schema.auditLogs)).filter(
      (a) => a.action === 'scan.requested' && a.resourceId === standard.job.id,
    );
    expect(audit!.metadata).toMatchObject({ approvedNetworks: 2 });
  });

  it('intersects the snapshot with the still-active networks at claim time', async () => {
    const d = await verifiedDomain();
    const a = await approve({ cidr: '8.8.8.0/24' });
    await approve({ cidr: '8.8.9.0/24' });
    const job = await requestScan(d.id, 'standard');
    expect(job.scopeSnapshot.approvedNetworks).toEqual(['8.8.8.0/24', '8.8.9.0/24']);

    await revoke(a.id);
    await approve({ cidr: '1.1.1.0/24' }); // approved after creation: never added
    const w = await registerWorker();
    const res = await workerCall(
      h,
      w.key,
      w.keyId,
      'claim',
      {},
      { now: clock, envExtra: ACTIVE_ON },
    );
    const claimed = claimResponseSchema.parse(await res.json()).job;
    expect(claimed?.id).toBe(job.job.id);
    expect(claimed?.snapshot.approvedNetworks).toEqual(['8.8.9.0/24']);
    // Everything else in the snapshot is returned unchanged.
    expect({ ...claimed!.snapshot, approvedNetworks: [] }).toEqual({
      ...job.scopeSnapshot,
      approvedNetworks: [],
    });
  });
});
