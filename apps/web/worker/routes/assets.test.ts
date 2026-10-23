// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { fingerprint } from '@exdomainvault/rules';
import {
  assetBulkDecisionResponseSchema,
  assetDetailResponseSchema,
  assetListResponseSchema,
  assetResponseSchema,
  errorResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { and, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const {
  assetIps,
  assets,
  auditLogs,
  discoveryObservations,
  domains,
  findingStatusHistory,
  findings,
  scanJobTargets,
  scanJobs,
} = schema;

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
  clock = new Date('2026-10-22T10:00:00.000Z');
  await t.db.delete(findings);
  await t.db.delete(scanJobs);
  await t.db.delete(assets);
  await t.db.delete(domains);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const ROLES: readonly Role[] = ['admin', 'analyst', 'asset_owner', 'viewer'];
const REASON = 'Confirmed with the service owner';
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

type Status = 'pending' | 'approved' | 'rejected' | 'suspended';

interface World {
  domainId: string;
  otherDomainId: string;
  ownerId: string;
  adminId: string;
  /** hostname → id */
  id: Record<string, string>;
}

/**
 * example.com: apex (pending), www (approved, owned by the asset owner, two IPs, one current),
 * cdn (pending, CloudFront hint), old (rejected), gone (suspended). example.net: mail (pending).
 */
async function seed(): Promise<World> {
  const adminId = await ensureUser(t, 'admin');
  const ownerId = await ensureUser(t, 'asset_owner');
  const [d] = await t.db.insert(domains).values({ fqdn: 'example.com' }).returning();
  const [o] = await t.db.insert(domains).values({ fqdn: 'example.net' }).returning();
  const row = (
    domainId: string,
    hostname: string,
    status: Status,
    over: Partial<typeof assets.$inferInsert> = {},
  ): typeof assets.$inferInsert => ({
    domainId,
    hostname,
    assetType: hostname === 'example.com' || hostname === 'example.net' ? 'apex' : 'subdomain',
    discoverySource: 'certificate_transparency',
    verificationStatus: status,
    ...(status === 'approved'
      ? { approvedBy: adminId, approvedAt: clock, monitoringEnabled: true }
      : {}),
    firstSeenAt: clock,
    lastSeenAt: clock,
    ...over,
  });
  const rows = await t.db
    .insert(assets)
    .values([
      row(d!.id, 'example.com', 'pending'),
      row(d!.id, 'www.example.com', 'approved', {
        ownerUserId: ownerId,
        discoverySource: 'manual',
        lastSeenAt: new Date(clock.getTime() + 60_000),
      }),
      row(d!.id, 'cdn.example.com', 'pending', {
        hostingHint: {
          provider: 'Amazon CloudFront',
          kind: 'cdn',
          matchedName: 'd1.cloudfront.net',
        },
        wildcardOnly: true,
      }),
      row(d!.id, 'old.example.com', 'rejected'),
      row(d!.id, 'gone.example.com', 'suspended'),
      row(o!.id, 'mail.example.net', 'pending'),
    ])
    .returning();
  const id = Object.fromEntries(rows.map((r) => [r.hostname, r.id]));
  await t.db.insert(assetIps).values([
    { assetId: id['www.example.com']!, ipAddress: '192.0.2.10', isCurrent: true, source: 'dns' },
    { assetId: id['www.example.com']!, ipAddress: '192.0.2.9', isCurrent: false, source: 'dns' },
  ]);
  return { domainId: d!.id, otherDomainId: o!.id, ownerId, adminId, id };
}

async function insertFinding(
  domainId: string,
  hostname: string,
  ruleId = 'ASSET-001',
  status: 'open' | 'acknowledged' | 'resolved' = 'open',
) {
  const component = ruleId === 'ASSET-001' ? hostname : 'other';
  const [r] = await t.db
    .insert(findings)
    .values({
      domainId,
      hostname,
      component,
      category: 'asset',
      ruleId,
      ruleVersion: 1,
      fingerprint: fingerprint(ruleId, domainId, hostname, component),
      title: 'Synthetic',
      description: 'Synthetic',
      severity: 'informational',
      confidence: 'medium',
      riskScore: 1,
      riskInputs: {},
      evidence: {},
      status,
      firstSeenAt: clock,
      lastSeenAt: clock,
      ...(status === 'resolved' ? { resolvedAt: clock } : {}),
    })
    .returning({ id: findings.id });
  return r!.id;
}

const list = async (role: Role, query = '') => {
  const res = await call(role, 'GET', `/assets${query}`);
  expect(res.status).toBe(200);
  return assetListResponseSchema.parse(await res.json());
};

describe('GET /assets', () => {
  it('lists every asset for admin, analyst and viewer with derived fields', async () => {
    const w = await seed();
    await insertFinding(w.domainId, 'www.example.com', 'TST-X');
    await insertFinding(w.domainId, 'www.example.com', 'TST-Y', 'resolved');
    for (const role of ['admin', 'analyst', 'viewer'] as const) {
      const body = await list(role);
      expect(body.total).toBe(6);
      expect(body.items.map((a) => a.hostname)).toEqual([
        'cdn.example.com',
        'example.com',
        'gone.example.com',
        'mail.example.net',
        'old.example.com',
        'www.example.com',
      ]);
    }
    const body = await list('viewer');
    const www = body.items.find((a) => a.hostname === 'www.example.com')!;
    expect(www).toMatchObject({
      domain: { id: w.domainId, fqdn: 'example.com' },
      assetType: 'subdomain',
      status: 'approved',
      source: 'manual',
      currentIps: ['192.0.2.10'],
      hostingHint: null,
      activeFindings: 1,
    });
    const cdn = body.items.find((a) => a.hostname === 'cdn.example.com')!;
    expect(cdn.hostingHint?.provider).toBe('Amazon CloudFront');
    expect(cdn.wildcardOnly).toBe(true);
  });

  it('filters, searches, sorts and paginates', async () => {
    const w = await seed();
    const names = async (q: string) => (await list('viewer', q)).items.map((a) => a.hostname);
    expect(await names('?status=pending')).toEqual([
      'cdn.example.com',
      'example.com',
      'mail.example.net',
    ]);
    expect(await names(`?domainId=${w.otherDomainId}`)).toEqual(['mail.example.net']);
    expect(await names('?source=manual')).toEqual(['www.example.com']);
    expect(await names('?thirdParty=true')).toEqual(['cdn.example.com']);
    expect(await names('?thirdParty=false')).toHaveLength(5);
    expect(await names('?q=WW')).toEqual(['www.example.com']);
    expect(await names('?q=%25')).toEqual([]); // LIKE wildcards are literal
    expect((await names('?sort=-lastSeenAt'))[0]).toBe('www.example.com');
    const page = await list('viewer', '?pageSize=2&page=2');
    expect(page).toMatchObject({ page: 2, pageSize: 2, total: 6 });
    expect(page.items.map((a) => a.hostname)).toEqual(['gone.example.com', 'mail.example.net']);
    await expectError(
      await call('viewer', 'GET', '/assets?status=bogus'),
      400,
      'validation_failed',
    );
  });

  it('shows asset owners only their own assets', async () => {
    const w = await seed();
    const body = await list('asset_owner');
    expect(body.items.map((a) => a.id)).toEqual([w.id['www.example.com']]);
    expect(body.total).toBe(1);
  });
});

describe('GET /assets/:id', () => {
  it('returns addresses and the latest discovery sightings', async () => {
    const w = await seed();
    const [job] = await t.db
      .insert(scanJobs)
      .values({
        jobType: 'discovery',
        profile: 'discovery',
        domainId: w.domainId,
        scopeSnapshot: {},
      })
      .returning();
    await t.db.insert(discoveryObservations).values(
      Array.from({ length: 55 }, (_, i) => ({
        resultId: `r-${i}`,
        assetId: w.id['cdn.example.com']!,
        scanJobId: job!.id,
        observedAt: new Date(clock.getTime() + i * 1000),
        checker: 'discovery',
        checkerVersion: '0.1.0',
        resultStatus: 'success' as const,
        evidence: { i },
        domainId: w.domainId,
        hostname: 'cdn.example.com',
        source: 'certificate_transparency',
        wildcard: i % 2 === 0,
      })),
    );
    const res = await call('viewer', 'GET', `/assets/${w.id['cdn.example.com']}`);
    expect(res.status).toBe(200);
    const body = assetDetailResponseSchema.parse(await res.json());
    expect(body.discovery).toHaveLength(50);
    expect(body.discovery[0]).toMatchObject({
      evidence: { i: 54 },
      wildcard: true,
      scanJobId: job!.id,
    });

    const www = assetDetailResponseSchema.parse(
      await (await call('viewer', 'GET', `/assets/${w.id['www.example.com']}`)).json(),
    );
    expect(www.ips.map((i) => [i.ipAddress, i.isCurrent])).toEqual([
      ['192.0.2.10', true],
      ['192.0.2.9', false],
    ]);
    expect(www.asset.currentIps).toEqual(['192.0.2.10']);
  });

  it('is 404 for unknown and (to asset owners) other assets', async () => {
    const w = await seed();
    await expectError(await call('viewer', 'GET', `/assets/${MISSING}`), 404, 'not_found');
    await expectError(await call('viewer', 'GET', '/assets/not-a-uuid'), 404, 'not_found');
    await expectError(
      await call('asset_owner', 'GET', `/assets/${w.id['cdn.example.com']}`),
      404,
      'not_found',
    );
    expect((await call('asset_owner', 'GET', `/assets/${w.id['www.example.com']}`)).status).toBe(
      200,
    );
  });
});

describe('GET /domains/:id/assets', () => {
  it('lists the domain assets, respecting visibility', async () => {
    const w = await seed();
    const res = await call('analyst', 'GET', `/domains/${w.otherDomainId}/assets`);
    expect(res.status).toBe(200);
    expect(assetListResponseSchema.parse(await res.json()).items.map((a) => a.hostname)).toEqual([
      'mail.example.net',
    ]);
    // A domainId query parameter cannot widen the scope.
    const scoped = assetListResponseSchema.parse(
      await (
        await call('viewer', 'GET', `/domains/${w.otherDomainId}/assets?domainId=${w.domainId}`)
      ).json(),
    );
    expect(scoped.items.map((a) => a.hostname)).toEqual(['mail.example.net']);
    const own = assetListResponseSchema.parse(
      await (await call('asset_owner', 'GET', `/domains/${w.domainId}/assets`)).json(),
    );
    expect(own.items.map((a) => a.hostname)).toEqual(['www.example.com']);
    await expectError(
      await call('asset_owner', 'GET', `/domains/${w.otherDomainId}/assets`),
      404,
      'not_found',
    );
    await expectError(await call('viewer', 'GET', `/domains/${MISSING}/assets`), 404, 'not_found');
  });
});

describe('asset decisions', () => {
  const decide = (role: Role, id: string, action: string, body: unknown = { reason: REASON }) =>
    call(role, 'POST', `/assets/${id}/${action}`, body);

  it('requires assets:approve', async () => {
    const w = await seed();
    for (const role of ['analyst', 'viewer', 'asset_owner'] as const) {
      for (const action of ['approve', 'reject', 'suspend']) {
        await expectError(await decide(role, w.id['mail.example.net']!, action), 403, 'forbidden');
      }
      await expectError(
        await call(role, 'POST', '/assets/bulk', {
          ids: [w.id['mail.example.net']],
          action: 'approve',
          reason: REASON,
        }),
        403,
        'forbidden',
      );
    }
  });

  it('allows exactly the transitions in allowedAssetActions', async () => {
    const w = await seed();
    const cases: [string, string, number][] = [
      // [hostname, action, expected status]
      ['example.com', 'reject', 409], // apex is never rejected
      ['example.com', 'suspend', 409],
      ['mail.example.net', 'suspend', 409],
      ['www.example.com', 'approve', 409], // already approved
      ['www.example.com', 'reject', 409],
      ['old.example.com', 'reject', 409],
      ['old.example.com', 'suspend', 409],
      ['gone.example.com', 'suspend', 409],
      ['gone.example.com', 'reject', 409],
    ];
    for (const [host, action, status] of cases) {
      const res = await decide('admin', w.id[host]!, action, {
        reason: REASON,
        ...(action === 'approve' ? { acknowledgeThirdPartyHosting: true } : {}),
      });
      if (status === 409) await expectError(res, 409, 'conflict', 'status');
    }
    // Nothing changed.
    const before = await t.db.select().from(assets);
    expect(before.every((a) => a.decidedAt === null)).toBe(true);

    const ok = async (host: string, action: string, expected: Status) => {
      const res = await decide('admin', w.id[host]!, action);
      expect(res.status).toBe(200);
      const body = assetResponseSchema.parse(await res.json());
      expect(body.asset.status).toBe(expected);
      expect(body.asset.decidedBy?.email).toBe('admin@example.com');
      expect(body.asset.decisionReason).toBe(REASON);
      return body.asset;
    };
    await ok('example.com', 'approve', 'approved');
    await ok('mail.example.net', 'reject', 'rejected');
    await ok('mail.example.net', 'approve', 'approved'); // rejected → approved
    await ok('www.example.com', 'suspend', 'suspended');
    await ok('www.example.com', 'approve', 'approved'); // suspended → approved
    await ok('gone.example.com', 'approve', 'approved');
    await ok('gone.example.com', 'suspend', 'suspended');

    const [www] = await t.db.select().from(assets).where(eq(assets.id, w.id['www.example.com']!));
    expect(www).toMatchObject({
      verificationStatus: 'approved',
      approvedBy: w.adminId,
      approvedAt: clock,
      decidedAt: clock,
      monitoringEnabled: true,
    });
    const [gone] = await t.db.select().from(assets).where(eq(assets.id, w.id['gone.example.com']!));
    expect(gone).toMatchObject({ verificationStatus: 'suspended', monitoringEnabled: false });

    await expectError(await decide('admin', MISSING, 'approve'), 404, 'not_found');
    await expectError(
      await decide('admin', w.id['old.example.com']!, 'approve', { reason: 'x' }),
      400,
      'validation_failed',
      'reason',
    );
    await expectError(
      await decide('admin', w.id['old.example.com']!, 'reject', { reason: REASON, extra: 1 }),
      400,
      'validation_failed',
    );
  });

  it('requires acknowledging third-party hosting to approve', async () => {
    const w = await seed();
    const cdn = w.id['cdn.example.com']!;
    await expectError(
      await decide('admin', cdn, 'approve'),
      400,
      'validation_failed',
      'acknowledgeThirdPartyHosting',
    );
    const res = await decide('admin', cdn, 'approve', {
      reason: REASON,
      acknowledgeThirdPartyHosting: true,
    });
    expect(res.status).toBe(200);
    const [audit] = await t.db
      .select()
      .from(auditLogs)
      .where(and(eq(auditLogs.action, 'asset.approved'), eq(auditLogs.resourceId, cdn)));
    expect(audit).toMatchObject({ actorUserId: w.adminId, actorType: 'user' });
    expect(audit!.metadata).toMatchObject({
      reason: REASON,
      from: 'pending',
      to: 'approved',
      acknowledgeThirdPartyHosting: true,
      hostingHint: { provider: 'Amazon CloudFront' },
    });
    // Rejecting a third-party candidate needs no acknowledgement.
    expect((await decide('admin', w.id['mail.example.net']!, 'reject')).status).toBe(200);
  });

  it('resolves the active ASSET-001 finding of the decided hostname', async () => {
    const w = await seed();
    const asset001 = await insertFinding(w.domainId, 'cdn.example.com');
    const other = await insertFinding(w.domainId, 'cdn.example.com', 'TST-OTHER');
    const elsewhere = await insertFinding(w.domainId, 'example.com');
    clock = new Date(clock.getTime() + 3600_000);
    expect(
      (await decide('admin', w.id['cdn.example.com']!, 'reject', { reason: REASON })).status,
    ).toBe(200);

    const status = async (id: string) =>
      (await t.db.select().from(findings).where(eq(findings.id, id)))[0]!;
    expect(await status(asset001)).toMatchObject({ status: 'resolved', resolvedAt: clock });
    expect((await status(other)).status).toBe('open');
    expect((await status(elsewhere)).status).toBe('open');
    const history = await t.db
      .select()
      .from(findingStatusHistory)
      .where(eq(findingStatusHistory.findingId, asset001));
    expect(history).toEqual([
      expect.objectContaining({
        fromStatus: 'open',
        toStatus: 'resolved',
        reason: 'asset_decided',
        changedBy: w.adminId,
        note: `Asset rejected: ${REASON}`,
      }),
    ]);
    const audit = await t.db
      .select()
      .from(auditLogs)
      .where(
        and(eq(auditLogs.action, 'finding.status_changed'), eq(auditLogs.resourceId, asset001)),
      );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({ reason: 'asset_decided', to: 'resolved' });
  });

  it('suspension stops in-flight active jobs that target the asset', async () => {
    const w = await seed();
    const www = w.id['www.example.com']!;
    await t.db.delete(schema.workerRegistry);
    const [worker] = await t.db.insert(schema.workerRegistry).values({ name: 'w1' }).returning();
    const job = (profile: string, status: 'queued' | 'running', active: boolean) => ({
      jobType: 'scan' as const,
      profile,
      domainId: w.domainId,
      status,
      scopeSnapshot: { version: 1, profile: { key: profile, config: { active } } },
      ...(status === 'running'
        ? {
            attempts: 1,
            workerId: worker!.id,
            leaseExpiresAt: new Date(clock.getTime() + 300_000),
            startedAt: clock,
          }
        : {}),
    });
    const jobs = await t.db
      .insert(scanJobs)
      .values([
        job('quick', 'running', true),
        job('standard', 'queued', true),
        job('passive', 'running', false),
        job('deep', 'running', true),
      ])
      .returning();
    const [running, queued, passive, unrelated] = jobs;
    await t.db.insert(scanJobTargets).values([
      { scanJobId: running!.id, assetId: www, targetHostname: 'www.example.com' },
      { scanJobId: queued!.id, assetId: www, targetHostname: 'www.example.com' },
      { scanJobId: passive!.id, assetId: www, targetHostname: 'www.example.com' },
      { scanJobId: unrelated!.id, assetId: w.id['example.com']!, targetHostname: 'example.com' },
    ]);

    expect((await decide('admin', www, 'suspend')).status).toBe(200);
    const jobRow = async (id: string) =>
      (await t.db.select().from(scanJobs).where(eq(scanJobs.id, id)))[0]!;
    expect((await jobRow(running!.id)).cancelRequestedAt).toEqual(clock);
    expect((await jobRow(passive!.id)).cancelRequestedAt).toBeNull();
    expect((await jobRow(unrelated!.id)).cancelRequestedAt).toBeNull();
    const targets = await t.db.select().from(scanJobTargets);
    const statusOf = (jobId: string) => targets.find((x) => x.scanJobId === jobId)!;
    expect(statusOf(queued!.id)).toMatchObject({ status: 'skipped', errorCode: 'asset_suspended' });
    expect(statusOf(running!.id).status).toBe('skipped');
    expect(statusOf(passive!.id).status).toBe('pending');
    const audits = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'scan.cancel_requested'));
    expect(audits.map((a) => a.resourceId)).toEqual([running!.id]);
  });
});

describe('POST /assets/bulk', () => {
  it('applies one decision set-based and reports skipped rows', async () => {
    const w = await seed();
    const f1 = await insertFinding(w.domainId, 'example.com');
    const f2 = await insertFinding(w.otherDomainId, 'mail.example.net');
    const res = await call('admin', 'POST', '/assets/bulk', {
      ids: [
        w.id['example.com'],
        w.id['mail.example.net'],
        w.id['old.example.com'], // rejected → approved
        w.id['www.example.com'], // already approved
        w.id['cdn.example.com'], // third party, not acknowledged
        MISSING,
      ],
      action: 'approve',
      reason: REASON,
    });
    expect(res.status).toBe(200);
    const body = assetBulkDecisionResponseSchema.parse(await res.json());
    expect(body.updated).toBe(3);
    expect(body.skipped).toEqual([
      { id: w.id['www.example.com'], code: 'no_change' },
      { id: w.id['cdn.example.com'], code: 'third_party_not_acknowledged' },
      { id: MISSING, code: 'not_found' },
    ]);
    const rows = await t.db.select().from(assets);
    const st = (h: string) => rows.find((a) => a.hostname === h)!.verificationStatus;
    expect([
      st('example.com'),
      st('mail.example.net'),
      st('old.example.com'),
      st('cdn.example.com'),
    ]).toEqual(['approved', 'approved', 'approved', 'pending']);
    const fs = await t.db.select().from(findings);
    expect(fs.filter((f) => [f1, f2].includes(f.id)).map((f) => f.status)).toEqual([
      'resolved',
      'resolved',
    ]);
    const audits = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'asset.approved'));
    expect(audits).toHaveLength(3);
    expect(audits.every((a) => (a.metadata as { bulk?: boolean }).bulk === true)).toBe(true);

    // Invalid transitions are skipped too.
    const rej = assetBulkDecisionResponseSchema.parse(
      await (
        await call('admin', 'POST', '/assets/bulk', {
          ids: [w.id['example.com'], w.id['cdn.example.com']],
          action: 'reject',
          reason: REASON,
        })
      ).json(),
    );
    expect(rej).toEqual({
      updated: 1,
      skipped: [{ id: w.id['example.com'], code: 'invalid_transition' }],
    });
  });

  it('validates the request', async () => {
    await seed();
    await expectError(
      await call('admin', 'POST', '/assets/bulk', { ids: [], action: 'approve', reason: REASON }),
      400,
      'validation_failed',
    );
    await expectError(
      await call('admin', 'POST', '/assets/bulk', {
        ids: Array.from({ length: 501 }, () => MISSING),
        action: 'approve',
        reason: REASON,
      }),
      400,
      'validation_failed',
    );
    await expectError(
      await call('admin', 'POST', '/assets/bulk', {
        ids: [MISSING],
        action: 'delete',
        reason: REASON,
      }),
      400,
      'validation_failed',
    );
  });
});

describe('roles', () => {
  it('every role with assets:read can list', async () => {
    await seed();
    for (const role of ROLES) expect((await call(role, 'GET', '/assets')).status).toBe(200);
  });
});
