// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  claimResponseSchema,
  discoveredNetworksResponseSchema,
  discoverySettingsResponseSchema,
  errorResponseSchema,
  workerCredentialCreatedResponseSchema,
  type ClaimedJob,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { proposedCidr } from '../services/discovered-networks.ts';
import {
  ensureUser,
  generateWorkerKey,
  harness,
  userCall,
  workerCall,
  type TestWorkerKey,
} from '../testing/harness.ts';

const { applicationSettings, assetIps, assets, auditLogs, domains, networkObservations, scanJobs } =
  schema;

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
  clock = new Date('2026-10-29T10:00:00.000Z');
  await t.db.delete(scanJobs);
  await t.db.delete(assets);
  await t.db.delete(domains);
  await t.db.delete(schema.workerRegistry);
  await t.db.delete(auditLogs);
  await t.db
    .insert(applicationSettings)
    .values({ key: 'discovery_org_names', value: ['Thai Union'] })
    .onConflictDoUpdate({ target: applicationSettings.key, set: { value: ['Thai Union'] } });
});
afterEach(() => vi.restoreAllMocks());

const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function expectError(res: Response, status: number, code: string, path?: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
  if (path) expect(body.error.details?.[0]?.path).toBe(path);
  return body.error;
}

const iso = (offsetSeconds = 0) => new Date(clock.getTime() + offsetSeconds * 1000).toISOString();

let workerSeq = 0;
async function registerWorker() {
  const key = await generateWorkerKey();
  const reg = await call('admin', 'POST', '/workers', {
    name: `net-${workerSeq++}`,
    publicKey: key.publicKey,
  });
  expect(reg.status).toBe(201);
  return { key, keyId: workerCredentialCreatedResponseSchema.parse(await reg.json()).credentialId };
}

interface Setup {
  w: { key: TestWorkerKey; keyId: string };
  domainId: string;
  job: ClaimedJob;
  apex: string;
}

async function addAsset(
  domainId: string,
  hostname: string,
  ips: { ip: string; current?: boolean }[],
  over: Partial<typeof assets.$inferInsert> = {},
) {
  const admin = await ensureUser(t, 'admin');
  const [a] = await t.db
    .insert(assets)
    .values({
      domainId,
      hostname,
      assetType: 'subdomain',
      discoverySource: 'manual',
      verificationStatus: 'approved',
      approvedBy: admin,
      approvedAt: clock,
      ...over,
    })
    .returning();
  if (ips.length > 0) {
    await t.db.insert(assetIps).values(
      ips.map(({ ip, current }) => ({
        assetId: a!.id,
        ipAddress: ip,
        isCurrent: current ?? true,
        source: 'dns',
      })),
    );
  }
  return a!;
}

/** example.com with assets; a discovery job requested through the API and claimed. */
async function setup(prepare?: (domainId: string) => Promise<void>): Promise<Setup> {
  const [d] = await t.db
    .insert(domains)
    .values({ fqdn: 'example.com', monitoringEnabled: true })
    .returning();
  const domainId = d!.id;
  await prepare?.(domainId);
  const w = await registerWorker();
  const res = await call('analyst', 'POST', `/domains/${domainId}/discovery`);
  expect(res.status).toBe(201);
  const claimed = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock });
  const job = claimResponseSchema.parse(await claimed.json()).job!;
  return { w, domainId, job, apex: job.targets[0]!.id };
}

const net = (targetId: string, over: Record<string, unknown> = {}) => ({
  kind: 'network',
  targetId,
  observedAt: iso(),
  checkerVersion: '0.1.0',
  resultStatus: 'success',
  evidence: { addresses: ['49.231.0.10'] },
  ipAddress: '49.231.0.10',
  startAddress: '49.231.0.0',
  endAddress: '49.231.3.255',
  cidrs: ['49.231.0.0/22'],
  registry: 'apnic',
  handle: '49.231.0.0 - 49.231.3.255',
  networkName: 'THAIUNION-TH',
  orgName: 'Thai Union Group Public Company Limited',
  country: 'TH',
  matchedOrg: false,
  ...over,
});

const aws = (targetId: string, over: Record<string, unknown> = {}) =>
  net(targetId, {
    ipAddress: '52.1.2.3',
    startAddress: '52.0.0.0',
    endAddress: '52.79.255.255',
    cidrs: ['52.0.0.0/10', '52.64.0.0/12'],
    registry: 'arin',
    handle: 'NET-52-0-0-0-1',
    networkName: 'AT-88-Z',
    orgName: 'Amazon Technologies Inc.',
    country: null,
    matchedOrg: true, // the worker's claim is never trusted
    evidence: { addresses: ['52.1.2.3'] },
    ...over,
  });

const submit = (s: Setup, resultId: string, observations: unknown[]) =>
  workerCall(
    h,
    s.w.key,
    s.w.keyId,
    'results',
    {
      jobId: s.job.id,
      attempt: s.job.attempt,
      resultId,
      targets: [],
      observations,
      complete: false,
    },
    { now: clock },
  );

describe('network job context', () => {
  it('sends the org names and the current public addresses of approved assets at claim', async () => {
    const s = await setup(async (domainId) => {
      await addAsset(domainId, 'www.example.com', [
        { ip: '49.231.0.10' },
        { ip: '2400:aa00::10' },
        { ip: '10.0.0.5' }, // private: never sent
        { ip: '49.231.0.99', current: false },
      ]);
      await addAsset(domainId, 'api.example.com', [{ ip: '52.1.2.3' }, { ip: '49.231.0.10' }]);
      await addAsset(domainId, 'cand.example.com', [{ ip: '185.10.20.5' }], {
        verificationStatus: 'pending',
        approvedBy: null,
        approvedAt: null,
      });
    });
    expect(s.job.network).toEqual({
      orgNames: ['Thai Union'],
      addresses: ['2400:aa00::10', '49.231.0.10', '52.1.2.3'],
    });
  });
});

describe('network observation ingestion', () => {
  it('stores observations and re-computes matchedOrg against the current setting', async () => {
    const s = await setup();
    const res = await submit(s, 'result-0001', [
      net(s.apex),
      aws(s.apex),
      net(s.apex, {
        resultStatus: 'error',
        evidence: { errorClass: 'http_error' },
        ipAddress: '185.10.20.5',
        startAddress: null,
        endAddress: null,
        cidrs: [],
        registry: null,
        handle: null,
        networkName: null,
        orgName: null,
        country: null,
      }),
    ]);
    expect(res.status).toBe(200);
    const rows = await t.db.select().from(networkObservations);
    expect(rows).toHaveLength(3);
    const byIp = Object.fromEntries(rows.map((r) => [r.ipAddress, r]));
    expect(byIp['49.231.0.10']).toMatchObject({
      matchedOrg: true,
      domainId: s.domainId,
      checker: 'network',
      cidrs: ['49.231.0.0/22'],
      registry: 'apnic',
    });
    expect(byIp['52.1.2.3']!.matchedOrg).toBe(false);
    expect(byIp['185.10.20.5']!.matchedOrg).toBe(false);

    // Idempotent: a duplicate delivery stores nothing.
    await submit(s, 'result-0001', [net(s.apex)]);
    expect(await t.db.select().from(networkObservations)).toHaveLength(3);
  });

  it('matches on evidence.entityNames as well', async () => {
    const s = await setup();
    await submit(s, 'result-0001', [
      net(s.apex, {
        orgName: 'Network Administrator',
        networkName: 'TU-NET',
        evidence: { entityNames: ['THAI-UNION Europe B.V.'] },
      }),
    ]);
    expect((await t.db.select().from(networkObservations))[0]!.matchedOrg).toBe(true);
  });

  it.each([
    ['ipAddress', { ipAddress: '10.1.2.3', startAddress: null, endAddress: null }],
    ['endAddress', { endAddress: null }],
    ['ipAddress', { ipAddress: '49.231.9.1' }],
    ['startAddress', { startAddress: '49.231.4.0' }],
    ['startAddress', { startAddress: '2400::' }],
    ['cidrs.0', { cidrs: ['49.231.0.0/40'] }],
  ])('rejects an invalid observation (%s)', async (field, over) => {
    const s = await setup();
    const res = await submit(s, 'result-0001', [net(s.apex, over)]);
    await expectError(res, 400, 'validation_failed', `observations.0.${field}`);
    expect(await t.db.select().from(networkObservations)).toHaveLength(0);
  });

  it('refuses network observations from a job whose profile does not list the check', async () => {
    const s = await setup();
    const [job] = await t.db.select().from(scanJobs).where(eq(scanJobs.id, s.job.id));
    const snapshot = job!.scopeSnapshot as {
      profile: { config: { checks: string[] } };
    };
    snapshot.profile.config.checks = ['discovery'];
    await t.db.update(scanJobs).set({ scopeSnapshot: snapshot }).where(eq(scanJobs.id, s.job.id));
    const res = await submit(s, 'result-0001', [net(s.apex)]);
    await expectError(res, 400, 'validation_failed', 'observations.0.kind');
  });

  it('stores reverse-DNS names as pending assets with source dns, never approved', async () => {
    const s = await setup();
    const ptr = (hostname: string, source = 'reverse_dns') => ({
      kind: 'discovery',
      targetId: s.apex,
      observedAt: iso(),
      checkerVersion: '0.1.0',
      resultStatus: 'success',
      evidence: { provider: source === 'reverse_dns' ? 'ptr' : 'crt.sh' },
      hostname,
      source,
      wildcard: false,
    });
    const res = await submit(s, 'result-0001', [
      ptr('erp.example.com'),
      ptr('both.example.com'),
      ptr('both.example.com', 'certificate_transparency'),
    ]);
    expect(res.status).toBe(200);
    const rows = await t.db.select().from(assets);
    const bySource = Object.fromEntries(
      rows.map((a) => [a.hostname, [a.discoverySource, a.verificationStatus]]),
    );
    expect(bySource).toEqual({
      'erp.example.com': ['dns', 'pending'],
      'both.example.com': ['certificate_transparency', 'pending'],
    });
    const sightings = await t.db.select().from(schema.discoveryObservations);
    expect(sightings.filter((o) => o.source === 'reverse_dns')).toHaveLength(2);
  });

  it('rejects reverse-DNS names outside the job domain', async () => {
    const s = await setup();
    const res = await submit(s, 'result-0001', [
      {
        kind: 'discovery',
        targetId: s.apex,
        observedAt: iso(),
        checkerVersion: '0.1.0',
        resultStatus: 'success',
        evidence: {},
        hostname: 'host.example.net',
        source: 'reverse_dns',
        wildcard: false,
      },
    ]);
    await expectError(res, 400, 'validation_failed', 'observations.0.hostname');
  });
});

describe('GET /networks/discovered', () => {
  async function populate() {
    let ids: { www: string; api: string } = { www: '', api: '' };
    const s = await setup(async (domainId) => {
      const owner = await ensureUser(t, 'asset_owner');
      const www = await addAsset(domainId, 'www.example.com', [{ ip: '49.231.0.10' }], {
        ownerUserId: owner,
      });
      const api = await addAsset(domainId, 'api.example.com', [{ ip: '52.1.2.3' }]);
      await addAsset(domainId, 'img.example.com', [{ ip: '52.1.2.4' }]);
      ids = { www: www.id, api: api.id };
    });
    clock = new Date(clock.getTime() + 60_000);
    await submit(s, 'result-0001', [
      net(s.apex, { observedAt: iso(-30), networkName: 'OLD-NAME' }),
      net(s.apex),
      aws(s.apex),
      // Matched range without a current asset address (owned space).
      net(s.apex, {
        ipAddress: '49.232.0.1',
        startAddress: '49.232.0.0',
        endAddress: '49.232.0.255',
        cidrs: ['49.232.0.0/24'],
        handle: 'TU-2',
      }),
    ]);
    return { s, ids };
  }

  it('lists matched networks with their assets and summarises other hosting', async () => {
    await populate();
    const res = await call('analyst', 'GET', '/networks/discovered');
    expect(res.status).toBe(200);
    const body = discoveredNetworksResponseSchema.parse(await res.json());
    expect(body.orgNames).toEqual(['Thai Union']);
    expect(body.total).toBe(3);
    expect(body.matched.map((n) => n.handle).sort()).toEqual(['49.231.0.0 - 49.231.3.255', 'TU-2']);
    const tu = body.matched.find((n) => n.cidrs[0] === '49.231.0.0/22')!;
    expect(tu).toMatchObject({
      registry: 'apnic',
      networkName: 'THAIUNION-TH', // latest observation wins
      cidrs: ['49.231.0.0/22'],
      addresses: ['49.231.0.10'],
      assetCount: 1,
      proposedCidr: '49.231.0.0/22',
      firstSeenAt: iso(-30),
      lastSeenAt: iso(),
    });
    expect(tu.assets.map((a) => a.hostname)).toEqual(['www.example.com']);
    const owned = body.matched.find((n) => n.handle === 'TU-2')!;
    expect(owned.assetCount).toBe(0);
    expect(body.hosting).toEqual([
      { orgName: 'Amazon Technologies Inc.', networks: 1, assetCount: 2 },
    ]);
  });

  it('re-evaluates matching when the organisation names change', async () => {
    await populate();
    const put = await call('admin', 'PUT', '/settings/discovery', {
      orgNames: ['Amazon Technologies'],
    });
    expect(put.status).toBe(200);
    const body = discoveredNetworksResponseSchema.parse(
      await (await call('viewer', 'GET', '/networks/discovered')).json(),
    );
    expect(body.matched.map((n) => n.orgName)).toEqual(['Amazon Technologies Inc.']);
    expect(body.matched[0]!.proposedCidr).toBeNull(); // /10 and /12 are broader than a /16
    expect(body.hosting.map((h) => h.orgName)).toEqual(['Thai Union Group Public Company Limited']);
  });

  it('shows asset owners only networks containing their assets', async () => {
    const { ids } = await populate();
    const body = discoveredNetworksResponseSchema.parse(
      await (await call('asset_owner', 'GET', '/networks/discovered')).json(),
    );
    expect(body.total).toBe(1);
    expect(body.matched).toHaveLength(1);
    expect(body.matched[0]!.assets).toEqual([{ id: ids.www, hostname: 'www.example.com' }]);
    expect(body.hosting).toEqual([]);
  });

  it('proposes only CIDRs the approved-networks form accepts', () => {
    expect(proposedCidr(['52.0.0.0/10', '52.64.0.0/16'])).toBe('52.64.0.0/16');
    expect(proposedCidr(['10.0.0.0/24'])).toBeNull();
    expect(proposedCidr([])).toBeNull();
  });
});

describe('/settings/discovery', () => {
  it('reads and replaces the organisation names, audited', async () => {
    const get = await call('admin', 'GET', '/settings/discovery');
    expect(discoverySettingsResponseSchema.parse(await get.json()).orgNames).toEqual([
      'Thai Union',
    ]);
    clock = new Date('2026-10-30T00:00:00.000Z');
    const put = await call('admin', 'PUT', '/settings/discovery', {
      orgNames: [' Thai Union ', 'TU Europe'],
    });
    expect(put.status).toBe(200);
    expect(discoverySettingsResponseSchema.parse(await put.json())).toEqual({
      orgNames: ['Thai Union', 'TU Europe'],
      updatedAt: '2026-10-30T00:00:00.000Z',
    });
    const audit = await t.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.action, 'settings.discovery_updated'));
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({
      before: ['Thai Union'],
      after: ['Thai Union', 'TU Europe'],
    });
  });

  it.each([
    [{ orgNames: ['x'] }, 'orgNames.0'],
    [{ orgNames: ['Thai Union', 'thai union'] }, 'orgNames'],
    [{ orgNames: Array.from({ length: 21 }, (_, i) => `Org ${i}`) }, 'orgNames'],
    [{ orgNames: 'Thai Union' }, 'orgNames'],
    [{ orgNames: [], extra: true }, ''],
  ])('validates the body (%j)', async (body, path) => {
    const res = await call('admin', 'PUT', '/settings/discovery', body);
    expect(res.status).toBe(400);
    const err = errorResponseSchema.parse(await res.json()).error;
    expect(err.code).toBe('validation_failed');
    if (path) expect(err.details?.[0]?.path).toBe(path);
  });

  it('is admin only', async () => {
    await expectError(await call('analyst', 'GET', '/settings/discovery'), 403, 'forbidden');
    await expectError(
      await call('analyst', 'PUT', '/settings/discovery', { orgNames: [] }),
      403,
      'forbidden',
    );
  });
});
