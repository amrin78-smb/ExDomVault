// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  claimResponseSchema,
  domainObservationsResponseSchema,
  errorResponseSchema,
  scanJobDetailResponseSchema,
  workerCredentialCreatedResponseSchema,
  type ClaimedJob,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ensureUser,
  generateWorkerKey,
  harness,
  userCall,
  workerCall,
  type TestWorkerKey,
} from '../testing/harness.ts';

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
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
  await t.db.delete(schema.workerRegistry);
});
afterEach(() => vi.restoreAllMocks());

const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function expectError(res: Response, status: number, code: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
  return body.error;
}

interface Setup {
  w: { key: TestWorkerKey; keyId: string };
  domainId: string;
  wwwAssetId: string;
  job: ClaimedJob;
  apex: string;
  www: string;
}

let workerSeq = 0;

/** example.com with an approved www asset; a passive scan claimed by a fresh worker. */
async function setup(): Promise<Setup> {
  const [d] = await t.db.insert(schema.domains).values({ fqdn: 'example.com' }).returning();
  const [a] = await t.db
    .insert(schema.assets)
    .values({
      domainId: d!.id,
      hostname: 'www.example.com',
      assetType: 'subdomain',
      discoverySource: 'dns',
      verificationStatus: 'approved',
      approvedAt: clock,
      approvedBy: await ensureUser(t, 'admin'),
    })
    .returning();
  const key = await generateWorkerKey();
  const reg = await call('admin', 'POST', '/workers', {
    name: `obs-${workerSeq++}`,
    publicKey: key.publicKey,
  });
  expect(reg.status).toBe(201);
  const w = {
    key,
    keyId: workerCredentialCreatedResponseSchema.parse(await reg.json()).credentialId,
  };
  return { w, domainId: d!.id, wwwAssetId: a!.id, ...(await scanAndClaim(w, d!.id)) };
}

async function scanAndClaim(w: Setup['w'], domainId: string) {
  const res = await call('analyst', 'POST', `/domains/${domainId}/scans`, { profile: 'passive' });
  expect(res.status).toBe(202);
  scanJobDetailResponseSchema.parse(await res.json());
  const claimed = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock });
  const job = claimResponseSchema.parse(await claimed.json()).job!;
  const byHost = (name: string) => job.targets.find((x) => x.hostname === name)!.id;
  return { job, apex: byHost('example.com'), www: byHost('www.example.com') };
}

const iso = (offsetSeconds = 0) => new Date(clock.getTime() + offsetSeconds * 1000).toISOString();

const dnsObs = (
  targetId: string,
  hostname: string,
  recordType: string,
  values: string[],
  at = iso(),
) => ({
  kind: 'dns',
  targetId,
  observedAt: at,
  checkerVersion: '0.1.0',
  resultStatus: 'success',
  evidence: { resolver: '192.0.2.53' },
  hostname,
  recordType,
  ttl: 300,
  values,
});

const regObs = (targetId: string, over: Record<string, unknown> = {}) => ({
  kind: 'registration',
  targetId,
  observedAt: iso(),
  checkerVersion: '0.1.0',
  resultStatus: 'success',
  evidence: {},
  registrar: 'Example Registrar',
  registeredAt: '2001-01-01T00:00:00.000Z',
  expiresAt: '2027-01-01T00:00:00.000Z',
  nameservers: ['ns1.example.net'],
  dataStatus: 'available',
  ...over,
});

const submit = (s: Setup, resultId: string, observations: unknown[], complete = false) =>
  workerCall(
    h,
    s.w.key,
    s.w.keyId,
    'results',
    { jobId: s.job.id, attempt: s.job.attempt, resultId, targets: [], observations, complete },
    { now: clock },
  );

const counts = async () => ({
  dns: (await t.db.select().from(schema.dnsObservations)).length,
  registration: (await t.db.select().from(schema.registrationObservations)).length,
  results: (await t.db.select().from(schema.scanJobResults)).length,
});

describe('observation ingestion', () => {
  it('stores dns and registration observations and ignores a duplicate submission', async () => {
    const s = await setup();
    const observations = [
      dnsObs(s.apex, 'example.com', 'A', ['192.0.2.1']),
      dnsObs(s.apex, '_dmarc.example.com', 'TXT', ['"v=DMARC1; p=reject"']),
      dnsObs(s.www, 'www.example.com', 'CNAME', ['example.com.']),
      regObs(s.apex),
    ];
    const first = await submit(s, 'result-0001', observations);
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ accepted: true, status: 'running' });
    expect(await counts()).toEqual({ dns: 3, registration: 1, results: 1 });

    const rows = await t.db.select().from(schema.dnsObservations);
    const www = rows.find((r) => r.hostname === 'www.example.com')!;
    expect(www).toMatchObject({
      resultId: `${s.job.id}:result-0001:2`,
      assetId: s.wwwAssetId,
      scanJobId: s.job.id,
      scanJobTargetId: s.www,
      checker: 'dns',
      checkerVersion: '0.1.0',
      resultStatus: 'success',
      recordType: 'CNAME',
      ttl: 300,
      recordValues: ['example.com.'],
    });
    const [reg] = await t.db.select().from(schema.registrationObservations);
    expect(reg).toMatchObject({ checker: 'rdap', domainId: s.domainId, dataStatus: 'available' });

    const again = await submit(s, 'result-0001', observations);
    expect(await again.json()).toEqual({ accepted: false, status: 'running' });
    expect(await counts()).toEqual({ dns: 3, registration: 1, results: 1 });
  });

  it('rejects observations for a target outside the job', async () => {
    const s = await setup();
    await expectError(
      await submit(s, 'result-0001', [dnsObs(crypto.randomUUID(), 'example.com', 'A', [])]),
      400,
      'validation_failed',
    );
    expect(await counts()).toEqual({ dns: 0, registration: 0, results: 0 });
  });

  it.each(['example.com.evil.net', 'evil-example.com', 'com', 'xexample.com'])(
    'rejects a dns hostname outside the job domain (%s)',
    async (hostname) => {
      const s = await setup();
      await expectError(
        await submit(s, 'result-0001', [
          dnsObs(s.apex, 'example.com', 'A', []),
          dnsObs(s.apex, hostname, 'A', ['192.0.2.1']),
        ]),
        400,
        'validation_failed',
      );
      // The whole submission is rejected atomically.
      expect(await counts()).toEqual({ dns: 0, registration: 0, results: 0 });
    },
  );

  it('accepts registration observations for the apex target only', async () => {
    const s = await setup();
    await expectError(await submit(s, 'result-0001', [regObs(s.www)]), 400, 'validation_failed');
    expect(await counts()).toEqual({ dns: 0, registration: 0, results: 0 });
  });

  it.each([
    ['in the future', 6 * 60],
    ['older than 7 days', -8 * 24 * 3600],
  ])('rejects observedAt %s', async (_label, offset) => {
    const s = await setup();
    await expectError(
      await submit(s, 'result-0001', [dnsObs(s.apex, 'example.com', 'A', [], iso(offset))]),
      400,
      'validation_failed',
    );
    expect(await counts()).toEqual({ dns: 0, registration: 0, results: 0 });
  });

  it('allows small forward clock skew', async () => {
    const s = await setup();
    const res = await submit(s, 'result-0001', [dnsObs(s.apex, 'example.com', 'A', [], iso(240))]);
    expect(res.status).toBe(200);
  });

  it('updates the domain registration fields and never regresses them', async () => {
    const s = await setup();
    await submit(s, 'result-0001', [regObs(s.apex, { observedAt: iso(-3600) })]);
    const domain = async () =>
      (await t.db.select().from(schema.domains).where(eq(schema.domains.id, s.domainId)))[0]!;
    expect(await domain()).toMatchObject({
      registrar: 'Example Registrar',
      registrationDataStatus: 'available',
      registeredAt: new Date('2001-01-01T00:00:00.000Z'),
      expiresAt: new Date('2027-01-01T00:00:00.000Z'),
    });

    // An older observation arriving later does not overwrite newer data.
    await submit(s, 'result-0002', [
      regObs(s.apex, { observedAt: iso(-7200), registrar: 'Old Registrar' }),
    ]);
    expect((await domain()).registrar).toBe('Example Registrar');

    // A failed lookup never changes the domain.
    await submit(s, 'result-0003', [
      regObs(s.apex, { resultStatus: 'error', registrar: null, dataStatus: 'unavailable' }),
    ]);
    expect(await domain()).toMatchObject({
      registrar: 'Example Registrar',
      registrationDataStatus: 'available',
    });

    // A newer successful "unavailable" keeps existing values but records the status.
    await submit(s, 'result-0004', [
      regObs(s.apex, {
        observedAt: iso(-60),
        registrar: null,
        registeredAt: null,
        expiresAt: null,
        dataStatus: 'unavailable',
      }),
    ]);
    expect(await domain()).toMatchObject({
      registrar: 'Example Registrar',
      registrationDataStatus: 'unavailable',
      expiresAt: new Date('2027-01-01T00:00:00.000Z'),
    });

    // A newer available observation applies.
    await submit(s, 'result-0005', [regObs(s.apex, { registrar: 'New Registrar' })]);
    expect(await domain()).toMatchObject({
      registrar: 'New Registrar',
      registrationDataStatus: 'available',
    });
    expect(await counts()).toMatchObject({ registration: 5 });
  });
});

describe('GET /domains/:id/observations', () => {
  it('returns the latest observation per hostname and record type, and the latest registration', async () => {
    const s = await setup();
    await submit(s, 'result-0001', [
      dnsObs(s.apex, 'example.com', 'A', ['192.0.2.1'], iso(-600)),
      dnsObs(s.apex, 'example.com', 'TXT', ['"old"'], iso(-600)),
      regObs(s.apex, { observedAt: iso(-600) }),
    ]);
    await submit(s, 'result-0002', [
      dnsObs(s.apex, 'example.com', 'A', ['192.0.2.2'], iso(-60)),
      dnsObs(s.apex, 'example.com', 'MX', ['10 mail.example.com.'], iso(-60)),
      dnsObs(s.www, 'www.example.com', 'AAAA', ['2001:db8::1'], iso(-60)),
      dnsObs(s.apex, '_dmarc.example.com', 'TXT', [], iso(-60)),
      regObs(s.apex, { observedAt: iso(-60), registrar: 'Latest Registrar' }),
    ]);

    const res = await call('viewer', 'GET', `/domains/${s.domainId}/observations`);
    expect(res.status).toBe(200);
    const body = domainObservationsResponseSchema.parse(await res.json());
    expect(body.dns.map((r) => [r.hostname, r.recordType, r.values])).toEqual([
      ['_dmarc.example.com', 'TXT', []],
      ['example.com', 'A', ['192.0.2.2']],
      ['example.com', 'MX', ['10 mail.example.com.']],
      ['example.com', 'TXT', ['"old"']],
      ['www.example.com', 'AAAA', ['2001:db8::1']],
    ]);
    expect(body.dns[1]).toMatchObject({ scanJobId: s.job.id, observedAt: iso(-60), ttl: 300 });
    expect(body.registration).toMatchObject({
      registrar: 'Latest Registrar',
      dataStatus: 'available',
      resultStatus: 'success',
      observedAt: iso(-60),
      nameservers: ['ns1.example.net'],
    });
  });

  it('returns empty results for a domain without observations', async () => {
    const [d] = await t.db.insert(schema.domains).values({ fqdn: 'example.org' }).returning();
    const res = await call('analyst', 'GET', `/domains/${d!.id}/observations`);
    expect(await res.json()).toEqual({ dns: [], registration: null });
  });

  it('enforces RBAC and returns 404 for an unknown domain', async () => {
    const [d] = await t.db.insert(schema.domains).values({ fqdn: 'example.org' }).returning();
    await expectError(
      await call('asset_owner', 'GET', `/domains/${d!.id}/observations`),
      403,
      'forbidden',
    );
    expect((await call('viewer', 'GET', `/domains/${d!.id}/observations`)).status).toBe(200);
    await expectError(
      await call('viewer', 'GET', `/domains/${crypto.randomUUID()}/observations`),
      404,
      'not_found',
    );
  });
});
