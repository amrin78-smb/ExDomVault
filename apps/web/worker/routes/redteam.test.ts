// @vitest-environment node
/**
 * Red-team attacks on the server-side scope enforcement (Milestone 6 gate): approved networks API,
 * scope snapshot / claim, observation ingestion and worker job ownership.
 * Every test asserts the SAFE behaviour: a failing test is an open vulnerability.
 */
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  approvedNetworkSchema,
  claimResponseSchema,
  errorResponseSchema,
  heartbeatResponseSchema,
  scanJobDetailResponseSchema,
  workerCredentialCreatedResponseSchema,
  type ClaimedJob,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.ts';
import {
  ORIGIN,
  ensureUser,
  generateWorkerKey,
  harness,
  signedHeaders,
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
  vi.spyOn(console, 'error').mockImplementation(() => {});
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
  env: Record<string, string> = ACTIVE_ON,
) => userCall(h, t, role, method, path, body, env);

async function expectError(res: Response, status: number, code?: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  if (code) expect(body.error.code).toBe(code);
  return body.error;
}

const validNet = {
  cidr: '8.8.8.0/24',
  label: 'Primary hosting',
  reason: 'Our own servers in the colocation rack',
  reviewBy: '2027-06-30',
};

async function approve(over: Record<string, unknown> = {}) {
  const res = await call('admin', 'POST', '/approved-networks', { ...validNet, ...over });
  expect(res.status).toBe(201);
  return approvedNetworkSchema.parse(await res.json());
}

const revokeNet = (id: string) =>
  call('admin', 'POST', `/approved-networks/${id}/revoke`, { reason: 'Servers decommissioned' });

const netRows = () => t.db.select().from(schema.approvedNetworks);

let workerSeq = 0;
interface W {
  key: TestWorkerKey;
  keyId: string;
  workerId: string;
}
async function registerWorker(): Promise<W> {
  const key = await generateWorkerKey();
  const res = await call('admin', 'POST', '/workers', {
    name: `rt-${workerSeq++}`,
    publicKey: key.publicKey,
  });
  expect(res.status).toBe(201);
  const body = workerCredentialCreatedResponseSchema.parse(await res.json());
  return { key, keyId: body.credentialId, workerId: body.worker.id };
}

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

async function asset(domainId: string, hostname: string, status: 'approved' | 'pending') {
  const [a] = await t.db
    .insert(schema.assets)
    .values({
      domainId,
      hostname,
      assetType: 'subdomain',
      discoverySource: 'dns',
      verificationStatus: status,
      ...(status === 'approved'
        ? { approvedAt: clock, approvedBy: await ensureUser(t, 'admin') }
        : {}),
    })
    .returning();
  return a!;
}

async function requestScan(domainId: string, profile: string, env = ACTIVE_ON) {
  const res = await call('analyst', 'POST', `/domains/${domainId}/scans`, { profile }, env);
  expect(res.status).toBe(202);
  return scanJobDetailResponseSchema.parse(await res.json());
}

async function claim(w: W, env: Record<string, string> = ACTIVE_ON) {
  const res = await workerCall(h, w.key, w.keyId, 'claim', {}, { now: clock, envExtra: env });
  expect(res.status).toBe(200);
  return claimResponseSchema.parse(await res.json()).job;
}

interface Active {
  w: W;
  domainId: string;
  networkId: string;
  job: ClaimedJob;
  apex: string;
  www: string;
}

/** Verified example.com, www approved, pending.example.com pending, 8.8.8.0/24 approved, claimed. */
async function setupActive(profile = 'standard'): Promise<Active> {
  const d = await verifiedDomain();
  await asset(d.id, 'www.example.com', 'approved');
  await asset(d.id, 'pending.example.com', 'pending');
  const net = await approve();
  const w = await registerWorker();
  await requestScan(d.id, profile);
  const job = (await claim(w))!;
  expect(job).not.toBeNull();
  const byHost = (name: string) => job.targets.find((x) => x.hostname === name)!.id;
  return {
    w,
    domainId: d.id,
    networkId: net.id,
    job,
    apex: byHost('example.com'),
    www: byHost('www.example.com'),
  };
}

async function setupPassive(): Promise<Active> {
  const d = await verifiedDomain();
  await asset(d.id, 'www.example.com', 'approved');
  const net = await approve();
  const w = await registerWorker();
  await requestScan(d.id, 'passive');
  const job = (await claim(w))!;
  const byHost = (name: string) => job.targets.find((x) => x.hostname === name)!.id;
  return {
    w,
    domainId: d.id,
    networkId: net.id,
    job,
    apex: byHost('example.com'),
    www: byHost('www.example.com'),
  };
}

const iso = (offsetMs = 0) => new Date(clock.getTime() + offsetMs).toISOString();

const base = (targetId: string) => ({
  targetId,
  observedAt: iso(),
  checkerVersion: '0.2.0',
  resultStatus: 'success',
});

const tlsObs = (targetId: string, over: Record<string, unknown> = {}) => ({
  kind: 'tls',
  ...base(targetId),
  evidence: {},
  hostname: 'www.example.com',
  ipAddress: '8.8.4.4',
  port: 443,
  protocolVersion: 'TLSv1.3',
  notBefore: null,
  notAfter: null,
  issuer: null,
  subject: null,
  subjectAltNames: [],
  fingerprintSha256: null,
  hostnameMatches: true,
  ...over,
});

const httpObs = (targetId: string, over: Record<string, unknown> = {}) => ({
  kind: 'http',
  ...base(targetId),
  evidence: {},
  url: 'https://www.example.com/',
  ipAddress: '8.8.4.4',
  statusCode: 200,
  finalUrl: 'https://www.example.com/',
  redirectCount: 0,
  hstsEnabled: true,
  ...over,
});

const portObs = (targetId: string, over: Record<string, unknown> = {}) => ({
  kind: 'port',
  ...base(targetId),
  evidence: {},
  ipAddress: '8.8.8.8',
  port: 443,
  protocol: 'tcp',
  state: 'open',
  service: 'https',
  ...over,
});

const submit = (
  s: Active,
  resultId: string,
  observations: unknown[],
  extra: { attempt?: number; jobId?: string; w?: W; env?: Record<string, string> } = {},
) => {
  const w = extra.w ?? s.w;
  return workerCall(
    h,
    w.key,
    w.keyId,
    'results',
    {
      jobId: extra.jobId ?? s.job.id,
      attempt: extra.attempt ?? s.job.attempt,
      resultId: `result-${resultId}`,
      targets: [],
      observations,
      complete: false,
    },
    { now: clock, envExtra: extra.env ?? ACTIVE_ON },
  );
};

const activeCounts = async () => ({
  tls: (await t.db.select().from(schema.tlsObservations)).length,
  http: (await t.db.select().from(schema.httpObservations)).length,
  port: (await t.db.select().from(schema.portObservations)).length,
});
const NONE = { tls: 0, http: 0, port: 0 };

// ================================================================================================
// RT-NET: approved networks API
// ================================================================================================

describe('RT-NET: approving non-public / too-broad networks via alternative encodings', () => {
  it.each([
    ['octal', '010.0.0.0/24'],
    ['hex', '0x0a.0.0.0/24'],
    ['integer', '167772160/24'],
    ['short form', '10.0/16'],
    ['fullwidth digits', '１０.0.0.0/24'],
    ['IPv4-mapped public', '::ffff:8.8.8.0/120'],
    ['IPv4-mapped hex', '::ffff:808:800/120'],
    ['IPv4-mapped private full form', '0:0:0:0:0:ffff:a00:0/120'],
    ['IPv4-mapped uppercase', '::FFFF:A00:0/120'],
    ['IPv4-compatible', '::8.8.8.0/120'],
    ['IPv4-translated', '::ffff:0:808:800/120'],
    ['NAT64', '64:ff9b::808:800/120'],
    ['6to4 of private', '2002:a00::/40'],
    ['Teredo', '2001::/32'],
    ['Teredo subnet', '2001:0:4136::/48'],
    ['bracketed', '[2606:4700::]/48'],
    ['zone id', '2606:4700::%eth0/48'],
    ['link-local', 'fe80::/32'],
    ['multicast v6', 'ff02::/32'],
    ['outside 2000::/3', '4000::/32'],
    ['2001::/23 IETF assignments (worker refuses)', '2001:100::/32'],
    ['3fff::/20 documentation (worker refuses)', '3fff::/32'],
    ['3fff::/20 documentation, inner /48', '3fff:abc::/48'],
    ['6to4 relay anycast', '192.88.99.0/24'],
    ['straddles 192.88.99.0/24', '192.88.0.0/16'],
    ['straddles documentation 198.51.100/24', '198.51.0.0/16'],
    ['benchmarking', '198.19.0.0/16'],
    ['CGNAT top', '100.127.255.0/24'],
    ['RFC1918 /32', '172.31.255.255'],
    ['class E', '240.0.0.0/16'],
    ['broadcast', '255.255.255.255'],
    ['/0 v4', '0.0.0.0/0'],
    ['/0 v6', '::/0'],
    ['public /0 with host bits', '8.8.8.8/0'],
    ['negative prefix', '8.8.8.0/-1'],
    ['prefix 33', '8.8.8.0/33'],
    ['IPv6 prefix 129', '2606:4700::/129'],
    ['leading-zero prefix', '8.8.8.0/024'],
    ['space inside', '8.8.8.0 /24'],
    ['too broad v4 /15', '8.8.0.0/15'],
    ['too broad v4 via host bits', '8.9.255.255/15'],
    ['too broad v6 /31', '2606:4700::/31'],
    ['NUL suffix', '8.8.8.0/24\u0000'],
  ])('rejects %s (%j)', async (_label, cidr) => {
    const res = await call('admin', 'POST', '/approved-networks', { ...validNet, cidr });
    await expectError(res, 400, 'validation_failed');
    expect(await netRows()).toHaveLength(0);
  });

  it('stores only the canonical form for unusual-but-valid spellings', async () => {
    const a = await approve({ cidr: '\t8.8.8.255/24\n' });
    expect(a.cidr).toBe('8.8.8.0/24');
    const b = await approve({ cidr: '2606:4700:0000:0000:0000:0000:0000:FFFF/32' });
    expect(b.cidr).toBe('2606:4700::/32');
    const rows = await netRows();
    expect(rows.map((r) => r.cidr).sort()).toEqual(['2606:4700::/32', '8.8.8.0/24']);
  });
});

describe('RT-NET: duplicates and overlaps through different spellings', () => {
  it.each([
    ['same network, host bits', '8.8.8.1/24'],
    ['same network, whitespace', ' 8.8.8.0/24 '],
    ['narrower', '8.8.8.128/25'],
    ['single host inside', '8.8.8.8'],
    ['broader /16', '8.8.255.255/16'],
  ])('refuses %s against 8.8.8.0/24', async (_label, cidr) => {
    await approve();
    await expectError(
      await call('admin', 'POST', '/approved-networks', { ...validNet, cidr }),
      409,
      'conflict',
    );
    expect(await netRows()).toHaveLength(1);
  });

  it('refuses IPv6 overlaps spelled differently', async () => {
    await approve({ cidr: '2606:4700::/32' });
    for (const cidr of ['2606:4700:0::/48', '2606:4700:0:0:0:0:0:1', '2606:4700:FFFF::/48']) {
      await expectError(
        await call('admin', 'POST', '/approved-networks', { ...validNet, cidr }),
        409,
        'conflict',
      );
    }
    expect(await netRows()).toHaveLength(1);
  });

  it('concurrent identical approvals produce exactly one active row', async () => {
    const results = await Promise.all(
      Array.from({ length: 4 }, () => call('admin', 'POST', '/approved-networks', validNet)),
    );
    expect(results.filter((r) => r.status === 201)).toHaveLength(1);
    expect(results.filter((r) => r.status === 409)).toHaveLength(3);
    expect(await netRows()).toHaveLength(1);
  });

  it('concurrent overlapping approvals produce at most one active row', async () => {
    const results = await Promise.all(
      ['8.8.8.0/24', '8.8.8.0/25', '8.8.0.0/16', '8.8.8.8'].map((cidr) =>
        call('admin', 'POST', '/approved-networks', { ...validNet, cidr }),
      ),
    );
    expect(results.filter((r) => r.status === 201)).toHaveLength(1);
    expect(await netRows()).toHaveLength(1);
  });
});

describe('RT-NET: review-date tricks', () => {
  it.each([
    ['yesterday', '2026-10-21'],
    ['far past', '1970-01-01'],
    ['exactly 24 months + 1 day', '2028-10-23'],
    ['the 24-month anniversary itself (end of day exceeds limit)', '2028-10-22'],
    ['far future', '9999-12-31'],
    ['invalid leap day', '2027-02-29'],
    ['day 31 in a 30-day month', '2027-06-31'],
    ['month 13', '2027-13-01'],
    ['day 00', '2027-06-00'],
    ['datetime string', '2027-06-30T00:00:00Z'],
    ['date with offset', '2027-06-30+14:00'],
    ['timezone suffix Z', '2027-06-30Z'],
    ['unpadded', '2027-6-30'],
    ['expanded year', '+002027-06-30'],
    ['five-digit year', '20270-06-30'],
    ['whitespace', ' 2027-06-30'],
    ['slashes', '2027/06/30'],
    ['epoch number', 1814400000],
    ['null', null],
  ])('rejects %s (%j)', async (_label, reviewBy) => {
    await expectError(
      await call('admin', 'POST', '/approved-networks', { ...validNet, reviewBy }),
      400,
      'validation_failed',
    );
    expect(await netRows()).toHaveLength(0);
  });

  it('accepts a real leap day within range and lapses at end of that UTC day', async () => {
    const n = await approve({ reviewBy: '2028-02-29' });
    expect(n.expiresAt).toBe('2028-02-29T23:59:59.999Z');
  });

  it('an approval reviewed "today" lapses at midnight UTC and is gone from new snapshots', async () => {
    const d = await verifiedDomain();
    await approve({ reviewBy: '2026-10-22' });
    clock = new Date('2026-10-23T00:00:00.000Z');
    const job = await requestScan(d.id, 'standard');
    expect(job.scopeSnapshot.approvedNetworks).toEqual([]);
  });
});

describe('RT-NET: RBAC and CSRF', () => {
  it.each<Role>(['analyst', 'viewer', 'asset_owner'])(
    '%s cannot list, approve or revoke',
    async (role) => {
      const n = await approve();
      await expectError(await call(role, 'GET', '/approved-networks'), 403, 'forbidden');
      await expectError(
        await call(role, 'POST', '/approved-networks', { ...validNet, cidr: '9.9.9.0/24' }),
        403,
        'forbidden',
      );
      await expectError(
        await call(role, 'POST', `/approved-networks/${n.id}/revoke`, {
          reason: 'Not ours anymore at all',
        }),
        403,
        'forbidden',
      );
      expect(await netRows()).toHaveLength(1);
      expect((await netRows())[0]!.revokedAt).toBeNull();
    },
  );

  const rawAdmin = async (path: string, body: unknown, headers: Record<string, string>) => {
    await ensureUser(t, 'admin');
    return createApp(h.deps).request(
      `/api/v1${path}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
      },
      h.env('admin', ACTIVE_ON) as unknown as Env,
    );
  };

  it.each([
    ['missing Origin', {}],
    ['foreign Origin', { Origin: 'https://evil.example' }],
    ['null Origin', { Origin: 'null' }],
    ['lookalike Origin', { Origin: `${ORIGIN}.evil.example` }],
    ['Origin with path', { Origin: `${ORIGIN}/` }],
    ['Origin different port', { Origin: 'http://localhost:8080' }],
  ])('rejects an approval with %s', async (_label, headers) => {
    await expectError(await rawAdmin('/approved-networks', validNet, headers), 403, 'forbidden');
    expect(await netRows()).toHaveLength(0);
  });

  it('rejects a cross-origin revoke', async () => {
    const n = await approve();
    await expectError(
      await rawAdmin(
        `/approved-networks/${n.id}/revoke`,
        { reason: 'Servers decommissioned' },
        { Origin: 'https://evil.example' },
      ),
      403,
      'forbidden',
    );
    expect((await netRows())[0]!.revokedAt).toBeNull();
  });

  it('rejects text/plain (simple-request) bodies even with a same-origin header', async () => {
    await ensureUser(t, 'admin');
    const res = await createApp(h.deps).request(
      '/api/v1/approved-networks',
      {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain', Origin: ORIGIN },
        body: JSON.stringify(validNet),
      },
      h.env('admin', ACTIVE_ON) as unknown as Env,
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(await netRows()).toHaveLength(0);
  });

  it('error bodies never leak internals', async () => {
    const res = await call('admin', 'POST', '/approved-networks', {
      ...validNet,
      cidr: '10.0.0.0/8',
    });
    const text = await res.text();
    expect(text).not.toMatch(/at \w+ \(|node_modules|postgres:|stack/i);
  });
});

// ================================================================================================
// RT-SNAP: snapshot and claim
// ================================================================================================

describe('RT-SNAP: scope snapshot and claim-time re-checks', () => {
  it('a network revoked after job creation is not handed to the worker at claim', async () => {
    const d = await verifiedDomain();
    const n = await approve();
    const job = await requestScan(d.id, 'standard');
    expect(job.scopeSnapshot.approvedNetworks).toEqual(['8.8.8.0/24']);
    expect((await revokeNet(n.id)).status).toBe(200);
    const w = await registerWorker();
    const claimed = (await claim(w))!;
    expect(claimed.id).toBe(job.job.id);
    expect(claimed.snapshot.approvedNetworks).toEqual([]);
  });

  it('revoke + broader re-approval never enlarges a queued job', async () => {
    const d = await verifiedDomain();
    const n = await approve();
    await requestScan(d.id, 'standard');
    await revokeNet(n.id);
    await approve({ cidr: '8.8.0.0/16' });
    const claimed = (await claim(await registerWorker()))!;
    expect(claimed.snapshot.approvedNetworks).toEqual([]);
  });

  it('a network that expired while the job waited is not handed out', async () => {
    const d = await verifiedDomain();
    await approve({ reviewBy: '2026-10-22' });
    await requestScan(d.id, 'standard');
    clock = new Date('2026-10-23T00:00:01.000Z');
    const claimed = (await claim(await registerWorker()))!;
    expect(claimed.snapshot.approvedNetworks).toEqual([]);
  });

  it('a network approved after creation is never added', async () => {
    const d = await verifiedDomain();
    await requestScan(d.id, 'standard');
    await approve();
    const claimed = (await claim(await registerWorker()))!;
    expect(claimed.snapshot.approvedNetworks).toEqual([]);
  });

  it('a retried (requeued) job does not regain a network revoked between attempts', async () => {
    const s = await setupActive();
    expect(s.job.snapshot.approvedNetworks).toEqual(['8.8.8.0/24']);
    const fail = await workerCall(
      h,
      s.w.key,
      s.w.keyId,
      'failures',
      {
        jobId: s.job.id,
        attempt: s.job.attempt,
        errorCode: 'boom',
        errorSummary: 'x',
        retryable: true,
      },
      { now: clock, envExtra: ACTIVE_ON },
    );
    expect(fail.status).toBe(200);
    await revokeNet(s.networkId);
    clock = new Date(clock.getTime() + 3600_000);
    const again = (await claim(s.w))!;
    expect(again.id).toBe(s.job.id);
    expect(again.attempt).toBe(2);
    expect(again.snapshot.approvedNetworks).toEqual([]);
  });

  it('passive jobs never carry networks, at creation or claim', async () => {
    const d = await verifiedDomain();
    await approve();
    const job = await requestScan(d.id, 'passive');
    expect(job.scopeSnapshot.approvedNetworks).toEqual([]);
    const claimed = (await claim(await registerWorker()))!;
    expect(claimed.snapshot.approvedNetworks).toEqual([]);
  });

  it('an active job is refused at claim when ACTIVE_SCANNING_ENABLED is off', async () => {
    const d = await verifiedDomain();
    await approve();
    const job = await requestScan(d.id, 'standard');
    const claimed = await claim(await registerWorker(), {});
    expect(claimed).toBeNull();
    const [row] = await t.db
      .select()
      .from(schema.scanJobs)
      .where(eq(schema.scanJobs.id, job.job.id));
    expect(row).toMatchObject({ status: 'cancelled', errorCode: 'active_scanning_disabled' });
  });

  it('an active job is refused at claim when the domain was revoked while queued', async () => {
    const d = await verifiedDomain();
    const job = await requestScan(d.id, 'quick');
    const rev = await call('admin', 'POST', `/domains/${d.id}/revoke`, {
      reason: 'We sold this domain last week',
    });
    expect(rev.status).toBe(200);
    expect(await claim(await registerWorker())).toBeNull();
    const [row] = await t.db
      .select()
      .from(schema.scanJobs)
      .where(eq(schema.scanJobs.id, job.job.id));
    expect(row!.status).toBe('cancelled');
  });

  it('active job creation is refused while ACTIVE_SCANNING_ENABLED is off', async () => {
    const d = await verifiedDomain();
    await expectError(
      await call('analyst', 'POST', `/domains/${d.id}/scans`, { profile: 'standard' }, {}),
      409,
      'conflict',
    );
  });

  it('an asset whose approval was withdrawn while the job was queued is not dispatched', async () => {
    const d = await verifiedDomain();
    const www = await asset(d.id, 'www.example.com', 'approved');
    await requestScan(d.id, 'quick');
    // Owner withdraws www (e.g. it moved to a third party) before a worker picks the job up.
    await t.db
      .update(schema.assets)
      .set({ verificationStatus: 'rejected' })
      .where(eq(schema.assets.id, www.id));
    const claimed = await claim(await registerWorker());
    const hosts = claimed?.targets.map((x) => x.hostname) ?? [];
    expect(hosts).not.toContain('www.example.com');
  });

  it('in-flight job: turning ACTIVE_SCANNING_ENABLED off tells the worker to stop', async () => {
    const s = await setupActive();
    const res = await workerCall(
      h,
      s.w.key,
      s.w.keyId,
      'heartbeat',
      { jobId: s.job.id, attempt: s.job.attempt },
      { now: clock, envExtra: {} }, // kill switch off
    );
    // Safe: the server refuses to extend the lease, or tells the worker to stop.
    if (res.status === 200) {
      expect(heartbeatResponseSchema.parse(await res.json()).cancelRequested).toBe(true);
    } else {
      expect(res.status).toBe(409);
    }
  });

  it('in-flight job: active evidence is refused after the kill switch is turned off', async () => {
    const s = await setupActive();
    const res = await submit(s, 'r-kill', [tlsObs(s.www)], { env: {} });
    expect(res.status).not.toBe(200);
    expect(await activeCounts()).toEqual(NONE);
  });

  it('in-flight job: revoking domain authorisation tells the worker to stop', async () => {
    const s = await setupActive();
    const rev = await call('admin', 'POST', `/domains/${s.domainId}/revoke`, {
      reason: 'We sold this domain last week',
    });
    expect(rev.status).toBe(200);
    const res = await workerCall(
      h,
      s.w.key,
      s.w.keyId,
      'heartbeat',
      { jobId: s.job.id, attempt: s.job.attempt },
      { now: clock, envExtra: ACTIVE_ON },
    );
    if (res.status === 200) {
      expect(heartbeatResponseSchema.parse(await res.json()).cancelRequested).toBe(true);
    } else {
      expect(res.status).toBe(409);
    }
  });

  it('in-flight job: active evidence is refused after domain authorisation is revoked', async () => {
    const s = await setupActive();
    await call('admin', 'POST', `/domains/${s.domainId}/revoke`, {
      reason: 'We sold this domain last week',
    });
    const res = await submit(s, 'r-revoked', [tlsObs(s.www)]);
    expect(res.status).not.toBe(200);
    expect(await activeCounts()).toEqual(NONE);
  });
});

// ================================================================================================
// RT-OBS: observation ingestion
// ================================================================================================

const PRIVATE_IPS: [string, string][] = [
  ['RFC1918', '10.0.0.5'],
  ['loopback', '127.0.0.1'],
  ['unspecified v4', '0.0.0.0'],
  ['broadcast', '255.255.255.255'],
  ['multicast v4', '224.0.0.1'],
  ['CGNAT metadata', '100.100.100.200'],
  ['link-local metadata', '169.254.169.254'],
  ['6to4 relay', '192.88.99.1'],
  ['mapped private', '::ffff:10.0.0.5'],
  ['mapped private hex', '::ffff:a00:5'],
  ['mapped private uppercase', '::FFFF:A00:5'],
  ['mapped private full', '0:0:0:0:0:ffff:a00:5'],
  ['mapped public', '::ffff:8.8.8.8'],
  ['compatible', '::10.0.0.5'],
  ['translated', '::ffff:0:a00:5'],
  ['NAT64', '64:ff9b::a00:5'],
  ['6to4', '2002:a00:5::1'],
  ['Teredo', '2001:0:a00:5::1'],
  ['v6 loopback', '::1'],
  ['v6 unspecified', '::'],
  ['v6 link-local', 'fe80::1'],
  ['v6 zone id', 'fe80::1%eth0'],
  ['v6 bracketed', '[2606:4700::1111]'],
  ['AWS v6 metadata ULA', 'fd00:ec2::254'],
  ['discard-only', '100::1'],
  ['outside 2000::/3', '4000::1'],
  ['2001::/23 IETF (worker refuses)', '2001:100::1'],
  ['3fff::/20 documentation (worker refuses)', '3fff::1'],
  ['octal', '010.0.0.5'],
  ['integer', '167772165'],
  ['short', '10.5'],
  ['whitespace', ' 8.8.4.4'],
];

describe('RT-OBS: non-public addresses in active evidence', () => {
  it.each(PRIVATE_IPS)('tls refuses %s (%s)', async (_label, ip) => {
    const s = await setupActive();
    expect((await submit(s, 'r1', [tlsObs(s.www, { ipAddress: ip })])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it.each(PRIVATE_IPS)('http refuses %s (%s)', async (_label, ip) => {
    const s = await setupActive();
    expect((await submit(s, 'r1', [httpObs(s.www, { ipAddress: ip })])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it.each(PRIVATE_IPS)('port refuses %s (%s)', async (_label, ip) => {
    const s = await setupActive();
    expect((await submit(s, 'r1', [portObs(s.apex, { ipAddress: ip })])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });
});

describe('RT-OBS: hostnames and URLs', () => {
  it.each([
    ['trailing dot', 'www.example.com.'],
    ['uppercase', 'WWW.EXAMPLE.COM'],
    ['suffix lookalike', 'evilexample.com'],
    ['domain as left label', 'example.com.evil.net'],
    ['homograph A-label', 'xn--exmple-cua.com'],
    ['cyrillic e', 'www.еxample.com'],
    ['empty leading label', '.example.com'],
    ['empty inner label', 'www..example.com'],
    ['hyphen-only label', '-.example.com'],
    ['IP literal', '8.8.4.4'],
    ['NUL', 'www.example.com\u0000'],
    ['not an approved asset (pending CT discovery)', 'pending.example.com'],
    ['not this target (apex claimed for www)', 'example.com'],
  ])('tls refuses hostname: %s (%j)', async (_label, hostname) => {
    const s = await setupActive();
    expect((await submit(s, 'r1', [tlsObs(s.www, { hostname })])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it.each([
    ['userinfo', 'https://user:pass@www.example.com/'],
    ['userinfo host swap', 'https://www.example.com@evil.net/'],
    ['userinfo with port', 'https://www.example.com:443@evil.net/'],
    ['backslash authority', 'https://www.example.com\\@evil.net/'],
    ['fragment before path', 'https://www.example.com#@evil.net'],
    ['query before path', 'https://www.example.com?@evil.net'],
    ['IPv6 literal', 'https://[::1]/'],
    ['IPv4 literal', 'http://127.0.0.1/'],
    ['integer host', 'http://2130706433/'],
    ['hex host', 'http://0x7f.1/'],
    ['trailing-dot host', 'https://www.example.com./'],
    ['uppercase scheme', 'HTTPS://www.example.com/'],
    ['uppercase host', 'https://WWW.example.com/'],
    ['port 0', 'https://www.example.com:0/'],
    ['port 65536', 'https://www.example.com:65536/'],
    ['leading-zero port', 'https://www.example.com:0443/'],
    ['file scheme', 'file:///etc/passwd'],
    ['gopher scheme', 'gopher://www.example.com/'],
    ['ws scheme', 'ws://www.example.com/'],
    ['scheme-relative', '//www.example.com/'],
    ['single slash', 'https:/www.example.com/'],
    ['CRLF injection', 'https://www.example.com/\r\nHost: evil.net'],
    ['space in path', 'https://www.example.com/ x'],
    ['homograph host', 'https://www.еxample.com/'],
    ['punycode homograph host', 'https://xn--exmple-cua.com/'],
    ['out of domain with domain in path', 'https://evil.net/https://www.example.com/'],
    ['empty inner label', 'https://www..example.com/'],
    ['not an approved asset', 'https://pending.example.com/'],
    ['too long', `https://www.example.com/${'a'.repeat(2048)}`],
  ])('http refuses url: %s', async (_label, url) => {
    const s = await setupActive();
    expect((await submit(s, 'r1', [httpObs(s.www, { url })])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it('accepts a legitimate explicit port and underscore-free host (positive control)', async () => {
    const s = await setupActive();
    const res = await submit(s, 'r1', [
      httpObs(s.www, { url: 'https://www.example.com:8443/a?b=c' }),
    ]);
    expect(res.status).toBe(200);
  });

  it.each([
    ['javascript', 'javascript:alert(1)'],
    ['data', 'data:text/html,<script>alert(1)</script>'],
    ['file', 'file:///etc/passwd'],
    ['CRLF', 'https://www.example.com/\r\n'],
  ])('http refuses finalUrl: %s', async (_label, finalUrl) => {
    const s = await setupActive();
    expect((await submit(s, 'r1', [httpObs(s.www, { finalUrl })])).status).toBe(400);
  });
});

describe('RT-OBS: port evidence vs profile and approved networks', () => {
  it.each([
    ['not in profile', { port: 12345 }],
    ['deep-only port on standard job', { port: 2375 }],
    ['port 0', { port: 0 }],
    ['port 65536', { port: 65536 }],
    ['udp', { protocol: 'udp' }],
    ['just below network', { ipAddress: '8.8.7.255' }],
    ['just above network', { ipAddress: '8.8.9.0' }],
    ['mapped spelling of an approved address', { ipAddress: '::ffff:8.8.8.8' }],
    ['other public', { ipAddress: '8.8.4.4' }],
  ])('refuses port evidence %s', async (_label, over) => {
    const s = await setupActive();
    expect((await submit(s, 'r1', [portObs(s.apex, over)])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it('refuses port evidence for a network approved only after the job was created', async () => {
    const s = await setupActive();
    await approve({ cidr: '9.9.9.0/24' });
    expect((await submit(s, 'r1', [portObs(s.apex, { ipAddress: '9.9.9.9' })])).status).toBe(400);
  });

  it('refuses port evidence after the network is revoked mid-job, even if later re-approved broader', async () => {
    const s = await setupActive();
    await revokeNet(s.networkId);
    await approve({ cidr: '8.8.0.0/16' });
    expect((await submit(s, 'r1', [portObs(s.apex)])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it('refuses port evidence after the network expires mid-job', async () => {
    const d = await verifiedDomain();
    await approve({ reviewBy: '2026-10-22' });
    const w = await registerWorker();
    await requestScan(d.id, 'standard');
    const job = (await claim(w))!;
    clock = new Date('2026-10-23T00:00:30.000Z');
    // Keep the lease alive.
    const res = await workerCall(
      h,
      w.key,
      w.keyId,
      'results',
      {
        jobId: job.id,
        attempt: job.attempt,
        resultId: 'result-r1',
        targets: [],
        observations: [portObs(job.targets[0]!.id, { observedAt: clock.toISOString() })],
        complete: false,
      },
      { now: clock, envExtra: ACTIVE_ON },
    );
    expect(res.status).toBe(400);
  });

  it.each([
    ['tls', tlsObs],
    ['http', httpObs],
    ['port', portObs],
  ])('refuses %s evidence on a passive job', async (_k, make) => {
    const s = await setupPassive();
    expect((await submit(s, 'r1', [make(s.www)])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it('refuses port evidence on a quick (web-tier) job', async () => {
    const s = await setupActive('quick');
    expect(s.job.snapshot.approvedNetworks).toEqual(['8.8.8.0/24']);
    expect((await submit(s, 'r1', [portObs(s.apex, { port: 443 })])).status).toBe(400);
  });
});

describe('RT-OBS: cross-job, idempotency, evidence and time', () => {
  it('refuses observations naming a target of another job', async () => {
    const s = await setupActive();
    const d2 = await verifiedDomain('example.org');
    const other = await requestScan(d2.id, 'quick');
    const foreignTarget = other.targets[0]!.id;
    const res = await submit(s, 'r1', [tlsObs(foreignTarget, { hostname: 'example.org' })]);
    expect(res.status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it('a duplicate resultId with a different payload stores nothing new', async () => {
    const s = await setupActive();
    expect((await submit(s, 'dup', [tlsObs(s.www, { protocolVersion: 'TLSv1.3' })])).status).toBe(
      200,
    );
    const second = await submit(s, 'dup', [
      tlsObs(s.www, { protocolVersion: 'SSLv3' }),
      portObs(s.apex),
      httpObs(s.www),
    ]);
    expect(await second.json()).toMatchObject({ accepted: false });
    expect(await activeCounts()).toEqual({ tls: 1, http: 0, port: 0 });
    const [row] = await t.db.select().from(schema.tlsObservations);
    expect(row!.protocolVersion).toBe('TLSv1.3');
  });

  it('a duplicate resultId with invalid (private-IP) evidence is not stored either', async () => {
    const s = await setupActive();
    await submit(s, 'dup', [tlsObs(s.www)]);
    const second = await submit(s, 'dup', [tlsObs(s.www, { ipAddress: '10.0.0.1' })]);
    expect(second.status).toBeLessThan(500);
    expect(await activeCounts()).toEqual({ tls: 1, http: 0, port: 0 });
  });

  it('refuses oversized evidence', async () => {
    const s = await setupActive();
    const evidence = { blob: 'x'.repeat(17_000) };
    expect((await submit(s, 'r1', [tlsObs(s.www, { evidence })])).status).toBe(400);
    const longKey = { ['k'.repeat(65)]: 1 };
    expect((await submit(s, 'r2', [tlsObs(s.www, { evidence: longKey })])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it('evidence keys __proto__ / constructor / prototype cannot pollute prototypes', async () => {
    const s = await setupActive();
    const path = '/api/v1/internal/worker/results';
    const raw =
      `{"jobId":"${s.job.id}","attempt":${s.job.attempt},"resultId":"result-proto","targets":[],"complete":false,` +
      `"observations":[${JSON.stringify(tlsObs(s.www)).replace(
        '"evidence":{}',
        '"evidence":{"__proto__":{"polluted":"yes","isAdmin":true},"constructor":{"prototype":{"polluted2":"yes"}},"prototype":{"x":1}}',
      )}]}`;
    const headers = await signedHeaders(s.w.key, s.w.keyId, 'POST', path, raw, { now: clock });
    const res = await createApp(h.deps).request(
      path,
      { method: 'POST', headers, body: raw },
      h.env('viewer', ACTIVE_ON) as unknown as Env,
    );
    expect(res.status).toBeLessThan(500);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted2).toBeUndefined();
    expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
    const rows = await t.db.select().from(schema.tlsObservations);
    for (const r of rows) {
      expect(Object.getPrototypeOf(r.evidence)).toBe(Object.prototype);
      expect((r.evidence as Record<string, unknown>).polluted).toBeUndefined();
    }
  });

  it('deeply nested evidence does not crash the API (no 500)', async () => {
    const s = await setupActive();
    let deep: unknown = 1;
    for (let i = 0; i < 4000; i++) deep = [deep];
    const res = await submit(s, 'r-deep', [tlsObs(s.www, { evidence: { deep } })]);
    expect(res.status).toBeLessThan(500);
  });

  it.each([
    ['5 min + 1 ms in the future', () => iso(5 * 60_000 + 1)],
    ['7 days + 1 ms in the past', () => iso(-7 * 86_400_000 - 1)],
    ['epoch', () => '1970-01-01T00:00:00.000Z'],
    ['year 9999', () => '9999-12-31T23:59:59.999Z'],
    ['leap second', () => '2026-10-22T09:59:60.000Z'],
    ['offset form', () => '2026-10-22T10:00:00+00:00'],
    ['no zone', () => '2026-10-22T10:00:00'],
    ['date only', () => '2026-10-22'],
    ['invalid day', () => '2026-02-30T10:00:00.000Z'],
  ])('refuses observedAt %s', async (_label, at) => {
    const s = await setupActive();
    expect((await submit(s, 'r1', [{ ...tlsObs(s.www), observedAt: at() }])).status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
  });

  it('accepts observedAt exactly at the window edges (positive control)', async () => {
    const s = await setupActive();
    expect(
      (await submit(s, 'r1', [{ ...tlsObs(s.www), observedAt: iso(5 * 60_000) }])).status,
    ).toBe(200);
  });

  it('one bad observation rejects the whole batch atomically (no partial storage)', async () => {
    const s = await setupActive();
    const res = await submit(s, 'r1', [
      tlsObs(s.www),
      httpObs(s.www),
      portObs(s.apex),
      portObs(s.apex, { ipAddress: '10.0.0.1' }),
    ]);
    expect(res.status).toBe(400);
    expect(await activeCounts()).toEqual(NONE);
    expect(await t.db.select().from(schema.scanJobResults)).toHaveLength(0);
  });
});

// ================================================================================================
// RT-WRK: worker auth and job ownership
// ================================================================================================

describe('RT-WRK: job ownership, replay and fencing', () => {
  it('another valid worker cannot heartbeat, submit or fail a job it does not hold', async () => {
    const s = await setupActive();
    const other = await registerWorker();
    const hb = await workerCall(
      h,
      other.key,
      other.keyId,
      'heartbeat',
      { jobId: s.job.id, attempt: s.job.attempt },
      { now: clock, envExtra: ACTIVE_ON },
    );
    await expectError(hb, 409, 'conflict');
    await expectError(await submit(s, 'r-steal', [tlsObs(s.www)], { w: other }), 409, 'conflict');
    const f = await workerCall(
      h,
      other.key,
      other.keyId,
      'failures',
      {
        jobId: s.job.id,
        attempt: s.job.attempt,
        errorCode: 'x',
        errorSummary: 'x',
        retryable: false,
      },
      { now: clock, envExtra: ACTIVE_ON },
    );
    await expectError(f, 409, 'conflict');
    expect(await activeCounts()).toEqual(NONE);
    const [row] = await t.db.select().from(schema.scanJobs).where(eq(schema.scanJobs.id, s.job.id));
    expect(row).toMatchObject({ status: 'claimed', workerId: s.w.workerId });
  });

  it("another worker reusing the holder's resultId learns nothing and stores nothing", async () => {
    const s = await setupActive();
    await submit(s, 'shared-id', [tlsObs(s.www)]);
    const other = await registerWorker();
    const res = await submit(s, 'shared-id', [tlsObs(s.www)], { w: other });
    await expectError(res, 409, 'conflict');
  });

  it('a replayed request (same nonce) is rejected and has no effect', async () => {
    const s = await setupActive();
    const path = '/api/v1/internal/worker/results';
    const body = JSON.stringify({
      jobId: s.job.id,
      attempt: s.job.attempt,
      resultId: 'result-replay',
      targets: [],
      observations: [tlsObs(s.www)],
      complete: false,
    });
    const headers = await signedHeaders(s.w.key, s.w.keyId, 'POST', path, body, {
      now: clock,
      nonce: 'replay-nonce-0123456789',
    });
    const send = () =>
      createApp(h.deps).request(
        path,
        { method: 'POST', headers, body },
        h.env('viewer', ACTIVE_ON) as unknown as Env,
      );
    expect((await send()).status).toBe(200);
    await expectError(await send(), 401, 'unauthenticated');
  });

  it('a request whose body differs from the signed body is rejected', async () => {
    const s = await setupActive();
    const path = '/api/v1/internal/worker/results';
    const signed = JSON.stringify({
      jobId: s.job.id,
      attempt: s.job.attempt,
      resultId: 'result-a',
      targets: [],
      observations: [tlsObs(s.www)],
      complete: false,
    });
    const tampered = signed.replace('8.8.4.4', '10.0.0.1');
    const headers = await signedHeaders(s.w.key, s.w.keyId, 'POST', path, tampered, {
      now: clock,
      signedBody: signed,
    });
    const res = await createApp(h.deps).request(
      path,
      { method: 'POST', headers, body: tampered },
      h.env('viewer', ACTIVE_ON) as unknown as Env,
    );
    await expectError(res, 401, 'unauthenticated');
  });

  it('a stale attempt (lease lost, job re-claimed) cannot submit or heartbeat', async () => {
    const s = await setupActive();
    // Lease expires; reaper requeues; the same worker claims attempt 2.
    clock = new Date(clock.getTime() + 10 * 60_000);
    const { reapExpiredLeases } = await import('../services/job-lifecycle.ts');
    await reapExpiredLeases(t.db, clock);
    clock = new Date(clock.getTime() + 60 * 60_000);
    const again = (await claim(s.w))!;
    expect(again.attempt).toBe(2);
    await expectError(
      await submit(s, 'r-stale', [tlsObs(s.www, { observedAt: clock.toISOString() })], {
        attempt: 1,
      }),
      409,
      'conflict',
    );
    const hb = await workerCall(
      h,
      s.w.key,
      s.w.keyId,
      'heartbeat',
      { jobId: s.job.id, attempt: 1 },
      { now: clock, envExtra: ACTIVE_ON },
    );
    await expectError(hb, 409, 'conflict');
    expect(await activeCounts()).toEqual(NONE);
  });

  it('a disabled worker can no longer submit for a job it holds', async () => {
    const s = await setupActive();
    const res = await call('admin', 'PATCH', `/workers/${s.w.workerId}`, { status: 'disabled' });
    expect(res.status).toBe(200);
    await expectError(await submit(s, 'r-dis', [tlsObs(s.www)]), 401, 'unauthenticated');
    expect(await activeCounts()).toEqual(NONE);
  });

  it('a timestamp outside the window is rejected even with a valid signature', async () => {
    const s = await setupActive();
    const res = await workerCall(
      h,
      s.w.key,
      s.w.keyId,
      'heartbeat',
      { jobId: s.job.id, attempt: s.job.attempt },
      { now: clock, timestamp: Math.floor(clock.getTime() / 1000) - 301, envExtra: ACTIVE_ON },
    );
    await expectError(res, 401, 'unauthenticated');
  });
});
