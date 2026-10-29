// @vitest-environment node
// Change timeline (Milestone 14): events derived from seeded observation sequences for every kind
// (unchanged runs, failed/partial runs and first observations produce nothing), asset-owner
// scoping, filters, the window and paging. Synthetic data on reserved names only.
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { changesResponseSchema, type ChangeEvent, type Role } from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { firstRow } from '../lib/db.ts';
import { seedDomain, seedJob, type DnsSpec, type Seed } from '../testing/findings-fixtures.ts';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

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
beforeEach(async () => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
  await t.db.delete(schema.auditLogs);
});
afterEach(() => vi.restoreAllMocks());

/** Day `n` of October 2026, at `hour` UTC. */
const oct = (n: number, hour = 1) => new Date(Date.UTC(2026, 9, n, hour));
let seq = 0;
const rid = () => `chg-${seq++}`;

async function list(role: Role, query = '') {
  const res = await userCall(h, t, role, 'GET', `/changes${query}`);
  expect(res.status, query).toBe(200);
  return changesResponseSchema.parse(await res.json());
}
const ofKind = async (kind: string, extra = '') =>
  (await list('admin', `?kind=${kind}${extra}`)).items;

/** A succeeded (or failed) job with no DNS rows, for the other observation kinds. */
const job = (s: Seed, at: Date, status: 'succeeded' | 'failed' = 'succeeded') =>
  seedJob(t, s.domainId, at, [], status);

const obs = (jobId: string, at: Date, status: 'success' | 'timeout' | 'error' | 'partial') => ({
  resultId: rid(),
  scanJobId: jobId,
  observedAt: at,
  checker: 'test',
  checkerVersion: 'test',
  resultStatus: status,
});

async function addAsset(
  s: Seed,
  hostname: string,
  over: Partial<typeof schema.assets.$inferInsert> = {},
): Promise<string> {
  return firstRow(
    await t.db
      .insert(schema.assets)
      .values({
        domainId: s.domainId,
        hostname,
        assetType: 'subdomain',
        discoverySource: 'manual',
        firstSeenAt: oct(1),
        ...over,
      })
      .returning(),
  ).id;
}

const a = (host: string, values: string[], status?: DnsSpec['status']): DnsSpec => ({
  hostname: host,
  recordType: 'A',
  values,
  status,
});

describe('DNS', () => {
  it('reports a record-set change once, ignoring first observations, reordering and failed runs', async () => {
    const s = await seedDomain(t, 'dns.example.com');
    const www = 'www.dns.example.com';
    await seedJob(t, s.domainId, oct(10), [a(www, ['192.0.2.1', '192.0.2.2'])]);
    await seedJob(t, s.domainId, oct(11), [a(www, ['192.0.2.2', '192.0.2.1'])]); // reordered
    await seedJob(t, s.domainId, oct(12), [a(www, ['198.51.100.9'])], 'failed'); // failed job
    await seedJob(t, s.domainId, oct(13), [a(www, [], 'timeout')]); // failed result
    await seedJob(t, s.domainId, oct(14), [a(www, ['192.0.2.2', '192.0.2.3'])]);
    await seedJob(t, s.domainId, oct(15), [a(www, ['192.0.2.3', '192.0.2.2'])]);

    const items = await ofKind('dns');
    expect(items).toHaveLength(1);
    const e = items[0]!;
    expect(e).toMatchObject({
      kind: 'dns',
      at: oct(14).toISOString(),
      domain: { id: s.domainId, fqdn: 'dns.example.com' },
      assetId: s.wwwAssetId, // resolved from the hostname (the observation has no asset id)
      hostname: www,
      subject: 'A record',
      before: ['192.0.2.1', '192.0.2.2'],
      after: ['192.0.2.2', '192.0.2.3'],
      severityHint: 'notable',
    });
    expect(e.summary).toBe(`A record of ${www} changed: added 192.0.2.3; removed 192.0.2.1`);
    // Deterministic id: the same data gives the same id.
    expect((await ofKind('dns'))[0]!.id).toBe(e.id);
  });

  it('treats a nameserver change as important, ignores SOA churn and case differences', async () => {
    const s = await seedDomain(t, 'ns.example.com');
    const host = 'ns.example.com';
    await seedJob(t, s.domainId, oct(10), [
      { hostname: host, recordType: 'NS', values: ['NS1.EXAMPLE.NET.'] },
      { hostname: host, recordType: 'SOA', values: ['ns1.example.net. h. 1 2 3 4 5'] },
    ]);
    await seedJob(t, s.domainId, oct(11), [
      { hostname: host, recordType: 'NS', values: ['ns1.example.net.'] },
      { hostname: host, recordType: 'SOA', values: ['ns1.example.net. h. 2 2 3 4 5'] },
    ]);
    await seedJob(t, s.domainId, oct(12), [
      { hostname: host, recordType: 'NS', values: ['ns2.example.org.'] },
    ]);
    const items = await ofKind('dns');
    expect(items.map((e) => [e.subject, e.severityHint])).toEqual([['NS record', 'important']]);
    expect(items[0]!.assetId).toBeNull(); // no asset for the apex in this seed
  });

  it('reports creation and removal of a record set (empty answers are values too)', async () => {
    const s = await seedDomain(t, 'txt.example.com');
    const host = '_dmarc.txt.example.com';
    const txt = (values: string[]): DnsSpec => ({ hostname: host, recordType: 'TXT', values });
    await seedJob(t, s.domainId, oct(10), [txt([])]);
    await seedJob(t, s.domainId, oct(11), [txt(['"v=DMARC1; p=none"'])]);
    await seedJob(t, s.domainId, oct(12), [txt(['"v=DMARC1; P=none"'])]); // TXT is case-sensitive
    await seedJob(t, s.domainId, oct(13), [txt([])]);
    const summaries = (await ofKind('dns')).map((e) => e.summary);
    expect(summaries).toEqual([
      `TXT record of ${host} removed (was "v=DMARC1; P=none")`,
      `TXT record of ${host} changed: added "v=DMARC1; P=none"; removed "v=DMARC1; p=none"`,
      `TXT record of ${host} created: "v=DMARC1; p=none"`,
    ]);
  });
});

describe('IP addresses', () => {
  it('reports addresses added after the initial set and addresses no longer current', async () => {
    const s = await seedDomain(t, 'ip.example.com');
    const ip = (ipAddress: string, first: Date, last: Date, isCurrent: boolean) =>
      t.db.insert(schema.assetIps).values({
        assetId: s.wwwAssetId,
        ipAddress,
        source: 'dns',
        firstSeenAt: first,
        lastSeenAt: last,
        isCurrent,
      });
    await ip('192.0.2.1', oct(10), oct(14), false); // initial, later gone
    await ip('192.0.2.2', oct(10, 1), oct(20), true); // initial set (same run): no event
    await ip('192.0.2.3', oct(15), oct(20), true); // added later
    const items = await ofKind('ip');
    expect(items.map((e) => [e.summary, e.severityHint])).toEqual([
      ['www.ip.example.com started resolving to 192.0.2.3', 'notable'],
      ['www.ip.example.com stopped resolving to 192.0.2.1 (last seen)', 'notable'],
    ]);
    expect(items[0]).toMatchObject({ before: null, after: { address: '192.0.2.3' } });
  });
});

describe('TLS', () => {
  const cert = (
    jobId: string,
    at: Date,
    v: { fp: string; issuer: string; protocol?: string; status?: 'success' | 'timeout' },
  ) =>
    t.db.insert(schema.tlsObservations).values({
      ...obs(jobId, at, v.status ?? 'success'),
      hostname: 'www.tls.example.com',
      ipAddress: '192.0.2.10',
      port: 443,
      protocolVersion: v.protocol ?? 'TLSv1.3',
      notBefore: oct(1),
      notAfter: new Date(Date.UTC(2027, 0, 1)),
      issuer: v.issuer,
      subject: 'CN=www.tls.example.com',
      fingerprintSha256: v.fp,
    });

  it('separates renewals (info) from issuer-organisation changes (important) and protocol changes', async () => {
    const s = await seedDomain(t, 'tls.example.com');
    const LE1 = "CN=R10,O=Let's Encrypt,C=US";
    const LE2 = "CN=R11,O=Let's Encrypt,C=US";
    const OTHER = 'CN=Other CA,O=Example Trust,C=US';
    const steps: [number, Parameters<typeof cert>[2]][] = [
      [10, { fp: 'aa', issuer: LE1 }],
      [11, { fp: 'aa', issuer: LE1 }], // unchanged
      [12, { fp: 'bb', issuer: LE2 }], // renewal, new intermediate of the same CA
      [13, { fp: 'zz', issuer: OTHER, status: 'timeout' }], // failed: ignored
      [14, { fp: 'cc', issuer: OTHER }], // different CA
      [15, { fp: 'cc', issuer: OTHER, protocol: 'TLSv1.2' }], // protocol only
    ];
    for (const [day, v] of steps) await cert(await job(s, oct(day)), oct(day), v);
    const items = await ofKind('tls');
    expect(items.map((e) => [e.at.slice(0, 10), e.subject, e.severityHint])).toEqual([
      ['2026-10-15', 'TLS protocol 443/tcp', 'info'],
      ['2026-10-14', 'certificate 443/tcp', 'important'],
      ['2026-10-12', 'certificate 443/tcp', 'info'],
    ]);
    expect(items[0]!.summary).toBe(
      'TLS protocol on www.tls.example.com:443 changed from TLSv1.3 to TLSv1.2',
    );
    expect(items[1]!.summary).toContain(`changed issuer from ${LE2} to ${OTHER}`);
    expect(items[1]!.before).toMatchObject({ fingerprint: ['bb'], notAfter: ['2027-01-01'] });
    expect(items[1]!.after).toMatchObject({ fingerprint: ['cc'], issuer: [OTHER] });
    expect(items[0]!.assetId).toBe(s.wwwAssetId);
  });
});

describe('HTTP and software', () => {
  const http = (
    jobId: string,
    at: Date,
    url: string,
    v: { code?: number; final?: string; hsts?: boolean | null; server?: string | null },
    status: 'success' | 'error' = 'success',
  ) =>
    t.db.insert(schema.httpObservations).values({
      ...obs(jobId, at, status),
      url,
      statusCode: status === 'success' ? (v.code ?? 200) : null,
      finalUrl: status === 'success' ? (v.final ?? url) : null,
      hstsEnabled: v.hsts ?? null,
      evidence: status === 'success' && v.server !== undefined ? { server: v.server } : {},
    });

  it('reports status, final URL and HSTS changes per URL; HSTS turned off is notable', async () => {
    const s = await seedDomain(t, 'http.example.com');
    const url = 'https://www.http.example.com/';
    const steps: [number, Parameters<typeof http>[3], ('success' | 'error')?][] = [
      [10, { hsts: true }],
      [11, { hsts: true }],
      [12, {}, 'error'],
      [13, { hsts: false }],
      [14, { hsts: false, code: 301, final: 'https://www.http.example.com/home' }],
    ];
    for (const [day, v, st] of steps) await http(await job(s, oct(day)), oct(day), url, v, st);
    const items = await ofKind('http');
    expect(items.map((e) => [e.summary, e.severityHint])).toEqual([
      [`${url}: status 200 → 301; final URL ${url} → https://www.http.example.com/home`, 'info'],
      [`${url}: HSTS on → off`, 'notable'],
    ]);
    expect(items[1]).toMatchObject({
      hostname: 'www.http.example.com',
      assetId: s.wwwAssetId,
      before: { statusCode: 200, hsts: true },
      after: { statusCode: 200, hsts: false },
    });
  });

  it('reports web server banner changes only between runs that recorded headers', async () => {
    const s = await seedDomain(t, 'sw.example.com');
    const url = 'https://www.sw.example.com/';
    const steps: [number, Parameters<typeof http>[3], ('success' | 'error')?][] = [
      [10, { server: 'nginx/1.24.0' }],
      [11, {}], // no headers recorded: not compared
      [12, { server: 'nginx/1.24.0' }],
      [13, { server: 'nginx/1.26.2' }], // version changed
      [14, { server: null }], // disappeared
      [15, {}, 'error'],
    ];
    for (const [day, v, st] of steps) await http(await job(s, oct(day)), oct(day), url, v, st);
    const items = await ofKind('software');
    expect(items.map((e) => [e.summary, e.severityHint])).toEqual([
      [`${url} no longer reports nginx/1.26.2`, 'info'],
      [`${url} now reports nginx/1.26.2 (was nginx/1.24.0)`, 'notable'],
    ]);
    expect(await ofKind('http')).toEqual([]); // status/HSTS unchanged
  });
});

describe('Ports', () => {
  it('reports state transitions; a port opening is important; failed runs are ignored', async () => {
    const s = await seedDomain(t, 'port.example.com');
    const steps: [number, string, ('success' | 'error')?][] = [
      [10, 'closed'],
      [11, 'closed'],
      [12, 'open', 'error'],
      [13, 'open'],
      [14, 'open'],
      [15, 'filtered'],
    ];
    for (const [day, state, st] of steps) {
      const j = await job(s, oct(day));
      await t.db.insert(schema.portObservations).values({
        ...obs(j, oct(day), st ?? 'success'),
        assetId: s.wwwAssetId,
        ipAddress: '192.0.2.20',
        port: 8443,
        protocol: 'tcp',
        state,
        evidence: state === 'open' ? { product: 'nginx', version: `1.2${day}` } : {},
      });
    }
    const items = await ofKind('port');
    expect(items.map((e) => [e.summary, e.severityHint, e.assetId])).toEqual([
      ['Port 192.0.2.20 8443/tcp became filtered (was open)', 'info', s.wwwAssetId],
      ['Port 192.0.2.20 8443/tcp opened (was closed)', 'important', s.wwwAssetId],
    ]);
    const sw = await ofKind('software');
    expect(sw.map((e) => e.summary)).toEqual([
      'Service on 192.0.2.20 8443/tcp now reports nginx 1.214 (was nginx 1.213)',
    ]);
  });
});

describe('Registration', () => {
  it('reports registrar, nameserver and expiry changes; redacted gaps are not removals', async () => {
    const s = await seedDomain(t, 'reg.example.com');
    const rows: [number, Partial<typeof schema.registrationObservations.$inferInsert>][] = [
      [10, { registrar: 'Registrar A', nameservers: ['ns1.a.example.'], expiresAt: oct(30) }],
      [11, { registrar: 'REGISTRAR A', nameservers: ['NS1.A.EXAMPLE'], expiresAt: oct(30) }],
      [12, { registrar: null, nameservers: [], expiresAt: null, dataStatus: 'unavailable' }],
      [13, { registrar: null, nameservers: [], expiresAt: null, dataStatus: 'redacted' }],
      [14, { registrar: 'Registrar B', nameservers: ['ns1.b.example'], expiresAt: oct(30) }],
      [15, { registrar: 'Registrar B', nameservers: ['ns1.b.example'], expiresAt: oct(31) }],
    ];
    for (const [day, v] of rows) {
      const j = await job(s, oct(day));
      await t.db.insert(schema.registrationObservations).values({
        ...obs(j, oct(day), 'success'),
        domainId: s.domainId,
        dataStatus: 'available',
        ...v,
      });
    }
    const items = await ofKind('registration');
    expect(items.map((e) => [e.subject, e.severityHint, e.summary])).toEqual([
      [
        'expiry date',
        'info',
        'Registration expiry of reg.example.com changed from 2026-10-30 to 2026-10-31',
      ],
      [
        'registrar',
        'important',
        'Registrar of reg.example.com changed from REGISTRAR A to Registrar B',
      ],
      [
        'nameservers',
        'important',
        'Nameservers of reg.example.com changed: added ns1.b.example; removed ns1.a.example',
      ],
    ]);
  });
});

describe('Assets', () => {
  it('reports newly discovered assets and approval decisions', async () => {
    const s = await seedDomain(t, 'asset.example.com');
    const id = await addAsset(s, 'new.asset.example.com', {
      discoverySource: 'certificate_transparency',
      firstSeenAt: oct(15),
    });
    await addAsset(s, 'old.asset.example.com', { firstSeenAt: new Date(Date.UTC(2026, 6, 1)) });
    const admin = await ensureUser(t, 'admin');
    await t.db.insert(schema.auditLogs).values({
      actorType: 'user',
      actorUserId: admin,
      action: 'asset.rejected',
      resourceType: 'asset',
      resourceId: id,
      createdAt: oct(16),
      metadata: { reason: 'Not ours' },
    });
    const items = await ofKind('asset');
    expect(items.map((e) => [e.summary, e.severityHint, e.assetId])).toEqual([
      ['Asset new.asset.example.com rejected: Not ours', 'info', id],
      ['New asset new.asset.example.com added (source: certificate transparency)', 'notable', id],
    ]);
  });
});

describe('scoping, filters, window and paging', () => {
  async function seedTwoDomains() {
    const mine = await seedDomain(t, 'mine.example.com', { owned: true });
    const other = await seedDomain(t, 'other.example.com');
    for (const s of [mine, other]) {
      const www = `www.${s.fqdn}`;
      await seedJob(t, s.domainId, oct(10), [
        a(www, ['192.0.2.1']),
        { hostname: s.fqdn, recordType: 'NS', values: ['ns1.example.net'] },
      ]);
      await seedJob(t, s.domainId, oct(12), [
        a(www, ['192.0.2.2']),
        { hostname: s.fqdn, recordType: 'NS', values: ['ns2.example.net'] },
      ]);
      await seedJob(t, s.domainId, oct(20), [
        a(www, ['192.0.2.3']),
        { hostname: s.fqdn, recordType: 'NS', values: ['ns2.example.net'] },
      ]);
    }
    return { mine, other };
  }

  it('shows asset owners only events on assets they own; readers see everything', async () => {
    const { mine } = await seedTwoDomains();
    const admin = await list('admin');
    expect(admin.total).toBe(6);
    expect(admin.counts).toEqual({ info: 0, notable: 4, important: 2 });
    const owner = await list('asset_owner');
    expect(owner.total).toBe(2);
    expect(owner.items.every((e) => e.assetId === mine.wwwAssetId)).toBe(true);
    expect((await list('viewer')).total).toBe(6);
    expect((await list('analyst')).total).toBe(6);
  });

  it('filters by domain, asset, kind and minimum importance', async () => {
    const { mine, other } = await seedTwoDomains();
    expect((await list('admin', `?domainId=${other.domainId}`)).total).toBe(3);
    const byAsset = await list('admin', `?assetId=${mine.wwwAssetId}`);
    expect(byAsset.items.map((e) => e.hostname)).toEqual([
      'www.mine.example.com',
      'www.mine.example.com',
    ]);
    expect(
      (await list('admin', `?assetId=${mine.wwwAssetId}&domainId=${other.domainId}`)).total,
    ).toBe(0);
    expect((await list('admin', `?assetId=${crypto.randomUUID()}`)).total).toBe(0);
    const important = await list('admin', '?importance=important');
    expect(important.items.map((e: ChangeEvent) => e.subject)).toEqual(['NS record', 'NS record']);
    expect((await list('admin', '?importance=notable')).total).toBe(6);
    expect((await list('admin', '?kind=ip,asset')).total).toBe(0);
  });

  it('defaults to the last 30 days, honours since/until and pages newest first', async () => {
    await seedTwoDomains();
    const def = await list('admin');
    expect(def.until).toBe(clock.toISOString());
    expect(def.since).toBe(new Date(clock.getTime() - 30 * 86_400_000).toISOString());

    // Only the 20th: its predecessor (the 12th) is before the window but within the look-back.
    const late = await list('admin', `?since=${oct(15).toISOString()}`);
    expect(late.total).toBe(2);
    expect(late.items.every((e) => e.at === oct(20).toISOString())).toBe(true);
    const early = await list('admin', `?until=${oct(15).toISOString()}`);
    expect(early.total).toBe(4);

    const p1 = await list('admin', '?pageSize=4');
    const p2 = await list('admin', '?pageSize=4&page=2');
    expect(p1.items).toHaveLength(4);
    expect(p2.items).toHaveLength(2);
    expect(p2.total).toBe(6);
    const all = [...p1.items, ...p2.items];
    expect(new Set(all.map((e) => e.id)).size).toBe(6);
    const times = all.map((e) => e.at);
    expect([...times].sort().reverse()).toEqual(times);

    const beyond = await list('admin', '?pageSize=4&page=5');
    expect(beyond.items).toEqual([]);
    expect(beyond.total).toBe(6);
    expect(beyond.counts.important).toBe(2);
  });

  it('is empty when nothing changed', async () => {
    const s = await seedDomain(t, 'quiet.example.com');
    await seedJob(t, s.domainId, oct(10), [a('www.quiet.example.com', ['192.0.2.1'])]);
    await seedJob(t, s.domainId, oct(11), [a('www.quiet.example.com', ['192.0.2.1'])]);
    const res = await list('admin');
    expect(res).toMatchObject({
      items: [],
      total: 0,
      counts: { info: 0, notable: 0, important: 0 },
    });
  });

  it('rejects invalid queries with the error envelope', async () => {
    for (const q of [
      '?kind=bogus',
      '?importance=high',
      '?since=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z',
      '?pageSize=101',
    ]) {
      const res = await userCall(h, t, 'admin', 'GET', `/changes${q}`);
      expect(res.status, q).toBe(400);
      const body = (await res.json()) as { error: { code: string } };
      expect(body.error.code).toBe('validation_failed');
    }
  });
});
