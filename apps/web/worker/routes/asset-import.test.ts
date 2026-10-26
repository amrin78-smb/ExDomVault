// @vitest-environment node
import { schema, type Database } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  ASSET_IMPORT_MAX_ENTRIES,
  assetImportResponseSchema,
  assetListResponseSchema,
  errorResponseSchema,
  type AssetImportResponse,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { importAssets, normaliseImportHostname } from '../services/asset-import.ts';
import { ensureUser, harness, userCall } from '../testing/harness.ts';

const { assets, auditLogs, domains, scanJobs } = schema;

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
  clock = new Date('2026-10-26T10:00:00.000Z');
  await t.db.delete(scanJobs);
  await t.db.delete(assets);
  await t.db.delete(domains);
  await t.db.delete(auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const call = (role: Role, method: string, path: string, body?: unknown) =>
  userCall(h, t, role, method, path, body);

async function addDomain(fqdn = 'example.com'): Promise<string> {
  const [d] = await t.db.insert(domains).values({ fqdn }).returning();
  return d!.id;
}

async function addApprovedAsset(domainId: string, hostname: string) {
  const admin = await ensureUser(t, 'admin');
  await t.db.insert(assets).values({
    domainId,
    hostname,
    assetType: 'subdomain',
    discoverySource: 'certificate_transparency',
    verificationStatus: 'approved',
    approvedBy: admin,
    approvedAt: clock,
    monitoringEnabled: true,
    hostingHint: null,
  });
}

async function importCall(
  domainId: string,
  body: Record<string, unknown>,
  role: Role = 'admin',
): Promise<{ res: Response; json: AssetImportResponse }> {
  const res = await call(role, 'POST', `/domains/${domainId}/assets/import`, body);
  const json = assetImportResponseSchema.parse(await res.json());
  return { res, json };
}

async function expectError(res: Response, status: number, code: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
}

const MIXED = [
  { hostname: 'WWW.Example.com.' }, // new (normalised)
  { hostname: 'app.example.com' }, // existing, approved
  { hostname: 'www.example.com' }, // duplicate
  { hostname: 'not a host' }, // invalid
  { hostname: 'evil-example.com' }, // out_of_domain (label boundary)
  { hostname: 'example.com.evil.net' }, // out_of_domain
  { hostname: 'com' }, // invalid (single label)
  { hostname: '_dmarc.example.com' }, // invalid (service label)
  { hostname: '*.example.com' }, // invalid (wildcard)
  { hostname: 'a.*.example.com' }, // invalid (wildcard label)
  { hostname: 'example.com' }, // new (apex)
  { hostname: 'cdn.example.com', cnameTarget: 'd111.cloudfront.net.' }, // new, third-party
];

describe('normaliseImportHostname', () => {
  it('canonicalises hosts and rejects non-hosts', () => {
    expect(normaliseImportHostname(' WWW.Example.COM. ')).toBe('www.example.com');
    expect(normaliseImportHostname('example.com')).toBe('example.com');
    expect(normaliseImportHostname('bücher.example.com')).toBe('xn--bcher-kva.example.com');
    expect(normaliseImportHostname('x.cloudfront.net')).toBe('x.cloudfront.net');
    for (const bad of [
      '',
      'com',
      '1.2.3.4',
      '::1',
      'http://example.com',
      'a..example.com',
      '-a.example.com',
      '_dmarc.example.com',
      '*.example.com',
      'a.*.example.com',
      `${'a'.repeat(64)}.example.com`,
      'xn--zz.example.com',
    ]) {
      expect(normaliseImportHostname(bad), bad).toBeNull();
    }
  });
});

describe('POST /domains/:id/assets/import', () => {
  it('classifies every row (dry run) without writing anything', async () => {
    const domainId = await addDomain();
    await addApprovedAsset(domainId, 'app.example.com');

    const { res, json } = await importCall(domainId, {
      entries: MIXED,
      dryRun: true,
      fileName: 'zone.txt',
    });
    expect(res.status).toBe(200);
    expect(json.dryRun).toBe(true);
    expect(json.rows.map((r) => [r.hostname, r.outcome])).toEqual([
      ['www.example.com', 'new'],
      ['app.example.com', 'existing'],
      ['www.example.com', 'duplicate'],
      ['not a host', 'invalid'],
      ['evil-example.com', 'out_of_domain'],
      ['example.com.evil.net', 'out_of_domain'],
      ['com', 'invalid'],
      ['_dmarc.example.com', 'invalid'],
      ['*.example.com', 'invalid'],
      ['a.*.example.com', 'invalid'],
      ['example.com', 'new'],
      ['cdn.example.com', 'new'],
    ]);
    expect(json.rows[1]!.existingStatus).toBe('approved');
    expect(json.rows[11]!.hostingHint).toMatchObject({ provider: 'Amazon CloudFront' });
    expect(json.summary).toEqual({
      total: 12,
      new: 3,
      existing: 1,
      duplicate: 1,
      invalid: 5,
      outOfDomain: 2,
      thirdPartyHosted: 1,
    });

    expect(await t.db.select().from(assets)).toHaveLength(1);
    expect(await t.db.select().from(auditLogs)).toHaveLength(0);
  });

  it('a parent domain is out of the domain', async () => {
    const domainId = await addDomain('shop.example.co.uk');
    const { json } = await importCall(domainId, {
      entries: [{ hostname: 'example.co.uk' }, { hostname: 'a.shop.example.co.uk' }],
      dryRun: true,
    });
    expect(json.rows.map((r) => r.outcome)).toEqual(['out_of_domain', 'new']);
  });

  it('imports new hosts as pending, unmonitored assets and audits once', async () => {
    const domainId = await addDomain();
    await addApprovedAsset(domainId, 'app.example.com');
    const [before] = await t.db.select().from(assets).where(eq(assets.hostname, 'app.example.com'));

    const { res, json } = await importCall(domainId, { entries: MIXED, fileName: 'zone.txt' });
    expect(res.status).toBe(201);
    expect(json.dryRun).toBe(false);
    expect(json.summary.new).toBe(3);

    const rows = await t.db.select().from(assets).where(eq(assets.domainId, domainId));
    const byHost = new Map(rows.map((r) => [r.hostname, r]));
    expect([...byHost.keys()].sort()).toEqual([
      'app.example.com',
      'cdn.example.com',
      'example.com',
      'www.example.com',
    ]);
    for (const host of ['www.example.com', 'example.com', 'cdn.example.com']) {
      const a = byHost.get(host)!;
      expect(a.verificationStatus).toBe('pending');
      expect(a.discoverySource).toBe('import');
      expect(a.monitoringEnabled).toBe(false);
      expect(a.approvedBy).toBeNull();
      expect(a.firstSeenAt.toISOString()).toBe(clock.toISOString());
    }
    expect(byHost.get('example.com')!.assetType).toBe('apex');
    expect(byHost.get('www.example.com')!.assetType).toBe('subdomain');
    expect(byHost.get('www.example.com')!.hostingHint).toBeNull();
    expect(byHost.get('cdn.example.com')!.hostingHint).toMatchObject({
      provider: 'Amazon CloudFront',
      matchedName: 'd111.cloudfront.net',
    });
    // The approved asset is untouched.
    expect(byHost.get('app.example.com')).toEqual(before);

    const audit = await t.db.select().from(auditLogs);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      action: 'asset.imported',
      resourceType: 'domain',
      resourceId: domainId,
      actorType: 'user',
    });
    expect(audit[0]!.metadata).toEqual({
      fileName: 'zone.txt',
      total: 12,
      new: 3,
      existing: 1,
      duplicate: 1,
      invalid: 5,
      outOfDomain: 2,
      thirdPartyHosted: 1,
    });
    // No jobs are queued by an import.
    expect(await t.db.select().from(scanJobs)).toHaveLength(0);

    // The imported asset shows up in the inventory as pending, source import.
    const list = await call('admin', 'GET', `/domains/${domainId}/assets?status=pending`);
    expect(list.status).toBe(200);
    const items = assetListResponseSchema.parse(await list.json()).items;
    const www = items.find((a) => a.hostname === 'www.example.com');
    expect(www).toMatchObject({ status: 'pending', source: 'import' });
    const cdn = items.find((a) => a.hostname === 'cdn.example.com');
    expect(cdn?.hostingHint?.provider).toBe('Amazon CloudFront');
  });

  it('re-importing is idempotent: every in-domain row is existing', async () => {
    const domainId = await addDomain();
    const entries = [{ hostname: 'a.example.com' }, { hostname: 'b.example.com' }];
    await importCall(domainId, { entries });
    const { json } = await importCall(domainId, { entries });
    expect(json.rows.map((r) => [r.outcome, r.existingStatus])).toEqual([
      ['existing', 'pending'],
      ['existing', 'pending'],
    ]);
    expect(json.summary.new).toBe(0);
    expect(await t.db.select().from(assets)).toHaveLength(2);
  });

  it('hosting hint uses every CNAME target for the hostname, including duplicate rows', async () => {
    const domainId = await addDomain();
    const { json } = await importCall(domainId, {
      entries: [
        { hostname: 'shop.example.com', cnameTarget: 'lb.example.net' },
        { hostname: 'shop.example.com', cnameTarget: 'shops.myshopify.com' },
        { hostname: 'plain.example.com', cnameTarget: 'origin.example.net' },
      ],
      dryRun: true,
    });
    expect(json.rows[0]!.hostingHint?.provider).toBe('Shopify');
    expect(json.rows[1]!.outcome).toBe('duplicate');
    expect(json.rows[2]!.hostingHint).toBeNull();
    expect(json.summary.thirdPartyHosted).toBe(1);
  });

  it('existing rows report the stored hosting hint, not the file', async () => {
    const domainId = await addDomain();
    await addApprovedAsset(domainId, 'app.example.com');
    const { json } = await importCall(domainId, {
      entries: [{ hostname: 'app.example.com', cnameTarget: 'x.cloudfront.net' }],
      dryRun: true,
    });
    expect(json.rows[0]).toMatchObject({ outcome: 'existing', hostingHint: null });
    expect(json.summary.thirdPartyHosted).toBe(0);
  });

  it('a host inserted concurrently is reported as existing, not an error', async () => {
    const domainId = await addDomain();
    // Simulate a racing insert: the row appears between planning and inserting.
    const db = t.db as unknown as Database;
    let raced = false;
    const racing = new Proxy(db, {
      get(target, prop, receiver) {
        if (prop !== 'transaction') return Reflect.get(target, prop, receiver);
        return (fn: (tx: Database) => Promise<unknown>) =>
          target.transaction(async (tx) => {
            const txDb = tx as unknown as Database;
            const wrapped = new Proxy(txDb, {
              get(inner, p, r) {
                if (p === 'insert' && !raced) {
                  raced = true;
                  return (table: unknown) => {
                    const real = Reflect.get(inner, p, r) as Database['insert'];
                    return {
                      values: (v: unknown) => ({
                        onConflictDoNothing: (o: unknown) => ({
                          returning: async (sel: unknown) => {
                            await inner.insert(assets).values({
                              domainId,
                              hostname: 'race.example.com',
                              assetType: 'subdomain',
                              discoverySource: 'certificate_transparency',
                            });
                            const q = real
                              .call(inner, table as typeof assets)
                              .values(v as never)
                              .onConflictDoNothing(o as never);
                            return q.returning(sel as never);
                          },
                        }),
                      }),
                    };
                  };
                }
                return Reflect.get(inner, p, r);
              },
            });
            return fn(wrapped);
          });
      },
    });
    const res = await importAssets(
      racing,
      domainId,
      {
        entries: [{ hostname: 'race.example.com' }, { hostname: 'calm.example.com' }],
        dryRun: false,
      },
      { userId: await ensureUser(t, 'admin'), requestId: crypto.randomUUID() },
      clock,
    );
    expect(raced).toBe(true);
    expect(res.rows.map((r) => [r.hostname, r.outcome, r.existingStatus])).toEqual([
      ['race.example.com', 'existing', 'pending'],
      ['calm.example.com', 'new', undefined],
    ]);
    expect(res.summary).toMatchObject({ new: 1, existing: 1 });
    const [raceRow] = await t.db
      .select()
      .from(assets)
      .where(eq(assets.hostname, 'race.example.com'));
    expect(raceRow!.discoverySource).toBe('certificate_transparency');
  });

  it('handles the maximum number of entries in one request', async () => {
    const domainId = await addDomain();
    const entries = Array.from({ length: ASSET_IMPORT_MAX_ENTRIES }, (_, i) => ({
      hostname: `host-${i}.example.com`,
      cnameTarget: `${'t'.repeat(200)}.example.net`,
    }));
    const { res, json } = await importCall(domainId, { entries, fileName: 'big.csv' });
    expect(res.status).toBe(201);
    expect(json.summary.new).toBe(ASSET_IMPORT_MAX_ENTRIES);
    expect(await t.db.select({ id: assets.id }).from(assets)).toHaveLength(
      ASSET_IMPORT_MAX_ENTRIES,
    );
  }, 60_000);

  it('only admins (domains:write) may import', async () => {
    const domainId = await addDomain();
    for (const role of ['analyst', 'asset_owner', 'viewer'] as const) {
      const res = await call(role, 'POST', `/domains/${domainId}/assets/import`, {
        entries: [{ hostname: 'www.example.com' }],
      });
      await expectError(res, 403, 'forbidden');
    }
    expect(await t.db.select().from(assets)).toHaveLength(0);
  });

  it('unknown domain is 404', async () => {
    const res = await call('admin', 'POST', `/domains/${crypto.randomUUID()}/assets/import`, {
      entries: [{ hostname: 'www.example.com' }],
    });
    await expectError(res, 404, 'not_found');
    const malformed = await call('admin', 'POST', '/domains/not-a-uuid/assets/import', {
      entries: [{ hostname: 'www.example.com' }],
    });
    await expectError(malformed, 404, 'not_found');
  });

  it('rejects invalid bodies with 400', async () => {
    const domainId = await addDomain();
    const path = `/domains/${domainId}/assets/import`;
    for (const body of [
      {},
      { entries: [] },
      {
        entries: Array.from({ length: ASSET_IMPORT_MAX_ENTRIES + 1 }, () => ({
          hostname: 'a.example.com',
        })),
      },
      { entries: [{ hostname: '' }] },
      { entries: [{ hostname: 'a'.repeat(254) }] },
      { entries: [{ hostname: 'a.example.com', extra: 1 }] },
      { entries: [{ hostname: 'a.example.com' }], fileName: 'f'.repeat(256) },
      { entries: [{ hostname: 'a.example.com' }], dryRun: 'yes' },
    ]) {
      await expectError(await call('admin', 'POST', path, body), 400, 'validation_failed');
    }
    expect(await t.db.select().from(assets)).toHaveLength(0);
  });
});
