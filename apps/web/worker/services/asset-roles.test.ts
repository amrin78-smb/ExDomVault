// @vitest-environment node
// assetRolesFor: evidence gathering for classifyAssetRole (Milestone 13), against PGlite.
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { firstRow } from '../lib/db.ts';
import { seedDomain, seedJob } from '../testing/findings-fixtures.ts';
import { assetRolesFor } from './asset-roles.ts';

let t: TestDatabase;
const now = new Date('2026-10-23T10:00:00.000Z');
const ago = (days: number) => new Date(now.getTime() - days * 86_400_000);
let seq = 0;

beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});
beforeEach(async () => {
  await t.db.delete(schema.scanJobs);
  await t.db.delete(schema.assets);
  await t.db.delete(schema.domains);
});

describe('assetRolesFor', () => {
  it('classifies from MX/NS answers, current open ports, recent HTTP and hosting', async () => {
    const s = await seedDomain(t, 'example.com');
    const add = async (
      hostname: string,
      hostingHint: Record<string, unknown> | null = null,
    ): Promise<string> =>
      firstRow(
        await t.db
          .insert(schema.assets)
          .values({
            domainId: s.domainId,
            hostname,
            assetType: 'subdomain',
            discoverySource: 'manual',
            hostingHint,
          })
          .returning(),
      ).id;
    const mail = await add('mail.example.com');
    const ns = await add('ns1.example.com');
    const ssh = await add('ssh.example.com');
    const db = await add('db.example.com');
    const closed = await add('closed.example.com');
    const web = await add('web.example.com');
    const oldWeb = await add('oldweb.example.com');
    const cdn = await add('cdn.example.com', {
      provider: 'Amazon CloudFront',
      kind: 'cdn',
      matchedName: 'd1.cloudfront.net',
    });
    const plain = await add('plain.example.com');

    // Apex MX/NS: the older answers are superseded (old-mx is no longer an MX target).
    await seedJob(t, s.domainId, ago(5), [
      { hostname: 'example.com', recordType: 'MX', values: ['10 old-mx.example.com.'] },
    ]);
    const job = await seedJob(t, s.domainId, ago(1), [
      { hostname: 'example.com', recordType: 'MX', values: ['10 MAIL.example.com.'] },
      { hostname: 'example.com', recordType: 'NS', values: ['ns1.example.com.'] },
    ]);
    const oldMx = await add('old-mx.example.com');

    const ip = async (assetId: string, ipAddress: string, isCurrent = true) =>
      t.db.insert(schema.assetIps).values({ assetId, ipAddress, isCurrent, source: 'dns' });
    await ip(ssh, '203.0.113.1');
    await ip(db, '203.0.113.2');
    await ip(db, '203.0.113.3', false); // no longer current: its open MySQL port does not count
    await ip(closed, '203.0.113.4');
    const port = (ipAddress: string, p: number, state: string, observedAt: Date) => ({
      resultId: `roles-${seq++}`,
      scanJobId: job,
      observedAt,
      checker: 'port',
      checkerVersion: 'test',
      resultStatus: 'success' as const,
      ipAddress,
      port: p,
      state,
    });
    await t.db.insert(schema.portObservations).values([
      port('203.0.113.1', 22, 'open', ago(1)),
      port('203.0.113.2', 443, 'open', ago(1)),
      port('203.0.113.3', 3306, 'open', ago(1)),
      // Latest state wins: SSH was open, now closed.
      port('203.0.113.4', 22, 'open', ago(3)),
      port('203.0.113.4', 22, 'closed', ago(1)),
    ]);
    const http = (assetId: string, observedAt: Date) => ({
      resultId: `roles-${seq++}`,
      assetId,
      scanJobId: job,
      observedAt,
      checker: 'http',
      checkerVersion: 'test',
      resultStatus: 'success' as const,
      url: 'https://x.example.com/',
      statusCode: 200,
    });
    await t.db.insert(schema.httpObservations).values([http(web, ago(10)), http(oldWeb, ago(40))]);

    const unknown = crypto.randomUUID();
    const roles = await assetRolesFor(
      t.db,
      [mail, ns, ssh, db, closed, web, oldWeb, cdn, plain, oldMx, unknown],
      now,
    );
    expect(Object.fromEntries([...roles].map(([id, role]) => [id, role]))).toEqual({
      [mail]: 'mail',
      [ns]: 'dns',
      [ssh]: 'remote_access',
      [db]: 'unclassified',
      [closed]: 'unclassified',
      [web]: 'web',
      [oldWeb]: 'unclassified',
      [cdn]: 'cloud_service',
      [plain]: 'unclassified',
      [oldMx]: 'unclassified',
      [unknown]: 'unclassified',
    });
    expect((await assetRolesFor(t.db, [], now)).size).toBe(0);
  });
});
