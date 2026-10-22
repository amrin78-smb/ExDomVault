// @vitest-environment node
import { schema } from '@exdomainvault/database';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import {
  bulkAuthoriseResponseSchema,
  createChallengeResponseSchema,
  domainDetailResponseSchema,
  domainListResponseSchema,
  errorResponseSchema,
  importConfirmResponseSchema,
  importPreviewResponseSchema,
  verifyDomainResponseSchema,
  type Role,
} from '@exdomainvault/shared';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp, type AppDeps } from '../app.ts';
import type { TxtLookup } from '../lib/doh.ts';
import { CHALLENGE_TTL_MS, sha256Hex } from '../services/domain-verification.ts';

const ORIGIN = 'http://localhost';
const HYPERDRIVE = { connectionString: 'postgres://u:p@db.example.invalid/app' };

let t: TestDatabase;
let clock: Date;
let dns: (name: string) => Promise<TxtLookup>;

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
  dns = async () => ({ status: 'nxdomain' });
  await t.db.delete(schema.domains);
  await t.db.delete(schema.auditLogs);
});
afterEach(() => vi.restoreAllMocks());

const deps: AppDeps = {
  connect: async () => ({ db: t.db, close: async () => {} }),
  domains: { resolveTxt: (name) => dns(name), now: () => clock },
};

async function ensureUser(role: Role): Promise<string> {
  const email = `${role}@example.com`;
  await t.db
    .insert(schema.users)
    .values({ email, role, authProvider: 'dev', authProviderSubject: `dev:${email}` })
    .onConflictDoNothing();
  return email;
}

async function call(
  role: Role,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  const email = await ensureUser(role);
  const env = {
    APP_ENV: 'development',
    APP_VERSION: 'test',
    AUTH_PROVIDER: 'dev',
    DEV_AUTH_EMAIL: email,
    HYPERDRIVE,
  };
  const init: RequestInit = {
    method,
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(method !== 'GET' ? { Origin: ORIGIN } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return createApp(deps).request(`/api/v1${path}`, init, env as unknown as Env);
}

async function addDomain(fqdn: string, extra: Record<string, unknown> = {}) {
  const res = await call('admin', 'POST', '/domains', { fqdn, ...extra });
  expect(res.status).toBe(201);
  return domainDetailResponseSchema.parse(await res.json()).domain;
}

const auditActions = async () =>
  (await t.db.select().from(schema.auditLogs).orderBy(schema.auditLogs.createdAt)).map(
    (a) => a.action,
  );

async function expectError(res: Response, status: number, code: string) {
  expect(res.status).toBe(status);
  const body = errorResponseSchema.parse(await res.json());
  expect(body.error.code).toBe(code);
  return body.error;
}

describe('POST /domains', () => {
  it('normalises the name, stores it and audits the creation', async () => {
    const domain = await addDomain('  Example.COM. ', {
      criticality: 'high',
      businessOwner: ' Ops ',
    });
    expect(domain).toMatchObject({
      fqdn: 'example.com',
      criticality: 'high',
      businessOwner: 'Ops',
      verificationStatus: 'unverified',
      monitoringEnabled: false,
      registrationDataStatus: 'unknown',
    });
    const [audit] = await t.db.select().from(schema.auditLogs);
    expect(audit).toMatchObject({
      action: 'domain.created',
      resourceId: domain.id,
      metadata: { fqdn: 'example.com', source: 'manual', criticality: 'high' },
    });
  });

  it('stores IDNs as A-labels and returns the Unicode form and warnings', async () => {
    const domain = await addDomain('münchen.de');
    expect(domain).toMatchObject({
      fqdn: 'xn--mnchen-3ya.de',
      unicodeFqdn: 'münchen.de',
      warnings: ['idn'],
    });
  });

  it('rejects duplicates, including differently written forms', async () => {
    await addDomain('example.com');
    for (const variant of ['example.com', 'EXAMPLE.com.', ' example.COM']) {
      const err = await expectError(
        await call('admin', 'POST', '/domains', { fqdn: variant }),
        409,
        'conflict',
      );
      expect(err.details).toEqual([
        { path: 'fqdn', message: 'This domain is already registered.' },
      ]);
    }
    expect(await auditActions()).toEqual(['domain.created']);
  });

  it.each([
    ['www.example.com', 'is a subdomain'],
    ['192.0.2.10', 'IP addresses'],
    ['*.example.com', 'Wildcards'],
    ['https://example.com/', 'no scheme'],
    ['foo.local', 'not a public top-level domain'],
  ])('rejects %s with a field error', async (fqdn, fragment) => {
    const err = await expectError(
      await call('admin', 'POST', '/domains', { fqdn }),
      400,
      'validation_failed',
    );
    expect(err.details?.[0]?.path).toBe('fqdn');
    expect(err.details?.[0]?.message).toContain(fragment);
  });

  it('validates the body schema strictly', async () => {
    await expectError(
      await call('admin', 'POST', '/domains', { fqdn: 'example.com', criticality: 'extreme' }),
      400,
      'validation_failed',
    );
    await expectError(
      await call('admin', 'POST', '/domains', {
        fqdn: 'example.com',
        verificationStatus: 'verified',
      }),
      400,
      'validation_failed',
    );
    await expectError(
      await call('admin', 'POST', '/domains', undefined, { 'Content-Type': 'text/plain' }),
      400,
      'bad_request',
    );
  });

  it('requires a same-origin request', async () => {
    const res = await call(
      'admin',
      'POST',
      '/domains',
      { fqdn: 'example.com' },
      { Origin: 'https://evil.example' },
    );
    await expectError(res, 403, 'forbidden');
  });
});

describe('RBAC', () => {
  it.each<[Role, string, string, unknown]>([
    ['analyst', 'POST', '/domains', { fqdn: 'example.com' }],
    ['viewer', 'POST', '/domains', { fqdn: 'example.com' }],
    ['asset_owner', 'GET', '/domains', undefined],
    ['analyst', 'POST', '/domains/import/preview', { csv: 'domain\nexample.com' }],
  ])('%s cannot %s %s', async (role, method, path, body) => {
    await expectError(await call(role, method, path, body), 403, 'forbidden');
  });

  it('analysts and viewers can read but not change or verify domains', async () => {
    const domain = await addDomain('example.com');
    for (const role of ['analyst', 'viewer'] as const) {
      expect((await call(role, 'GET', '/domains')).status).toBe(200);
      expect((await call(role, 'GET', `/domains/${domain.id}`)).status).toBe(200);
      await expectError(
        await call(role, 'PATCH', `/domains/${domain.id}`, { criticality: 'low' }),
        403,
        'forbidden',
      );
      await expectError(
        await call(role, 'POST', `/domains/${domain.id}/verification`),
        403,
        'forbidden',
      );
      await expectError(await call(role, 'POST', `/domains/${domain.id}/verify`), 403, 'forbidden');
    }
    expect(await auditActions()).toEqual(['domain.created']);
  });
});

describe('GET /domains', () => {
  beforeEach(async () => {
    await addDomain('alpha.com', { criticality: 'low' });
    await addDomain('bravo.org', { criticality: 'critical' });
    await addDomain('charlie.net', { criticality: 'high' });
  });

  it('lists with pagination and sorting', async () => {
    const res = await call('viewer', 'GET', '/domains?pageSize=2&sort=-criticality');
    const body = domainListResponseSchema.parse(await res.json());
    expect(body).toMatchObject({ page: 1, pageSize: 2, total: 3 });
    expect(body.items.map((d) => d.fqdn)).toEqual(['bravo.org', 'charlie.net']);

    const page2 = domainListResponseSchema.parse(
      await (await call('viewer', 'GET', '/domains?pageSize=2&page=2&sort=-criticality')).json(),
    );
    expect(page2.items.map((d) => d.fqdn)).toEqual(['alpha.com']);
  });

  it('filters by search text, criticality and status', async () => {
    const search = domainListResponseSchema.parse(
      await (await call('viewer', 'GET', '/domains?q=RAV')).json(),
    );
    expect(search.items.map((d) => d.fqdn)).toEqual(['bravo.org']);

    const crit = domainListResponseSchema.parse(
      await (await call('viewer', 'GET', '/domains?criticality=high')).json(),
    );
    expect(crit.items.map((d) => d.fqdn)).toEqual(['charlie.net']);

    const verified = domainListResponseSchema.parse(
      await (await call('viewer', 'GET', '/domains?verificationStatus=verified')).json(),
    );
    expect(verified.total).toBe(0);
  });

  it('treats LIKE wildcards in search as literal text', async () => {
    const body = domainListResponseSchema.parse(
      await (await call('viewer', 'GET', '/domains?q=%25')).json(),
    );
    expect(body.total).toBe(0);
  });

  it('enforces page size limits', async () => {
    await expectError(
      await call('viewer', 'GET', '/domains?pageSize=1000'),
      400,
      'validation_failed',
    );
    await expectError(
      await call('viewer', 'GET', '/domains?sort=password'),
      400,
      'validation_failed',
    );
  });
});

describe('GET and PATCH /domains/:id', () => {
  it('returns 404 for unknown and malformed ids', async () => {
    await expectError(
      await call('viewer', 'GET', `/domains/${crypto.randomUUID()}`),
      404,
      'not_found',
    );
    await expectError(await call('viewer', 'GET', '/domains/not-a-uuid'), 404, 'not_found');
  });

  it('updates owner and criticality with an audit record of the change', async () => {
    const domain = await addDomain('example.com');
    const res = await call('admin', 'PATCH', `/domains/${domain.id}`, {
      criticality: 'critical',
      businessOwner: 'Security team',
    });
    expect(res.status).toBe(200);
    const body = domainDetailResponseSchema.parse(await res.json());
    expect(body.domain).toMatchObject({ criticality: 'critical', businessOwner: 'Security team' });

    const [audit] = await t.db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'domain.updated'));
    expect(audit?.metadata).toMatchObject({
      changes: {
        criticality: { from: 'medium', to: 'critical' },
        businessOwner: { from: null, to: 'Security team' },
      },
    });
  });

  it('clears the business owner with an empty string or null', async () => {
    const domain = await addDomain('example.com', { businessOwner: 'Ops' });
    const body = domainDetailResponseSchema.parse(
      await (await call('admin', 'PATCH', `/domains/${domain.id}`, { businessOwner: '' })).json(),
    );
    expect(body.domain.businessOwner).toBeNull();
  });

  it('rejects empty and unknown patches', async () => {
    const domain = await addDomain('example.com');
    await expectError(
      await call('admin', 'PATCH', `/domains/${domain.id}`, {}),
      400,
      'validation_failed',
    );
    await expectError(
      await call('admin', 'PATCH', `/domains/${domain.id}`, { fqdn: 'other.com' }),
      400,
      'validation_failed',
    );
  });

  it('allows passive monitoring on unverified domains', async () => {
    const domain = await addDomain('example.com');
    const res = await call('admin', 'PATCH', `/domains/${domain.id}`, { monitoringEnabled: true });
    expect(res.status).toBe(200);
    expect(domainDetailResponseSchema.parse(await res.json()).domain.monitoringEnabled).toBe(true);
  });
});

describe('DNS TXT verification', () => {
  async function startVerification(domainId: string) {
    const res = await call('admin', 'POST', `/domains/${domainId}/verification`);
    expect(res.status).toBe(201);
    return createChallengeResponseSchema.parse(await res.json());
  }

  async function verify(domainId: string) {
    const res = await call('admin', 'POST', `/domains/${domainId}/verify`);
    expect(res.status).toBe(200);
    return verifyDomainResponseSchema.parse(await res.json());
  }

  it('issues a challenge, stores only its hash, and shows the record once', async () => {
    const domain = await addDomain('example.com');
    const { challenge, record } = await startVerification(domain.id);
    expect(record.type).toBe('TXT');
    expect(record.name).toBe('_exdomainvault-challenge.example.com');
    expect(record.value).toMatch(/^exdomainvault-verification=[A-Za-z0-9_-]{43}$/);
    expect(challenge.expiresAt).toBe(new Date(clock.getTime() + CHALLENGE_TTL_MS).toISOString());

    const [row] = await t.db.select().from(schema.domainVerifications);
    const token = record.value.split('=')[1]!;
    expect(row!.challengeHash).toBe(await sha256Hex(token));
    expect(JSON.stringify(row)).not.toContain(token);

    // Detail view shows the challenge state but never the value again.
    const detailText = await (await call('admin', 'GET', `/domains/${domain.id}`)).text();
    expect(detailText).not.toContain(token);
    const detail = domainDetailResponseSchema.parse(JSON.parse(detailText));
    expect(detail.domain.verificationStatus).toBe('pending');
    expect(detail.verification).toMatchObject({ id: challenge.id, status: 'pending' });

    const [audit] = await t.db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'domain.verification_started'));
    expect(JSON.stringify(audit)).not.toContain(token);
  });

  it('verifies when the published TXT value matches', async () => {
    const domain = await addDomain('example.com');
    const { record } = await startVerification(domain.id);
    const queried: string[] = [];
    dns = async (name) => {
      queried.push(name);
      return { status: 'ok', records: ['v=spf1 -all', record.value], authenticated: true };
    };

    const result = await verify(domain.id);
    expect(queried).toEqual(['_exdomainvault-challenge.example.com']);
    expect(result.outcome).toBe('verified');
    expect(result.domain).toMatchObject({
      verificationStatus: 'verified',
      verifiedAt: clock.toISOString(),
    });
    expect(result.verification?.status).toBe('verified');

    const [audit] = await t.db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'domain.verified'));
    expect(audit?.metadata).toMatchObject({ method: 'dns_txt', dnssecAuthenticated: true });

    // Verification grants nothing else: no assets, no scan scope.
    expect(await t.db.select().from(schema.assets)).toEqual([]);

    // Already verified: no new challenge, no re-check.
    await expectError(
      await call('admin', 'POST', `/domains/${domain.id}/verification`),
      409,
      'conflict',
    );
    await expectError(await call('admin', 'POST', `/domains/${domain.id}/verify`), 409, 'conflict');

    expect(result.domain).toMatchObject({
      verificationMethod: 'dns_txt',
      verificationExpiresAt: null,
    });
  });

  it('reports a missing record, a wrong value and DNS errors without verifying', async () => {
    const domain = await addDomain('example.com');
    await startVerification(domain.id);

    dns = async () => ({ status: 'nxdomain' });
    expect((await verify(domain.id)).outcome).toBe('record_not_found');

    clock = new Date(clock.getTime() + 60_000);
    dns = async () => ({
      status: 'ok',
      records: ['exdomainvault-verification=not-the-right-token'],
      authenticated: false,
    });
    const mismatch = await verify(domain.id);
    expect(mismatch.outcome).toBe('value_mismatch');
    expect(mismatch.verification?.failureReason).toBe('value_mismatch');

    clock = new Date(clock.getTime() + 60_000);
    dns = async () => ({ status: 'error', detail: 'TimeoutError' });
    expect((await verify(domain.id)).outcome).toBe('dns_error');

    const detail = domainDetailResponseSchema.parse(
      await (await call('admin', 'GET', `/domains/${domain.id}`)).json(),
    );
    expect(detail.domain.verificationStatus).toBe('pending');
    expect((await auditActions()).filter((a) => a === 'domain.verification_failed')).toHaveLength(
      3,
    );
  });

  it('does not accept a value from a different (superseded) challenge', async () => {
    const domain = await addDomain('example.com');
    const first = await startVerification(domain.id);
    const second = await startVerification(domain.id);
    expect(second.record.value).not.toBe(first.record.value);

    dns = async () => ({ status: 'ok', records: [first.record.value], authenticated: false });
    expect((await verify(domain.id)).outcome).toBe('value_mismatch');

    const statuses = (await t.db.select().from(schema.domainVerifications))
      .map((r) => r.status)
      .sort();
    expect(statuses).toEqual(['pending', 'superseded']);
  });

  it('expires challenges after the TTL even if the correct record is published', async () => {
    const domain = await addDomain('example.com');
    const { record } = await startVerification(domain.id);
    dns = async () => ({ status: 'ok', records: [record.value], authenticated: false });

    clock = new Date(clock.getTime() + CHALLENGE_TTL_MS);
    const result = await verify(domain.id);
    expect(result.outcome).toBe('expired');
    expect(result.domain.verificationStatus).toBe('unverified');
    expect(result.verification?.status).toBe('expired');
    expect(await auditActions()).toContain('domain.verification_expired');
  });

  it('accepts a matching record until the moment the challenge expires', async () => {
    const domain = await addDomain('example.com');
    const { record } = await startVerification(domain.id);
    dns = async () => ({ status: 'ok', records: [record.value], authenticated: false });
    clock = new Date(clock.getTime() + CHALLENGE_TTL_MS - 1);
    expect((await verify(domain.id)).outcome).toBe('verified');
  });

  it('throttles repeated checks', async () => {
    const domain = await addDomain('example.com');
    await startVerification(domain.id);
    let lookups = 0;
    dns = async () => {
      lookups++;
      return { status: 'nxdomain' };
    };
    expect((await verify(domain.id)).outcome).toBe('record_not_found');
    expect((await verify(domain.id)).outcome).toBe('too_soon');
    expect(lookups).toBe(1);
    clock = new Date(clock.getTime() + 11_000);
    expect((await verify(domain.id)).outcome).toBe('record_not_found');
    expect(lookups).toBe(2);
  });

  it('requires a challenge before checking', async () => {
    const domain = await addDomain('example.com');
    await expectError(await call('admin', 'POST', `/domains/${domain.id}/verify`), 409, 'conflict');
  });
});

describe('CSV import', () => {
  const csv = [
    'domain,criticality,business_owner',
    'alpha.com,high,Ops',
    'Bravo.ORG.,,',
    'www.charlie.net,low,',
    'alpha.com,low,',
    'existing.com,medium,',
    'delta.io,extreme,',
    '"echo.com","critical","Smith, J"',
  ].join('\n');

  it('previews with per-row errors and duplicate detection, writing nothing', async () => {
    await addDomain('existing.com');
    const res = await call('admin', 'POST', '/domains/import/preview', { csv });
    expect(res.status).toBe(200);
    const preview = importPreviewResponseSchema.parse(await res.json());
    expect(preview.fileErrors).toEqual([]);
    expect(preview.rows.map((r) => [r.line, r.fqdn, r.status])).toEqual([
      [2, 'alpha.com', 'valid'],
      [3, 'bravo.org', 'valid'],
      [4, null, 'invalid'],
      [5, 'alpha.com', 'duplicate_in_file'],
      [6, 'existing.com', 'already_registered'],
      [7, 'delta.io', 'invalid'],
      [8, 'echo.com', 'valid'],
    ]);
    expect(preview.rows[6]).toMatchObject({ criticality: 'critical', businessOwner: 'Smith, J' });
    expect(preview.summary).toEqual({
      total: 7,
      valid: 3,
      invalid: 2,
      duplicateInFile: 1,
      alreadyRegistered: 1,
    });
    expect((await t.db.select().from(schema.domains)).map((d) => d.fqdn)).toEqual(['existing.com']);
  });

  it('imports only valid rows after confirmation, with audit records', async () => {
    await addDomain('existing.com');
    const preview = importPreviewResponseSchema.parse(
      await (await call('admin', 'POST', '/domains/import/preview', { csv })).json(),
    );
    const res = await call('admin', 'POST', '/domains/import', { csv, digest: preview.digest });
    expect(res.status).toBe(201);
    const result = importConfirmResponseSchema.parse(await res.json());
    expect(result.created.map((d) => d.fqdn).sort()).toEqual([
      'alpha.com',
      'bravo.org',
      'echo.com',
    ]);
    expect(result.skipped).toBe(4);
    expect(result.authorised).toBe(0);

    const actions = await auditActions();
    expect(actions.filter((a) => a === 'domain.created')).toHaveLength(4);
    expect(actions).toContain('domain.import_completed');
  });

  it('refuses to import a file that differs from the preview', async () => {
    const preview = importPreviewResponseSchema.parse(
      await (await call('admin', 'POST', '/domains/import/preview', { csv })).json(),
    );
    await expectError(
      await call('admin', 'POST', '/domains/import', {
        csv: `${csv}\nfoxtrot.com,,`,
        digest: preview.digest,
      }),
      400,
      'bad_request',
    );
    expect(await t.db.select().from(schema.domains)).toEqual([]);
  });

  it.each([
    ['name\nexample.com', 'Unknown column'],
    ['criticality\nhigh', 'must include a "domain" column'],
    ['domain', 'no domains'],
    ['domain\n"unterminated', 'not valid CSV'],
  ])('reports file-level problems for %j', async (input, fragment) => {
    const preview = importPreviewResponseSchema.parse(
      await (await call('admin', 'POST', '/domains/import/preview', { csv: input })).json(),
    );
    expect(preview.rows).toEqual([]);
    expect(preview.fileErrors.join(' ')).toContain(fragment);
  });

  it('limits the number of rows', async () => {
    const big = ['domain', ...Array.from({ length: 1001 }, (_, i) => `d${i}.com`)].join('\n');
    const preview = importPreviewResponseSchema.parse(
      await (await call('admin', 'POST', '/domains/import/preview', { csv: big })).json(),
    );
    expect(preview.fileErrors[0]).toContain('more than 1000 rows');
  });
});

describe('administrator authorisation', () => {
  const auth = {
    reason: 'Owned by the group; DNS is managed by the registrar',
    reference: 'CSC-7740752',
    reviewBy: '2027-10-22',
  };

  it('authorises a domain with an audited, labelled attestation', async () => {
    const domain = await addDomain('example.com');
    const res = await call('admin', 'POST', `/domains/${domain.id}/authorise`, auth);
    expect(res.status).toBe(200);
    const body = domainDetailResponseSchema.parse(await res.json());
    expect(body.domain).toMatchObject({
      verificationStatus: 'verified',
      verificationMethod: 'admin_attestation',
      verifiedAt: clock.toISOString(),
      verificationExpiresAt: '2027-10-22T23:59:59.999Z',
    });
    expect(body.verification).toMatchObject({
      method: 'admin_attestation',
      status: 'verified',
      recordName: null,
      reason: auth.reason,
      reference: auth.reference,
    });
    const [audit] = await t.db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'domain.authorised'));
    expect(audit?.metadata).toMatchObject({
      method: 'admin_attestation',
      reason: auth.reason,
      reference: auth.reference,
      source: 'manual',
    });
    // Nothing else is granted.
    expect(await t.db.select().from(schema.assets)).toEqual([]);
  });

  it('supersedes a pending DNS challenge and refuses an already verified domain', async () => {
    const domain = await addDomain('example.com');
    await call('admin', 'POST', `/domains/${domain.id}/verification`);
    expect((await call('admin', 'POST', `/domains/${domain.id}/authorise`, auth)).status).toBe(200);
    const statuses = (await t.db.select().from(schema.domainVerifications)).map((r) => [
      r.method,
      r.status,
    ]);
    expect(statuses).toContainEqual(['dns_txt', 'superseded']);
    await expectError(
      await call('admin', 'POST', `/domains/${domain.id}/authorise`, auth),
      409,
      'conflict',
    );
    await expectError(await call('admin', 'POST', `/domains/${domain.id}/verify`), 409, 'conflict');
  });

  it.each([
    [{ ...auth, reason: 'too short' }, 'reason'],
    [{ ...auth, reviewBy: '2026-10-21' }, 'reviewBy'],
    [{ ...auth, reviewBy: '2028-11-01' }, 'reviewBy'],
    [{ ...auth, reviewBy: '22/10/2027' }, 'reviewBy'],
    [{ reason: auth.reason }, 'reviewBy'],
  ])('validates %j', async (body, field) => {
    const domain = await addDomain('example.com');
    const err = await expectError(
      await call('admin', 'POST', `/domains/${domain.id}/authorise`, body),
      400,
      'validation_failed',
    );
    expect(err.details?.map((d) => d.path)).toContain(field);
  });

  it('is limited to roles with domains:verify', async () => {
    const domain = await addDomain('example.com');
    for (const role of ['analyst', 'viewer', 'asset_owner'] as const) {
      await expectError(
        await call(role, 'POST', `/domains/${domain.id}/authorise`, auth),
        403,
        'forbidden',
      );
      await expectError(
        await call(role, 'POST', '/domains/authorise', { ...auth, domainIds: [domain.id] }),
        403,
        'forbidden',
      );
      await expectError(
        await call(role, 'POST', `/domains/${domain.id}/revoke`, {
          reason: 'No longer ours, sold',
        }),
        403,
        'forbidden',
      );
    }
  });

  it('authorises in bulk, skipping verified and unknown domains', async () => {
    const a = await addDomain('alpha.com');
    const b = await addDomain('bravo.com');
    await call('admin', 'POST', `/domains/${b.id}/authorise`, auth);
    const missing = crypto.randomUUID();
    const res = await call('admin', 'POST', '/domains/authorise', {
      ...auth,
      domainIds: [a.id, b.id, missing],
    });
    expect(res.status).toBe(200);
    const body = bulkAuthoriseResponseSchema.parse(await res.json());
    expect(body.authorised).toEqual([{ id: a.id, fqdn: 'alpha.com' }]);
    expect(body.skipped).toEqual([
      { id: b.id, fqdn: 'bravo.com', reason: 'already_verified' },
      { id: missing, fqdn: null, reason: 'not_found' },
    ]);
  });

  it('lapses on the review date, audited as a system action', async () => {
    const domain = await addDomain('example.com');
    await call('admin', 'POST', `/domains/${domain.id}/authorise`, {
      ...auth,
      reviewBy: '2026-11-01',
    });

    clock = new Date('2026-11-01T23:59:59.000Z');
    let detail = domainDetailResponseSchema.parse(
      await (await call('viewer', 'GET', `/domains/${domain.id}`)).json(),
    );
    expect(detail.domain.verificationStatus).toBe('verified');

    clock = new Date('2026-11-02T00:00:00.000Z');
    const list = domainListResponseSchema.parse(
      await (await call('viewer', 'GET', '/domains')).json(),
    );
    expect(list.items[0]).toMatchObject({
      verificationStatus: 'unverified',
      verificationMethod: null,
    });
    detail = domainDetailResponseSchema.parse(
      await (await call('viewer', 'GET', `/domains/${domain.id}`)).json(),
    );
    expect(detail.verification).toMatchObject({
      status: 'expired',
      failureReason: 'review_date_passed',
    });
    expect(await auditActions()).toContain('domain.authorisation_lapsed');
  });

  it('revokes either method with a reason, after which DNS verification can start again', async () => {
    const domain = await addDomain('example.com');
    await call('admin', 'POST', `/domains/${domain.id}/authorise`, auth);
    await expectError(
      await call('admin', 'POST', `/domains/${domain.id}/revoke`, { reason: 'short' }),
      400,
      'validation_failed',
    );
    const res = await call('admin', 'POST', `/domains/${domain.id}/revoke`, {
      reason: 'Domain was transferred out',
    });
    expect(res.status).toBe(200);
    const body = domainDetailResponseSchema.parse(await res.json());
    expect(body.domain).toMatchObject({
      verificationStatus: 'revoked',
      verificationMethod: null,
      verifiedAt: null,
    });
    expect(body.verification?.status).toBe('revoked');
    const [audit] = await t.db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'domain.verification_revoked'));
    expect(audit?.metadata).toMatchObject({
      reason: 'Domain was transferred out',
      previousMethod: 'admin_attestation',
    });

    await expectError(
      await call('admin', 'POST', `/domains/${domain.id}/revoke`, {
        reason: 'Domain was transferred out',
      }),
      409,
      'conflict',
    );
    expect((await call('admin', 'POST', `/domains/${domain.id}/verification`)).status).toBe(201);
  });

  it('can authorise every domain created by an import, in the same transaction', async () => {
    await addDomain('existing.com');
    const csv = 'domain\nalpha.com\nexisting.com\nbravo.org';
    const preview = importPreviewResponseSchema.parse(
      await (await call('admin', 'POST', '/domains/import/preview', { csv })).json(),
    );
    const res = await call('admin', 'POST', '/domains/import', {
      csv,
      digest: preview.digest,
      authorisation: auth,
    });
    expect(res.status).toBe(201);
    expect(importConfirmResponseSchema.parse(await res.json())).toMatchObject({
      skipped: 1,
      authorised: 2,
    });
    const rows = await t.db.select().from(schema.domains).orderBy(schema.domains.fqdn);
    expect(rows.map((r) => [r.fqdn, r.verificationMethod])).toEqual([
      ['alpha.com', 'admin_attestation'],
      ['bravo.org', 'admin_attestation'],
      ['existing.com', null],
    ]);
    const sources = (
      await t.db
        .select()
        .from(schema.auditLogs)
        .where(eq(schema.auditLogs.action, 'domain.authorised'))
    ).map((a) => a.metadata.source);
    expect(sources).toEqual(['import', 'import']);
  });

  it('rolls back the whole import when the authorisation is invalid', async () => {
    const csv = 'domain\nalpha.com';
    const preview = importPreviewResponseSchema.parse(
      await (await call('admin', 'POST', '/domains/import/preview', { csv })).json(),
    );
    await expectError(
      await call('admin', 'POST', '/domains/import', {
        csv,
        digest: preview.digest,
        authorisation: { ...auth, reviewBy: '2020-01-01' },
      }),
      400,
      'validation_failed',
    );
    expect(await t.db.select().from(schema.domains)).toEqual([]);
  });
});
