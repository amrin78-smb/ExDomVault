import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  assetIps,
  assets,
  domains,
  findings,
  scanJobs,
  scanProfiles,
  users,
} from './schema/index.ts';
import { createTestDatabase, type TestDatabase } from './testing.ts';

let t: TestDatabase;

beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});

/** Runs `fn` and returns the PostgreSQL constraint name it violated. */
async function violation(fn: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await fn();
  } catch (err) {
    const e = err as { constraint?: string; cause?: { constraint?: string; message?: string } };
    return e.constraint ?? e.cause?.constraint ?? e.cause?.message ?? String(err);
  }
  return undefined;
}

async function seedDomainAndAsset(fqdn: string) {
  const [domain] = await t.db.insert(domains).values({ fqdn }).returning();
  const [asset] = await t.db
    .insert(assets)
    .values({ domainId: domain!.id, hostname: fqdn, assetType: 'apex', discoverySource: 'manual' })
    .returning();
  return { domain: domain!, asset: asset! };
}

const finding = (assetId: string, fingerprint: string) => ({
  assetId,
  ruleId: 'DNS-003',
  ruleVersion: 1,
  fingerprint,
  title: 'Missing DMARC policy',
  description: 'No DMARC record was observed.',
  severity: 'medium' as const,
  confidence: 'high' as const,
  riskScore: 40,
  riskInputs: {},
  evidence: {},
  firstSeenAt: new Date('2026-10-01T00:00:00Z'),
  lastSeenAt: new Date('2026-10-02T00:00:00Z'),
});

describe('migrations', () => {
  it('create every table from the design', async () => {
    const { rows } = await t.pglite.query<{ table_name: string }>(
      "select table_name from information_schema.tables where table_schema = 'public' order by 1",
    );
    expect(rows.map((r) => r.table_name)).toEqual([
      'advisories',
      'application_settings',
      'asset_ips',
      'assets',
      'audit_logs',
      'discovery_observations',
      'dns_observations',
      'domain_verifications',
      'domains',
      'finding_status_history',
      'findings',
      'http_observations',
      'notification_preferences',
      'port_observations',
      'registration_observations',
      'scan_job_targets',
      'scan_jobs',
      'scan_profiles',
      'security_rules',
      'tls_observations',
      'users',
      'worker_registry',
    ]);
  });

  it('are idempotent when re-applied', async () => {
    const again = await createTestDatabase();
    const { rows } = await again.pglite.query<{ n: number }>(
      'select count(*)::int as n from drizzle.__drizzle_migrations',
    );
    expect(rows[0]!.n).toBeGreaterThan(0);
    await again.close();
  });
});

describe('constraints', () => {
  it('rejects duplicate and non-normalised domains', async () => {
    await seedDomainAndAsset('example.com');
    expect(await violation(() => t.db.insert(domains).values({ fqdn: 'example.com' }))).toBe(
      'domains_fqdn_key',
    );
    expect(await violation(() => t.db.insert(domains).values({ fqdn: 'Example.org' }))).toBe(
      'domains_fqdn_normalised',
    );
    expect(await violation(() => t.db.insert(domains).values({ fqdn: 'example.net.' }))).toBe(
      'domains_fqdn_normalised',
    );
  });

  it('requires verified_at exactly when a domain is verified', async () => {
    expect(
      await violation(() =>
        t.db.insert(domains).values({ fqdn: 'verified.example', verificationStatus: 'verified' }),
      ),
    ).toBe('domains_verified_at_consistent');
  });

  it('allows only one non-resolved finding per fingerprint', async () => {
    const { asset } = await seedDomainAndAsset('findings.example');
    await t.db.insert(findings).values(finding(asset.id, 'fp-1'));
    expect(await violation(() => t.db.insert(findings).values(finding(asset.id, 'fp-1')))).toBe(
      'findings_active_fingerprint_key',
    );

    // Once resolved, a new active finding with the same fingerprint is allowed.
    await t.db.execute(
      sql`update findings set status = 'resolved', resolved_at = now() where fingerprint = 'fp-1'`,
    );
    await expect(t.db.insert(findings).values(finding(asset.id, 'fp-1'))).resolves.toBeDefined();
  });

  it('requires accepted-risk details', async () => {
    const { asset } = await seedDomainAndAsset('risk.example');
    expect(
      await violation(() =>
        t.db.insert(findings).values({ ...finding(asset.id, 'fp-risk'), status: 'accepted_risk' }),
      ),
    ).toBe('findings_accepted_risk_complete');
  });

  it('keeps users emails lowercase and unique', async () => {
    await t.db.insert(users).values({ email: 'a@example.com', authProvider: 'dev' });
    expect(
      await violation(() =>
        t.db.insert(users).values({ email: 'A@example.com', authProvider: 'dev' }),
      ),
    ).toBe('users_email_lowercase');
    expect(
      await violation(() =>
        t.db.insert(users).values({ email: 'a@example.com', authProvider: 'cloudflare_access' }),
      ),
    ).toBe('users_email_key');
  });

  it('forbids monitoring an unapproved asset', async () => {
    const [domain] = await t.db.insert(domains).values({ fqdn: 'monitor.example' }).returning();
    expect(
      await violation(() =>
        t.db.insert(assets).values({
          domainId: domain!.id,
          hostname: 'www.monitor.example',
          assetType: 'subdomain',
          discoverySource: 'certificate_transparency',
          monitoringEnabled: true,
        }),
      ),
    ).toBe('assets_monitoring_requires_approval');
  });

  it('stores IPv4 and IPv6 addresses as inet', async () => {
    const { asset } = await seedDomainAndAsset('ip.example');
    await t.db.insert(assetIps).values([
      { assetId: asset.id, ipAddress: '192.0.2.10', source: 'dns' },
      { assetId: asset.id, ipAddress: '2001:db8::1', source: 'dns' },
    ]);
    expect(
      await violation(() =>
        t.db.insert(assetIps).values({ assetId: asset.id, ipAddress: 'not-an-ip', source: 'dns' }),
      ),
    ).toMatch(/invalid input syntax for type inet/);
  });

  it('requires a lease and worker for claimed jobs', async () => {
    await t.db.insert(scanProfiles).values({
      key: 'quick',
      name: 'Quick',
      description: 'Test profile',
      config: {},
    });
    expect(
      await violation(() =>
        t.db.insert(scanJobs).values({
          jobType: 'scan',
          profile: 'quick',
          status: 'claimed',
          scopeSnapshot: {},
        }),
      ),
    ).toBe('scan_jobs_lease_when_active');
  });
});
