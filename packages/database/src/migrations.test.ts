import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  approvedNetworks,
  assetIps,
  assets,
  domainVerifications,
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

const finding = (domainId: string, assetId: string | null, fingerprint: string) => ({
  domainId,
  assetId,
  hostname: 'findings.example',
  component: 'dmarc',
  category: 'email',
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
      'approved_networks',
      'asset_ips',
      'assets',
      'audit_logs',
      'discovery_observations',
      'dns_observations',
      'domain_verifications',
      'domains',
      'finding_comments',
      'finding_status_history',
      'findings',
      'http_observations',
      'intel_feeds',
      'notification_preferences',
      'port_observations',
      'registration_observations',
      'scan_job_results',
      'scan_job_targets',
      'scan_jobs',
      'scan_profiles',
      'security_rules',
      'software_eol_cycles',
      'software_inventory',
      'tls_observations',
      'users',
      'vulnerability_advisories',
      'worker_credentials',
      'worker_registry',
      'worker_request_nonces',
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
        t.db.insert(domains).values({
          fqdn: 'verified.example',
          verificationStatus: 'verified',
          verificationMethod: 'dns_txt',
        }),
      ),
    ).toBe('domains_verified_at_consistent');
  });

  it('requires a verification method exactly when verified, and a review date for attestations', async () => {
    const verifiedAt = new Date();
    expect(
      await violation(() =>
        t.db
          .insert(domains)
          .values({ fqdn: 'nomethod.example', verificationStatus: 'verified', verifiedAt }),
      ),
    ).toBe('domains_verification_method_consistent');
    expect(
      await violation(() =>
        t.db.insert(domains).values({
          fqdn: 'attested.example',
          verificationStatus: 'verified',
          verifiedAt,
          verificationMethod: 'admin_attestation',
        }),
      ),
    ).toBe('domains_attestation_has_review_date');
    expect(
      await violation(() =>
        t.db.insert(domains).values({
          fqdn: 'dns.example',
          verificationStatus: 'verified',
          verifiedAt,
          verificationMethod: 'dns_txt',
          verificationExpiresAt: new Date(Date.now() + 86_400_000),
        }),
      ),
    ).toBe('domains_attestation_has_review_date');
  });

  it('requires a hash for DNS challenges and a reason for attestations', async () => {
    const [d] = await t.db.insert(domains).values({ fqdn: 'challenge.example' }).returning();
    const base = { domainId: d!.id, expiresAt: new Date(Date.now() + 3_600_000) };
    expect(
      await violation(() =>
        t.db.insert(domainVerifications).values({ ...base, method: 'dns_txt' }),
      ),
    ).toBe('domain_verifications_method_fields');
    expect(
      await violation(() =>
        t.db
          .insert(domainVerifications)
          .values({ ...base, method: 'admin_attestation', challengeHash: 'x' }),
      ),
    ).toBe('domain_verifications_method_fields');
    await t.db.insert(domainVerifications).values({
      ...base,
      method: 'admin_attestation',
      reason: 'Registered by Group IT',
      status: 'verified',
    });
  });

  it('allows only one non-resolved finding per fingerprint', async () => {
    const { domain, asset } = await seedDomainAndAsset('findings.example');
    await t.db.insert(findings).values(finding(domain.id, asset.id, 'fp-1'));
    expect(
      await violation(() => t.db.insert(findings).values(finding(domain.id, asset.id, 'fp-1'))),
    ).toBe('findings_active_fingerprint_key');

    // Once resolved, a new active finding with the same fingerprint is allowed.
    await t.db.execute(
      sql`update findings set status = 'resolved', resolved_at = now() where fingerprint = 'fp-1'`,
    );
    await expect(
      t.db.insert(findings).values(finding(domain.id, asset.id, 'fp-1')),
    ).resolves.toBeDefined();
  });

  it('requires accepted-risk details', async () => {
    const { domain, asset } = await seedDomainAndAsset('risk.example');
    expect(
      await violation(() =>
        t.db
          .insert(findings)
          .values({ ...finding(domain.id, asset.id, 'fp-risk'), status: 'accepted_risk' }),
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

  it('seeds the server-defined scan profiles', async () => {
    const rows = await t.db.select().from(scanProfiles).orderBy(scanProfiles.key);
    expect(rows.map((r) => [r.key, (r.config as { active: boolean }).active])).toEqual([
      ['deep', true],
      ['discovery', false],
      ['passive', false],
      ['quick', true],
      ['standard', true],
    ]);
  });

  it('allows one queued or active job per domain and profile', async () => {
    const [d] = await t.db.insert(domains).values({ fqdn: 'jobs.example' }).returning();
    const job = {
      jobType: 'scan' as const,
      profile: 'passive',
      domainId: d!.id,
      scopeSnapshot: {},
    };
    await t.db.insert(scanJobs).values(job);
    expect(await violation(() => t.db.insert(scanJobs).values(job))).toBe(
      'scan_jobs_one_active_per_domain_profile',
    );
    await t.db.insert(scanJobs).values({ ...job, status: 'succeeded' });
    await t.db.insert(scanJobs).values({ ...job, profile: 'quick' });
  });

  it('requires a lease and worker for claimed jobs', async () => {
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

describe('0003_approved_networks', () => {
  const network = (cidr: string, over: Partial<typeof approvedNetworks.$inferInsert> = {}) => ({
    cidr,
    label: 'Office',
    reason: 'Our own server range',
    createdAt: new Date('2026-10-01T00:00:00Z'),
    expiresAt: new Date('2027-10-01T00:00:00Z'),
    ...over,
  });

  it('stores networks as cidr and rejects host bits or garbage', async () => {
    const [row] = await t.db.insert(approvedNetworks).values(network('8.8.4.0/24')).returning();
    expect(row!.cidr).toBe('8.8.4.0/24');
    expect(
      await violation(() => t.db.insert(approvedNetworks).values(network('8.8.5.1/24'))),
    ).toMatch(/invalid cidr value/);
    expect(await violation(() => t.db.insert(approvedNetworks).values(network('nope')))).toMatch(
      /invalid input syntax for type cidr/,
    );
  });

  it('allows one active (unrevoked) approval per network', async () => {
    await t.db.insert(approvedNetworks).values(network('9.9.9.0/24'));
    expect(await violation(() => t.db.insert(approvedNetworks).values(network('9.9.9.0/24')))).toBe(
      'approved_networks_cidr_active_key',
    );
    await t.db.insert(approvedNetworks).values(
      network('9.9.9.0/24', {
        revokedAt: new Date('2026-10-02T00:00:00Z'),
        revokeReason: 'gone',
      }),
    );
  });

  it('requires a reason, an expiry after creation and a revoke reason', async () => {
    expect(
      await violation(() =>
        t.db.insert(approvedNetworks).values(network('1.0.0.0/24', { reason: '   ' })),
      ),
    ).toBe('approved_networks_reason_not_empty');
    expect(
      await violation(() =>
        t.db
          .insert(approvedNetworks)
          .values(network('1.0.1.0/24', { expiresAt: new Date('2026-09-01T00:00:00Z') })),
      ),
    ).toBe('approved_networks_expiry_after_creation');
    expect(
      await violation(() =>
        t.db
          .insert(approvedNetworks)
          .values(network('1.0.2.0/24', { revokedAt: new Date('2026-10-02T00:00:00Z') })),
      ),
    ).toBe('approved_networks_revoke_reason');
  });
});

describe('0004_findings_engine', () => {
  it('allows domain-level findings without an asset and validates the category', async () => {
    const { domain } = await seedDomainAndAsset('domainlevel.example');
    await expect(
      t.db.insert(findings).values(finding(domain.id, null, 'fp-domain')),
    ).resolves.toBeDefined();
    expect(
      await violation(() =>
        t.db
          .insert(findings)
          .values({ ...finding(domain.id, null, 'fp-cat'), category: 'speculation' }),
      ),
    ).toBe('findings_category_valid');
  });

  it('deletes the findings of a deleted domain', async () => {
    const { domain } = await seedDomainAndAsset('cascade.example');
    await t.db.insert(findings).values(finding(domain.id, null, 'fp-cascade'));
    await t.db.execute(sql`delete from domains where id = ${domain.id}`);
    const { rows } = await t.pglite.query(
      "select count(*)::int as n from findings where fingerprint = 'fp-cascade'",
    );
    expect(rows).toEqual([{ n: 0 }]);
  });

  it('adds rules_evaluated_at (null by default) to scan jobs', async () => {
    const { rows } = await t.pglite.query<{ is_nullable: string }>(
      "select is_nullable from information_schema.columns where table_name = 'scan_jobs' and column_name = 'rules_evaluated_at'",
    );
    expect(rows).toEqual([{ is_nullable: 'YES' }]);
  });
});

describe('0001_domain_authorisation', () => {
  it('backfills domains verified before the migration as DNS-verified', async () => {
    const { readFileSync, readdirSync } = await import('node:fs');
    const { PGlite } = await import('@electric-sql/pglite');
    const { MIGRATIONS_FOLDER } = await import('./testing.ts');
    const file = (prefix: string) => {
      const name = readdirSync(MIGRATIONS_FOLDER).find((f) => f.startsWith(prefix));
      return readFileSync(`${MIGRATIONS_FOLDER}/${name}`, 'utf8').replaceAll(
        '--> statement-breakpoint',
        '',
      );
    };
    const pg = new PGlite();
    try {
      await pg.exec(file('0000_'));
      await pg.exec(
        "INSERT INTO domains (fqdn, verification_status, verified_at) VALUES ('old.example', 'verified', now()), ('new.example', 'unverified', NULL)",
      );
      // One multi-statement exec runs in a single implicit transaction, like the migrator.
      await pg.exec(file('0001_'));
      const { rows } = await pg.query<{ fqdn: string; verification_method: string | null }>(
        'SELECT fqdn, verification_method FROM domains ORDER BY fqdn',
      );
      expect(rows).toEqual([
        { fqdn: 'new.example', verification_method: null },
        { fqdn: 'old.example', verification_method: 'dns_txt' },
      ]);
    } finally {
      await pg.close();
    }
  });
});

describe('0008_inventory_geo', () => {
  it('adds a nullable ISO alpha-2 country code to asset addresses', async () => {
    const { asset } = await seedDomainAndAsset('geo.example');
    const [row] = await t.db
      .insert(assetIps)
      .values({ assetId: asset.id, ipAddress: '192.0.2.20', source: 'dns' })
      .returning();
    expect(row!.countryCode).toBeNull();
    await t.db
      .insert(assetIps)
      .values({ assetId: asset.id, ipAddress: '192.0.2.21', source: 'dns', countryCode: 'NL' });
    for (const bad of ['nl', 'NLD', 'N', '1A', '']) {
      expect(
        await violation(() =>
          t.db.insert(assetIps).values({
            assetId: asset.id,
            ipAddress: `192.0.2.${30 + bad.length}`,
            source: 'dns',
            countryCode: bad,
          }),
        ),
      ).toBe('asset_ips_country_code_format');
    }
  });

  it('indexes the latest-per-key lookups of the inventory views', async () => {
    const { rows } = await t.pglite.query<{ indexname: string }>(
      "select indexname from pg_indexes where indexname in ('port_observations_ip_port_time_idx', 'tls_observations_host_port_time_idx') order by 1",
    );
    expect(rows.map((r) => r.indexname)).toEqual([
      'port_observations_ip_port_time_idx',
      'tls_observations_host_port_time_idx',
    ]);
  });
});
