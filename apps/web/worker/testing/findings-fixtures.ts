// Test-only fixtures for rules evaluation and findings API tests (synthetic data, reserved names).
import { schema, type Database } from '@exdomainvault/database';
import type { TestDatabase } from '@exdomainvault/database/testing';
import type { Advisory, FindingCandidate, Rule, RuleOutcome } from '@exdomainvault/rules';
import { eq } from 'drizzle-orm';
import { firstRow } from '../lib/db.ts';
import { buildSnapshot, listProfiles } from '../services/scans.ts';
import { ensureUser } from './harness.ts';

const advisory = (f: FindingCandidate): Advisory => ({
  title: `Fix: ${f.title}`,
  summary: `Observed on ${f.hostname}.`,
  businessImpact: 'Synthetic impact.',
  recommendedActions: ['Do the synthetic thing.'],
  references: ['https://example.com/reference'],
});

const doc = {
  evidenceRequirements: 'Successful DNS observations.',
  detection: 'Synthetic detection.',
  resolution: 'Synthetic resolution.',
};

/** TST-DMARC: the apex has no `v=DMARC1` TXT record at `_dmarc.<apex>` (domain-level finding). */
export const dmarcRule: Rule = {
  id: 'TST-DMARC',
  version: 1,
  category: 'email',
  title: 'Synthetic DMARC rule',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  ...doc,
  evaluate({ context, current }): RuleOutcome {
    const apex = context.domain.fqdn;
    const obs = current.dns.find((o) => o.hostname === `_dmarc.${apex}` && o.recordType === 'TXT');
    if (!obs || obs.resultStatus !== 'success') return { findings: [], checked: [] };
    const checked = [{ hostname: apex, component: 'dmarc' }];
    if (obs.values.some((v) => v.includes('v=DMARC1'))) return { findings: [], checked };
    return {
      findings: [
        {
          hostname: apex,
          component: 'dmarc',
          title: 'No DMARC policy published',
          description: 'No DMARC record was observed.',
          severity: 'medium',
          confidence: 'high',
          exposure: 'public_record',
          evidence: { values: obs.values, observedAt: obs.observedAt },
        },
      ],
      checked,
    };
  },
  advisory,
};

/** TST-ACHANGE: an A record set differs from the previous known-good one. */
export const aChangeRule: Rule = {
  id: 'TST-ACHANGE',
  version: 1,
  category: 'dns',
  title: 'Synthetic A change rule',
  requires: ['dns'],
  requiresChecks: ['dns'],
  // Change detection: the baseline moves with every scan, so users may resolve by hand.
  manualResolution: true,
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  ...doc,
  evaluate({ current, previous }): RuleOutcome {
    const out: RuleOutcome = { findings: [], checked: [] };
    for (const o of current.dns) {
      if (o.recordType !== 'A' || o.resultStatus !== 'success') continue;
      const before = previous.dns.find((p) => p.hostname === o.hostname && p.recordType === 'A');
      if (!before) continue;
      out.checked.push({ hostname: o.hostname, component: 'a-change' });
      if (before.values.join(',') !== o.values.join(',')) {
        out.findings.push({
          hostname: o.hostname,
          component: 'a-change',
          title: 'A records changed',
          description: 'The A record set differs from the previous observation.',
          severity: 'low',
          confidence: 'high',
          exposure: 'public_record',
          evidence: { previous: before.values, current: o.values, previousJob: before.scanJobId },
        });
      }
    }
    return out;
  },
  advisory,
};

/** TST-HOST: every hostname with a successful non-empty A record set (high severity, per host). */
export const hostRule: Rule = {
  id: 'TST-HOST',
  version: 2,
  category: 'exposure',
  title: 'Synthetic host rule',
  requires: ['dns'],
  requiresChecks: ['dns'],
  defaultSeverity: 'high',
  defaultConfidence: 'medium',
  ...doc,
  evaluate({ current }): RuleOutcome {
    const out: RuleOutcome = { findings: [], checked: [] };
    for (const o of current.dns) {
      if (o.recordType !== 'A' || o.resultStatus !== 'success') continue;
      out.checked.push({ hostname: o.hostname, component: 'a' });
      if (o.values.length > 0) {
        out.findings.push({
          hostname: o.hostname,
          component: 'a',
          title: `Host ${o.hostname} resolves`,
          description: 'Synthetic host finding.',
          severity: 'high',
          confidence: 'medium',
          exposure: 'network_service',
          evidence: { values: o.values },
        });
      }
    }
    return out;
  },
  advisory,
};

export const FAKE_RULES: readonly Rule[] = [dmarcRule, aChangeRule, hostRule];

export interface Seed {
  domainId: string;
  fqdn: string;
  wwwAssetId: string;
}

/** A domain with an approved `www` asset (owned by the asset_owner test user when `owned`). */
export async function seedDomain(
  t: TestDatabase,
  fqdn: string,
  opts: { owned?: boolean; criticality?: 'low' | 'medium' | 'high' | 'critical' } = {},
): Promise<Seed> {
  const admin = await ensureUser(t, 'admin');
  const owner = opts.owned ? await ensureUser(t, 'asset_owner') : null;
  const d = firstRow(
    await t.db
      .insert(schema.domains)
      .values({ fqdn, criticality: opts.criticality ?? 'high' })
      .returning(),
  );
  const a = firstRow(
    await t.db
      .insert(schema.assets)
      .values({
        domainId: d.id,
        hostname: `www.${fqdn}`,
        assetType: 'subdomain',
        discoverySource: 'manual',
        verificationStatus: 'approved',
        approvedBy: admin,
        approvedAt: new Date('2026-10-01T00:00:00Z'),
        ownerUserId: owner,
      })
      .returning(),
  );
  return { domainId: d.id, fqdn, wwwAssetId: a.id };
}

export interface DnsSpec {
  hostname: string;
  recordType: string;
  values: string[];
  status?: 'success' | 'partial' | 'error' | 'timeout' | 'skipped';
}

let seq = 0;

/** A finished passive job for the domain with the given DNS observations. */
export async function seedJob(
  t: TestDatabase,
  domainId: string,
  completedAt: Date,
  dns: DnsSpec[],
  status: 'succeeded' | 'failed' | 'cancelled' = 'succeeded',
): Promise<string> {
  const db: Database = t.db;
  const domain = firstRow(await db.select().from(schema.domains).where(eqId(domainId)));
  const profile = firstRow((await listProfiles(db)).filter((p) => p.key === 'passive'));
  const snapshot = buildSnapshot(
    domain,
    profile,
    [{ assetId: null, hostname: domain.fqdn }],
    'manual',
    null,
    completedAt,
  );
  const job = firstRow(
    await db
      .insert(schema.scanJobs)
      .values({
        jobType: 'scan',
        profile: 'passive',
        domainId,
        status,
        scopeSnapshot: snapshot,
        createdAt: completedAt,
        scheduledAt: completedAt,
        startedAt: completedAt,
        completedAt,
        attempts: 1,
      })
      .returning(),
  );
  if (dns.length > 0) {
    await db.insert(schema.dnsObservations).values(
      dns.map((o) => ({
        resultId: `fixture-${seq++}`,
        scanJobId: job.id,
        observedAt: completedAt,
        checker: 'dns',
        checkerVersion: 'test',
        resultStatus: o.status ?? 'success',
        hostname: o.hostname,
        recordType: o.recordType,
        ttl: 300,
        recordValues: o.values,
      })),
    );
  }
  return job.id;
}

const eqId = (id: string) => eq(schema.domains.id, id);

/** DNS observations for `fqdn`: DMARC present or not, plus A records for the apex and www. */
export function dnsFor(
  fqdn: string,
  opts: {
    dmarc?: boolean;
    dmarcStatus?: DnsSpec['status'];
    apexA?: string[];
    wwwA?: string[];
  } = {},
): DnsSpec[] {
  return [
    {
      hostname: `_dmarc.${fqdn}`,
      recordType: 'TXT',
      values: opts.dmarc ? ['"v=DMARC1; p=reject"'] : [],
      status: opts.dmarcStatus ?? 'success',
    },
    { hostname: fqdn, recordType: 'A', values: opts.apexA ?? [] },
    ...(opts.wwwA ? [{ hostname: `www.${fqdn}`, recordType: 'A', values: opts.wwwA }] : []),
  ];
}
