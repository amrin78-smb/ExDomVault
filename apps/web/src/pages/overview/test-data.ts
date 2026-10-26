// Test-only: canned overview responses (dashboard + attack surface), valid against the contracts.
import type {
  AttackSurfaceResponse,
  DashboardResponse,
  ScanJob,
  ScanProfile,
} from '@exdomainvault/shared';
import { DOMAIN_ID } from '../findings/test-data.ts';

export const NOW = '2026-10-26T12:00:00.000Z';
export const FINDING_A = '11111111-1111-4111-8111-111111111111';
export const FINDING_B = '22222222-2222-4222-8222-222222222222';
export const SCAN_A = '33333333-3333-4333-8333-333333333333';
export const ASSET_A = '44444444-4444-4444-8444-444444444444';
export const JOB_ID = '55555555-5555-4555-8555-555555555555';
const ref = { id: DOMAIN_ID, fqdn: 'example.com' };

export const DASHBOARD_PATH = (range = 30) => `GET /api/v1/dashboard?range=${range}`;
export const SURFACE_PATH = 'GET /api/v1/attack-surface';

const days = (n: number) =>
  Array.from({ length: n }, (_, i) =>
    new Date(Date.parse('2026-10-26T00:00:00Z') - (n - 1 - i) * 86_400_000)
      .toISOString()
      .slice(0, 10),
  );

export function dashboard(
  overrides: Partial<DashboardResponse> = {},
  range = 30,
): DashboardResponse {
  const series = (start: number, end: number) =>
    Array.from({ length: range + 1 }, (_, i) => Math.round(start + ((end - start) * i) / range));
  return {
    generatedAt: NOW,
    range,
    lastScanAt: '2026-10-26T09:30:00.000Z',
    stats: {
      domains: { value: 12, delta: 2, series: series(10, 12), active: 9 },
      assets: { value: 340, delta: 15, series: series(325, 340), pending: 27 },
      openFindings: { value: 50, delta: 5, series: series(45, 50) },
      criticalHigh: { value: 8, delta: -2, series: series(10, 8) },
      expiringCertificates: { value: 3, delta: null, series: [] },
      eolSoftware: { value: 4, delta: null, series: [], kev: 1 },
    },
    severity: { critical: 5, high: 15, medium: 20, low: 8, informational: 2 },
    trend: days(range + 1).map((date, i) => ({
      date,
      critical: i % 5 === 0 ? 1 : 0,
      high: i % 3 === 0 ? 1 : 0,
      medium: 1,
      low: 0,
      informational: 0,
      resolved: i % 4 === 0 ? 1 : 0,
    })),
    topRemediation: [
      {
        findingId: FINDING_A,
        title: 'Known-exploited vulnerability possibly present',
        ruleId: 'SOFT-002',
        severity: 'critical',
        riskScore: 92,
        domain: ref,
        hostname: 'vpn.example.com',
        cves: ['CVE-2024-3400'],
        assetRole: 'remote_access',
      },
      {
        findingId: FINDING_B,
        title: 'Certificate expires within 14 days',
        ruleId: 'TLS-003',
        severity: 'high',
        riskScore: 71,
        domain: ref,
        hostname: null,
        cves: [],
        assetRole: null,
      },
    ],
    latestScans: [
      {
        id: SCAN_A,
        jobType: 'scan',
        domain: ref,
        profile: 'standard',
        status: 'succeeded',
        createdAt: '2026-10-26T09:00:00.000Z',
        completedAt: '2026-10-26T09:30:00.000Z',
      },
      {
        id: crypto.randomUUID(),
        jobType: 'scan',
        domain: { id: crypto.randomUUID(), fqdn: 'example.org' },
        profile: 'passive',
        status: 'failed',
        createdAt: '2026-10-25T09:00:00.000Z',
        completedAt: '2026-10-25T09:01:00.000Z',
      },
      {
        id: crypto.randomUUID(),
        jobType: 'discovery',
        domain: ref,
        profile: 'discovery',
        status: 'running',
        createdAt: '2026-10-26T11:00:00.000Z',
        completedAt: null,
      },
    ],
    certificateExpiry: [
      cert('expired.example.com', -2),
      cert('soon.example.com', 5),
      cert('week.example.com', 7),
      cert('fortnight.example.com', 14),
      cert('month.example.com', 30),
      cert('later.example.com', 45),
    ].slice(0, 5),
    recentAssets: [
      {
        id: ASSET_A,
        hostname: 'new.example.com',
        domain: ref,
        status: 'pending',
        source: 'certificate_transparency',
        role: 'web',
        firstSeenAt: '2026-10-25T00:00:00.000Z',
      },
      {
        id: crypto.randomUUID(),
        hostname: 'old.example.com',
        domain: ref,
        status: 'pending',
        source: 'dns',
        role: 'unclassified',
        firstSeenAt: '2026-09-01T00:00:00.000Z',
      },
      {
        id: crypto.randomUUID(),
        hostname: 'mail.example.com',
        domain: ref,
        status: 'approved',
        source: 'manual',
        role: 'mail',
        firstSeenAt: '2026-10-20T00:00:00.000Z',
      },
    ],
    topSoftware: [
      {
        product: 'nginx',
        productLabel: 'nginx',
        versions: ['1.18.0', '1.24.0'],
        hosts: 14,
        eolHosts: 3,
        kevCves: 0,
      },
      {
        product: 'pan-os',
        productLabel: 'PAN-OS',
        versions: ['10.2.3'],
        hosts: 2,
        eolHosts: 0,
        kevCves: 2,
      },
    ],
    ...overrides,
  };
}

export function cert(hostname: string, daysLeft: number) {
  return {
    hostname,
    domain: ref,
    notAfter: new Date(Date.parse(NOW) + daysLeft * 86_400_000).toISOString(),
    daysLeft,
    issuer: 'CN=Example CA',
  };
}

/** What an asset owner gets: no domain counts and no scans (they lack those permissions). */
export function ownerDashboard(): DashboardResponse {
  const d = dashboard();
  return {
    ...d,
    lastScanAt: null,
    stats: { ...d.stats, domains: { value: 0, delta: null, series: [], active: 0 } },
    latestScans: [],
  };
}

/** A dashboard with nothing collected yet. */
export function emptyDashboard(): DashboardResponse {
  const zero = { value: 0, delta: 0, series: [0, 0] };
  return {
    generatedAt: NOW,
    range: 30,
    lastScanAt: null,
    stats: {
      domains: { ...zero, active: 0 },
      assets: { ...zero, pending: 0 },
      openFindings: zero,
      criticalHigh: zero,
      expiringCertificates: { value: 0, delta: null, series: [] },
      eolSoftware: { value: 0, delta: null, series: [], kev: 0 },
    },
    severity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    trend: [],
    topRemediation: [],
    latestScans: [],
    certificateExpiry: [],
    recentAssets: [],
    topSoftware: [],
  };
}

export function attackSurface(
  overrides: Partial<AttackSurfaceResponse> = {},
): AttackSurfaceResponse {
  return {
    totals: { approvedAssets: 40, currentIps: 60, openPorts: 25, thirdPartyHosted: 10 },
    assetRoles: [
      { role: 'web', assets: 20 },
      { role: 'mail', assets: 10 },
      { role: 'dns', assets: 5 },
      { role: 'remote_access', assets: 0 },
      { role: 'file_transfer', assets: 0 },
      { role: 'database', assets: 0 },
      { role: 'cloud_service', assets: 0 },
      { role: 'unclassified', assets: 5 },
    ],
    hostingProviders: [],
    countries: [
      { country: 'DE', assets: 10, ips: 20 },
      { country: 'US', assets: 8, ips: 15 },
      { country: 'SG', assets: 4, ips: 10 },
      { country: 'BR', assets: 2, ips: 5 },
    ],
    continents: [
      { continent: 'Europe', assets: 10, ips: 20 },
      { continent: 'North America', assets: 8, ips: 15 },
      { continent: 'Asia', assets: 4, ips: 10 },
      { continent: 'South America', assets: 2, ips: 5 },
    ],
    unknownCountryIps: 10,
    geoAttribution: 'IP geolocation by DB-IP (db-ip.com), CC BY 4.0',
    exposedServices: [],
    ...overrides,
  };
}

export const emptySurface = (): AttackSurfaceResponse =>
  attackSurface({
    totals: { approvedAssets: 0, currentIps: 0, openPorts: 0, thirdPartyHosted: 0 },
    assetRoles: attackSurface().assetRoles.map((r) => ({ ...r, assets: 0 })),
    countries: [],
    continents: [],
    unknownCountryIps: 0,
    geoAttribution: null,
  });

const passiveConfig = {
  active: false,
  checks: ['dns', 'rdap'],
  tcpPorts: [],
  timeouts: { connectMs: 3000, readMs: 5000, targetSeconds: 60 },
  concurrency: 4,
  ratePerSecond: 5,
  maxTargets: 50,
} satisfies ScanProfile['config'];

export const profiles = {
  activeScanningEnabled: true,
  items: [
    {
      key: 'passive',
      name: 'Passive',
      description: 'DNS and RDAP only.',
      version: 1,
      defaultSchedule: 'daily',
      enabled: true,
      config: passiveConfig,
    },
    {
      key: 'standard',
      name: 'Standard',
      description: 'Certificates, HTTP and ports.',
      version: 1,
      defaultSchedule: 'weekly',
      enabled: true,
      config: {
        ...passiveConfig,
        active: true,
        checks: ['dns', 'tls_certificate', 'http_availability'],
      },
    },
  ],
};

export const queuedJob = (domainId: string, fqdn: string, profile: string): ScanJob => ({
  id: JOB_ID,
  jobType: 'scan',
  profile,
  domain: { id: domainId, fqdn },
  status: 'queued',
  priority: 100,
  reason: null,
  trigger: 'manual',
  requestedBy: null,
  createdAt: NOW,
  scheduledAt: NOW,
  startedAt: null,
  completedAt: null,
  leaseExpiresAt: null,
  attempts: 0,
  maxAttempts: 3,
  worker: null,
  progress: null,
  cancelRequestedAt: null,
  errorCode: null,
  errorSummary: null,
  targetCounts: { pending: 1, running: 0, succeeded: 0, failed: 0, skipped: 0 },
});

export const jobDetail = (j: ScanJob, verificationStatus: 'verified' | 'unverified') => ({
  job: j,
  targets: [],
  scopeSnapshot: {
    version: 1,
    createdAt: j.createdAt,
    requestedBy: null,
    trigger: 'manual',
    domain: {
      id: j.domain?.id,
      fqdn: j.domain?.fqdn,
      verificationStatus,
      verificationMethod: verificationStatus === 'verified' ? 'dns_txt' : null,
      verificationExpiresAt: null,
    },
    profile: { key: j.profile, version: 1, config: passiveConfig },
    targets: [],
  },
});
