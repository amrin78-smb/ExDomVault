import type { Severity } from '@exdomainvault/shared';

/**
 * DEVELOPMENT FIXTURES — synthetic values for laying out the dashboard before the database exists.
 * These are not scan results. Only rendered when DEV_FIXTURES_ENABLED is true, always beneath
 * the development-data banner. Hostnames use the reserved example.* domains (RFC 2606).
 */
export interface OverviewSummary {
  domainsMonitored: number;
  verifiedAssets: number;
  pendingAssets: number;
  openFindingsBySeverity: Record<Severity, number>;
  latestScan: { profile: string; status: string; completedAt: string } | null;
  worker: { name: string; status: 'healthy' | 'stale' | 'offline'; lastSeenAt: string } | null;
  expiringCertificates: { hostname: string; expiresAt: string }[];
  recentDnsChanges: { hostname: string; recordType: string; change: string; observedAt: string }[];
  topPriorities: { id: string; title: string; asset: string; severity: Severity }[];
}

// `import.meta.env.DEV` is replaced with `false` in production builds, so this data is
// eliminated from the production bundle entirely.
export const overviewFixture: OverviewSummary | null = import.meta.env.DEV
  ? {
      domainsMonitored: 3,
      verifiedAssets: 14,
      pendingAssets: 5,
      openFindingsBySeverity: { critical: 0, high: 2, medium: 4, low: 6, informational: 3 },
      latestScan: { profile: 'Quick', status: 'succeeded', completedAt: '2026-10-21T02:14:00Z' },
      worker: { name: 'home-worker-01', status: 'healthy', lastSeenAt: '2026-10-21T09:58:00Z' },
      expiringCertificates: [
        { hostname: 'shop.example.com', expiresAt: '2026-11-01T00:00:00Z' },
        { hostname: 'mail.example.org', expiresAt: '2026-11-03T00:00:00Z' },
      ],
      recentDnsChanges: [
        {
          hostname: 'example.com',
          recordType: 'NS',
          change: 'Nameserver set changed',
          observedAt: '2026-10-20T03:00:00Z',
        },
        {
          hostname: 'api.example.net',
          recordType: 'CNAME',
          change: 'Target changed',
          observedAt: '2026-10-19T03:00:00Z',
        },
      ],
      topPriorities: [
        {
          id: 'fx-1',
          title: 'Certificate expires within 14 days',
          asset: 'shop.example.com',
          severity: 'high',
        },
        {
          id: 'fx-2',
          title: 'Potential dangling CNAME requiring validation',
          asset: 'old.example.net',
          severity: 'high',
        },
        { id: 'fx-3', title: 'Missing DMARC policy', asset: 'example.org', severity: 'medium' },
      ],
    }
  : null;
