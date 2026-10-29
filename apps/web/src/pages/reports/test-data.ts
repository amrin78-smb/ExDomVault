// Test-only synthetic report data (reserved example.* names, RFC 2606).
import type { ReportSummaryResponse } from '@exdomainvault/shared';
import { DOMAIN_ID, FINDING_ID, NO_CATEGORIES } from '../findings/test-data.ts';

export const REPORT_PATHS = {
  summary: 'GET /api/v1/reports/summary',
  monthly: 'GET /api/v1/reports/monthly',
  csv: (query = '') => `/api/v1/reports/findings.csv${query}`,
} as const;

export const OTHER_DOMAIN_ID = '2f3e4d5c-6b7a-4a8b-9c0d-1e2f3a4b5c6d';

/** 30 UTC days ending 2026-10-22, with a little activity. */
export const trend = (): ReportSummaryResponse['trend'] =>
  Array.from({ length: 30 }, (_, i) => {
    const d = new Date(Date.UTC(2026, 8, 23 + i));
    return {
      date: d.toISOString().slice(0, 10),
      created: i % 5 === 0 ? 3 : 1,
      resolved: i % 7 === 0 ? 2 : 0,
    };
  });

export const reportSummary = (
  overrides: Partial<ReportSummaryResponse> = {},
): ReportSummaryResponse => ({
  generatedAt: '2026-10-22T12:00:00.000Z',
  coverage: {
    domains: 339,
    monitoredDomains: 320,
    verifiedDomains: 41,
    approvedAssets: 812,
    pendingAssets: 27,
    lastScanAt: '2026-10-22T03:00:00.000Z',
  },
  findings: {
    open: 58,
    bySeverity: { critical: 2, high: 9, medium: 20, low: 17, informational: 10 },
    byStatus: {
      open: 40,
      acknowledged: 6,
      remediation_in_progress: 7,
      accepted_risk: 3,
      resolved: 120,
    },
    byCategory: NO_CATEGORIES as ReportSummaryResponse['findings']['byCategory'],
    meanDaysToResolve: 6.42,
  },
  trendDays: 30,
  trend: trend(),
  topDomains: [
    {
      domain: { id: DOMAIN_ID, fqdn: 'example.com' },
      criticality: 'high',
      openFindings: 12,
      riskTotal: 540,
      highestSeverity: 'critical',
    },
    {
      domain: { id: OTHER_DOMAIN_ID, fqdn: 'example.org' },
      criticality: 'medium',
      openFindings: 4,
      riskTotal: 130,
      highestSeverity: 'medium',
    },
  ],
  byBusinessOwner: [
    {
      businessOwner: 'Retail',
      domains: 120,
      openFindings: 30,
      highOrCritical: 6,
      overdue: 3,
      averageScore: 82.4,
      grade: 'B',
      grades: { A: 40, B: 50, C: 20, D: 6, F: 4 },
    },
    {
      businessOwner: null,
      domains: 19,
      openFindings: 5,
      highOrCritical: 1,
      overdue: 0,
      averageScore: null,
      grade: null,
      grades: { A: 0, B: 0, C: 0, D: 0, F: 0 },
    },
  ],
  expiringRegistrations: [
    {
      domain: { id: OTHER_DOMAIN_ID, fqdn: 'example.org' },
      expiresAt: '2026-10-19T00:00:00.000Z',
      daysLeft: -3,
    },
    {
      domain: { id: DOMAIN_ID, fqdn: 'example.com' },
      expiresAt: '2026-11-30T00:00:00.000Z',
      daysLeft: 39,
    },
  ],
  expiringCertificates: [
    {
      domain: { id: DOMAIN_ID, fqdn: 'example.com' },
      hostname: 'shop.example.com',
      notAfter: '2026-11-01T00:00:00.000Z',
      daysLeft: 10,
      issuer: 'Example CA',
    },
  ],
  sla: {
    policy: { critical: 7, high: 30, medium: 90, low: 180, informational: null },
    overdue: 3,
    overdueBySeverity: { critical: 1, high: 2, medium: 0, low: 0, informational: 0 },
    windowDays: 90,
    resolvedWithSla: 20,
    resolvedWithinSla: 17,
    compliancePercent: 85,
    meanDaysToResolveBySeverity: {
      critical: 4.5,
      high: 21.25,
      medium: null,
      low: null,
      informational: null,
    },
  },
  acceptedRisksDue: [
    {
      findingId: FINDING_ID,
      title: 'Certificate expires within 14 days',
      domain: { id: DOMAIN_ID, fqdn: 'example.com' },
      reviewAt: '2026-10-20T00:00:00.000Z',
    },
  ],
  ...overrides,
});
