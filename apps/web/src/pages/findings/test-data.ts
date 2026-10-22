// Test-only synthetic findings (reserved example.* names, RFC 2606).
import {
  RULE_CATEGORIES,
  type AdvisoryDto,
  type Domain,
  type Finding,
  type FindingDetailResponse,
} from '@exdomainvault/shared';

export const DOMAIN_ID = '0b8e3f9a-4c1d-4e5f-8a7b-1c2d3e4f5a6b';
export const FINDING_ID = '5c6d7e8f-9a0b-4c1d-8e2f-3a4b5c6d7e8f';

export const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: FINDING_ID,
  ruleId: 'TLS-003',
  ruleVersion: 1,
  category: 'tls',
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  hostname: 'shop.example.com',
  component: 'certificate:443',
  assetId: null,
  title: 'Certificate expires within 14 days',
  description: 'The certificate served on port 443 expires on 1 November 2026.',
  severity: 'high',
  confidence: 'high',
  riskScore: 60,
  riskInputs: {
    model: 'v1',
    severity: 'high',
    severityWeight: 75,
    exposure: 'web',
    exposureFactor: 1,
    criticality: 'medium',
    criticalityFactor: 0.85,
  },
  status: 'open',
  evidence: {
    notAfter: '2026-11-01T00:00:00Z',
    daysRemaining: 10,
    sanNames: ['shop.example.com', 'www.shop.example.com'],
    chain: { issuer: 'Example CA', depth: 2 },
  },
  firstSeenAt: '2026-10-20T03:00:00.000Z',
  lastSeenAt: '2026-10-22T03:00:00.000Z',
  resolvedAt: null,
  recurrenceCount: 1,
  assignee: null,
  acceptedRisk: null,
  manualResolution: false,
  createdAt: '2026-10-20T03:00:00.000Z',
  updatedAt: '2026-10-22T03:00:00.000Z',
  ...overrides,
});

export const advisory = (overrides: Partial<AdvisoryDto> = {}): AdvisoryDto => ({
  id: crypto.randomUUID(),
  findingId: FINDING_ID,
  title: 'Renew the certificate for shop.example.com',
  summary: 'Visitors will see a browser warning once the certificate expires.',
  businessImpact: 'Customers may be unable to reach the shop.',
  recommendedActions: ['Renew the certificate', 'Automate renewal'],
  references: ['https://example.org/tls-renewal'],
  createdAt: '2026-10-20T03:00:00.000Z',
  updatedAt: '2026-10-20T03:00:00.000Z',
  ...overrides,
});

export const detailOf = (
  overrides: Partial<FindingDetailResponse> = {},
): FindingDetailResponse => ({
  finding: finding(),
  advisory: advisory(),
  history: [
    {
      id: crypto.randomUUID(),
      fromStatus: null,
      toStatus: 'open',
      changedBy: null,
      reason: 'detected',
      note: null,
      scanJobId: null,
      createdAt: '2026-10-20T03:00:00.000Z',
    },
    {
      id: crypto.randomUUID(),
      fromStatus: 'resolved',
      toStatus: 'open',
      changedBy: null,
      reason: 'recurrence',
      note: null,
      scanJobId: null,
      createdAt: '2026-10-22T03:00:00.000Z',
    },
  ],
  comments: [],
  rule: {
    id: 'TLS-003',
    version: 1,
    detection: 'The leaf certificate notAfter is within 14 days of the scan.',
    resolution: 'Resolved when a later TLS check sees a certificate valid for more than 14 days.',
    evidenceRequirements: 'A successful TLS handshake recording the leaf certificate.',
  },
  ...overrides,
});

export const page = <T>(items: T[], total = items.length) => ({
  items,
  page: 1,
  pageSize: 25,
  total,
});

export const domain = (overrides: Partial<Domain> = {}): Domain => ({
  id: DOMAIN_ID,
  fqdn: 'example.com',
  unicodeFqdn: 'example.com',
  warnings: [],
  registrar: null,
  registeredAt: null,
  expiresAt: null,
  registrationDataStatus: 'unknown',
  criticality: 'medium',
  businessOwner: null,
  verificationStatus: 'unverified',
  verifiedAt: null,
  verificationMethod: null,
  verificationExpiresAt: null,
  monitoringEnabled: false,
  createdAt: '2026-10-22T10:00:00.000Z',
  updatedAt: '2026-10-22T10:00:00.000Z',
  ...overrides,
});

/** Zero count for every rule category (the summary schema requires each key). */
export const NO_CATEGORIES = Object.fromEntries(RULE_CATEGORIES.map((c) => [c, 0]));

export const ANALYST = {
  id: '7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d',
  email: 'analyst@example.com',
  displayName: 'Ana Lyst',
};
export const OWNER = {
  id: '8b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e',
  email: 'owner@example.com',
  displayName: null,
};
export const assignable = {
  items: [
    { ...ANALYST, role: 'analyst' as const },
    { ...OWNER, role: 'asset_owner' as const },
  ],
};
