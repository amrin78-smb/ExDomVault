// Test-only synthetic assets (reserved example.* names, RFC 2606; documentation IPs, RFC 5737).
import type { Asset, AssetDetailResponse } from '@exdomainvault/shared';

export const DOMAIN_ID = '0b8e3f9a-4c1d-4e5f-8a7b-1c2d3e4f5a6b';
export const ASSET_ID = '3e4f5a6b-7c8d-4e9f-8a0b-1c2d3e4f5a6b';
export const JOB_ID = '7d1f8c2e-3b4a-4c5d-9e6f-0a1b2c3d4e5f';
export const ADMIN = { id: '9c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f', email: 'admin@example.com' };

export const asset = (overrides: Partial<Asset> = {}): Asset => ({
  id: ASSET_ID,
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  hostname: 'shop.example.com',
  assetType: 'subdomain',
  status: 'pending',
  source: 'certificate_transparency',
  firstSeenAt: '2026-10-20T03:00:00.000Z',
  lastSeenAt: '2026-10-22T03:00:00.000Z',
  currentIps: ['192.0.2.10'],
  hostingHint: null,
  wildcardOnly: false,
  decidedBy: null,
  decidedAt: null,
  decisionReason: null,
  activeFindings: 0,
  ...overrides,
});

export const CLOUDFRONT = {
  provider: 'Amazon CloudFront',
  kind: 'cdn',
  matchedName: 'd111.cloudfront.net',
} as const;

export const detailOf = (
  a: Asset = asset(),
  overrides: Partial<AssetDetailResponse> = {},
): AssetDetailResponse => ({
  asset: a,
  ips: [
    {
      ipAddress: '192.0.2.10',
      firstSeenAt: '2026-10-20T03:00:00.000Z',
      lastSeenAt: '2026-10-22T03:00:00.000Z',
      isCurrent: true,
      source: 'dns',
    },
    {
      ipAddress: '198.51.100.7',
      firstSeenAt: '2026-09-01T03:00:00.000Z',
      lastSeenAt: '2026-10-01T03:00:00.000Z',
      isCurrent: false,
      source: 'dns',
    },
  ],
  discovery: [
    {
      source: 'certificate_transparency',
      observedAt: '2026-10-20T03:00:00.000Z',
      wildcard: false,
      scanJobId: JOB_ID,
      evidence: { issuer: 'Example CA' },
    },
  ],
  ...overrides,
});

export const page = <T>(items: T[], total = items.length, pageNo = 1) => ({
  items,
  page: pageNo,
  pageSize: 25,
  total,
});
