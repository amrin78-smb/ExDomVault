// Test-only synthetic inventory rows (reserved example.* names, RFC 2606; documentation IPs,
// RFC 5737 / RFC 3849). CVE ids are real KEV entries used only as identifiers.
import type {
  AttackSurfaceResponse,
  CertificateItem,
  CertificatesResponse,
  PortItem,
  PortsResponse,
  VulnerabilityItem,
} from '@exdomainvault/shared';
import { DOMAIN_ID } from '../../pages/findings/test-data.ts';

export { DOMAIN_ID };
export const ASSET_ID = '7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d';
export const ASSET_ID_2 = '8b9c0d1e-2f3a-4b4c-9d5e-6f7a8b9c0d1e';

/** Request paths of the Milestone 13 inventory endpoints, matching the server routes. */
export const INVENTORY_PATHS = {
  ports: (query = '') => `GET /api/v1/ports${query}`,
  certificates: (query = '') => `GET /api/v1/certificates${query}`,
  vulnerabilities: (query = '') => `GET /api/v1/vulnerabilities${query}`,
  attackSurface: 'GET /api/v1/attack-surface',
  domains: 'GET /api/v1/domains?pageSize=100',
} as const;

const iso = (offsetDays: number) => new Date(Date.now() + offsetDays * 86_400_000).toISOString();

export const portItem = (overrides: Partial<PortItem> = {}): PortItem => ({
  ipAddress: '192.0.2.10',
  port: 443,
  protocol: 'tcp',
  state: 'open',
  service: 'https',
  hostnames: [{ assetId: ASSET_ID, hostname: 'shop.example.com' }],
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  country: 'DE',
  policyViolation: false,
  firstObservedAt: iso(-10),
  lastObservedAt: iso(-1),
  ...overrides,
});

export const portsPage = (
  items: PortItem[],
  counts: PortsResponse['counts'] = { open: items.length, closed: 0, filtered: 0 },
  total = items.length,
): PortsResponse => ({ items, page: 1, pageSize: 25, total, counts });

export const attackSurface = (
  exposedServices: AttackSurfaceResponse['exposedServices'] = [],
): AttackSurfaceResponse => ({
  totals: { approvedAssets: 0, currentIps: 0, openPorts: 0, thirdPartyHosted: 0 },
  assetRoles: [],
  hostingProviders: [],
  countries: [],
  continents: [],
  unknownCountryIps: 0,
  geoAttribution: null,
  exposedServices,
});

export const certificateItem = (overrides: Partial<CertificateItem> = {}): CertificateItem => ({
  hostname: 'shop.example.com',
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  assetId: ASSET_ID,
  ipAddress: '192.0.2.10',
  port: 443,
  issuer: 'Example Test CA',
  subject: 'CN=shop.example.com',
  subjectAltNames: ['shop.example.com', 'www.shop.example.com'],
  notBefore: '2026-08-01T00:00:00.000Z',
  notAfter: '2026-12-30T00:00:00.000Z',
  daysLeft: 60,
  hostnameMatches: true,
  trusted: true,
  protocolVersion: 'TLSv1.3',
  status: 'valid',
  observedAt: iso(-1),
  ...overrides,
});

export const certCounts = (
  counts: Partial<CertificatesResponse['counts']> = {},
): CertificatesResponse['counts'] => ({
  expired: 0,
  expiring: 0,
  valid: 0,
  mismatch: 0,
  untrusted: 0,
  ...counts,
});

export const certificatesPage = (
  items: CertificateItem[],
  counts = certCounts({ valid: items.length }),
  total = items.length,
): CertificatesResponse => ({ items, page: 1, pageSize: 25, total, counts });

export const vulnerabilityItem = (
  overrides: Partial<VulnerabilityItem> = {},
): VulnerabilityItem => ({
  cve: 'CVE-2021-41773',
  title: 'Apache HTTP Server Path Traversal',
  cvss: 7.5,
  kev: true,
  knownRansomwareUse: true,
  products: [{ product: 'apache_httpd', productLabel: 'Apache HTTP Server' }],
  affectedHosts: 3,
  affectedDomains: 1,
  openFindings: 2,
  kevDateAdded: '2021-11-03',
  kevDueDate: null,
  ...overrides,
});

export const vulnerabilitiesPage = (items: VulnerabilityItem[], total = items.length) => ({
  items,
  page: 1,
  pageSize: 25,
  total,
});
