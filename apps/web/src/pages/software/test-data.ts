// Test-only synthetic software inventory (reserved example.* names, RFC 2606; documentation IPs).
import type { IntelFeedStatus, SoftwareItem, SoftwareSummaryResponse } from '@exdomainvault/shared';
import { DOMAIN_ID } from '../findings/test-data.ts';

export { DOMAIN_ID };
export const SOFTWARE_ID = '3e4f5a6b-7c8d-4e9f-8a0b-1c2d3e4f5a6b';

export const softwareItem = (overrides: Partial<SoftwareItem> = {}): SoftwareItem => ({
  id: SOFTWARE_ID,
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  hostname: 'shop.example.com',
  ipAddress: '192.0.2.10',
  port: 443,
  source: 'http_header',
  product: 'apache_httpd',
  productLabel: 'Apache HTTP Server',
  version: '2.4.49',
  banner: 'Apache/2.4.49 (Ubuntu)',
  backportHint: { distribution: 'Ubuntu' },
  firstSeenAt: '2026-10-20T03:00:00.000Z',
  lastSeenAt: '2026-10-22T03:00:00.000Z',
  eol: { cycle: '2.4', eolDate: null, isEol: false, latestInCycle: '2.4.62' },
  knownExploited: [{ cveId: 'CVE-2021-41773', cvss: 7.5, ransomware: true }],
  ...overrides,
});

export const eolPhp = (overrides: Partial<SoftwareItem> = {}): SoftwareItem =>
  softwareItem({
    id: '4f5a6b7c-8d9e-4f0a-9b1c-2d3e4f5a6b7c',
    hostname: 'legacy.example.com',
    product: 'php',
    productLabel: 'PHP',
    version: '7.4.3',
    banner: 'PHP/7.4.3',
    backportHint: null,
    eol: { cycle: '7.4', eolDate: '2022-11-28', isEol: true, latestInCycle: '7.4.33' },
    knownExploited: [],
    ...overrides,
  });

export const hiddenSsh = (overrides: Partial<SoftwareItem> = {}): SoftwareItem =>
  softwareItem({
    id: '5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d',
    hostname: null,
    ipAddress: '2001:db8::5',
    port: 22,
    source: 'service_identification',
    product: 'openssh',
    productLabel: 'OpenSSH',
    version: null,
    banner: 'OpenSSH',
    backportHint: null,
    eol: null,
    knownExploited: [],
    ...overrides,
  });

export const softwarePage = (items: SoftwareItem[], total = items.length, pageSize = 50) => ({
  items,
  page: 1,
  pageSize,
  total,
});

export const summary = (): SoftwareSummaryResponse => ({
  products: [
    {
      product: 'php',
      productLabel: 'PHP',
      hosts: 4,
      eol: 3,
      knownExploited: 0,
      versions: [
        { version: '7.4.3', hosts: 2 },
        { version: '8.3.1', hosts: 1 },
        { version: null, hosts: 1 },
      ],
    },
    {
      product: 'apache_httpd',
      productLabel: 'Apache HTTP Server',
      hosts: 2,
      eol: 0,
      knownExploited: 1,
      versions: [{ version: '2.4.49', hosts: 2 }],
    },
  ],
});

export const feed = (overrides: Partial<IntelFeedStatus> = {}): IntelFeedStatus => ({
  feed: 'endoflife',
  lastSuccessAt: '2026-10-23T02:00:00.000Z',
  lastAttemptAt: '2026-10-23T02:00:00.000Z',
  lastError: null,
  items: 412,
  sourceVersion: null,
  pending: 0,
  ...overrides,
});

export const feeds = (): { feeds: IntelFeedStatus[] } => ({
  feeds: [
    feed(),
    feed({ feed: 'cisa_kev', items: 37, sourceVersion: '2026.10.22' }),
    feed({
      feed: 'nvd',
      items: 30,
      pending: 7,
      lastSuccessAt: '2026-10-22T02:00:00.000Z',
      lastError: 'http_429',
    }),
  ],
});
