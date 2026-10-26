import type {
  Domain,
  DomainObservationsResponse,
  HttpSnapshot,
  PortSnapshot,
  TlsSnapshot,
} from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDomainCards } from '../../testing/domain-cards.ts';
import { ok, renderAt, stubApi } from '../../testing/stub-api.tsx';

const DOMAIN_ID = '0b8e3f9a-4c1d-4e5f-8a7b-1c2d3e4f5a6b';
const JOB_ID = '7d1f8c2e-3b4a-4c5d-9e6f-0a1b2c3d4e5f';
const DAY_MS = 86_400_000;
const FINGERPRINT = 'ab'.repeat(32);

const domain = (overrides: Partial<Domain> = {}): Domain => ({
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
  verificationStatus: 'verified',
  verifiedAt: '2026-10-01T10:00:00.000Z',
  verificationMethod: 'dns_txt',
  verificationExpiresAt: null,
  monitoringEnabled: true,
  createdAt: '2026-10-22T10:00:00.000Z',
  updatedAt: '2026-10-22T10:00:00.000Z',
  ...overrides,
});

const base = {
  resultStatus: 'success' as const,
  observedAt: '2026-10-22T09:00:00.000Z',
  scanJobId: JOB_ID,
};

const tls = (overrides: Partial<TlsSnapshot> = {}): TlsSnapshot => ({
  hostname: 'example.com',
  ipAddress: '93.184.215.14',
  port: 443,
  protocolVersion: 'TLSv1.3',
  notBefore: '2026-08-01T00:00:00.000Z',
  notAfter: new Date(Date.now() + 80.5 * DAY_MS).toISOString(),
  issuer: 'CN=Example CA,O=Example Trust',
  subject: 'CN=example.com',
  subjectAltNames: ['example.com', 'www.example.com'],
  fingerprintSha256: FINGERPRINT,
  hostnameMatches: true,
  evidence: { trusted: true, chainLength: 2 },
  ...base,
  ...overrides,
});

const http = (overrides: Partial<HttpSnapshot> = {}): HttpSnapshot => ({
  url: 'http://example.com/',
  ipAddress: '93.184.215.14',
  statusCode: 200,
  finalUrl: 'https://www.example.com/',
  redirectCount: 2,
  hstsEnabled: false,
  evidence: {
    securityHeaders: {
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
    },
    server: 'nginx/1.18.0',
    'x-powered-by': 'PHP/7.4.3',
    hops: [
      { url: 'http://example.com/', ip: '93.184.215.14', status: 301, decision: 'followed' },
      { url: 'https://www.example.com/', ip: '93.184.215.14', status: 200, decision: 'final' },
    ],
  },
  ...base,
  ...overrides,
});

const port = (overrides: Partial<PortSnapshot> = {}): PortSnapshot => ({
  ipAddress: '203.0.113.10',
  port: 443,
  protocol: 'tcp',
  state: 'open',
  service: 'https',
  evidence: { method: 'nmap-sT' },
  ...base,
  ...overrides,
});

function stubPage(
  observations: Partial<DomainObservationsResponse>,
  { activeScanningEnabled = false } = {},
) {
  return stubApi('analyst', {
    [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain: domain(), verification: null }),
    'GET /api/v1/scan-profiles': ok({
      activeScanningEnabled,
      items: [
        {
          key: 'passive',
          name: 'Passive',
          description: 'DNS and RDAP only.',
          version: 1,
          defaultSchedule: 'daily',
          enabled: true,
          config: profileConfig(false),
        },
        {
          key: 'standard',
          name: 'Standard',
          description: 'Certificates, HTTP and ports.',
          version: 1,
          defaultSchedule: 'weekly',
          enabled: true,
          config: profileConfig(true),
        },
      ],
    }),
    [`GET /api/v1/scans?domainId=${DOMAIN_ID}&pageSize=5`]: ok({
      items: [],
      page: 1,
      pageSize: 5,
      total: 0,
    }),
    [`GET /api/v1/domains/${DOMAIN_ID}/observations`]: ok({
      dns: [],
      registration: null,
      tls: [],
      http: [],
      ports: [],
      ...observations,
    }),
  });
}

function profileConfig(active: boolean) {
  return {
    active,
    checks: active ? ['dns', 'rdap', 'tls_certificate', 'tcp_ports'] : ['dns', 'rdap'],
    tcpPorts: active ? [443] : [],
    timeouts: { connectMs: 3000, readMs: 5000, targetSeconds: 60 },
    concurrency: 2,
    ratePerSecond: 2,
    maxTargets: 50,
  };
}

const card = (name: string) => screen.findByRole('region', { name });

beforeEach(openDomainCards);
afterEach(() => vi.unstubAllGlobals());

describe('Domain page: TLS certificates', () => {
  it('shows certificate details with neutral badges and collapsed SANs', async () => {
    stubPage({ tls: [tls()] });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card('TLS certificates');
    const section = await within(c).findByRole('region', { name: 'example.com' });
    expect(within(section).getByText('CN=example.com')).toBeInTheDocument();
    expect(within(section).getByText('CN=Example CA,O=Example Trust')).toBeInTheDocument();
    expect(within(section).getByText('TLSv1.3')).toBeInTheDocument();
    expect(within(section).getByText('93.184.215.14')).toBeInTheDocument();
    expect(within(section).getByText(FINGERPRINT)).toHaveClass('font-mono');
    expect(within(section).getByText('Hostname matches').className).not.toMatch(/red|amber/);
    expect(within(section).getByText('Trusted chain')).toBeInTheDocument();
    const expiry = within(section).getByTestId('cert-expiry');
    expect(expiry).toHaveTextContent('80 days left');
    expect(expiry.className).not.toMatch(/amber|red/);
    const summary = within(section).getByText('2 subject alternative names');
    expect(summary.closest('details')).not.toHaveAttribute('open');
  });

  it('marks expired certificates red, expiring amber, and hostname mismatches', async () => {
    stubPage({
      tls: [
        tls({
          hostname: 'old.example.com',
          notAfter: new Date(Date.now() - 2.5 * DAY_MS).toISOString(),
          hostnameMatches: false,
          evidence: { trusted: false, verifyError: 'certificate has expired' },
        }),
        tls({
          hostname: 'soon.example.com',
          notAfter: new Date(Date.now() + 12.5 * DAY_MS).toISOString(),
        }),
      ],
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card('TLS certificates');
    const old = await within(c).findByRole('region', { name: 'old.example.com' });
    const oldExpiry = within(old).getByTestId('cert-expiry');
    expect(oldExpiry).toHaveTextContent('expired 3 days ago');
    expect(oldExpiry.className).toContain('red');
    expect(within(old).getByText('Hostname mismatch')).toBeInTheDocument();
    expect(within(old).getByText('Not trusted')).toBeInTheDocument();
    expect(within(old).getByText('certificate has expired')).toBeInTheDocument();

    const soon = within(c).getByRole('region', { name: 'soon.example.com' });
    const soonExpiry = within(soon).getByTestId('cert-expiry');
    expect(soonExpiry).toHaveTextContent('12 days left');
    expect(soonExpiry.className).toContain('amber');
  });

  it('shows an empty state when no certificate was collected', async () => {
    stubPage({});
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card('TLS certificates');
    expect(await within(c).findByText('No certificates collected yet')).toBeInTheDocument();
    expect(within(c).getByRole('link', { name: 'Settings → Scan profiles' })).toHaveAttribute(
      'href',
      '/settings?tab=profiles',
    );
  });
});

describe('Domain page: HTTP', () => {
  it('shows status, redirects, missing HSTS, header table and disclosed software', async () => {
    stubPage({ http: [http()] });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card('HTTP');
    const heading = await within(c).findByRole('heading', { level: 3 });
    expect(heading).toHaveTextContent('http://example.com/ → https://www.example.com/');
    expect(within(c).getByText('2 redirects')).toBeInTheDocument();
    expect(within(c).getByText('HSTS missing')).toBeInTheDocument();

    const table = within(c).getByRole('table', { name: 'Security headers of http://example.com/' });
    const row = (name: string) => within(table).getByRole('rowheader', { name }).closest('tr')!;
    expect(within(row('content-security-policy')).getByText("default-src 'self'")).toBeVisible();
    expect(within(row('x-content-type-options')).getByText('nosniff')).toBeVisible();
    expect(within(row('strict-transport-security')).getByText('Missing')).toBeVisible();
    expect(within(row('permissions-policy')).getByText('Missing')).toBeVisible();

    expect(within(c).getByText('Disclosed software (not verified)')).toBeInTheDocument();
    expect(within(c).getByText('nginx/1.18.0')).toBeInTheDocument();
    expect(within(c).getByText('PHP/7.4.3')).toBeInTheDocument();
  });

  it('shows a refused redirect hop as not followed', async () => {
    stubPage({
      http: [
        http({
          url: 'https://example.com/',
          finalUrl: 'https://example.com/',
          redirectCount: 0,
          statusCode: 302,
          hstsEnabled: true,
          evidence: {
            securityHeaders: { 'strict-transport-security': 'max-age=31536000' },
            hops: [
              {
                url: 'https://example.com/',
                ip: '93.184.215.14',
                status: 302,
                decision: 'followed',
              },
              {
                url: 'https://login.other.test/',
                ip: null,
                status: null,
                decision: 'redirect_out_of_scope',
              },
            ],
          },
        }),
      ],
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card('HTTP');
    const hops = await within(c).findByRole('list', { name: 'Requests for https://example.com/' });
    const items = within(hops).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[1]).toHaveTextContent('https://login.other.test/');
    expect(items[1]).toHaveTextContent('redirect_out_of_scope — not followed');
    expect(within(c).getByText('HSTS enabled')).toBeInTheDocument();
    expect(within(c).queryByText('Disclosed software (not verified)')).not.toBeInTheDocument();
  });

  it('shows an empty state when no HTTP response was collected', async () => {
    stubPage({});
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card('HTTP');
    expect(await within(c).findByText('No HTTP responses collected yet')).toBeInTheDocument();
    expect(within(c).getByRole('link', { name: 'Settings → Scan profiles' })).toHaveAttribute(
      'href',
      '/settings?tab=profiles',
    );
  });
});

describe('Domain page: ports', () => {
  it('groups ports by address and explains the approved-network rule', async () => {
    stubPage({
      ports: [
        port({ port: 22, service: 'ssh', evidence: { product: 'OpenSSH', version: '9.6' } }),
        port({ ipAddress: '203.0.113.20', port: 80, state: 'closed', service: null }),
        port(),
      ],
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card('Ports');
    const first = await within(c).findByRole('table', { name: '203.0.113.10' });
    expect(
      within(first)
        .getAllByRole('rowheader')
        .map((h) => h.textContent),
    ).toEqual(['22/tcp', '443/tcp']);
    expect(within(first).getByText('OpenSSH 9.6 (not verified)')).toBeInTheDocument();
    const second = within(c).getByRole('table', { name: '203.0.113.20' });
    expect(within(second).getByText('closed')).toBeInTheDocument();
    expect(within(c).getByText(/only on addresses inside networks an administrator/)).toBeVisible();
  });

  it('shows an empty state with the explanation when nothing was probed', async () => {
    stubPage({});
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card('Ports');
    expect(await within(c).findByText('No ports probed')).toBeInTheDocument();
    expect(within(c).getByText(/approved in Settings/)).toBeInTheDocument();
  });
});

describe('Domain page layout and scan tiers', () => {
  it('orders the cards by usefulness: findings and software first, raw observations last', async () => {
    stubPage({});
    renderAt(`/domains/${DOMAIN_ID}`);
    await card('Ports');
    const names = screen
      .getAllByRole('region')
      .map((r) => r.getAttribute('aria-label'))
      .filter((n): n is string => n !== null);
    expect(names).toEqual([
      'Findings',
      'Software',
      'Assets',
      'Scans',
      'Ownership verification',
      'Ownership and monitoring',
      'Registration',
      'Ports',
      'DNS records',
      'TLS certificates',
      'HTTP',
    ]);
  });

  it('describes the tier rule when an active profile is selected', async () => {
    stubPage({}, { activeScanningEnabled: true });
    renderAt(`/domains/${DOMAIN_ID}`);
    const scans = await card('Scans');
    const select = await within(scans).findByRole('combobox');
    expect(within(scans).queryByTestId('tier-note')).not.toBeInTheDocument();
    expect(within(scans).getByRole('option', { name: 'Standard' })).toBeEnabled();
    await userEvent.selectOptions(select, 'standard');
    expect(within(scans).getByTestId('tier-note')).toHaveTextContent(
      /like a normal visitor.*only on approved networks/,
    );
  });
});

describe('Domain page: collapsible cards', () => {
  // A first visit: no remembered choices.
  beforeEach(() => window.localStorage.clear());

  const header = async (title: string) =>
    within(await card(title)).getByRole('button', { name: new RegExp(`^${title}`) });

  const threeCerts = {
    tls: [
      tls(),
      tls({ hostname: 'www.example.com' }),
      tls({
        hostname: 'mail.example.com',
        subject: 'CN=mail.example.com',
        notAfter: new Date(Date.now() + 10.5 * DAY_MS).toISOString(),
      }),
    ],
  };

  it('starts detail cards collapsed with a summary, and the key cards open', async () => {
    stubPage(threeCerts);
    renderAt(`/domains/${DOMAIN_ID}`);
    const tlsHeader = await header('TLS certificates');
    expect(tlsHeader).toHaveAttribute('aria-expanded', 'false');
    expect(await within(tlsHeader).findByText('3 certificates · 1 expiring soon')).toBeVisible();
    expect(
      within(await card('TLS certificates')).getByText('CN=mail.example.com'),
    ).not.toBeVisible();

    for (const title of ['Findings', 'Software', 'Assets']) {
      expect(await header(title)).toHaveAttribute('aria-expanded', 'true');
    }
    for (const title of ['Scans', 'Ownership verification', 'Ownership and monitoring']) {
      expect(await header(title)).toHaveAttribute('aria-expanded', 'false');
    }
    expect(await header('Ownership verification')).toHaveTextContent('Verified by DNS');
    expect(await header('Ownership and monitoring')).toHaveTextContent(
      'Medium · no owner set · monitoring on',
    );
    expect(await header('Scans')).toHaveTextContent('No scans yet');
  });

  it('opens on click and remembers the choice in this browser', async () => {
    stubPage(threeCerts);
    renderAt(`/domains/${DOMAIN_ID}`);
    const tlsHeader = await header('TLS certificates');
    await within(tlsHeader).findByText(/3 certificates/);
    await userEvent.click(tlsHeader);
    expect(tlsHeader).toHaveAttribute('aria-expanded', 'true');
    expect(window.localStorage.getItem('exdv.card.domain.tls')).toBe('1');
    expect(within(tlsHeader).queryByText(/3 certificates/)).not.toBeInTheDocument();
    expect(within(await card('TLS certificates')).getByText('CN=mail.example.com')).toBeVisible();

    await userEvent.click(tlsHeader);
    expect(tlsHeader).toHaveAttribute('aria-expanded', 'false');
    expect(window.localStorage.getItem('exdv.card.domain.tls')).toBe('0');
  });

  it('respects a stored choice when the page is shown again', async () => {
    window.localStorage.setItem('exdv.card.domain.tls', '1');
    window.localStorage.setItem('exdv.card.domain.findings', '0');
    stubPage(threeCerts);
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(await header('TLS certificates')).toHaveAttribute('aria-expanded', 'true');
    expect(await header('Findings')).toHaveAttribute('aria-expanded', 'false');
    // Cards without a stored choice keep their defaults.
    expect(await header('HTTP')).toHaveAttribute('aria-expanded', 'false');
    expect(await header('Software')).toHaveAttribute('aria-expanded', 'true');
  });

  it('expands and collapses every card at once', async () => {
    stubPage(threeCerts);
    renderAt(`/domains/${DOMAIN_ID}`);
    await card('HTTP');
    // The title-bar button of each card (entries inside open cards are regions too).
    const headers = () =>
      screen
        .getAllByRole('region')
        .flatMap((r) => [...r.querySelectorAll(':scope > div > h2 > button[aria-expanded]')]);
    expect(headers()).toHaveLength(11);

    await userEvent.click(screen.getByRole('button', { name: 'Expand all' }));
    for (const b of headers()) expect(b).toHaveAttribute('aria-expanded', 'true');
    expect(window.localStorage.getItem('exdv.card.domain.http')).toBe('1');

    await userEvent.click(screen.getByRole('button', { name: 'Collapse all' }));
    for (const b of headers()) expect(b).toHaveAttribute('aria-expanded', 'false');
    expect(window.localStorage.getItem('exdv.card.domain.findings')).toBe('0');
  });

  it('summarises HTTP, ports and registration while collapsed', async () => {
    stubPage({
      http: [http(), http({ url: 'https://example.com/', hstsEnabled: true })],
      ports: [
        port(),
        port({ port: 80, service: 'http' }),
        port({ ipAddress: '203.0.113.11', port: 22, service: 'ssh' }),
        port({ ipAddress: '203.0.113.11', port: 25, state: 'closed', service: null }),
      ],
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(await within(await header('HTTP')).findByText('2 URLs · HSTS on 1')).toBeVisible();
    expect(await header('Ports')).toHaveTextContent('3 open on 2 addresses');
    expect(await header('Registration')).toHaveTextContent('Not collected yet');
  });

  it('shows the first five certificates of a long list, with a control for the rest', async () => {
    window.localStorage.setItem('exdv.card.domain.tls', '1');
    stubPage({
      tls: Array.from({ length: 7 }, (_, i) => tls({ hostname: `h${i}.example.com` })),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const tlsCard = await card('TLS certificates');
    expect(await within(tlsCard).findByText('h4.example.com')).toBeInTheDocument();
    expect(within(tlsCard).queryByText('h5.example.com')).not.toBeInTheDocument();
    await userEvent.click(within(tlsCard).getByRole('button', { name: 'Show all 7 certificates' }));
    expect(within(tlsCard).getByText('h6.example.com')).toBeInTheDocument();
  });
});
