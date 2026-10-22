import type {
  DnsRecordSet,
  Domain,
  DomainObservationsResponse,
  RegistrationSnapshot,
} from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { formatDateTime } from '../../lib/format.ts';
import { ok, renderAt, stubApi, type Handler } from '../../testing/stub-api.tsx';

const DOMAIN_ID = '0b8e3f9a-4c1d-4e5f-8a7b-1c2d3e4f5a6b';
const JOB_ID = '7d1f8c2e-3b4a-4c5d-9e6f-0a1b2c3d4e5f';
const OBS_PATH = `GET /api/v1/domains/${DOMAIN_ID}/observations`;
const DAY_MS = 86_400_000;

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
  verificationStatus: 'unverified',
  verifiedAt: null,
  verificationMethod: null,
  verificationExpiresAt: null,
  monitoringEnabled: true,
  createdAt: '2026-10-22T10:00:00.000Z',
  updatedAt: '2026-10-22T10:00:00.000Z',
  ...overrides,
});

const snapshot = (overrides: Partial<RegistrationSnapshot> = {}): RegistrationSnapshot => ({
  registrar: 'Example Registrar, Inc.',
  registeredAt: '2001-03-04T00:00:00.000Z',
  expiresAt: new Date(Date.now() + 10.5 * DAY_MS).toISOString(),
  nameservers: ['ns1.example.net', 'ns2.example.net'],
  dataStatus: 'available',
  resultStatus: 'success',
  observedAt: '2026-10-22T09:00:00.000Z',
  scanJobId: JOB_ID,
  ...overrides,
});

const record = (overrides: Partial<DnsRecordSet> = {}): DnsRecordSet => ({
  hostname: 'example.com',
  recordType: 'A',
  ttl: 300,
  values: ['192.0.2.10'],
  resultStatus: 'success',
  observedAt: '2026-10-22T09:00:00.000Z',
  scanJobId: JOB_ID,
  ...overrides,
});

function stubPage(
  observations: Handler | DomainObservationsResponse,
  domainOverrides: Partial<Domain> = {},
) {
  return stubApi('viewer', {
    [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({
      domain: domain(domainOverrides),
      verification: null,
    }),
    'GET /api/v1/scan-profiles': ok({ activeScanningEnabled: false, items: [] }),
    [`GET /api/v1/scans?domainId=${DOMAIN_ID}&pageSize=5`]: ok({
      items: [],
      page: 1,
      pageSize: 5,
      total: 0,
    }),
    [OBS_PATH]: typeof observations === 'function' ? observations : ok(observations),
  });
}

const registrationCard = () => screen.findByRole('region', { name: 'Registration' });
const dnsCard = () => screen.findByRole('region', { name: 'DNS records' });

afterEach(() => vi.unstubAllGlobals());

describe('Domain registration observations', () => {
  it('shows the latest registration snapshot with an expiry countdown', async () => {
    stubPage({ dns: [], registration: snapshot() });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await registrationCard();
    expect(await within(card).findByText('Example Registrar, Inc.')).toBeInTheDocument();
    expect(within(card).getByText('ns1.example.net')).toBeInTheDocument();
    expect(within(card).getByText('ns2.example.net')).toBeInTheDocument();
    const countdown = within(card).getByTestId('expiry-countdown');
    expect(countdown).toHaveTextContent('in 10 days');
    expect(countdown.className).toContain('amber');
    expect(
      within(card).getByRole('link', { name: formatDateTime('2026-10-22T09:00:00.000Z') }),
    ).toHaveAttribute('href', `/scans/${JOB_ID}`);
  });

  it('marks an expired registration and leaves distant expiry neutral', async () => {
    stubPage({
      dns: [],
      registration: snapshot({ expiresAt: new Date(Date.now() - 3.5 * DAY_MS).toISOString() }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await registrationCard();
    const countdown = await within(card).findByTestId('expiry-countdown');
    expect(countdown).toHaveTextContent('expired 4 days ago');
    expect(countdown.className).toContain('red');
  });

  it('explains redacted registration data', async () => {
    stubPage({
      dns: [],
      registration: snapshot({
        dataStatus: 'redacted',
        registrar: null,
        registeredAt: null,
        expiresAt: null,
        nameservers: [],
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await registrationCard();
    expect(
      await within(card).findByText('The registry withholds registration details for privacy.'),
    ).toBeInTheDocument();
    expect(within(card).queryByText('Registrar')).not.toBeInTheDocument();
  });

  it('explains unavailable registration data', async () => {
    stubPage({
      dns: [],
      registration: snapshot({
        dataStatus: 'unavailable',
        resultStatus: 'timeout',
        registrar: null,
        registeredAt: null,
        expiresAt: null,
        nameservers: [],
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await registrationCard();
    expect(
      await within(card).findByText('No registration data could be obtained.'),
    ).toBeInTheDocument();
    expect(within(card).getByText('RDAP lookup timed out.')).toBeInTheDocument();
  });

  it('falls back to the domain fields when nothing has been observed', async () => {
    stubPage({ dns: [], registration: null });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await registrationCard();
    expect(await within(card).findByText(/Not collected yet/)).toHaveTextContent(
      /passive scan.*daily/,
    );
  });

  it('uses available domain fields when there is no observation', async () => {
    stubPage(
      { dns: [], registration: null },
      {
        registrationDataStatus: 'available',
        registrar: 'Domain Registrar Ltd',
        expiresAt: '2099-01-01T00:00:00.000Z',
      },
    );
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await registrationCard();
    expect(await within(card).findByText('Domain Registrar Ltd')).toBeInTheDocument();
    expect(within(card).getByTestId('expiry-countdown').className).not.toMatch(/amber|red/);
  });
});

describe('Domain DNS observations', () => {
  it('groups records by hostname, apex first, types in a stable order', async () => {
    stubPage({
      dns: [
        record({
          hostname: '_dmarc.example.com',
          recordType: 'TXT',
          values: ['v=DMARC1; p=reject'],
          observedAt: '2026-10-22T09:05:00.000Z',
        }),
        record({ recordType: 'MX', values: ['10 mx1.example.net.', '20 mx2.example.net.'] }),
        record({ recordType: 'A' }),
        record({ recordType: 'AAAA', values: [] }),
        record({ recordType: 'CAA', values: [], ttl: null, resultStatus: 'timeout' }),
      ],
      registration: null,
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await dnsCard();
    const headings = await within(card).findAllByRole('heading', { level: 3 });
    expect(headings.map((h) => h.textContent)).toEqual(['example.com', '_dmarc.example.com']);

    const apex = within(card).getByRole('table', { name: 'example.com' });
    const rowHeaders = within(apex)
      .getAllByRole('rowheader')
      .map((h) => h.textContent);
    expect(rowHeaders).toEqual(['A', 'AAAA', 'MX', 'CAA']);

    const mxRow = within(apex).getByRole('rowheader', { name: 'MX' }).closest('tr')!;
    expect(
      within(mxRow)
        .getAllByRole('listitem')
        .map((li) => li.textContent),
    ).toEqual(['10 mx1.example.net.', '20 mx2.example.net.']);
    const aaaaRow = within(apex).getByRole('rowheader', { name: 'AAAA' }).closest('tr')!;
    expect(within(aaaaRow).getByText('No records')).toBeInTheDocument();
    const caaRow = within(apex).getByRole('rowheader', { name: 'CAA' }).closest('tr')!;
    expect(within(caaRow).getByText('lookup timed out')).toBeInTheDocument();
    expect(within(caaRow).queryByText('No records')).not.toBeInTheDocument();

    const dmarc = within(card).getByRole('table', { name: '_dmarc.example.com' });
    expect(within(dmarc).getByText('v=DMARC1; p=reject')).toBeInTheDocument();

    expect(within(card).getByText(/Most recent observation/)).toHaveTextContent(
      formatDateTime('2026-10-22T09:05:00.000Z'),
    );
  });

  it('explains how to collect DNS data when nothing has been observed', async () => {
    stubPage({ dns: [], registration: null });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await dnsCard();
    expect(await within(card).findByText('No DNS records collected yet')).toBeInTheDocument();
    expect(within(card).getByText(/passive scan.*Scans card/)).toBeInTheDocument();
  });

  it('shows an alert when observations fail but still renders the domain page', async () => {
    stubPage(() => ({
      status: 500,
      body: {
        error: { code: 'internal_error', message: 'Something went wrong.', requestId: 'req-9' },
      },
    }));
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(await screen.findByRole('heading', { level: 1, name: 'example.com' })).toBeVisible();
    const alerts = await screen.findAllByRole('alert');
    expect(alerts.map((a) => a.textContent).join(' ')).toMatch(/Could not load DNS records/);
    expect(alerts[0]).toHaveTextContent('Request ID: req-9');
    expect(screen.getByRole('region', { name: 'Scans' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Ownership verification' })).toBeInTheDocument();
  });
});
