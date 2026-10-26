// Subdomains page: subdomain-only API query, URL filters, grouped view, paging, banner, states.
import type { Role } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ASSET_PATHS,
  apiError,
  ok,
  renderAt,
  stubApi,
  type Handler,
} from '../../testing/stub-api.tsx';
import { CLOUDFRONT, DOMAIN_ID, asset, page } from '../assets/test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const OTHER_DOMAIN = { id: '1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f', fqdn: 'example.net' };
const LIST = (q = '') => ASSET_PATHS.list(`?assetType=subdomain${q}`);
const PENDING = (domain = '') =>
  ASSET_PATHS.list(`?assetType=subdomain&status=pending&pageSize=1${domain}`);
const DOMAINS = 'GET /api/v1/domains?pageSize=100';
const domainRow = (id: string, fqdn: string) => ({
  id,
  fqdn,
  unicodeFqdn: fqdn,
  warnings: [],
  registrar: null,
  registeredAt: null,
  expiresAt: null,
  registrationDataStatus: 'unknown',
  criticality: 'medium',
  businessOwner: null,
  verificationStatus: 'verified',
  verifiedAt: '2026-10-20T00:00:00.000Z',
  verificationMethod: 'dns_txt',
  verificationExpiresAt: null,
  monitoringEnabled: true,
  createdAt: '2026-10-20T00:00:00.000Z',
  updatedAt: '2026-10-20T00:00:00.000Z',
});

const ROWS = [
  asset({ role: 'web', status: 'approved', source: 'certificate_transparency' }),
  asset({
    id: '4f5a6b7c-8d9e-4f0a-9b1c-2d3e4f5a6b7c',
    hostname: 'cdn.example.com',
    hostingHint: CLOUDFRONT,
    source: 'dns',
    currentIps: [],
  }),
  asset({
    id: '5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d',
    hostname: 'mail.example.net',
    domain: OTHER_DOMAIN,
    source: 'import',
    role: 'mail',
  }),
];

function stub(role: Role = 'viewer', handlers: Record<string, Handler> = {}) {
  return stubApi(role, {
    [DOMAINS]: ok(
      page([domainRow(DOMAIN_ID, 'example.com'), domainRow(OTHER_DOMAIN.id, OTHER_DOMAIN.fqdn)]),
    ),
    [LIST()]: ok(page(ROWS)),
    [PENDING()]: ok(page([], 2)),
    ...handlers,
  });
}

describe('Subdomains page', () => {
  it('lists only subdomains with source, status, role, IPs and hosting', async () => {
    const calls = stub();
    renderAt('/subdomains');
    const table = await screen.findByRole('table');
    expect(calls.map((c) => c.path)).toContain('/api/v1/assets?assetType=subdomain');
    const rows = within(table).getAllByRole('row');
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((h) => h.textContent),
    ).toEqual([
      'Hostname',
      'Domain',
      'Source',
      'Status',
      'Role',
      'Current IPs',
      'Hosting',
      'First seen',
      'Last seen',
    ]);
    const first = within(rows[1]!);
    expect(first.getByRole('link', { name: 'shop.example.com' })).toHaveAttribute(
      'href',
      `/assets/${ROWS[0]!.id}`,
    );
    expect(first.getByText('CT logs')).toBeInTheDocument();
    expect(first.getByText('Approved')).toBeInTheDocument();
    expect(first.getByText('Web server')).toBeInTheDocument();
    expect(first.getByText('192.0.2.10')).toBeInTheDocument();
    expect(within(rows[2]!).getByText('DNS')).toBeInTheDocument();
    expect(within(rows[2]!).getByText('Amazon CloudFront')).toBeInTheDocument();
    expect(within(rows[2]!).getByText('None resolved')).toBeInTheDocument();
    expect(within(rows[3]!).getByText('Import')).toBeInTheDocument();
  });

  it('keeps filters in the URL and always asks for subdomains', async () => {
    const calls = stub('viewer', {
      [LIST(
        `&status=pending&domainId=${DOMAIN_ID}&source=certificate_transparency&role=web&q=shop`,
      )]: ok(page([ROWS[0]!])),
      [PENDING(`&domainId=${DOMAIN_ID}`)]: ok(page([], 0)),
    });
    const router = renderAt('/subdomains');
    await screen.findByRole('table');
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'pending');
    await userEvent.selectOptions(await screen.findByLabelText('Domain'), DOMAIN_ID);
    await userEvent.selectOptions(screen.getByLabelText('Source'), 'certificate_transparency');
    await userEvent.selectOptions(screen.getByLabelText('Role'), 'web');
    await userEvent.type(screen.getByLabelText('Search subdomains'), 'shop{Enter}');
    expect(Object.fromEntries(new URLSearchParams(router.state.location.search))).toEqual({
      status: 'pending',
      domainId: DOMAIN_ID,
      source: 'certificate_transparency',
      role: 'web',
      q: 'shop',
    });
    await screen.findByText('Search: shop');
    expect(calls.filter((c) => c.path.includes('pageSize=1') === false).at(-1)?.path).toBe(
      `/api/v1/assets?assetType=subdomain&status=pending&domainId=${DOMAIN_ID}&source=certificate_transparency&role=web&q=shop`,
    );
    expect(
      calls.every(
        (c) => !c.path.startsWith('/api/v1/assets') || c.path.includes('assetType=subdomain'),
      ),
    ).toBe(true);
  });

  it('groups by domain with collapsible groups and counts', async () => {
    stub();
    const router = renderAt('/subdomains');
    await screen.findByRole('table');
    await userEvent.click(screen.getByRole('button', { name: 'By domain' }));
    expect(router.state.location.search).toBe('?view=grouped');
    const com = await screen.findByRole('region', { name: 'example.com' });
    const net = screen.getByRole('region', { name: 'example.net' });
    expect(within(com).getByText('2 on this page')).toBeInTheDocument();
    expect(within(net).getByText('1 on this page')).toBeInTheDocument();
    expect(within(com).queryByRole('columnheader', { name: 'Domain' })).not.toBeInTheDocument();
    const toggle = within(com).getByRole('button', { name: /example\.com/ });
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(within(com).queryByRole('link', { name: 'shop.example.com' })).not.toBeInTheDocument();
    expect(within(net).getByRole('link', { name: 'mail.example.net' })).toBeInTheDocument();
  });

  it('pages through results', async () => {
    const calls = stub('viewer', {
      [LIST()]: ok(page(ROWS, 60)),
      [LIST('&page=2')]: ok({ ...page([ROWS[2]!], 60, 2) }),
    });
    const router = renderAt('/subdomains');
    await screen.findByText('1–25 of 60');
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(router.state.location.search).toBe('?page=2');
    expect(await screen.findByText('26–50 of 60')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/assets?assetType=subdomain&page=2');
  });

  it('links the pending banner to the review queue', async () => {
    stub();
    renderAt('/subdomains');
    const banner = await screen.findByText(/2 discovered subdomains are waiting for review/);
    expect(
      within(banner.parentElement!).getByRole('link', { name: 'Review pending' }),
    ).toHaveAttribute('href', '/assets?status=pending');
  });

  it('offers Import hosts for a selected domain only to domain writers', async () => {
    stub('admin', {
      [LIST(`&domainId=${DOMAIN_ID}`)]: ok(page([ROWS[0]!])),
      [PENDING(`&domainId=${DOMAIN_ID}`)]: ok(page([], 0)),
    });
    renderAt(`/subdomains?domainId=${DOMAIN_ID}`);
    expect(await screen.findByRole('link', { name: 'Import hosts' })).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}/import-hosts`,
    );
    expect(screen.getByRole('button', { name: /Export subdomains/ })).toBeInTheDocument();
  });

  it('hides Import hosts from viewers', async () => {
    stub('viewer', {
      [LIST(`&domainId=${DOMAIN_ID}`)]: ok(page([ROWS[0]!])),
      [PENDING(`&domainId=${DOMAIN_ID}`)]: ok(page([], 0)),
    });
    renderAt(`/subdomains?domainId=${DOMAIN_ID}`);
    await screen.findByRole('table');
    expect(screen.queryByRole('link', { name: 'Import hosts' })).not.toBeInTheDocument();
  });

  it('shows empty states (unfiltered and filtered) and errors', async () => {
    stub('viewer', { [LIST()]: ok(page([])), [LIST('&q=zzz')]: ok(page([])) });
    const router = renderAt('/subdomains');
    expect(await screen.findByText('No subdomains yet')).toBeInTheDocument();
    await router.navigate('/subdomains?q=zzz');
    expect(await screen.findByText('No subdomains match these filters')).toBeInTheDocument();
    vi.unstubAllGlobals();
    stub('viewer', { [LIST()]: apiError(500, 'internal_error', 'Boom.') });
    await router.navigate('/subdomains');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load subdomains');
  });
});
