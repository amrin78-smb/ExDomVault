// Certificates inventory page (Milestone 13).
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DaysLeftPill } from '../../components/inventory/CertificateBadges.tsx';
import { daysLeftTone } from '../../components/inventory/format.ts';
import {
  ASSET_ID,
  DOMAIN_ID,
  INVENTORY_PATHS,
  certCounts,
  certificateItem,
  certificatesPage,
} from '../../components/inventory/test-data.ts';
import { apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { domain, page } from '../findings/test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const COUNTS = certCounts({ expired: 1, expiring: 4, mismatch: 2, untrusted: 0, valid: 10 });

const expired = () =>
  certificateItem({
    hostname: 'old.example.com',
    assetId: null,
    issuer: 'Legacy Test CA',
    notAfter: '2026-10-21T00:00:00.000Z',
    daysLeft: -5,
    status: 'expired',
    ipAddress: '2001:db8::7',
    port: 8443,
  });

function stubCerts(handlers: Parameters<typeof stubApi>[1] = {}) {
  return stubApi('viewer', {
    [INVENTORY_PATHS.certificates()]: ok(
      certificatesPage([expired(), certificateItem()], COUNTS, 17),
    ),
    [INVENTORY_PATHS.domains]: ok(page([domain()])),
    ...handlers,
  });
}

const rowOf = (text: string) => {
  const row = screen.getByText(text).closest('tr');
  if (!row) throw new Error(`row for ${text} missing`);
  return within(row);
};

describe('days-left pill', () => {
  it.each([
    [-3, 'red', 'Expired 3 days ago'],
    [-1, 'red', 'Expired 1 day ago'],
    [0, 'red', 'Expires today'],
    [7, 'red', '7 days left'],
    [8, 'amber', '8 days left'],
    [14, 'amber', '14 days left'],
    [15, 'blue', '15 days left'],
    [30, 'blue', '30 days left'],
    [31, 'neutral', '31 days left'],
  ] as const)('%i days → %s "%s"', (days, tone, text) => {
    expect(daysLeftTone(days)).toBe(tone);
    render(<DaysLeftPill daysLeft={days} />);
    expect(screen.getByText(text)).toHaveAttribute('data-tone', tone);
  });

  it('says unknown when there is no expiry date', () => {
    render(<DaysLeftPill daysLeft={null} />);
    expect(screen.getByText('Unknown')).toBeInTheDocument();
  });
});

describe('Certificates page', () => {
  it('is reachable from the navigation (no longer a placeholder)', async () => {
    stubCerts();
    renderAt('/');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    await userEvent.click(within(nav).getByRole('link', { name: 'Certificates' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Certificates' })).toBeInTheDocument();
    expect(screen.queryByText(/Milestone 13/)).not.toBeInTheDocument();
  });

  it('renders hostname, domain, issuer, validity, days left, status, protocol and address', async () => {
    stubCerts();
    renderAt('/certificates');
    await screen.findByText('old.example.com');

    const valid = rowOf('shop.example.com');
    expect(valid.getByRole('link', { name: 'shop.example.com' })).toHaveAttribute(
      'href',
      `/assets/${ASSET_ID}`,
    );
    expect(valid.getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}`,
    );
    expect(valid.getByText('Example Test CA')).toBeInTheDocument();
    expect(valid.getByText(/Aug 1, 2026 – Dec 30, 2026/)).toBeInTheDocument();
    expect(valid.getByText('60 days left')).toBeInTheDocument();
    expect(valid.getByText('Valid')).toBeInTheDocument();
    expect(valid.getByText('TLSv1.3')).toBeInTheDocument();
    expect(valid.getByText('192.0.2.10:443')).toBeInTheDocument();

    const old = rowOf('old.example.com');
    // No asset: plain text, not a link.
    expect(old.queryByRole('link', { name: 'old.example.com' })).not.toBeInTheDocument();
    expect(old.getByText('Expired 5 days ago')).toBeInTheDocument();
    expect(old.getByText('Expired')).toBeInTheDocument();
    expect(old.getByText('[2001:db8::7]:8443')).toBeInTheDocument();
  });

  it('expands a row to show subject, SANs, hostname match and chain trust', async () => {
    stubCerts();
    renderAt('/certificates');
    const toggle = await screen.findByRole('button', {
      name: 'Show certificate details for shop.example.com:443',
    });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByText('CN=shop.example.com')).not.toBeInTheDocument();
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('CN=shop.example.com')).toBeVisible();
    expect(screen.getByText('www.shop.example.com')).toBeInTheDocument();
    expect(screen.getByText('Matches')).toBeInTheDocument();
    expect(screen.getByText('Trusted')).toBeInTheDocument();
    await userEvent.click(toggle);
    expect(screen.queryByText('CN=shop.example.com')).not.toBeInTheDocument();
  });

  it('shows status tabs with server counts and filters by status through the URL', async () => {
    const calls = stubCerts({
      [INVENTORY_PATHS.certificates('?status=expiring')]: ok(
        certificatesPage([certificateItem({ daysLeft: 12, status: 'expiring' })], COUNTS, 4),
      ),
    });
    const router = renderAt('/certificates');
    const tabs = within(await screen.findByRole('group', { name: 'Certificate status' }));
    await screen.findByText('old.example.com');
    expect(tabs.getByRole('button', { name: 'All (17)' })).toHaveAttribute('aria-pressed', 'true');
    expect(tabs.getByRole('button', { name: 'Expired (1)' })).toBeInTheDocument();
    expect(tabs.getByRole('button', { name: 'Mismatch (2)' })).toBeInTheDocument();
    expect(tabs.getByRole('button', { name: 'Untrusted (0)' })).toBeInTheDocument();
    expect(tabs.getByRole('button', { name: 'Valid (10)' })).toBeInTheDocument();

    await userEvent.click(tabs.getByRole('button', { name: 'Expiring ≤30 days (4)' }));
    expect(router.state.location.search).toBe('?status=expiring');
    expect(await screen.findByText('12 days left')).toHaveAttribute('data-tone', 'amber');
    expect(calls.map((c) => c.path)).toContain('/api/v1/certificates?status=expiring');
  });

  it('keeps search, domain and sort in the URL and sends them to the API', async () => {
    const calls = stubCerts({
      [INVENTORY_PATHS.certificates('?q=legacy')]: ok(certificatesPage([expired()], COUNTS)),
      [INVENTORY_PATHS.certificates(`?domainId=${DOMAIN_ID}&q=legacy`)]: ok(
        certificatesPage([expired()], COUNTS),
      ),
      [INVENTORY_PATHS.certificates(`?domainId=${DOMAIN_ID}&q=legacy&sort=hostname`)]: ok(
        certificatesPage([], certCounts()),
      ),
    });
    const router = renderAt('/certificates');
    await screen.findByText('shop.example.com');
    await userEvent.type(screen.getByLabelText('Search certificates'), 'legacy');
    await userEvent.click(screen.getByRole('button', { name: 'Search' }));
    await userEvent.selectOptions(await screen.findByLabelText('Domain'), DOMAIN_ID);
    await userEvent.selectOptions(screen.getByLabelText('Sort by'), 'hostname');
    expect(router.state.location.search).toBe(`?q=legacy&domainId=${DOMAIN_ID}&sort=hostname`);
    expect(await screen.findByText('No certificates match these filters')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain(
      `/api/v1/certificates?domainId=${DOMAIN_ID}&q=legacy&sort=hostname`,
    );
  });

  it('paginates through the URL', async () => {
    const calls = stubCerts({
      [INVENTORY_PATHS.certificates('?page=2')]: ok({
        ...certificatesPage([certificateItem({ hostname: 'p2.example.com' })], COUNTS, 40),
        page: 2,
      }),
      [INVENTORY_PATHS.certificates()]: ok(certificatesPage([certificateItem()], COUNTS, 40)),
    });
    const router = renderAt('/certificates');
    expect(await screen.findByText('1–25 of 40')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(router.state.location.search).toBe('?page=2');
    expect(await screen.findByText('p2.example.com')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/certificates?page=2');
  });

  it('explains how certificates are collected when there are none', async () => {
    stubCerts({ [INVENTORY_PATHS.certificates()]: ok(certificatesPage([], certCounts())) });
    renderAt('/certificates');
    expect(await screen.findByText('No certificates observed yet')).toBeInTheDocument();
    expect(screen.getByText(/TLS check of a/)).toHaveTextContent(/Quick scan or higher/);
  });

  it('shows the permission-denied state on 403, not the raw error', async () => {
    stubCerts({ [INVENTORY_PATHS.certificates()]: apiError(403, 'forbidden', 'Forbidden') });
    renderAt('/certificates');
    expect(
      await screen.findByText('You do not have access to this information'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
