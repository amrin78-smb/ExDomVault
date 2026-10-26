// Open Ports inventory page (Milestone 13).
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ASSET_ID,
  ASSET_ID_2,
  DOMAIN_ID,
  INVENTORY_PATHS,
  attackSurface,
  portItem,
  portsPage,
} from '../../components/inventory/test-data.ts';
import { apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { domain, page } from '../findings/test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const COUNTS = { open: 2, filtered: 5, closed: 1 };

const rdp = () =>
  portItem({
    ipAddress: '198.51.100.7',
    port: 3389,
    service: 'ms-wbt-server',
    country: null,
    policyViolation: true,
    hostnames: [
      { assetId: ASSET_ID, hostname: 'a.example.com' },
      { assetId: ASSET_ID_2, hostname: 'b.example.com' },
      { assetId: crypto.randomUUID(), hostname: 'c.example.com' },
      { assetId: crypto.randomUUID(), hostname: 'd.example.com' },
      { assetId: crypto.randomUUID(), hostname: 'e.example.com' },
    ],
  });

function stubPorts(handlers: Parameters<typeof stubApi>[1] = {}) {
  return stubApi('viewer', {
    [INVENTORY_PATHS.ports()]: ok(portsPage([portItem(), rdp()], COUNTS, 2)),
    [INVENTORY_PATHS.attackSurface]: ok(attackSurface([{ port: 443, service: 'https', ips: 12 }])),
    [INVENTORY_PATHS.domains]: ok(page([domain()])),
    ...handlers,
  });
}

const rowOf = (text: string) => {
  const row = screen.getByText(text).closest('tr');
  if (!row) throw new Error(`row for ${text} missing`);
  return within(row);
};

describe('Open Ports page', () => {
  it('is reachable from the navigation (no longer a placeholder)', async () => {
    stubPorts();
    renderAt('/');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    await userEvent.click(within(nav).getByRole('link', { name: 'Open Ports' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Open Ports' })).toBeInTheDocument();
    expect(screen.queryByText(/Milestone 13/)).not.toBeInTheDocument();
    expect(screen.getByRole('note', { name: 'Where port data comes from' })).toHaveTextContent(
      'Ports are only probed on approved networks (Standard/Deep scans).',
    );
  });

  it('renders rows with country, hostname chips, domain link, policy badge and times', async () => {
    stubPorts();
    renderAt('/ports');
    await screen.findByText('192.0.2.10');

    const https = rowOf('192.0.2.10');
    expect(https.getByText('DE')).toBeInTheDocument();
    expect(https.getByText('https')).toBeInTheDocument();
    expect(https.getByRole('link', { name: 'shop.example.com' })).toHaveAttribute(
      'href',
      `/assets/${ASSET_ID}`,
    );
    expect(https.getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}`,
    );
    expect(https.getByText('No violation')).toBeInTheDocument();
    expect(https.getByText('10 days ago')).toBeInTheDocument();
    const last = https.getByText('yesterday').closest('time');
    expect(last).toHaveAttribute('title', expect.stringMatching(/UTC$/));

    const rdpRow = rowOf('198.51.100.7');
    expect(rdpRow.getByRole('link', { name: 'Not allowed by exposure policy' })).toHaveAttribute(
      'href',
      '/findings?ruleId=EXP-002&q=198.51.100.7',
    );
    expect(rdpRow.getAllByRole('link', { name: /\.example\.com$/ })).toHaveLength(3);
    await userEvent.click(rdpRow.getByRole('button', { name: '+2 more' }));
    expect(rdpRow.getAllByRole('link', { name: /\.example\.com$/ })).toHaveLength(5);
  });

  it('shows state tabs with counts from the server and switches state via the URL', async () => {
    const calls = stubPorts({
      [INVENTORY_PATHS.ports('?state=filtered')]: ok(portsPage([], COUNTS, 5)),
    });
    const router = renderAt('/ports');
    const tabs = within(await screen.findByRole('group', { name: 'Port state' }));
    await screen.findByText('192.0.2.10');
    expect(tabs.getByRole('button', { name: 'Open (2)' })).toHaveAttribute('aria-pressed', 'true');
    expect(tabs.getByRole('button', { name: 'Filtered (5)' })).toBeInTheDocument();
    expect(tabs.getByRole('button', { name: 'Closed (1)' })).toBeInTheDocument();
    expect(tabs.getByRole('button', { name: 'All (8)' })).toBeInTheDocument();

    await userEvent.click(tabs.getByRole('button', { name: 'Filtered (5)' }));
    expect(router.state.location.search).toBe('?state=filtered');
    expect(await screen.findByText('No ports match these filters')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/ports?state=filtered');
  });

  it('keeps search, port, domain and sort in the URL and sends them to the API', async () => {
    const calls = stubPorts({
      [INVENTORY_PATHS.ports('?q=shop')]: ok(portsPage([portItem()])),
      [INVENTORY_PATHS.ports('?port=443&q=shop')]: ok(portsPage([portItem()])),
      [INVENTORY_PATHS.ports(`?port=443&domainId=${DOMAIN_ID}&q=shop`)]: ok(
        portsPage([portItem()]),
      ),
      [INVENTORY_PATHS.ports(`?port=443&domainId=${DOMAIN_ID}&q=shop&sort=last_observed`)]: ok(
        portsPage([portItem()]),
      ),
    });
    const router = renderAt('/ports');
    await screen.findByText('198.51.100.7');
    await userEvent.type(screen.getByLabelText('Search ports'), 'shop');
    await userEvent.click(screen.getByRole('button', { name: 'Search' }));
    await userEvent.type(screen.getByLabelText('Port'), '443{Enter}');
    await userEvent.selectOptions(await screen.findByLabelText('Domain'), DOMAIN_ID);
    await userEvent.selectOptions(screen.getByLabelText('Sort by'), 'last_observed');
    expect(router.state.location.search).toBe(
      `?q=shop&port=443&domainId=${DOMAIN_ID}&sort=last_observed`,
    );
    await screen.findByText('192.0.2.10');
    expect(calls.map((c) => c.path)).toContain(
      `/api/v1/ports?port=443&domainId=${DOMAIN_ID}&q=shop&sort=last_observed`,
    );
  });

  it('filters by a top service from the summary strip', async () => {
    stubPorts({ [INVENTORY_PATHS.ports('?port=443')]: ok(portsPage([portItem()])) });
    const router = renderAt('/ports');
    const strip = within(await screen.findByRole('region', { name: /Most exposed services/ }));
    await userEvent.click(strip.getByRole('button', { name: /Filter port 443 \(https\): 12/ }));
    expect(router.state.location.search).toBe('?port=443');
  });

  it('paginates through the URL', async () => {
    const calls = stubPorts({
      [INVENTORY_PATHS.ports()]: ok(portsPage([portItem()], { ...COUNTS, open: 30 }, 30)),
      [INVENTORY_PATHS.ports('?page=2')]: ok({
        ...portsPage([rdp()], { ...COUNTS, open: 30 }, 30),
        page: 2,
      }),
    });
    const router = renderAt('/ports');
    expect(await screen.findByText('1–25 of 30')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(router.state.location.search).toBe('?page=2');
    expect(await screen.findByText('26–30 of 30')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/ports?page=2');
  });

  it('explains how to get port data when nothing is observed', async () => {
    stubPorts({
      [INVENTORY_PATHS.ports()]: ok(portsPage([], { open: 0, filtered: 0, closed: 0 })),
      [INVENTORY_PATHS.attackSurface]: ok(attackSurface()),
    });
    renderAt('/ports');
    expect(await screen.findByText('No open ports observed')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Settings → Workers and networks' })).toHaveAttribute(
      'href',
      '/settings',
    );
    expect(screen.queryByRole('region', { name: /Most exposed services/ })).not.toBeInTheDocument();
  });

  it('shows the error with a working Retry', async () => {
    let fail = true;
    stubPorts({
      [INVENTORY_PATHS.ports()]: () =>
        fail
          ? apiError(500, 'internal_error', 'Something went wrong')()
          : ok(portsPage([portItem()]))(),
    });
    renderAt('/ports');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load ports');
    fail = false;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('192.0.2.10')).toBeInTheDocument();
  });
});
