// The Milestone 13 shell: theme, top-bar search (command palette), notifications, organisation.
import type { OpsAlertsResponse, SearchResponse } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PERMISSIONS, apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { THEME_STORAGE_KEY, initTheme } from '../../lib/theme.ts';
import { NO_CATEGORIES } from '../../pages/findings/test-data.ts';

const DOMAIN = { id: '0b8c7c3e-4a51-4d0e-9d55-1d2c3b4a5f60', fqdn: 'example.com' };
const ASSET_ID = '5f0e2d1c-3b4a-4c5d-8e6f-7a8b9c0d1e2f';
const FINDING_ID = '9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d';

const RESULTS: SearchResponse = {
  q: 'exa',
  domains: [DOMAIN],
  assets: [{ id: ASSET_ID, hostname: 'www.example.com', domain: DOMAIN }],
  ips: [{ ipAddress: '203.0.113.10', assets: [{ id: ASSET_ID, hostname: 'www.example.com' }] }],
  ports: [{ ipAddress: '203.0.113.10', port: 443, service: 'https', hostname: 'www.example.com' }],
  software: [
    {
      product: 'nginx',
      productLabel: 'nginx',
      version: '1.18.0',
      hostname: 'www.example.com',
      domain: DOMAIN,
    },
  ],
  vulnerabilities: [{ cve: 'CVE-2024-38475', kev: true, affectedHosts: 2 }],
  findings: [
    { id: FINDING_ID, title: 'Certificate expires soon', severity: 'critical', domain: DOMAIN },
  ],
};

const searchPath = (q: string) => `GET /api/v1/search?q=${encodeURIComponent(q)}`;

const ALERTS: OpsAlertsResponse['alerts'] = [
  { kind: 'worker_outage', severity: 'critical', message: 'Down.', since: null },
  { kind: 'active_scanning_disabled', severity: 'info', message: 'Passive only.', since: null },
];

const summary = (critical: number) => ({
  bySeverity: { critical, high: 4, medium: 0, low: 0, informational: 0 },
  total: critical + 4,
  byCategory: NO_CATEGORIES,
});

const me = (organisation?: string | null) =>
  ok({
    user: {
      id: crypto.randomUUID(),
      email: 'analyst@example.com',
      displayName: 'Ana Lyst',
      role: 'analyst',
    },
    permissions: PERMISSIONS.analyst,
    authProvider: 'cloudflare_access',
    ...(organisation === undefined ? {} : { organisation }),
  });

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  document.documentElement.classList.remove('dark');
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Theme', () => {
  it('defaults to dark before the first render', () => {
    initTheme();
    expect(document.documentElement).toHaveClass('dark');
  });

  it('applies a remembered light choice', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light');
    initTheme();
    expect(document.documentElement).not.toHaveClass('dark');
  });

  it('falls back to dark when storage is blocked', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    initTheme();
    expect(document.documentElement).toHaveClass('dark');
  });

  it('switches from the user menu and remembers the choice', async () => {
    initTheme();
    stubApi('analyst', { 'GET /api/v1/me': me() });
    renderAt('/');
    await userEvent.click(await screen.findByRole('button', { name: /Account menu/ }));
    await userEvent.click(screen.getByRole('menuitem', { name: /Theme: Dark/ }));
    expect(document.documentElement).not.toHaveClass('dark');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');

    await userEvent.click(screen.getByRole('menuitem', { name: /Theme: Light/ }));
    expect(document.documentElement).toHaveClass('dark');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');
  });

  it('offers Cloudflare Access sign-out in the user menu', async () => {
    stubApi('analyst', { 'GET /api/v1/me': me() });
    renderAt('/');
    await userEvent.click(await screen.findByRole('button', { name: /Account menu/ }));
    const menu = screen.getByRole('menu', { name: 'Account' });
    expect(within(menu).getByText('analyst@example.com')).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: 'Sign out' })).toHaveAttribute(
      'href',
      '/cdn-cgi/access/logout',
    );
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('menu')).toBeNull();
  });
});

describe('Command palette', () => {
  it('opens with Ctrl+K, searches after a pause, groups results and opens one with Enter', async () => {
    const calls = stubApi('analyst', { [searchPath('exa')]: ok(RESULTS) });
    const router = renderAt('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });

    await userEvent.keyboard('{Control>}k{/Control}');
    const dialog = screen.getByRole('dialog', { name: 'Search' });
    const input = within(dialog).getByRole('combobox');
    expect(input).toHaveFocus();

    await userEvent.type(input, 'e');
    // One character never searches.
    expect(within(dialog).getByText(/Type at least 2 characters/)).toBeInTheDocument();
    await userEvent.type(input, 'xa');
    const listbox = await within(dialog).findByRole('listbox');
    await within(listbox).findByRole('option', { name: /^www\.example\.com/ });
    // Debounced: only the final query reached the API.
    expect(calls.filter((c) => c.path.startsWith('/api/v1/search')).map((c) => c.path)).toEqual([
      '/api/v1/search?q=exa',
    ]);

    for (const label of [
      'Domains',
      'Subdomains / hosts',
      'IP addresses',
      'Open ports',
      'Software',
      'Vulnerabilities',
      'Findings',
    ]) {
      expect(within(listbox).getByRole('group', { name: label })).toBeInTheDocument();
    }
    expect(
      within(within(listbox).getByRole('group', { name: 'Findings' })).getByText('Critical'),
    ).toBeInTheDocument();

    // The first option is active; ArrowDown moves to the host, Enter opens it.
    const options = within(listbox).getAllByRole('option');
    expect(options[0]).toHaveAttribute('aria-selected', 'true');
    await userEvent.keyboard('{ArrowDown}');
    expect(options[1]).toHaveAttribute('aria-selected', 'true');
    expect(input).toHaveAttribute('aria-activedescendant', options[1]!.id);
    await userEvent.keyboard('{Enter}');
    expect(router.state.location.pathname).toBe(`/assets/${ASSET_ID}`);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it.each([
    ['IP addresses', /203\.0\.113\.10/, `/assets/${ASSET_ID}`, ''],
    ['Open ports', /203\.0\.113\.10:443/, '/ports', '?q=203.0.113.10'],
    ['Software', /nginx 1\.18\.0/, '/software', '?q=nginx'],
    ['Vulnerabilities', /CVE-2024-38475/, '/vulnerabilities', '?q=CVE-2024-38475'],
    ['Findings', /Certificate expires soon/, `/findings/${FINDING_ID}`, ''],
    ['Domains', /^example\.com$/, `/domains/${DOMAIN.id}`, ''],
  ])('links %s results to the right page', async (group, name, pathname, search) => {
    stubApi('analyst', { [searchPath('exa')]: ok(RESULTS) });
    const router = renderAt('/');
    await userEvent.click(screen.getByRole('button', { name: /Search domains, subdomains, IPs/ }));
    await userEvent.type(screen.getByRole('combobox'), 'exa');
    const g = await screen.findByRole('group', { name: group });
    await userEvent.click(within(g).getByRole('option', { name }));
    expect(router.state.location.pathname).toBe(pathname);
    expect(router.state.location.search).toBe(search);
  });

  it('closes with Escape and returns focus to the search box', async () => {
    stubApi('analyst', {});
    renderAt('/');
    const trigger = screen.getByRole('button', { name: /Search domains, subdomains, IPs/ });
    await userEvent.click(trigger);
    expect(screen.getByRole('dialog', { name: 'Search' })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(trigger).toHaveFocus();
  });

  it('keeps focus inside the dialog on Tab', async () => {
    stubApi('analyst', {});
    renderAt('/');
    await userEvent.keyboard('{Meta>}k{/Meta}');
    const dialog = screen.getByRole('dialog', { name: 'Search' });
    await userEvent.tab();
    expect(within(dialog).getByRole('button', { name: 'Close search' })).toHaveFocus();
    await userEvent.tab();
    expect(within(dialog).getByRole('combobox')).toHaveFocus();
  });

  it('explains a search endpoint that is not available', async () => {
    stubApi('analyst', {}); // every unknown path is a 404
    renderAt('/');
    await userEvent.keyboard('{Control>}k{/Control}');
    await userEvent.type(screen.getByRole('combobox'), 'example');
    const alert = await within(screen.getByRole('dialog')).findByRole('alert');
    expect(alert).toHaveTextContent('Search is unavailable');
    expect(alert).toHaveTextContent('Search is not available yet on this server.');
  });

  it('shows the API message for other failures and an empty state for no hits', async () => {
    stubApi('analyst', {
      [searchPath('boom')]: apiError(500, 'internal_error', 'Something went wrong.'),
      [searchPath('nothing')]: ok({
        q: 'nothing',
        domains: [],
        assets: [],
        ips: [],
        ports: [],
        software: [],
        vulnerabilities: [],
        findings: [],
      }),
    });
    renderAt('/');
    await userEvent.keyboard('{Control>}k{/Control}');
    const input = screen.getByRole('combobox');
    await userEvent.type(input, 'boom');
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toHaveTextContent(
      'Something went wrong.',
    );
    await userEvent.clear(input);
    await userEvent.type(input, 'nothing');
    expect(await screen.findByText('No results for “nothing”.')).toBeInTheDocument();
    expect(within(screen.getByRole('dialog')).queryByRole('alert')).toBeNull();
  });
});

describe('Notifications', () => {
  it('counts active alerts plus open critical findings and lists them', async () => {
    stubApi('admin', {
      'GET /api/v1/ops/alerts': ok({ alerts: ALERTS }),
      'GET /api/v1/findings/summary': ok(summary(3)),
    });
    renderAt('/scans');
    const bell = await screen.findByRole('button', { name: 'Notifications, 5 active' });
    expect(screen.getByTestId('notification-count')).toHaveTextContent('5');

    await userEvent.click(bell);
    const panel = screen.getByRole('region', { name: 'Notifications' });
    expect(within(panel).getByRole('link', { name: /3 open critical findings/ })).toHaveAttribute(
      'href',
      '/findings?severity=critical',
    );
    expect(within(panel).getByText('Active scanning is disabled')).toBeInTheDocument();
    expect(within(panel).getByRole('link', { name: 'Open System health' })).toHaveAttribute(
      'href',
      '/settings?tab=health',
    );
  });

  it('shares one alerts request with the banner', async () => {
    const calls = stubApi('admin', { 'GET /api/v1/ops/alerts': ok({ alerts: ALERTS }) });
    renderAt('/scans');
    await screen.findByRole('button', { name: 'Notifications, 2 active' });
    expect(calls.filter((c) => c.path === '/api/v1/ops/alerts')).toHaveLength(1);
  });

  it('shows no badge and does not ask for findings without permission', async () => {
    const calls = stubApi('viewer', {
      'GET /api/v1/me': ok({
        user: {
          id: crypto.randomUUID(),
          email: 'v@example.com',
          displayName: null,
          role: 'viewer',
        },
        permissions: ['domains:read'],
        authProvider: 'cloudflare_access',
      }),
    });
    renderAt('/scans');
    const bell = await screen.findByRole('button', { name: 'Notifications' });
    await screen.findByText('v@example.com');
    expect(screen.queryByTestId('notification-count')).toBeNull();
    expect(calls.some((c) => c.path.startsWith('/api/v1/findings/summary'))).toBe(false);
    await userEvent.click(bell);
    expect(screen.getByText('No active alerts or open critical findings.')).toBeInTheDocument();
  });
});

describe('Organisation card', () => {
  it('shows the organisation from /me', async () => {
    stubApi('analyst', { 'GET /api/v1/me': me('Acme Corporation') });
    renderAt('/');
    const card = await screen.findByRole('region', { name: 'Organisation' });
    expect(card).toHaveTextContent('Acme Corporation');
  });

  it.each([
    ['null', null],
    ['absent', undefined],
  ])('is hidden when the organisation is %s', async (_label, organisation) => {
    stubApi('analyst', { 'GET /api/v1/me': me(organisation) });
    renderAt('/');
    expect(await screen.findByText('Ana Lyst')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Organisation' })).toBeNull();
  });
});
