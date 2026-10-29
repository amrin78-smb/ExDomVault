import type { Worker } from '@exdomainvault/shared';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RECENT_CHANGES_PATH, changesPage } from '../components/changes/test-data.ts';
import { apiError, ok, renderAt, stubApi, type Handler } from '../testing/stub-api.tsx';
import { DOMAIN_ID, domain, page } from './findings/test-data.ts';
import {
  ASSET_A,
  DASHBOARD_PATH,
  FINDING_A,
  JOB_ID,
  SCAN_A,
  SURFACE_PATH,
  attackSurface,
  dashboard,
  emptyDashboard,
  emptySurface,
  jobDetail,
  ownerDashboard,
  profiles,
  queuedJob,
} from './overview/test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const ALL: Record<string, Handler> = {
  [DASHBOARD_PATH(30)]: ok(dashboard()),
  [DASHBOARD_PATH(7)]: ok(dashboard({}, 7)),
  [SURFACE_PATH]: ok(attackSurface()),
  // Milestone 14: the Recent changes card.
  [RECENT_CHANGES_PATH]: ok(changesPage([])),
};

const card = (name: string) => screen.findByRole('region', { name });
const stat = (key: string) => screen.findByTestId(`stat-${key}`);
const count = (calls: { path: string }[], prefix: string) =>
  calls.filter((c) => c.path.startsWith(prefix)).length;

describe('Overview: headline numbers', () => {
  it('shows each stat with its hint, delta and link, from one dashboard request', async () => {
    const calls = stubApi('analyst', ALL);
    renderAt('/');

    const domains = await stat('domains');
    expect(within(domains).getByTestId('stat-value')).toHaveTextContent('12');
    expect(domains).toHaveTextContent('Domains monitored');
    expect(domains).toHaveTextContent('9 active');
    expect(domains).toHaveAttribute('href', '/domains');
    // Domains going up is good news.
    expect(within(domains).getByTestId('delta')).toHaveAttribute('data-tone', 'good');
    expect(within(domains).getByTestId('delta')).toHaveTextContent('▲ +2');
    expect(within(domains).getByTestId('sparkline')).toBeInTheDocument();

    const assets = await stat('assets');
    expect(within(assets).getByTestId('stat-value')).toHaveTextContent('340');
    expect(assets).toHaveTextContent('27 pending review');
    expect(assets).toHaveAttribute('href', '/assets');

    const open = await stat('openFindings');
    expect(within(open).getByTestId('stat-value')).toHaveTextContent('50');
    expect(open).toHaveTextContent('Not yet resolved');
    // Findings going up is bad news.
    expect(within(open).getByTestId('delta')).toHaveAttribute('data-tone', 'bad');
    expect(open).toHaveAttribute('href', '/findings');

    const critical = await stat('criticalHigh');
    expect(within(critical).getByTestId('delta')).toHaveTextContent('▼ −2');
    expect(within(critical).getByTestId('delta')).toHaveAttribute('data-tone', 'good');
    expect(critical).toHaveTextContent('Down 2 over the last 30 days');
    expect(critical).toHaveAttribute('href', '/findings?sort=-severity');

    // No history for these: no delta, no sparkline.
    const certs = await stat('expiringCertificates');
    expect(within(certs).getByTestId('stat-value')).toHaveTextContent('3');
    expect(within(certs).queryByTestId('delta')).toBeNull();
    expect(within(certs).queryByTestId('sparkline')).toBeNull();
    expect(certs).toHaveAttribute('href', '/certificates?status=expiring');

    const eol = await stat('eolSoftware');
    expect(eol).toHaveTextContent('1 possibly KEV-affected');
    expect(eol).toHaveAttribute('href', '/software');

    expect(screen.getByTestId('last-scan')).toHaveTextContent(/Last scan: .*UTC/);
    await screen.findByRole('region', { name: 'Asset types' });
    expect(count(calls, '/api/v1/dashboard')).toBe(1);
    expect(count(calls, '/api/v1/attack-surface')).toBe(1);
  });

  it('refetches only the dashboard when the range changes, and keeps it in the URL', async () => {
    const calls = stubApi('analyst', ALL);
    const router = renderAt('/');
    await stat('domains');
    await userEvent.click(screen.getByRole('button', { name: 'Last 7 days' }));
    expect(screen.getByRole('button', { name: 'Last 7 days' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await waitFor(() =>
      expect(calls.some((c) => c.path === '/api/v1/dashboard?range=7')).toBe(true),
    );
    expect(router.state.location.search).toBe('?range=7');
    expect(await screen.findByText(/Down 2 over the last 7 days/)).toBeInTheDocument();
    expect(count(calls, '/api/v1/attack-surface')).toBe(1);
  });
});

describe('Overview: charts', () => {
  it('shows severity counts and shares in the donut legend', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const sev = await card('Findings by severity');
    expect(await within(sev).findByTestId('legend-count-critical')).toHaveTextContent('5');
    expect(within(sev).getByTestId('legend-pct-critical')).toHaveTextContent('10%');
    expect(within(sev).getByTestId('legend-pct-high')).toHaveTextContent('30%');
    expect(within(sev).getByTestId('legend-pct-medium')).toHaveTextContent('40%');
    expect(within(sev).getByTestId('legend-pct-low')).toHaveTextContent('16%');
    expect(within(sev).getByTestId('legend-pct-informational')).toHaveTextContent('4%');
    expect(
      within(sev).getByRole('img', { name: /Open findings by severity: Critical 5 \(10%\)/ }),
    ).toBeInTheDocument();
    expect(within(sev).getByRole('link', { name: /View all findings/ })).toHaveAttribute(
      'href',
      '/findings',
    );
    expect(within(sev).getByRole('link', { name: /Critical/ })).toHaveAttribute(
      'href',
      '/findings?severity=critical',
    );
  });

  it('draws the findings trend with a legend and a data table', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const trend = await card('Findings trend');
    expect(
      await within(trend).findByRole('img', { name: /New findings per day by severity/ }),
    ).toBeInTheDocument();
    const table = within(trend).getByRole('table', { hidden: true });
    expect(within(table).getAllByRole('row', { hidden: true })).toHaveLength(32);
    expect(within(trend).getByRole('list', { name: /legend/ })).toHaveTextContent('Critical');
  });

  it('shows asset types from the attack surface with the approved total in the centre', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const types = await card('Asset types');
    expect(await within(types).findByTestId('legend-count-web')).toHaveTextContent('20');
    expect(within(types).getByTestId('legend-pct-web')).toHaveTextContent('50%');
    expect(within(types).getByText('Web server')).toBeInTheDocument();
    expect(within(types).queryByText('Database')).toBeNull(); // zero roles are not listed
    expect(within(types).getByText('40')).toBeInTheDocument();
    expect(within(types).getByRole('link', { name: /Attack surface/ })).toHaveAttribute(
      'href',
      '/attack-surface',
    );
  });
});

describe('Overview: lists', () => {
  it('links top remediation priorities to their findings, highest risk first', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const top = await card('Top remediation priorities');
    const first = await within(top).findByRole('link', {
      name: 'Known-exploited vulnerability possibly present, risk 92',
    });
    expect(first).toHaveAttribute('href', `/findings/${FINDING_A}`);
    expect(first).toHaveTextContent('CVE-2024-3400 · vpn.example.com · Remote access');
    expect(first).toHaveTextContent('Critical');
    // No hostname: falls back to the domain.
    expect(within(top).getByRole('link', { name: /Certificate expires/ })).toHaveTextContent(
      'example.com',
    );
    expect(within(top).getByRole('link', { name: /View all/ })).toHaveAttribute(
      'href',
      '/findings?sort=-riskScore',
    );
  });

  it('lists the latest scans with status and links', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const scans = await card('Latest scans');
    expect(await within(scans).findByText('Succeeded')).toBeInTheDocument();
    expect(within(scans).getByText('Failed')).toBeInTheDocument();
    expect(within(scans).getByText('Running')).toBeInTheDocument();
    expect(within(scans).getByRole('link', { name: /standard/i })).toHaveAttribute(
      'href',
      `/scans/${SCAN_A}`,
    );
    expect(within(scans).getAllByRole('link', { name: 'example.com' })[0]).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}`,
    );
  });

  it('colours certificate expiry pills by days left', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const certs = await card('Certificate expiry');
    await within(certs).findByText('expired.example.com');
    const tones = within(certs)
      .getAllByTestId('expiry-pill')
      .map((p) => p.getAttribute('data-tone'));
    // -2, 5, 7 → red; 14 → amber; 30 → blue.
    expect(tones).toEqual(['red', 'red', 'red', 'amber', 'blue']);
    expect(within(certs).getByText(/Expired 2 days ago/)).toBeInTheDocument();
    expect(within(certs).getByText(/Expires in 14 days/)).toBeInTheDocument();
    expect(within(certs).getByRole('link', { name: /View all/ })).toHaveAttribute(
      'href',
      '/certificates',
    );
  });

  it('uses slate for certificates more than 30 days out', async () => {
    const { cert } = await import('./overview/test-data.ts');
    stubApi('analyst', {
      ...ALL,
      [DASHBOARD_PATH(30)]: ok(dashboard({ certificateExpiry: [cert('later.example.com', 45)] })),
    });
    renderAt('/');
    const certs = await card('Certificate expiry');
    expect(await within(certs).findByTestId('expiry-pill')).toHaveAttribute('data-tone', 'slate');
  });

  it('shows recently discovered assets with type, status and links', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const recent = await card('Recently discovered assets');
    const row = (await within(recent).findByRole('link', { name: 'new.example.com' })).closest(
      'tr',
    )!;
    expect(within(row).getByText('Web server')).toBeInTheDocument();
    expect(within(row).getByText('New')).toBeInTheDocument();
    expect(within(recent).getByRole('link', { name: 'new.example.com' })).toHaveAttribute(
      'href',
      `/assets/${ASSET_A}`,
    );
    const old = within(recent).getByRole('link', { name: 'old.example.com' }).closest('tr')!;
    expect(within(old).getByText('Pending')).toBeInTheDocument();
    const mail = within(recent).getByRole('link', { name: 'mail.example.com' }).closest('tr')!;
    expect(within(mail).getByText('Approved')).toBeInTheDocument();
    expect(within(recent).getByRole('link', { name: /View all/ })).toHaveAttribute(
      'href',
      '/assets?status=pending&sort=-firstSeenAt',
    );
  });

  it('shows exposed software with KEV and EOL badges', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const sw = await card('Exposed software (top 5)');
    expect(await within(sw).findByRole('link', { name: 'PAN-OS' })).toHaveAttribute(
      'href',
      '/software?q=pan-os',
    );
    const badges = within(sw).getAllByTestId('kev-badge');
    expect(badges.map((b) => b.getAttribute('data-tone'))).toEqual(['neutral', 'red']);
    expect(badges[1]).toHaveTextContent('2 KEV');
    expect(within(sw).getByText('3 EOL')).toBeInTheDocument();
    expect(within(sw).getByText('1.18.0, 1.24.0')).toBeInTheDocument();
  });

  it('summarises regions by continent with the DB-IP attribution', async () => {
    stubApi('analyst', ALL);
    renderAt('/');
    const region = await card('Attack surface by region');
    expect(await within(region).findByTestId('region-Europe')).toHaveTextContent('20');
    const list = within(region).getByRole('list', { name: 'IP addresses by continent' });
    expect(list).toHaveTextContent('Europe20 40%');
    expect(list).toHaveTextContent('Others5 10%');
    expect(within(region).getByText(/10 not yet located/)).toBeInTheDocument();
    const attribution = await within(region).findByRole('link', { name: /DB-IP/ });
    expect(attribution).toHaveAttribute('href', 'https://db-ip.com');
    expect(within(region).getByRole('link', { name: /Open attack surface map/ })).toHaveAttribute(
      'href',
      '/attack-surface',
    );
  });
});

describe('Overview: states', () => {
  it('shows helpful empty states and never invents numbers', async () => {
    stubApi('analyst', {
      [DASHBOARD_PATH(30)]: ok(emptyDashboard()),
      [SURFACE_PATH]: ok(emptySurface()),
    });
    renderAt('/');
    expect(await screen.findByText('No open findings')).toBeInTheDocument();
    expect(screen.getByText('No new findings in the last 30 days')).toBeInTheDocument();
    expect(screen.getByText('Nothing to prioritise')).toBeInTheDocument();
    expect(screen.getByText('No scans have run')).toBeInTheDocument();
    expect(screen.getByText('No certificates collected yet')).toBeInTheDocument();
    expect(screen.getByText(/run a Standard scan/i)).toBeInTheDocument();
    expect(screen.getByText('No assets discovered yet')).toBeInTheDocument();
    expect(screen.getByText('No software recorded yet')).toBeInTheDocument();
    expect(await screen.findByText('No approved assets yet')).toBeInTheDocument();
    expect(screen.getByText('No locations yet')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /DB-IP/ })).toBeNull();
    expect(screen.getByTestId('last-scan')).toHaveTextContent('No completed scans yet');
    // Zero change is stated, not coloured.
    expect(within(await stat('openFindings')).getByTestId('delta')).toHaveTextContent('▬ 0');
  });

  it('shows skeletons while loading', async () => {
    stubApi('analyst', {
      [DASHBOARD_PATH(30)]: () => ({ status: 200, body: dashboard() }),
      [SURFACE_PATH]: ok(attackSurface()),
    });
    renderAt('/');
    expect(await screen.findByRole('status', { name: 'Loading headline numbers' })).toBeVisible();
    expect(await stat('domains')).toBeInTheDocument();
  });

  it('shows an inline error with retry on each card, and recovers', async () => {
    let fail = true;
    const calls = stubApi('analyst', {
      ...ALL,
      [DASHBOARD_PATH(30)]: () =>
        fail
          ? apiError(500, 'internal_error', 'Something went wrong.')()
          : { status: 200, body: dashboard() },
    });
    renderAt('/');
    const top = await card('Top remediation priorities');
    expect(await within(top).findByRole('alert')).toHaveTextContent('Could not load');
    // The attack-surface cards still render.
    expect(
      await within(await card('Asset types')).findByTestId('legend-count-web'),
    ).toBeInTheDocument();
    fail = false;
    await userEvent.click(within(top).getByRole('button', { name: 'Retry' }));
    expect(
      await within(top).findByRole('link', { name: /Known-exploited vulnerability/ }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(count(calls, '/api/v1/dashboard')).toBe(2);
  });

  it('renders a permission-limited response gracefully for an asset owner', async () => {
    const calls = stubApi('asset_owner', {
      [DASHBOARD_PATH(30)]: ok(ownerDashboard()),
      [SURFACE_PATH]: ok(attackSurface()),
      [RECENT_CHANGES_PATH]: ok(changesPage([])),
    });
    renderAt('/');
    const domains = await stat('domains');
    expect(within(domains).getByLabelText('No data')).toBeInTheDocument();
    expect(domains).toHaveTextContent('Not visible to your role');
    expect(domains.tagName).not.toBe('A');
    const scans = await card('Latest scans');
    expect(within(scans).getByText('Scan history is not visible to your role')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Run scan' })).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(within(await stat('openFindings')).getByTestId('stat-value')).toHaveTextContent('50');
    expect(calls.some((c) => c.path.startsWith('/api/v1/workers'))).toBe(false);
  });

  it('warns administrators when no worker has polled recently', async () => {
    const worker: Worker = {
      id: crypto.randomUUID(),
      name: 'home-worker-01',
      status: 'active',
      version: '0.1.0',
      lastSeenAt: '2026-01-01T00:00:00.000Z',
      createdAt: '2026-01-01T00:00:00.000Z',
      credentials: [],
    };
    stubApi('admin', { ...ALL, 'GET /api/v1/workers': ok({ items: [worker] }) });
    renderAt('/');
    expect(
      await screen.findByText(/No scanning worker has polled in the last 10 minutes/),
    ).toHaveTextContent('home-worker-01');
  });

  it('never requests worker health for non-administrators', async () => {
    const calls = stubApi('viewer', ALL);
    renderAt('/');
    await stat('domains');
    expect(calls.some((c) => c.path.startsWith('/api/v1/workers'))).toBe(false);
    expect(screen.queryByRole('button', { name: 'Run scan' })).toBeNull();
  });
});

describe('Overview: Run scan', () => {
  it('picks an eligible domain and profile, requests the scan and follows it', async () => {
    const verified = domain({
      fqdn: 'example.com',
      verificationStatus: 'verified',
      verificationMethod: 'dns_txt',
      verifiedAt: '2026-10-01T00:00:00.000Z',
      monitoringEnabled: true,
    });
    const unverifiedId = '66666666-6666-4666-8666-666666666666';
    const unverified = domain({ id: unverifiedId, fqdn: 'example.net', monitoringEnabled: true });
    const ignored = domain({ id: crypto.randomUUID(), fqdn: 'example.io' });
    const calls = stubApi('analyst', {
      ...ALL,
      'GET /api/v1/domains?pageSize=25': ok(page([verified, unverified, ignored])),
      'GET /api/v1/domains?q=net&pageSize=25': ok(page([unverified])),
      'GET /api/v1/scan-profiles': ok(profiles),
      [`POST /api/v1/domains/${DOMAIN_ID}/scans`]: () => ({
        status: 202,
        body: jobDetail(queuedJob(DOMAIN_ID, 'example.com', 'standard'), 'verified'),
      }),
      [`GET /api/v1/scans/${JOB_ID}`]: ok(
        jobDetail(queuedJob(DOMAIN_ID, 'example.com', 'standard'), 'verified'),
      ),
    });
    const router = renderAt('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Run scan' }));
    const dialog = await screen.findByRole('dialog', { name: 'Run scan' });
    const submit = within(dialog).getByRole('button', { name: 'Run scan' });
    expect(submit).toBeDisabled();

    // Only monitored or verified domains are offered, with their verification state.
    expect(await within(dialog).findByRole('radio', { name: /example\.com/ })).toBeInTheDocument();
    expect(within(dialog).queryByRole('radio', { name: /example\.io/ })).toBeNull();
    expect(within(dialog).getByRole('radio', { name: /example\.net/ })).toHaveAccessibleName(
      /Unverified/i,
    );

    // An unverified domain cannot use an active profile.
    await userEvent.click(within(dialog).getByRole('radio', { name: /example\.net/ }));
    const select = within(dialog).getByRole('combobox');
    expect(
      within(select).getByRole('option', { name: /Standard \(needs verification\)/ }),
    ).toBeDisabled();
    expect(select).toHaveValue('passive');

    // Search narrows the list.
    await userEvent.type(within(dialog).getByRole('searchbox', { name: 'Search domains' }), 'net');
    await waitFor(() =>
      expect(within(dialog).queryByRole('radio', { name: /example\.com/ })).toBeNull(),
    );
    await userEvent.clear(within(dialog).getByRole('searchbox', { name: 'Search domains' }));
    await userEvent.click(await within(dialog).findByRole('radio', { name: /example\.com/ }));
    await userEvent.selectOptions(select, 'standard');
    expect(within(dialog).getByText('Certificates, HTTP and ports.')).toBeInTheDocument();
    await userEvent.click(submit);

    await waitFor(() => expect(router.state.location.pathname).toBe(`/scans/${JOB_ID}`));
    expect(calls.find((c) => c.method === 'POST')).toMatchObject({
      path: `/api/v1/domains/${DOMAIN_ID}/scans`,
      body: { profile: 'standard' },
    });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('closes on Escape without requesting anything', async () => {
    const calls = stubApi('analyst', {
      ...ALL,
      'GET /api/v1/domains?pageSize=25': ok(page([])),
      'GET /api/v1/scan-profiles': ok(profiles),
    });
    renderAt('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Run scan' }));
    const dialog = await screen.findByRole('dialog', { name: 'Run scan' });
    expect(await within(dialog).findByText('No monitored or verified domains yet.')).toBeVisible();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });
});
