// Attack surface page: tiles, map card (continent legend, attribution), breakdown cards, states.
import { DBIP_ATTRIBUTION, type AttackSurfaceResponse } from '@exdomainvault/shared';
import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';

beforeEach(() => localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

const PATH = 'GET /api/v1/attack-surface';

const surface = (overrides: Partial<AttackSurfaceResponse> = {}): AttackSurfaceResponse => ({
  totals: { approvedAssets: 14, currentIps: 21, openPorts: 9, thirdPartyHosted: 5 },
  assetRoles: [
    { role: 'web', assets: 9 },
    { role: 'mail', assets: 2 },
    { role: 'dns', assets: 0 },
    { role: 'remote_access', assets: 1 },
    { role: 'file_transfer', assets: 0 },
    { role: 'database', assets: 0 },
    { role: 'cloud_service', assets: 1 },
    { role: 'unclassified', assets: 1 },
  ],
  hostingProviders: [
    { provider: 'Amazon CloudFront', kind: 'cdn', assets: 4 },
    { provider: null, kind: null, assets: 9 },
  ],
  countries: [
    { country: 'US', assets: 8, ips: 12 },
    { country: 'DE', assets: 3, ips: 6 },
    { country: 'JP', assets: 1, ips: 2 },
  ],
  continents: [
    { continent: 'North America', assets: 8, ips: 12 },
    { continent: 'Europe', assets: 3, ips: 6 },
    { continent: 'Asia', assets: 1, ips: 2 },
  ],
  unknownCountryIps: 1,
  geoAttribution: DBIP_ATTRIBUTION,
  exposedServices: [
    { port: 443, service: 'https', ips: 15 },
    { port: 22, service: null, ips: 2 },
  ],
  ...overrides,
});

const NO_GEO: Partial<AttackSurfaceResponse> = {
  countries: [],
  continents: [],
  unknownCountryIps: 21,
  geoAttribution: null,
};

async function open(data = surface()) {
  const calls = stubApi('viewer', { [PATH]: ok(data) });
  renderAt('/attack-surface');
  await screen.findByRole('heading', { level: 1, name: 'Attack surface' });
  await screen.findByText('Approved assets');
  return calls;
}

const card = (name: string) => within(screen.getByRole('region', { name }));

describe('Attack surface page', () => {
  it('shows the summary tiles', async () => {
    await open();
    const tiles: [string, string][] = [
      ['Approved assets', '14'],
      ['Current IPs', '21'],
      ['Open ports', '9'],
      ['Third-party hosted', '5'],
    ];
    for (const [label, value] of tiles) {
      expect(screen.getByText(label).parentElement).toHaveTextContent(value);
    }
  });

  it('shows the continent legend with shares of geolocated IPs and the not-geolocated note', async () => {
    await open();
    const legend = within(screen.getByRole('list', { name: 'Assets by region' }));
    const items = legend.getAllByRole('listitem').map((li) => li.textContent);
    expect(items).toEqual([
      'North America60%8 assets · 12 IPs',
      'Europe30%3 assets · 6 IPs',
      'Asia10%1 asset · 2 IPs',
    ]);
    expect(screen.getByText('Not geolocated: 1 IP')).toBeInTheDocument();
  });

  it('draws the map with tooltips and zoom, and shows the DB-IP attribution', async () => {
    await open();
    const germany = await screen.findByRole('button', { name: 'Germany: 3 assets, 6 IPs' });
    fireEvent.mouseEnter(germany);
    expect(screen.getByRole('tooltip')).toHaveTextContent('Germany3 assets · 6 IPs');
    const link = screen.getByRole('link', { name: DBIP_ATTRIBUTION });
    expect(link).toHaveAttribute('href', 'https://db-ip.com');
    fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
    expect(screen.getByTestId('map-viewport').getAttribute('transform')).toMatch(/scale\(1\.6\)/);
  });

  it('shows an empty state and no attribution before anything is geolocated', async () => {
    await open(surface(NO_GEO));
    const map = card('Assets by country');
    expect(map.getByText('No country data yet')).toBeInTheDocument();
    expect(
      map.getByText(/Country data appears after the next scan — the worker adds it to DNS results/),
    ).toHaveTextContent('21 IPs not geolocated');
    expect(screen.queryByRole('link', { name: DBIP_ATTRIBUTION })).not.toBeInTheDocument();
    expect(screen.queryByRole('group', { name: /World map/ })).not.toBeInTheDocument();
    expect(card('Countries').getByText('No country data yet')).toBeInTheDocument();
  });

  it('links asset types to the filtered asset list', async () => {
    await open();
    const types = card('Asset types');
    expect(types.getByRole('link', { name: 'Web server' })).toHaveAttribute(
      'href',
      '/assets?status=approved&role=web',
    );
    expect(types.getByRole('link', { name: 'Mail server' })).toHaveAttribute(
      'href',
      '/assets?status=approved&role=mail',
    );
    // Sorted by count: Web first.
    expect(types.getAllByRole('link')[0]).toHaveTextContent('Web server');
  });

  it('lists hosting providers, exposed services and countries', async () => {
    await open();
    const hosting = card('Hosting providers');
    expect(hosting.getByText('Amazon CloudFront')).toBeInTheDocument();
    expect(hosting.getByText('CDN')).toBeInTheDocument();
    expect(hosting.getByText('No third-party provider detected')).toBeInTheDocument();

    const services = card('Exposed services');
    expect(services.getByRole('link', { name: '443 · https' })).toHaveAttribute(
      'href',
      '/ports?port=443',
    );
    expect(services.getByRole('link', { name: '22' })).toHaveAttribute('href', '/ports?port=22');

    const rows = card('Countries').getAllByRole('row').slice(1);
    expect(rows.map((r) => r.textContent)).toEqual([
      '🇺🇸United States812',
      '🇩🇪Germany36',
      '🇯🇵Japan12',
    ]);
  });

  it('shows the error with a retry', async () => {
    stubApi('viewer', { [PATH]: apiError(500, 'internal_error', 'Boom.') });
    renderAt('/attack-surface');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load the attack surface');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
});

describe('drill-down links', () => {
  it('links tiles, regions and countries to the matching filtered asset list', async () => {
    await open();
    expect(screen.getByRole('link', { name: /Approved assets/ })).toHaveAttribute(
      'href',
      '/assets?status=approved',
    );
    expect(screen.getByRole('link', { name: /Third-party hosted/ })).toHaveAttribute(
      'href',
      '/assets?status=approved&thirdParty=true',
    );
    expect(screen.getByRole('link', { name: /Open ports/ })).toHaveAttribute('href', '/ports');
    const regions = screen.getByRole('list', { name: 'Assets by region' });
    expect(within(regions).getByRole('link', { name: /North America/ })).toHaveAttribute(
      'href',
      '/assets?status=approved&continent=North%20America',
    );
    expect(screen.getByRole('link', { name: 'Germany' })).toHaveAttribute(
      'href',
      '/assets?status=approved&country=DE',
    );
  });

  it('opens the assets of a country clicked on the map', async () => {
    const calls = stubApi('viewer', { [PATH]: ok(surface()) });
    renderAt('/attack-surface');
    const germany = await screen.findByRole('button', { name: /^Germany: 3 assets/ });
    fireEvent.click(germany);
    expect(await screen.findByText('Country: Germany')).toBeInTheDocument();
    const assetCall = calls.find((c) => c.path.startsWith('/api/v1/assets?'));
    expect(assetCall?.path).toContain('country=DE');
    expect(assetCall?.path).toContain('status=approved');
  });
});
