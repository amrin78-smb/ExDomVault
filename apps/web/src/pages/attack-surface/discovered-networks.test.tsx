// Attack surface (Milestone 15): IP ranges registered to the organisation and other hosting networks.
import {
  DBIP_ATTRIBUTION,
  type AttackSurfaceResponse,
  type DiscoveredNetwork,
  type DiscoveredNetworksResponse,
  type Role,
} from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';

beforeEach(() => localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

const surface: AttackSurfaceResponse = {
  totals: { approvedAssets: 3, currentIps: 3, openPorts: 0, thirdPartyHosted: 1 },
  assetRoles: [],
  hostingProviders: [],
  countries: [],
  continents: [],
  unknownCountryIps: 3,
  geoAttribution: DBIP_ATTRIBUTION,
  exposedServices: [],
};

const ASSET_ID = '7d0f2a8e-1c3b-4f5a-9e6d-2b4c6a8e0f13';

const network = (over: Partial<DiscoveredNetwork> = {}): DiscoveredNetwork => ({
  key: 'apnic:49.231.0.0 - 49.231.3.255',
  registry: 'apnic',
  handle: '49.231.0.0 - 49.231.3.255',
  networkName: 'THAIUNION-TH',
  orgName: 'Thai Union Group Public Company Limited',
  country: 'TH',
  cidrs: ['49.231.0.0/22'],
  startAddress: '49.231.0.0',
  endAddress: '49.231.3.255',
  matched: true,
  addresses: ['49.231.0.10'],
  assetCount: 1,
  assets: [{ id: ASSET_ID, hostname: 'www.example.com' }],
  proposedCidr: '49.231.0.0/22',
  firstSeenAt: '2026-10-20T00:00:00.000Z',
  lastSeenAt: '2026-10-28T00:00:00.000Z',
  ...over,
});

const networks = (over: Partial<DiscoveredNetworksResponse> = {}): DiscoveredNetworksResponse => ({
  orgNames: ['Thai Union'],
  matched: [network()],
  hosting: [
    { orgName: 'Amazon Technologies Inc.', networks: 2, assetCount: 5 },
    { orgName: 'Microsoft Corporation', networks: 1, assetCount: 1 },
  ],
  total: 4,
  ...over,
});

async function open(role: Role, data: DiscoveredNetworksResponse | null = networks()) {
  const calls = stubApi(role, {
    'GET /api/v1/attack-surface': ok(surface),
    'GET /api/v1/networks/discovered': data ? ok(data) : apiError(500, 'internal_error', 'Boom.'),
  });
  renderAt('/attack-surface');
  await screen.findByRole('heading', { level: 1, name: 'Attack surface' });
  return calls;
}

describe('Attack surface: discovered networks', () => {
  it('lists ranges registered to the organisation with their assets', async () => {
    await open('viewer');
    const card = await screen.findByRole('region', {
      name: 'IP ranges registered to your organisation',
    });
    expect(within(card).getByText(/“Thai Union”/)).toBeInTheDocument();
    const item = within(card).getByRole('listitem', { name: '49.231.0.0/22' });
    expect(within(item).getByText('49.231.0.0/22')).toHaveClass('font-mono');
    expect(
      within(item).getByText(/Thai Union Group Public Company Limited · APNIC · TH/),
    ).toBeVisible();
    expect(within(item).getByText('1 asset')).toBeInTheDocument();
    expect(within(item).getByRole('link', { name: 'www.example.com' })).toHaveAttribute(
      'href',
      `/assets/${ASSET_ID}`,
    );
    // Only administrators who manage scan policy can propose a range.
    expect(within(item).queryByRole('link', { name: 'Propose as approved network' })).toBeNull();
  });

  it('lets administrators propose a range to the approved-networks form, pre-filled', async () => {
    stubApi('admin', {
      'GET /api/v1/attack-surface': ok(surface),
      'GET /api/v1/networks/discovered': ok(networks()),
      'GET /api/v1/workers': ok({ items: [] }),
      'GET /api/v1/approved-networks': ok({ items: [] }),
    });
    const router = renderAt('/attack-surface');
    const link = await screen.findByRole('link', { name: 'Propose as approved network' });
    const href = link.getAttribute('href')!;
    expect(href).toBe(
      '/settings?proposeCidr=49.231.0.0%2F22&proposeLabel=Thai+Union+Group+Public+Company+Limited',
    );
    await router.navigate(href);
    const form = await screen.findByRole('form', { name: 'Approve a network' });
    expect(within(form).getByText(/Pre-filled from a network registered/)).toBeInTheDocument();
    expect(within(form).getByDisplayValue('49.231.0.0/22')).toBeInTheDocument();
    expect(
      within(form).getByDisplayValue('Thai Union Group Public Company Limited'),
    ).toBeInTheDocument();
    // The reason is left for the administrator: the form cannot be submitted yet.
    expect(within(form).getByRole('button', { name: /approve/i })).toBeDisabled();
  });

  it('hides the proposal when no registered prefix fits the approval limit', async () => {
    stubApi('admin', {
      'GET /api/v1/attack-surface': ok(surface),
      'GET /api/v1/networks/discovered': ok(
        networks({ matched: [network({ proposedCidr: null, cidrs: ['49.0.0.0/8'] })] }),
      ),
      'GET /api/v1/workers': ok({ items: [] }),
    });
    renderAt('/attack-surface');
    await screen.findByRole('listitem', { name: '49.0.0.0/8' });
    expect(screen.queryByRole('link', { name: 'Propose as approved network' })).toBeNull();
  });

  it('summarises other hosting networks by organisation', async () => {
    await open('analyst');
    const card = await screen.findByRole('region', { name: 'Other hosting networks' });
    const rows = within(card).getAllByRole('listitem');
    expect(rows.map((r) => r.textContent)).toEqual([
      'Amazon Technologies Inc.5',
      'Microsoft Corporation1',
    ]);
    expect(within(rows[0]!).getByLabelText('5 assets in 2 networks')).toBeInTheDocument();
  });

  it('shows empty states', async () => {
    await open('viewer', networks({ matched: [], hosting: [], total: 0, orgNames: [] }));
    expect(
      await screen.findByText('No ranges registered to your organisation found'),
    ).toBeInTheDocument();
    expect(screen.getByText(/matched against no organisation names/)).toBeInTheDocument();
    expect(screen.getByText('No other networks observed')).toBeInTheDocument();
  });

  it('a failure here never hides the rest of the page', async () => {
    await open('viewer', null);
    expect(
      await screen.findByText('Network ownership (RDAP) is not available right now.'),
    ).toBeInTheDocument();
    expect(screen.getByText('Approved assets')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
