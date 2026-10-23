// Assets card on the domain page: counts by status, links and "Run discovery".
import type { Role } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { domain } from '../findings/test-data.ts';
import {
  ASSET_PATHS,
  apiError,
  ok,
  renderAt,
  stubApi,
  type Handler,
} from '../../testing/stub-api.tsx';
import { DOMAIN_ID, JOB_ID, asset, page } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const ASSETS = ASSET_PATHS.domainAssets(DOMAIN_ID, '?page=1&pageSize=100');

function stubDomain(role: Role, handlers: Record<string, Handler> = {}) {
  return stubApi(role, {
    [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain: domain(), verification: null }),
    [ASSETS]: ok({
      ...page([
        asset({ id: crypto.randomUUID(), assetType: 'apex', status: 'approved' }),
        asset({ id: crypto.randomUUID() }),
        asset({ id: crypto.randomUUID() }),
        asset({ id: crypto.randomUUID(), status: 'rejected' }),
      ]),
      pageSize: 100,
    }),
    ...handlers,
  });
}

const card = () => screen.findByRole('region', { name: 'Assets' });

describe('Domain assets card', () => {
  it('counts assets by status and links to the filtered Assets page', async () => {
    stubDomain('viewer');
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card();
    expect(await within(c).findByTestId('asset-count-pending')).toHaveTextContent('2');
    expect(within(c).getByTestId('asset-count-approved')).toHaveTextContent('1');
    expect(within(c).getByTestId('asset-count-rejected')).toHaveTextContent('1');
    expect(within(c).getByTestId('asset-count-suspended')).toHaveTextContent('0');
    expect(within(c).getByRole('link', { name: 'Review 2 pending' })).toHaveAttribute(
      'href',
      `/assets?domainId=${DOMAIN_ID}`,
    );
    expect(within(c).getByRole('link', { name: 'All assets of this domain' })).toHaveAttribute(
      'href',
      `/assets?domainId=${DOMAIN_ID}&status=all`,
    );
    expect(within(c).getByText(/never contacts\s+your hosts/)).toBeInTheDocument();
  });

  it('reads every page for the counts', async () => {
    const calls = stubDomain('viewer', {
      [ASSETS]: ok({ ...page([asset({ id: crypto.randomUUID() })], 2), pageSize: 100 }),
      [ASSET_PATHS.domainAssets(DOMAIN_ID, '?page=2&pageSize=100')]: ok({
        ...page([asset({ id: crypto.randomUUID(), status: 'suspended' })], 2, 2),
        pageSize: 100,
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card();
    expect(await within(c).findByTestId('asset-count-suspended')).toHaveTextContent('1');
    expect(within(c).getByTestId('asset-count-pending')).toHaveTextContent('1');
    expect(calls.filter((x) => x.path.includes('/assets?'))).toHaveLength(2);
  });

  it.each<Role>(['viewer'])('hides Run discovery from %s (no scans:request)', async (role) => {
    stubDomain(role);
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card();
    await within(c).findByTestId('asset-count-pending');
    expect(within(c).queryByRole('button', { name: 'Run discovery' })).not.toBeInTheDocument();
  });

  it.each<Role>(['analyst', 'admin'])('lets %s run discovery', async (role) => {
    const calls = stubDomain(role, {
      [ASSET_PATHS.discovery(DOMAIN_ID)]: ok({ scanJobId: JOB_ID, created: true }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card();
    await within(c).findByTestId('asset-count-pending');
    await userEvent.click(within(c).getByRole('button', { name: 'Run discovery' }));
    expect(calls.some((x) => x.method === 'POST' && x.path.endsWith('/discovery'))).toBe(true);
    const status = await within(c).findByRole('status');
    expect(status).toHaveTextContent('Discovery queued.');
    expect(within(status).getByRole('link', { name: 'View the discovery job' })).toHaveAttribute(
      'href',
      `/scans/${JOB_ID}`,
    );
  });

  it('says when discovery is already queued', async () => {
    stubDomain('analyst', {
      [ASSET_PATHS.discovery(DOMAIN_ID)]: ok({ scanJobId: JOB_ID, created: false }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card();
    await within(c).findByTestId('asset-count-pending');
    await userEvent.click(within(c).getByRole('button', { name: 'Run discovery' }));
    expect(await within(c).findByRole('status')).toHaveTextContent(
      'Discovery is already queued or running for this domain.',
    );
  });

  it('shows a refused discovery request', async () => {
    stubDomain('analyst', {
      [ASSET_PATHS.discovery(DOMAIN_ID)]: apiError(403, 'forbidden', 'Not allowed.'),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card();
    await within(c).findByTestId('asset-count-pending');
    await userEvent.click(within(c).getByRole('button', { name: 'Run discovery' }));
    expect(await within(c).findByRole('alert')).toHaveTextContent('Discovery was not requested');
  });

  it('shows a load error inside the card', async () => {
    stubDomain('viewer', { [ASSETS]: apiError(500, 'internal_error', 'Boom.') });
    renderAt(`/domains/${DOMAIN_ID}`);
    const c = await card();
    expect(await within(c).findByRole('alert')).toHaveTextContent('Could not load assets');
  });
});
