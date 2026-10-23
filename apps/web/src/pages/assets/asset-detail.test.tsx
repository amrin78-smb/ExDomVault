// Asset detail: decision panel per status/type/role, form validation, errors and history tables.
import type { AssetStatus, Role } from '@exdomainvault/shared';
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
import { ADMIN, ASSET_ID, CLOUDFRONT, DOMAIN_ID, JOB_ID, asset, detailOf } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

async function openAsset(role: Role, detail = detailOf(), handlers: Record<string, Handler> = {}) {
  const calls = stubApi(role, { [ASSET_PATHS.detail(ASSET_ID)]: ok(detail), ...handlers });
  renderAt(`/assets/${ASSET_ID}`);
  const panel = await screen.findByRole('region', { name: 'Review' });
  return { calls, panel };
}

const buttons = (panel: HTMLElement) =>
  within(panel)
    .queryAllByRole('button')
    .map((b) => b.textContent);

describe('Asset detail: display', () => {
  it('shows the header, IP history and discovery sightings', async () => {
    await openAsset(
      'viewer',
      detailOf(asset({ hostingHint: CLOUDFRONT, wildcardOnly: true, activeFindings: 3 })),
    );
    expect(screen.getByRole('heading', { level: 1, name: 'shop.example.com' })).toBeInTheDocument();
    expect(screen.getAllByText('Pending review')[0]).toBeInTheDocument();
    expect(screen.getAllByText('Amazon CloudFront').length).toBeGreaterThan(0);
    expect(screen.getByText('Wildcard only')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}`,
    );

    const ips = within(screen.getByRole('region', { name: 'IP addresses' }));
    const rows = ips.getAllByRole('row').slice(1);
    expect(rows.map((r) => within(r).getByRole('rowheader').textContent)).toEqual([
      '192.0.2.10',
      '198.51.100.7',
    ]);
    expect(within(rows[0]!).getByText('Current')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Past')).toBeInTheDocument();

    const sightings = within(screen.getByRole('region', { name: 'Discovery sightings' }));
    expect(sightings.getByText('Certificate logs')).toBeInTheDocument();
    expect(sightings.getByText('No')).toBeInTheDocument();
    expect(sightings.getByRole('link', { name: /Discovery job of/ })).toHaveAttribute(
      'href',
      `/scans/${JOB_ID}`,
    );

    expect(screen.getByRole('link', { name: '3 active findings' })).toHaveAttribute(
      'href',
      `/findings?q=shop.example.com&domainId=${DOMAIN_ID}`,
    );
  });

  it('shows who decided, when and why', async () => {
    const { panel } = await openAsset(
      'viewer',
      detailOf(
        asset({
          status: 'approved',
          decidedBy: ADMIN,
          decidedAt: '2026-10-21T09:30:00.000Z',
          decisionReason: 'Our storefront.',
        }),
      ),
    );
    expect(within(panel).getByText('admin@example.com')).toBeInTheDocument();
    expect(within(panel).getByText('Our storefront.')).toBeInTheDocument();
    expect(within(panel).getByText(/21 Oct 2026|Oct 21, 2026/)).toBeInTheDocument();
  });

  it('shows a load error', async () => {
    stubApi('viewer', {
      [ASSET_PATHS.detail(ASSET_ID)]: apiError(404, 'not_found', 'Asset not found.'),
    });
    renderAt(`/assets/${ASSET_ID}`);
    expect(await screen.findByRole('alert')).toHaveTextContent('Asset not found.');
  });
});

describe('Asset detail: decisions offered', () => {
  it.each<[AssetStatus, 'apex' | 'subdomain', string[]]>([
    ['pending', 'subdomain', ['Approve', 'Reject']],
    ['pending', 'apex', ['Approve']],
    ['approved', 'subdomain', ['Suspend']],
    ['approved', 'apex', ['Suspend']],
    ['suspended', 'subdomain', ['Approve']],
    ['rejected', 'subdomain', ['Approve']],
  ])('offers admins on a %s %s: %j', async (status, assetType, expected) => {
    const { panel } = await openAsset('admin', detailOf(asset({ status, assetType })));
    expect(buttons(panel)).toEqual(expected);
  });

  it.each<Role>(['analyst', 'viewer', 'asset_owner'])('offers %s no decisions', async (role) => {
    const { panel } = await openAsset(role);
    expect(buttons(panel)).toEqual([]);
    expect(within(panel).getByText(/Only administrators approve/)).toBeInTheDocument();
  });
});

describe('Asset detail: decision form', () => {
  it('approves with a reason and shows the new state', async () => {
    const approved = asset({
      status: 'approved',
      decidedBy: ADMIN,
      decidedAt: '2026-10-23T09:00:00.000Z',
      decisionReason: 'Our storefront',
    });
    const { calls, panel } = await openAsset('admin', detailOf(), {
      [ASSET_PATHS.decide(ASSET_ID, 'approve')]: ok({ asset: approved }),
    });
    await userEvent.click(within(panel).getByRole('button', { name: 'Approve' }));
    const form = within(panel).getByRole('form', { name: 'Approve shop.example.com' });
    // No hosting hint: no acknowledgement.
    expect(within(form).queryByRole('checkbox')).not.toBeInTheDocument();
    await userEvent.click(within(form).getByRole('button', { name: 'Approve' }));
    expect(within(form).getByText('A reason is required.')).toBeInTheDocument();
    expect(within(form).getByLabelText(/Reason/)).toHaveAttribute('aria-invalid', 'true');

    await userEvent.type(within(form).getByLabelText(/Reason/), '  Our storefront  ');
    await userEvent.click(within(form).getByRole('button', { name: 'Approve' }));
    expect(calls.find((c) => c.method === 'POST')).toMatchObject({
      path: `/api/v1/assets/${ASSET_ID}/approve`,
      body: { reason: 'Our storefront', acknowledgeThirdPartyHosting: false },
    });
    expect(await within(panel).findByRole('status')).toHaveTextContent(
      'shop.example.com was approved.',
    );
    expect(buttons(panel)).toEqual(['Suspend']);
    expect(within(panel).getByText('admin@example.com')).toBeInTheDocument();
  });

  it('requires the third-party acknowledgement to approve a hinted asset', async () => {
    const { calls, panel } = await openAsset(
      'admin',
      detailOf(asset({ hostingHint: CLOUDFRONT })),
      {
        [ASSET_PATHS.decide(ASSET_ID, 'approve')]: ok({
          asset: asset({ hostingHint: CLOUDFRONT, status: 'approved' }),
        }),
      },
    );
    await userEvent.click(within(panel).getByRole('button', { name: 'Approve' }));
    const form = within(panel).getByRole('form', { name: 'Approve shop.example.com' });
    await userEvent.type(within(form).getByLabelText(/Reason/), 'CDN for the shop');
    await userEvent.click(within(form).getByRole('button', { name: 'Approve' }));
    expect(
      within(form).getByText('Confirm the third-party hosting acknowledgement to approve.'),
    ).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    const ack = within(form).getByRole('checkbox', {
      name: /addresses operated by Amazon CloudFront as a normal visitor would.*approved network/,
    });
    await userEvent.click(ack);
    await userEvent.click(within(form).getByRole('button', { name: 'Approve' }));
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      reason: 'CDN for the shop',
      acknowledgeThirdPartyHosting: true,
    });
  });

  it('does not ask for the acknowledgement when suspending a hinted asset', async () => {
    const { calls, panel } = await openAsset(
      'admin',
      detailOf(asset({ hostingHint: CLOUDFRONT, status: 'approved' })),
      {
        [ASSET_PATHS.decide(ASSET_ID, 'suspend')]: ok({
          asset: asset({ hostingHint: CLOUDFRONT, status: 'suspended' }),
        }),
      },
    );
    await userEvent.click(within(panel).getByRole('button', { name: 'Suspend' }));
    const form = within(panel).getByRole('form', { name: 'Suspend shop.example.com' });
    expect(within(form).queryByRole('checkbox')).not.toBeInTheDocument();
    await userEvent.type(within(form).getByLabelText(/Reason/), 'Decommissioned');
    await userEvent.click(within(form).getByRole('button', { name: 'Suspend' }));
    expect(calls.find((c) => c.method === 'POST')).toMatchObject({
      path: `/api/v1/assets/${ASSET_ID}/suspend`,
      body: { reason: 'Decommissioned' },
    });
    expect(await within(panel).findByRole('status')).toHaveTextContent('was suspended');
  });

  it('explains a 409 and offers a reload', async () => {
    let loads = 0;
    const { calls, panel } = await openAsset('admin', detailOf(), {
      [ASSET_PATHS.detail(ASSET_ID)]: () => ({
        status: 200,
        body: loads++ === 0 ? detailOf() : detailOf(asset({ status: 'rejected' })),
      }),
      [ASSET_PATHS.decide(ASSET_ID, 'reject')]: apiError(
        409,
        'conflict',
        'This decision is not possible from the asset’s current status.',
        [{ path: 'status', message: 'Invalid transition.' }],
      ),
    });
    await userEvent.click(within(panel).getByRole('button', { name: 'Reject' }));
    await userEvent.type(within(panel).getByLabelText(/Reason/), 'Not ours');
    await userEvent.click(within(panel).getByRole('button', { name: 'Reject' }));
    const alert = await within(panel).findByRole('alert');
    expect(alert).toHaveTextContent('The asset changed since this page loaded');
    expect(alert).toHaveTextContent('not possible from the asset’s current status');

    await userEvent.click(within(panel).getByRole('button', { name: 'Reload the asset' }));
    const reloaded = await screen.findByRole('region', { name: 'Review' });
    expect(within(reloaded).getByRole('button', { name: 'Approve' })).toBeInTheDocument();
    expect(calls.filter((c) => c.path === `/api/v1/assets/${ASSET_ID}`)).toHaveLength(2);
  });

  it('names a missing acknowledgement reported by the server (400)', async () => {
    const { panel } = await openAsset('admin', detailOf(asset({ hostingHint: CLOUDFRONT })), {
      [ASSET_PATHS.decide(ASSET_ID, 'approve')]: apiError(
        400,
        'validation_failed',
        'The request is invalid.',
        [
          {
            path: 'acknowledgeThirdPartyHosting',
            message: 'Acknowledge third-party hosting to approve this asset.',
          },
        ],
      ),
    });
    await userEvent.click(within(panel).getByRole('button', { name: 'Approve' }));
    await userEvent.type(within(panel).getByLabelText(/Reason/), 'CDN for the shop');
    await userEvent.click(within(panel).getByRole('checkbox'));
    await userEvent.click(within(panel).getByRole('button', { name: 'Approve' }));
    const alert = await within(panel).findByRole('alert');
    expect(alert).toHaveTextContent('Third-party hosting must be acknowledged');
    expect(alert).toHaveTextContent('Acknowledge third-party hosting to approve this asset.');
    expect(within(panel).queryByRole('button', { name: 'Reload the asset' })).toBeNull();
  });

  it('cancels with the keyboard and returns to the actions', async () => {
    const { panel } = await openAsset('admin');
    within(panel).getByRole('button', { name: 'Reject' }).focus();
    await userEvent.keyboard('{Enter}');
    expect(within(panel).getByLabelText(/Reason/)).toBeInTheDocument();
    within(panel).getByRole('button', { name: 'Cancel' }).focus();
    await userEvent.keyboard('{Enter}');
    expect(buttons(panel)).toEqual(['Approve', 'Reject']);
  });
});
