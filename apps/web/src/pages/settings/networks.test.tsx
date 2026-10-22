import type { ApprovedNetwork } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { addMonthsIso } from '../../lib/format.ts';
import { ok, renderAt, stubApi } from '../../testing/stub-api.tsx';

const DAY_MS = 86_400_000;
const NET_ID = '3c1e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f60';

const network = (overrides: Partial<ApprovedNetwork> = {}): ApprovedNetwork => ({
  id: NET_ID,
  cidr: '203.0.113.0/24',
  label: 'Head office web servers',
  reason: 'Our own colocated web servers at the head office',
  reference: 'CHG-1234',
  createdBy: { id: crypto.randomUUID(), email: 'admin@example.com' },
  createdAt: '2026-10-01T10:00:00.000Z',
  expiresAt: new Date(Date.now() + 200 * DAY_MS).toISOString(),
  revokedAt: null,
  revokeReason: null,
  ...overrides,
});

const baseHandlers = {
  'GET /api/v1/workers': ok({ items: [] }),
};

const section = () => screen.findByRole('region', { name: 'Approved networks' });

afterEach(() => vi.unstubAllGlobals());

describe('Settings: approved networks', () => {
  it('lists networks with review-date emphasis and revoked state', async () => {
    stubApi('admin', {
      ...baseHandlers,
      'GET /api/v1/approved-networks': ok({
        items: [
          network(),
          network({
            id: crypto.randomUUID(),
            cidr: '198.51.100.0/28',
            label: 'Mail relay',
            reference: null,
            expiresAt: new Date(Date.now() + 10.5 * DAY_MS).toISOString(),
          }),
          network({
            id: crypto.randomUUID(),
            cidr: '2001:db8:1::/48',
            label: 'Old datacentre',
            revokedAt: '2026-10-10T10:00:00.000Z',
            revokeReason: 'Datacentre decommissioned last week',
          }),
        ],
      }),
    });
    renderAt('/settings');
    const card = await section();
    expect(within(card).getByText(/Port probes and service identification only/)).toBeVisible();
    expect(within(card).getByText(/do not need an approval/)).toBeVisible();

    const head = await within(card).findByRole('listitem', { name: 'Head office web servers' });
    expect(within(head).getByText('203.0.113.0/24')).toHaveClass('font-mono');
    expect(within(head).getByText('Reference: CHG-1234')).toBeInTheDocument();
    expect(within(head).getByText(/Approved by admin@example.com/)).toBeInTheDocument();
    expect(within(head).getByTestId('review-date').className).not.toMatch(/amber|red/);

    const mail = within(card).getByRole('listitem', { name: 'Mail relay' });
    const review = within(mail).getByTestId('review-date');
    expect(review).toHaveTextContent('(in 10 days)');
    expect(review.className).toContain('amber');

    const old = within(card).getByRole('listitem', { name: 'Old datacentre' });
    expect(within(old).getByText('Revoked')).toBeInTheDocument();
    expect(within(old).getByText(/Datacentre decommissioned/)).toBeInTheDocument();
    expect(within(old).queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
  });

  it('approves a network with a default review date one year ahead', async () => {
    let items: ApprovedNetwork[] = [];
    const calls = stubApi('admin', {
      ...baseHandlers,
      'GET /api/v1/approved-networks': () => ok({ items })(),
      'POST /api/v1/approved-networks': () => {
        items = [network()];
        return { status: 201, body: items[0] };
      },
    });
    renderAt('/settings');
    const card = await section();
    expect(await within(card).findByText('No approved networks')).toBeInTheDocument();
    expect(within(card).getByLabelText('Review by')).toHaveValue(addMonthsIso(12));

    const submit = within(card).getByRole('button', { name: 'Approve network' });
    await userEvent.type(within(card).getByLabelText('Network (CIDR)'), '203.0.113.0/24');
    await userEvent.type(within(card).getByLabelText('Label'), 'Head office web servers');
    await userEvent.type(within(card).getByLabelText('Reason'), 'short');
    expect(submit).toBeDisabled();
    await userEvent.type(within(card).getByLabelText('Reason'), ' but now long enough');
    await userEvent.click(submit);

    expect(
      await within(card).findByRole('listitem', { name: 'Head office web servers' }),
    ).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      cidr: '203.0.113.0/24',
      label: 'Head office web servers',
      reason: 'short but now long enough',
      reference: null,
      reviewBy: addMonthsIso(12),
    });
    expect(within(card).getByLabelText('Network (CIDR)')).toHaveValue('');
  });

  it('shows server validation errors', async () => {
    stubApi('admin', {
      ...baseHandlers,
      'GET /api/v1/approved-networks': ok({ items: [] }),
      'POST /api/v1/approved-networks': () => ({
        status: 400,
        body: {
          error: {
            code: 'validation_failed',
            message: 'The request is invalid.',
            requestId: 'req-42',
            details: [{ path: 'cidr', message: 'Private address ranges cannot be approved.' }],
          },
        },
      }),
    });
    renderAt('/settings');
    const card = await section();
    await within(card).findByText('No approved networks');
    await userEvent.type(within(card).getByLabelText('Network (CIDR)'), '10.0.0.0/8');
    await userEvent.type(within(card).getByLabelText('Label'), 'Internal');
    await userEvent.type(within(card).getByLabelText('Reason'), 'Internal network range');
    await userEvent.click(within(card).getByRole('button', { name: 'Approve network' }));
    const alert = await within(card).findByRole('alert');
    expect(alert).toHaveTextContent('The network was not approved');
    expect(alert).toHaveTextContent('Private address ranges cannot be approved.');
    expect(alert).toHaveTextContent('Request ID: req-42');
  });

  it('revokes a network after a reason and confirmation', async () => {
    let revoked = false;
    const calls = stubApi('admin', {
      ...baseHandlers,
      'GET /api/v1/approved-networks': () =>
        ok({
          items: [
            revoked
              ? network({
                  revokedAt: '2026-10-22T10:00:00.000Z',
                  revokeReason: 'Servers moved to a provider',
                })
              : network(),
          ],
        })(),
      [`POST /api/v1/approved-networks/${NET_ID}/revoke`]: () => {
        revoked = true;
        return ok(network({ revokedAt: '2026-10-22T10:00:00.000Z' }))();
      },
    });
    renderAt('/settings');
    const card = await section();
    const row = await within(card).findByRole('listitem', { name: 'Head office web servers' });
    await userEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
    const dialog = within(row).getByRole('alertdialog', {
      name: 'Confirm revoking 203.0.113.0/24',
    });
    const confirm = within(dialog).getByRole('button', { name: 'Revoke approval' });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByRole('textbox'), 'Servers moved to a provider');
    await userEvent.click(confirm);

    expect(await within(card).findByText('Revoked')).toBeInTheDocument();
    expect(calls.find((c) => c.path.endsWith('/revoke'))?.body).toEqual({
      reason: 'Servers moved to a provider',
    });
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('is hidden from users without scan policy permission', async () => {
    const calls = stubApi('analyst', {});
    renderAt('/settings');
    expect(await screen.findByText('Administrators only')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Approved networks' })).not.toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith('/api/v1/approved-networks'))).toBe(false);
  });
});
