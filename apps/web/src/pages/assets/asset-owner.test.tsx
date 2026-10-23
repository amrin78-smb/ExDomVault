// Asset detail: owner display and the owner picker (assets:approve), its user sources and errors.
import type { Asset, Role } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ADMIN_PATHS,
  ASSET_PATHS,
  apiError,
  ok,
  renderAt,
  stubApi,
  type Handler,
} from '../../testing/stub-api.tsx';
import { OWNER_ID, user, usersPage } from '../settings/test-data.ts';
import { ASSET_ID, asset, detailOf } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const ACTIVE_USERS = ADMIN_PATHS.users('?active=true&pageSize=100');
const OWNER = user({ id: OWNER_ID, email: 'owner@example.com', role: 'asset_owner' });

async function openOwner(role: Role, a: Asset = asset(), handlers: Record<string, Handler> = {}) {
  const calls = stubApi(role, {
    [ASSET_PATHS.detail(ASSET_ID)]: ok(detailOf(a)),
    [ACTIVE_USERS]: ok(usersPage([user(), OWNER])),
    ...handlers,
  });
  renderAt(`/assets/${ASSET_ID}`);
  const panel = within(await screen.findByRole('region', { name: 'Owner' }));
  return { calls, panel };
}

describe('Asset detail: owner', () => {
  it('shows the owner and explains asset-owner visibility, read-only for viewers', async () => {
    const { panel, calls } = await openOwner(
      'viewer',
      asset({ owner: { id: OWNER_ID, email: 'owner@example.com' } }),
    );
    expect(panel.getByText('owner@example.com')).toBeInTheDocument();
    expect(panel.getByText(/see only the assets they own and those assets/)).toBeInTheDocument();
    expect(panel.queryByRole('button', { name: 'Change owner' })).not.toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith('/api/v1/users'))).toBe(false);
  });

  it('assigns an owner from the active users list', async () => {
    const { panel, calls } = await openOwner('admin', asset(), {
      [ASSET_PATHS.setOwner(ASSET_ID)]: () =>
        ok({ asset: asset({ owner: { id: OWNER_ID, email: 'owner@example.com' } }) })(),
    });
    expect(panel.getByText('No owner assigned')).toBeInTheDocument();
    // Users are loaded only when the picker opens.
    expect(calls.some((c) => c.path.startsWith('/api/v1/users'))).toBe(false);
    await userEvent.click(panel.getByRole('button', { name: 'Change owner' }));

    const select = await panel.findByLabelText('Owner');
    expect(
      within(select)
        .getAllByRole('option')
        .map((o) => o.textContent),
    ).toEqual([
      'Unassigned',
      'analyst@example.com (Security analyst)',
      'owner@example.com (Asset owner)',
    ]);
    const save = panel.getByRole('button', { name: 'Save owner' });
    expect(save).toBeDisabled();
    await userEvent.selectOptions(select, OWNER_ID);
    await userEvent.click(save);

    expect(await panel.findByText('owner@example.com now owns shop.example.com.')).toHaveAttribute(
      'role',
      'status',
    );
    expect(panel.getByText('owner@example.com', { selector: 'span' })).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PATCH')).toMatchObject({
      path: `/api/v1/assets/${ASSET_ID}`,
      body: { ownerUserId: OWNER_ID },
    });
  });

  it('clears the owner with Unassigned', async () => {
    const { panel, calls } = await openOwner(
      'admin',
      asset({ owner: { id: OWNER_ID, email: 'owner@example.com' } }),
      { [ASSET_PATHS.setOwner(ASSET_ID)]: ok({ asset: asset() }) },
    );
    await userEvent.click(panel.getByRole('button', { name: 'Change owner' }));
    const select = await panel.findByLabelText('Owner');
    expect(select).toHaveValue(OWNER_ID);
    await userEvent.selectOptions(select, '');
    await userEvent.click(panel.getByRole('button', { name: 'Save owner' }));
    expect(await panel.findByText('shop.example.com no longer has an owner.')).toBeInTheDocument();
    expect(panel.getByText('No owner assigned')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ ownerUserId: null });
  });

  it('keeps an inactive current owner selectable', async () => {
    const { panel } = await openOwner(
      'admin',
      asset({ owner: { id: crypto.randomUUID(), email: 'gone@example.com' } }),
    );
    await userEvent.click(panel.getByRole('button', { name: 'Change owner' }));
    const select = await panel.findByLabelText('Owner');
    expect(
      within(select).getByRole('option', { name: 'gone@example.com (current, inactive)' }),
    ).toBeInTheDocument();
  });

  it('uses the assignable users list without users:manage', async () => {
    // A custom permission set: may approve assets but not manage users.
    const calls = stubApi('analyst', {
      'GET /api/v1/me': ok({
        user: {
          id: crypto.randomUUID(),
          email: 'lead@example.com',
          displayName: null,
          role: 'analyst',
        },
        permissions: ['assets:read', 'assets:approve', 'findings:assign'],
        authProvider: 'cloudflare_access',
      }),
      [ASSET_PATHS.detail(ASSET_ID)]: ok(detailOf()),
      [ADMIN_PATHS.assignable]: ok({
        items: [
          { id: OWNER_ID, email: 'owner@example.com', displayName: null, role: 'asset_owner' },
        ],
      }),
    });
    renderAt(`/assets/${ASSET_ID}`);
    const panel = within(await screen.findByRole('region', { name: 'Owner' }));
    await userEvent.click(panel.getByRole('button', { name: 'Change owner' }));
    const select = await panel.findByLabelText('Owner');
    expect(within(select).getAllByRole('option')).toHaveLength(2);
    expect(calls.some((c) => c.path === '/api/v1/users/assignable')).toBe(true);
    expect(calls.some((c) => c.path.startsWith('/api/v1/users?'))).toBe(false);
  });

  it('shows errors from loading users and from saving', async () => {
    const { panel } = await openOwner('admin', asset(), {
      [ASSET_PATHS.setOwner(ASSET_ID)]: apiError(
        400,
        'validation_failed',
        'The request is invalid.',
        [{ path: 'ownerUserId', message: 'The owner must be an active user.' }],
      ),
    });
    await userEvent.click(panel.getByRole('button', { name: 'Change owner' }));
    await userEvent.selectOptions(await panel.findByLabelText('Owner'), OWNER_ID);
    await userEvent.click(panel.getByRole('button', { name: 'Save owner' }));
    const alert = await panel.findByRole('alert');
    expect(alert).toHaveTextContent('The owner was not changed');
    expect(alert).toHaveTextContent('The owner must be an active user.');
    expect(panel.getByText('No owner assigned')).toBeInTheDocument();
  });

  it('shows a load error with a way back', async () => {
    const { panel } = await openOwner('admin', asset(), {
      [ACTIVE_USERS]: apiError(503, 'service_unavailable', 'The database is unavailable.'),
    });
    await userEvent.click(panel.getByRole('button', { name: 'Change owner' }));
    expect(await panel.findByRole('alert')).toHaveTextContent('Could not load users');
    await userEvent.click(panel.getByRole('button', { name: 'Cancel' }));
    expect(panel.getByRole('button', { name: 'Change owner' })).toBeInTheDocument();
  });
});
