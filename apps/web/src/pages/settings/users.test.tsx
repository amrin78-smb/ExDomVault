// Settings → Users: permission gating, add-user validation, guard messages and own-row controls.
import type { User } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ADMIN_PATHS,
  apiError,
  meAs,
  ok,
  renderAt,
  stubApi,
  type Handler,
} from '../../testing/stub-api.tsx';
import { OTHER_ID, SELF, SELF_ID, user, usersPage } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const LIST = ADMIN_PATHS.users('?page=1&pageSize=25');

function openUsers(items: User[] = [SELF, user()], handlers: Record<string, Handler> = {}) {
  const calls = stubApi('admin', {
    'GET /api/v1/me': meAs('admin', SELF_ID, 'admin@example.com'),
    [LIST]: ok(usersPage(items)),
    ...handlers,
  });
  const router = renderAt('/settings?tab=users');
  return { calls, router };
}

const usersTable = async () => within(await screen.findByRole('table', { name: 'Users' }));
const rowOf = async (email: string) =>
  (await usersTable()).getByRole('rowheader', { name: new RegExp(email) }).closest('tr')!;

/** A message announced through a live status region. */
async function announced(text: string | RegExp) {
  const el = await screen.findByText(text);
  expect(el.closest('[role="status"]')).not.toBeNull();
  return el;
}

const usersCard = () => within(screen.getByRole('region', { name: 'Users' }));

async function manage(email: string) {
  await userEvent.click(
    within(await rowOf(email)).getByRole('button', { name: `Manage ${email}` }),
  );
  return within(screen.getByRole('group', { name: `Manage ${email}` }));
}

describe('Settings: users section visibility', () => {
  it('is offered only to user administrators', async () => {
    const calls = stubApi('analyst', {});
    renderAt('/settings?tab=users');
    expect(await screen.findByText('Administrators only')).toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: 'Settings sections' });
    expect(within(nav).queryByRole('link', { name: 'Users' })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: 'Audit log' })).not.toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'Scan profiles' })).toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith('/api/v1/users'))).toBe(false);
  });

  it('lists users with role, status, sign-in state and last login', async () => {
    openUsers([
      SELF,
      user(),
      user({
        id: crypto.randomUUID(),
        email: 'new@example.com',
        displayName: null,
        role: 'viewer',
        isActive: false,
        signedIn: false,
        lastLoginAt: null,
      }),
    ]);
    const nav = await screen.findByRole('navigation', { name: 'Settings sections' });
    expect(within(nav).getByRole('link', { name: 'Users' })).toHaveAttribute(
      'aria-current',
      'page',
    );

    const self = within(await rowOf('admin@example.com'));
    expect(self.getByText('You')).toBeInTheDocument();
    expect(self.getByText('Administrator')).toBeInTheDocument();

    const fresh = within(await rowOf('new@example.com'));
    expect(fresh.getByText('Viewer')).toBeInTheDocument();
    expect(fresh.getByText('Inactive')).toBeInTheDocument();
    expect(fresh.getByText('Not yet')).toBeInTheDocument();
    expect(fresh.getByText('Never')).toBeInTheDocument();
  });

  it('keeps filters in the URL and sends them to the API', async () => {
    const { calls, router } = openUsers([SELF, user()], {
      [ADMIN_PATHS.users('?page=1&pageSize=25&role=admin')]: ok(usersPage([SELF])),
      [ADMIN_PATHS.users('?page=1&pageSize=25&q=ada&role=admin')]: ok(usersPage([SELF])),
    });
    await usersTable();
    await userEvent.selectOptions(usersCard().getByLabelText('Role'), 'admin');
    expect(router.state.location.search).toBe('?tab=users&role=admin');
    await userEvent.type(usersCard().getByLabelText('Email or name'), 'ada');
    await userEvent.click(usersCard().getByRole('button', { name: 'Search' }));
    expect(router.state.location.search).toBe('?tab=users&role=admin&q=ada');
    await screen.findByRole('table', { name: 'Users' });
    expect(calls.map((c) => c.path)).toContain('/api/v1/users?page=1&pageSize=25&q=ada&role=admin');
  });
});

describe('Settings: add a user', () => {
  it('explains the Cloudflare Access requirement and first sign-in binding', async () => {
    openUsers();
    const form = within(await screen.findByRole('form', { name: 'Add a user' }));
    expect(form.getByText(/also be allowed by the Cloudflare Access policy/)).toBeInTheDocument();
    expect(form.getByText(/identity is bound on first sign-in/)).toBeInTheDocument();
  });

  it('validates the email before sending', async () => {
    const { calls } = openUsers();
    const form = within(await screen.findByRole('form', { name: 'Add a user' }));
    await userEvent.type(form.getByLabelText('Email'), 'not-an-email');
    await userEvent.click(form.getByRole('button', { name: 'Add user' }));
    const email = form.getByLabelText('Email');
    expect(email).toHaveAttribute('aria-invalid', 'true');
    expect(email).toHaveAccessibleDescription('Enter a valid email address.');
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('adds a user and reports it', async () => {
    const { calls } = openUsers([SELF], {
      [ADMIN_PATHS.createUser]: () => ({
        status: 201,
        body: {
          user: user({
            id: crypto.randomUUID(),
            email: 'owner@example.com',
            displayName: 'Own Er',
            role: 'asset_owner',
            signedIn: false,
            lastLoginAt: null,
          }),
        },
      }),
    });
    const form = within(await screen.findByRole('form', { name: 'Add a user' }));
    await userEvent.type(form.getByLabelText('Email'), ' owner@example.com ');
    await userEvent.type(form.getByLabelText('Name (optional)'), 'Own Er');
    await userEvent.selectOptions(form.getByLabelText('Role'), 'asset_owner');
    await userEvent.click(form.getByRole('button', { name: 'Add user' }));

    await announced(/owner@example\.com was added as Asset owner/);
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      email: 'owner@example.com',
      displayName: 'Own Er',
      role: 'asset_owner',
    });
    expect(form.getByLabelText('Email')).toHaveValue('');
  });

  it('shows the duplicate-email conflict in plain words', async () => {
    openUsers([SELF], {
      [ADMIN_PATHS.createUser]: apiError(409, 'conflict', 'Conflict.', [
        { path: 'email', message: 'email already exists' },
      ]),
    });
    const form = within(await screen.findByRole('form', { name: 'Add a user' }));
    await userEvent.type(form.getByLabelText('Email'), 'admin@example.com');
    await userEvent.click(form.getByRole('button', { name: 'Add user' }));
    const alert = await form.findByRole('alert');
    expect(alert).toHaveTextContent('The user was not added');
    expect(alert).toHaveTextContent('A user with this email address already exists.');
    expect(alert).toHaveTextContent('Request ID: req-test');
  });
});

describe('Settings: editing users', () => {
  it('disables role and deactivation controls on the signed-in user’s own row', async () => {
    openUsers();
    const editor = await manage('admin@example.com');
    expect(editor.getByText(/This is your own account/)).toBeInTheDocument();
    expect(editor.getByLabelText('Role')).toBeDisabled();
    expect(editor.getByRole('button', { name: 'Change role' })).toBeDisabled();
    expect(editor.getByRole('button', { name: 'Deactivate' })).toBeDisabled();
    expect(editor.getByLabelText('Display name')).toBeEnabled();
  });

  it('changes a role after an announced confirmation', async () => {
    let items = [SELF, user()];
    const { calls } = openUsers(undefined, {
      [LIST]: () => ok(usersPage(items))(),
      [ADMIN_PATHS.updateUser(OTHER_ID)]: () => {
        items = [SELF, user({ role: 'admin' })];
        return ok({ user: items[1] })();
      },
    });
    const editor = await manage('analyst@example.com');
    await userEvent.selectOptions(editor.getByLabelText('Role'), 'admin');
    await userEvent.click(editor.getByRole('button', { name: 'Change role' }));

    const dialog = editor.getByRole('alertdialog', {
      name: 'Change the role of Ana Lyst (analyst@example.com) from Security analyst to Administrator?',
    });
    expect(dialog).toHaveFocus();
    expect(dialog).toHaveAccessibleDescription(/Administrators can manage users/);
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm role change' }));

    await announced(/analyst@example\.com is now Administrator\./);
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ role: 'admin' });
    expect(
      within(await rowOf('analyst@example.com')).getByText('Administrator'),
    ).toBeInTheDocument();
  });

  it('cancels a confirmation with Escape without sending anything', async () => {
    const { calls } = openUsers();
    const editor = await manage('analyst@example.com');
    await userEvent.click(editor.getByRole('button', { name: 'Deactivate' }));
    expect(editor.getByRole('alertdialog', { name: /Deactivate Ana Lyst/ })).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    expect(editor.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false);
  });

  it('explains the last-administrator guard when deactivating', async () => {
    const other = user({ role: 'admin', email: 'boss@example.com', displayName: null });
    const { calls } = openUsers([SELF, other], {
      [ADMIN_PATHS.updateUser(OTHER_ID)]: apiError(409, 'conflict', 'Conflict.', [
        { path: 'isActive', message: 'last admin' },
      ]),
    });
    const editor = await manage('boss@example.com');
    await userEvent.click(editor.getByRole('button', { name: 'Deactivate' }));
    await userEvent.click(editor.getByRole('button', { name: 'Confirm deactivation' }));
    const alert = await editor.findByRole('alert');
    expect(alert).toHaveTextContent('The change was not saved');
    expect(alert).toHaveTextContent(
      'This is the last active administrator, so they cannot be deactivated.',
    );
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ isActive: false });
  });

  it('explains the last-administrator guard when demoting', async () => {
    const other = user({ role: 'admin', email: 'boss@example.com', displayName: null });
    openUsers([SELF, other], {
      [ADMIN_PATHS.updateUser(OTHER_ID)]: apiError(409, 'conflict', 'Conflict.', [
        { path: 'role', message: 'last admin' },
      ]),
    });
    const editor = await manage('boss@example.com');
    await userEvent.selectOptions(editor.getByLabelText('Role'), 'viewer');
    await userEvent.click(editor.getByRole('button', { name: 'Change role' }));
    await userEvent.click(editor.getByRole('button', { name: 'Confirm role change' }));
    expect(await editor.findByRole('alert')).toHaveTextContent(
      'This is the last active administrator, so their role cannot be changed.',
    );
  });

  it('explains the self guard if the server refuses a self change', async () => {
    openUsers(undefined, {
      [ADMIN_PATHS.updateUser(SELF_ID)]: apiError(409, 'conflict', 'Conflict.', [
        { path: 'isActive', message: 'self' },
      ]),
    });
    // The UI disables self deactivation; renaming is allowed and goes to the server.
    const editor = await manage('admin@example.com');
    const name = editor.getByLabelText('Display name');
    await userEvent.clear(name);
    await userEvent.type(name, 'Ada');
    await userEvent.click(editor.getByRole('button', { name: 'Save name' }));
    expect(await editor.findByRole('alert')).toHaveTextContent(
      'You cannot deactivate your own account.',
    );
  });

  it('activates an inactive user without a confirmation and renames users', async () => {
    let items = [SELF, user({ isActive: false })];
    const { calls } = openUsers(undefined, {
      [LIST]: () => ok(usersPage(items))(),
      [ADMIN_PATHS.updateUser(OTHER_ID)]: (body) => {
        const patch = body as Partial<User>;
        items = [SELF, { ...items[1]!, ...patch }];
        return ok({ user: items[1] })();
      },
    });
    let editor = await manage('analyst@example.com');
    await userEvent.click(editor.getByRole('button', { name: 'Activate' }));
    await announced(/analyst@example\.com was activated\./);

    editor = await manage('analyst@example.com');
    const name = editor.getByLabelText('Display name');
    await userEvent.clear(name);
    await userEvent.click(editor.getByRole('button', { name: 'Save name' }));
    await announced(/analyst@example\.com's name was cleared\./);
    expect(calls.filter((c) => c.method === 'PATCH').map((c) => c.body)).toEqual([
      { isActive: true },
      { displayName: null },
    ]);
  });
});
