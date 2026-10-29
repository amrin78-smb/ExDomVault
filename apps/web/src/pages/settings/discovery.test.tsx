// Settings → Discovery (Milestone 15): organisation names for network-ownership discovery.
import type { DiscoverySettings } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';

afterEach(() => vi.unstubAllGlobals());

const PATH = '/api/v1/settings/discovery';

describe('Settings: discovery organisation names', () => {
  it('is a tab for administrators only', async () => {
    stubApi('analyst', {});
    renderAt('/settings');
    await screen.findByRole('navigation', { name: 'Settings sections' });
    expect(screen.queryByRole('link', { name: 'Discovery' })).toBeNull();
  });

  it('edits the names as chips and saves them', async () => {
    let saved: DiscoverySettings | null = null;
    const calls = stubApi('admin', {
      [`GET ${PATH}`]: ok({ orgNames: ['Thai Union'], updatedAt: null }),
      [`PUT ${PATH}`]: (body) => {
        saved = body as DiscoverySettings;
        return {
          status: 200,
          body: { ...(body as object), updatedAt: '2026-10-29T10:00:00.000Z' },
        };
      },
    });
    renderAt('/settings?tab=discovery');
    const form = await screen.findByRole('form', { name: 'Organisation names' });
    const chips = within(form).getByRole('list', { name: 'Configured organisation names' });
    expect(
      within(chips)
        .getAllByRole('listitem')
        .map((li) => li.textContent),
    ).toEqual(['Thai Union']);
    const save = within(form).getByRole('button', { name: 'Save names' });
    expect(save).toBeDisabled();

    const input = within(form).getByLabelText('Add a name');
    await userEvent.type(input, 'thai union{Enter}');
    expect(screen.getByText('“thai union” is already in the list.')).toBeInTheDocument();
    await userEvent.clear(input);
    await userEvent.type(input, '  TU   Europe {Enter}');
    await userEvent.click(within(form).getByRole('button', { name: 'Remove Thai Union' }));
    await userEvent.type(input, 'Thai Union Group');
    await userEvent.click(within(form).getByRole('button', { name: 'Add' }));
    expect(
      within(chips)
        .getAllByRole('listitem')
        .map((li) => li.textContent),
    ).toEqual(['TU Europe', 'Thai Union Group']);
    await userEvent.click(save);
    expect(await screen.findByText(/Saved\. Matching uses the new names/)).toBeInTheDocument();
    expect(saved).toEqual({ orgNames: ['TU Europe', 'Thai Union Group'] });
    expect(calls.filter((c) => c.method === 'PUT')).toHaveLength(1);
    expect(screen.getByText(/never approves a range for scanning/)).toBeInTheDocument();
  });

  it('shows a server validation error', async () => {
    stubApi('admin', {
      [`GET ${PATH}`]: ok({ orgNames: [], updatedAt: null }),
      [`PUT ${PATH}`]: apiError(400, 'validation_failed', 'The request is invalid.'),
    });
    renderAt('/settings?tab=discovery');
    const form = await screen.findByRole('form', { name: 'Organisation names' });
    expect(within(form).getByText(/No names: no network will be shown as yours/)).toBeVisible();
    await userEvent.type(within(form).getByLabelText('Add a name'), 'Thai Union{Enter}');
    await userEvent.click(within(form).getByRole('button', { name: 'Save names' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Could not save the organisation names',
    );
  });
});
