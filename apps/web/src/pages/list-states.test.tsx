// Shared list-page states: permission-denied instead of raw 403s, and stale data after a failed refresh.
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiError, ok, renderAt, stubApi, type Handler } from '../testing/stub-api.tsx';
import { page } from './findings/test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const forbidden = apiError(403, 'forbidden', 'Missing permission.');

describe('List pages: permission denied', () => {
  it.each([
    ['/domains', 'GET /api/v1/domains'],
    ['/assets', 'GET /api/v1/assets?status=pending'],
    ['/scans', 'GET /api/v1/scans'],
    ['/findings', 'GET /api/v1/findings'],
    ['/advisories', 'GET /api/v1/advisories'],
  ])('%s shows a permission-denied state for a 403', async (path, request) => {
    stubApi('asset_owner', { [request]: forbidden });
    renderAt(path);
    expect(
      await screen.findByText('You do not have access to this information'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});

describe('List pages: stale data', () => {
  it('keeps the scan list on screen with a notice when a refresh fails, and retries', async () => {
    let fail = false;
    const scans: Handler = () =>
      fail ? apiError(500, 'internal_error', 'Boom.')() : ok(page([]))();
    stubApi('viewer', { 'GET /api/v1/scans': scans });
    renderAt('/scans');
    expect(await screen.findByText('No scans yet')).toBeInTheDocument();

    fail = true;
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await screen.findByText(/refresh failed — Boom\./)).toHaveTextContent(
      /Showing data from .* UTC/,
    );
    expect(screen.getByText('No scans yet')).toBeInTheDocument();

    fail = false;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await vi.waitFor(() => expect(screen.queryByText(/refresh failed/)).not.toBeInTheDocument());
  });

  it('offers a retry when the first load fails', async () => {
    let calls = 0;
    stubApi('viewer', {
      'GET /api/v1/advisories': () =>
        ++calls === 1 ? apiError(500, 'internal_error', 'Boom.')() : ok(page([]))(),
    });
    renderAt('/advisories');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load advisories');
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No advisories')).toBeInTheDocument();
  });
});
