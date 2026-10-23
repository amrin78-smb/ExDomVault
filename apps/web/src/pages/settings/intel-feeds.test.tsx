// Settings → Intelligence feeds: status per feed, errors, permissions and the manual sync.
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SOFTWARE_PATHS, apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { feed, feeds } from '../software/test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const TAB = '/settings?tab=intel';

describe('Settings: intelligence feeds', () => {
  it('shows each feed with last success, last attempt, items, source version and NVD backlog', async () => {
    stubApi('admin', { [SOFTWARE_PATHS.feeds]: ok(feeds()) });
    renderAt(TAB);
    const nav = screen.getByRole('navigation', { name: 'Settings sections' });
    expect(await within(nav).findByRole('link', { name: 'Intelligence feeds' })).toHaveAttribute(
      'aria-current',
      'page',
    );

    const eol = within(await screen.findByRole('listitem', { name: 'endoflife.date' }));
    expect(eol.getByText('Up to date')).toBeInTheDocument();
    expect(eol.getByText('412')).toBeInTheDocument();
    expect(eol.getAllByText('Oct 23, 2026, 2:00 AM UTC')).toHaveLength(2);

    const kev = within(
      screen.getByRole('listitem', { name: 'CISA Known Exploited Vulnerabilities' }),
    );
    expect(kev.getByText('2026.10.22')).toBeInTheDocument();
    expect(kev.getByText('37')).toBeInTheDocument();

    const nvd = within(
      screen.getByRole('listitem', { name: 'NVD (National Vulnerability Database)' }),
    );
    expect(
      nvd.getByText(/7 known-exploited CVEs are waiting for their NVD record/),
    ).toBeInTheDocument();
    // A failed attempt is stated in words, not colour alone.
    expect(nvd.getByText('Last attempt failed')).toBeInTheDocument();
    expect(nvd.getByText('http_429')).toBeInTheDocument();
  });

  it('marks a feed that has never synchronised', async () => {
    stubApi('admin', {
      [SOFTWARE_PATHS.feeds]: ok({
        feeds: [feed({ lastSuccessAt: null, lastAttemptAt: null, items: 0 })],
      }),
    });
    renderAt(TAB);
    const eol = within(await screen.findByRole('listitem', { name: 'endoflife.date' }));
    expect(eol.getByText('Never synchronised')).toBeInTheDocument();
    expect(eol.getAllByText('Never')).toHaveLength(2);
  });

  it('lets an administrator sync now and refreshes the status', async () => {
    let synced = false;
    const calls = stubApi('admin', {
      [SOFTWARE_PATHS.feeds]: () => ({
        status: 200,
        body: synced
          ? { feeds: [feed({ items: 500, lastSuccessAt: '2026-10-23T09:00:00.000Z' })] }
          : feeds(),
      }),
      [SOFTWARE_PATHS.sync]: () => {
        synced = true;
        return { status: 200, body: { feeds: [] } };
      },
    });
    renderAt(TAB);
    await screen.findByRole('listitem', { name: 'endoflife.date' });
    await userEvent.click(screen.getByRole('button', { name: 'Sync now' }));
    expect(await screen.findByText(/Sync finished/)).toHaveAttribute('role', 'status');
    expect(await screen.findByText('500')).toBeInTheDocument();
    expect(
      calls.filter((c) => c.method === 'POST' && c.path === '/api/v1/intel/feeds/sync'),
    ).toHaveLength(1);
  });

  it('shows a failed sync as an error and keeps the status', async () => {
    stubApi('admin', {
      [SOFTWARE_PATHS.feeds]: ok(feeds()),
      [SOFTWARE_PATHS.sync]: apiError(503, 'service_unavailable', 'A feed could not be reached.'),
    });
    renderAt(TAB);
    await screen.findByRole('listitem', { name: 'endoflife.date' });
    await userEvent.click(screen.getByRole('button', { name: 'Sync now' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('The feeds were not synchronised');
    expect(alert).toHaveTextContent('A feed could not be reached.');
    expect(alert).toHaveTextContent('req-test');
    expect(screen.getByRole('listitem', { name: 'endoflife.date' })).toBeInTheDocument();
  });

  it('hides the sync button from roles without settings:manage', async () => {
    stubApi('analyst', { [SOFTWARE_PATHS.feeds]: ok(feeds()) });
    renderAt(TAB);
    await screen.findByRole('listitem', { name: 'endoflife.date' });
    expect(screen.queryByRole('button', { name: 'Sync now' })).not.toBeInTheDocument();
  });

  it('shows the permission-denied state when the API refuses the status', async () => {
    stubApi('viewer', { [SOFTWARE_PATHS.feeds]: apiError(403, 'forbidden', 'Forbidden') });
    renderAt(TAB);
    expect(await screen.findByText('Feed status is visible to administrators')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('is listed for read-only roles (they hold findings:read)', async () => {
    stubApi('viewer', {});
    renderAt('/settings');
    const nav = await screen.findByRole('navigation', { name: 'Settings sections' });
    expect(
      await within(nav).findByRole('link', { name: 'Intelligence feeds' }),
    ).toBeInTheDocument();
  });
});
