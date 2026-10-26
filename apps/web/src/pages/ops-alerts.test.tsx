// The global operational alert banner in the app shell: kinds, admin link, dismissal, polling and
// fail-silent behaviour.
import type { OpsAlertsResponse } from '@exdomainvault/shared';
import { act, cleanup, fireEvent, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ALERTS_POLL_MS } from '../lib/ops-alerts.ts';
import { OPS_PATHS, apiError, ok, renderAt, stubApi } from '../testing/stub-api.tsx';

type Alert = OpsAlertsResponse['alerts'][number];

const OUTAGE: Alert = {
  kind: 'worker_outage',
  severity: 'critical',
  message: 'Scanning is delayed.',
  since: '2026-10-23T08:00:00.000Z',
};
const FEEDS: Alert = {
  kind: 'feeds_stale',
  severity: 'warning',
  message: 'CISA KEV has not synchronised for 3 days.',
  since: '2026-10-20T00:00:00.000Z',
};
const DISABLED: Alert = {
  kind: 'active_scanning_disabled',
  severity: 'info',
  message: 'Only passive checks run until an administrator enables active scanning.',
  since: null,
};

const region = () => screen.getByRole('status', { name: 'System alerts' });
const alertsCalls = (calls: { path: string }[]) =>
  calls.filter((c) => c.path === '/api/v1/ops/alerts').length;

beforeEach(() => sessionStorage.clear());
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Operational alert banner', () => {
  it('announces a worker outage politely and links admins to System health', async () => {
    stubApi('admin', { [OPS_PATHS.alerts]: ok({ alerts: [OUTAGE] }) });
    renderAt('/');
    expect(
      await screen.findByText(
        'Scanning is delayed: the scanning worker has not been seen since Oct 23, 2026, 8:00 AM UTC.',
      ),
    ).toBeInTheDocument();
    expect(region()).toHaveAttribute('aria-live', 'polite');
    expect(within(region()).getByRole('link', { name: 'Open System health' })).toHaveAttribute(
      'href',
      '/settings?tab=health',
    );
    // Non-blocking: the page underneath still renders.
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();
  });

  it('gives non-admins the outage notice without the System health link', async () => {
    stubApi('viewer', { [OPS_PATHS.alerts]: ok({ alerts: [OUTAGE] }) });
    renderAt('/');
    expect(await screen.findByText(/Scanning is delayed/)).toBeInTheDocument();
    expect(within(region()).queryByRole('link')).toBeNull();
  });

  it('shows stale feeds and disabled active scanning as warning and info', async () => {
    stubApi('admin', { [OPS_PATHS.alerts]: ok({ alerts: [FEEDS, DISABLED] }) });
    renderAt('/');
    const feeds = (await screen.findByText('Intelligence feeds are out of date')).closest('li');
    expect(feeds).toHaveAttribute('data-kind', 'feeds_stale');
    expect(feeds).toHaveTextContent(FEEDS.message);
    expect(feeds?.className).toContain('amber');
    const disabled = screen.getByText('Active scanning is disabled').closest('li');
    expect(disabled).toHaveTextContent(DISABLED.message);
    expect(disabled?.className).toContain('sky');
  });

  it('can be dismissed for the session, and stays dismissed after a reload', async () => {
    stubApi('admin', { [OPS_PATHS.alerts]: ok({ alerts: [OUTAGE, DISABLED] }) });
    renderAt('/');
    await userEvent.click(
      await screen.findByRole('button', { name: /^Dismiss: Scanning is delayed/ }),
    );
    expect(screen.queryByText(/Scanning is delayed/)).toBeNull();
    expect(screen.getByText('Active scanning is disabled')).toBeInTheDocument();

    // A fresh render (page reload) in the same session keeps it dismissed.
    cleanup();
    renderAt('/');
    expect(await screen.findByText('Active scanning is disabled')).toBeInTheDocument();
    expect(screen.queryByText(/Scanning is delayed/)).toBeNull();
  });

  it('shows a new occurrence of a dismissed alert again', async () => {
    sessionStorage.setItem(
      'exdomainvault.dismissedAlerts',
      JSON.stringify(['worker_outage@2026-10-22T00:00:00.000Z']),
    );
    stubApi('admin', { [OPS_PATHS.alerts]: ok({ alerts: [OUTAGE] }) });
    renderAt('/');
    expect(await screen.findByText(/Scanning is delayed/)).toBeInTheDocument();
  });

  it('still dismisses when session storage is unavailable', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    stubApi('admin', { [OPS_PATHS.alerts]: ok({ alerts: [OUTAGE] }) });
    renderAt('/');
    await userEvent.click(
      await screen.findByRole('button', { name: /^Dismiss: Scanning is delayed/ }),
    );
    expect(screen.queryByText(/Scanning is delayed/)).toBeNull();
  });

  it.each([
    ['a 403', apiError(403, 'forbidden', 'Not allowed.')],
    ['a server error', apiError(500, 'internal_error', 'Boom.')],
    ['a malformed body', ok({ alerts: [{ kind: 'unknown' }] })],
  ])('fails silently on %s', async (_label, handler) => {
    const calls = stubApi('admin', { [OPS_PATHS.alerts]: handler });
    renderAt('/');
    await vi.waitFor(() => expect(alertsCalls(calls)).toBeGreaterThan(0));
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument();
    expect(region()).toBeEmptyDOMElement();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('polls every two minutes and re-checks when the window regains focus', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let alerts: Alert[] = [];
    const calls = stubApi('admin', { [OPS_PATHS.alerts]: () => ok({ alerts })() });
    renderAt('/');
    await vi.waitFor(() => expect(alertsCalls(calls)).toBe(1));
    expect(region()).toBeEmptyDOMElement();

    alerts = [OUTAGE];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ALERTS_POLL_MS);
    });
    expect(await screen.findByText(/Scanning is delayed/)).toBeInTheDocument();
    expect(alertsCalls(calls)).toBe(2);

    alerts = [];
    act(() => {
      fireEvent.focus(window);
    });
    await vi.waitFor(() => expect(alertsCalls(calls)).toBe(3));
    await vi.waitFor(() => expect(region()).toBeEmptyDOMElement());
  });
});
