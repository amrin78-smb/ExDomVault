// Settings → System health: rendering of every block, permissions, auto-refresh and stale data.
import type { OpsHealthResponse } from '@exdomainvault/shared';
import { act, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HEALTH_REFRESH_MS } from '../../components/settings/SystemHealthSection.tsx';
import { OPS_PATHS, apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { feeds } from '../software/test-data.ts';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const TAB = '/settings?tab=health';

function health(overrides: Partial<OpsHealthResponse> = {}): OpsHealthResponse {
  return {
    generatedAt: '2026-10-23T10:00:00.000Z',
    workers: [
      {
        id: '0b8f3c1e-7a2d-4e5f-9a1b-2c3d4e5f6a7b',
        name: 'home-1',
        lastSeenAt: '2026-10-23T09:59:00.000Z',
        status: 'online',
        version: '0.12.0',
      },
      {
        id: '1c9a4d2f-8b3e-4f60-8b2c-3d4e5f6a7b8c',
        name: 'spare',
        lastSeenAt: null,
        status: 'never_seen',
        version: null,
      },
    ],
    outage: { active: false, since: null, queuedJobs: 0 },
    queue: {
      queued: 4,
      running: 1,
      oldestQueuedAgeSeconds: 754,
      byProfile: [
        { profile: 'passive', queued: 3, running: 1 },
        { profile: 'quick', queued: 1, running: 0 },
      ],
    },
    scans: {
      last24h: {
        succeeded: 19,
        failed: 1,
        cancelled: 2,
        successRate: 0.95,
        p50DurationSeconds: 42,
        p95DurationSeconds: 380,
      },
      last7d: {
        succeeded: 0,
        failed: 0,
        cancelled: 0,
        successRate: null,
        p50DurationSeconds: null,
        p95DurationSeconds: null,
      },
    },
    failuresByCode: [
      { code: 'dns_timeout', count: 3 },
      { code: 'scope_rejected', count: 1 },
    ],
    database: { ok: true, latencyMs: 12 },
    feeds: feeds().feeds,
    retention: {
      lastRunAt: '2026-10-23T03:00:00.000Z',
      deletedLastRun: 1520,
      policy: { observationDays: 180, scanJobDays: 365 },
    },
    ...overrides,
  };
}

describe('Settings: system health', () => {
  it('shows workers, queue, scan outcomes, failures, database, feeds and retention', async () => {
    stubApi('admin', { [OPS_PATHS.health]: ok(health()) });
    renderAt(TAB);
    const nav = screen.getByRole('navigation', { name: 'Settings sections' });
    expect(await within(nav).findByRole('link', { name: 'System health' })).toHaveAttribute(
      'aria-current',
      'page',
    );

    const workers = within(await screen.findByRole('region', { name: 'Workers' }));
    const online = workers.getByRole('row', { name: /home-1/ });
    // Status is stated in words (with an icon), never colour alone.
    expect(within(online).getByText('Online')).toBeInTheDocument();
    expect(within(online).getByText('Oct 23, 2026, 9:59 AM UTC')).toBeInTheDocument();
    expect(within(online).getByText('0.12.0')).toBeInTheDocument();
    expect(
      within(workers.getByRole('row', { name: /spare/ })).getByText('Never seen'),
    ).toBeInTheDocument();

    expect(screen.getByRole('region', { name: 'Worker outage' })).toHaveTextContent(
      'No worker outage',
    );

    const queue = within(screen.getByRole('region', { name: 'Queue' }));
    expect(queue.getByText('12 min')).toBeInTheDocument();
    expect(
      within(queue.getByRole('row', { name: /passive/ })).getAllByRole('cell')[1],
    ).toHaveTextContent('3');

    const scans = within(screen.getByRole('table', { name: 'Scan outcomes' }));
    const day = within(scans.getByRole('row', { name: /Last 24 hours/ }));
    expect(day.getByText('95%')).toBeInTheDocument();
    expect(day.getByText('42 s')).toBeInTheDocument();
    expect(day.getByText('6 min')).toBeInTheDocument();
    // No jobs → no rate and no durations, shown as dashes rather than 0%.
    expect(within(scans.getByRole('row', { name: /Last 7 days/ })).getAllByText('—')).toHaveLength(
      3,
    );

    const failures = within(screen.getByRole('list', { name: 'Top failure codes' }));
    expect(failures.getByText('dns_timeout')).toBeInTheDocument();

    expect(screen.getByRole('region', { name: 'Database' })).toHaveTextContent(
      'Reachable12 ms round trip',
    );
    expect(screen.getByRole('listitem', { name: 'endoflife.date' })).toBeInTheDocument();
    const retention = within(screen.getByRole('region', { name: 'Retention' }));
    expect(retention.getByText('1520')).toBeInTheDocument();
    expect(retention.getByText(/180 days/)).toBeInTheDocument();
    expect(retention.getByText('365 days')).toBeInTheDocument();
  });

  it('highlights an active worker outage and an unreachable database', async () => {
    stubApi('admin', {
      [OPS_PATHS.health]: ok(
        health({
          outage: { active: true, since: '2026-10-23T08:00:00.000Z', queuedJobs: 7 },
          database: { ok: false, latencyMs: null },
        }),
      ),
    });
    renderAt(TAB);
    const outage = await screen.findByRole('region', { name: 'Worker outage' });
    expect(outage).toHaveTextContent('Worker outage since Oct 23, 2026, 8:00 AM UTC');
    expect(outage).toHaveTextContent('7 jobs are queued');
    expect(screen.getByRole('region', { name: 'Database' })).toHaveTextContent(
      'Not respondingLatency unknown',
    );
  });

  it('is hidden from non-administrators and never requested for them', async () => {
    const calls = stubApi('analyst', { [OPS_PATHS.health]: ok(health()) });
    renderAt(TAB);
    expect(await screen.findByText('Administrators only')).toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: 'Settings sections' });
    expect(within(nav).queryByRole('link', { name: 'System health' })).toBeNull();
    expect(calls.some((c) => c.path === '/api/v1/ops/health')).toBe(false);
  });

  it('shows the permission-denied state when the API refuses', async () => {
    stubApi('admin', { [OPS_PATHS.health]: apiError(403, 'forbidden', 'Not allowed.') });
    renderAt(TAB);
    expect(
      await screen.findByText('System health is visible to administrators'),
    ).toBeInTheDocument();
  });

  it('refreshes every minute and keeps the last data, marked stale, when a refresh fails', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let n = 0;
    const calls = stubApi('admin', {
      [OPS_PATHS.health]: () => {
        n += 1;
        return n === 1
          ? { status: 200, body: health() }
          : apiError(503, 'service_unavailable', 'Try later.')();
      },
    });
    renderAt(TAB);
    expect(await screen.findByRole('region', { name: 'Workers' })).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(HEALTH_REFRESH_MS);
    });
    expect(await screen.findByText(/refresh failed — Try later\./)).toBeInTheDocument();
    // The earlier data is still on screen.
    expect(screen.getByRole('region', { name: 'Workers' })).toHaveTextContent('home-1');
    expect(calls.filter((c) => c.path === '/api/v1/ops/health')).toHaveLength(2);
  });

  it('refreshes on demand', async () => {
    const calls = stubApi('admin', { [OPS_PATHS.health]: ok(health()) });
    renderAt(TAB);
    await userEvent.click(await screen.findByRole('button', { name: 'Refresh' }));
    await vi.waitFor(() =>
      expect(calls.filter((c) => c.path === '/api/v1/ops/health')).toHaveLength(2),
    );
  });
});
