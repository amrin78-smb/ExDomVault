// Settings → Scan profiles → Scheduled scans: read-only vs admin, confirmation, PUT body, warnings.
import type { ScanScheduleResponse } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ADMIN_PATHS,
  apiError,
  ok,
  renderAt,
  stubApi,
  type Handler,
} from '../../testing/stub-api.tsx';

afterEach(() => vi.unstubAllGlobals());

const schedule = (overrides: Partial<ScanScheduleResponse> = {}): ScanScheduleResponse => ({
  schedule: { enabled: false, profile: 'quick', intervalDays: 1 },
  updatedAt: null,
  updatedBy: null,
  eligibleDomains: 4,
  activeScanningEnabled: true,
  scheduledLast24h: 0,
  ...overrides,
});

function open(role: 'admin' | 'viewer' | 'analyst', handlers: Record<string, Handler>) {
  const calls = stubApi(role, {
    [ADMIN_PATHS.scanProfiles]: ok({ activeScanningEnabled: true, items: [] }),
    ...handlers,
  });
  renderAt('/settings?tab=profiles');
  return calls;
}

const card = async () => within(await screen.findByRole('region', { name: 'Scheduled scans' }));

describe('Settings: scheduled scans', () => {
  it('shows the current state read-only to users without scan_policies:manage', async () => {
    const calls = open('analyst', {
      [ADMIN_PATHS.scanSchedule]: ok(
        schedule({
          schedule: { enabled: true, profile: 'standard', intervalDays: 7 },
          updatedAt: '2026-10-20T09:30:00.000Z',
          updatedBy: { id: crypto.randomUUID(), email: 'root@example.com' },
          eligibleDomains: 12,
          scheduledLast24h: 3,
        }),
      ),
    });
    const c = await card();
    const summary = within(await c.findByLabelText('Current schedule'));
    expect(summary.getByText('On')).toBeInTheDocument();
    expect(summary.getByText('Standard')).toBeInTheDocument();
    expect(summary.getByText('About every 7 days')).toBeInTheDocument();
    expect(summary.getByText('12')).toBeInTheDocument();
    expect(summary.getByText('3')).toBeInTheDocument();
    expect(summary.getByText(/root@example\.com/)).toBeInTheDocument();
    expect(c.getByText('Only administrators can change the schedule.')).toBeInTheDocument();
    expect(c.queryByRole('form')).not.toBeInTheDocument();
    expect(c.queryByRole('button')).not.toBeInTheDocument();
    expect(c.queryByRole('switch')).not.toBeInTheDocument();
    expect(c.queryByText(/server switch is off/)).not.toBeInTheDocument();
    expect(calls.every((call) => call.method === 'GET')).toBe(true);
  });

  it('warns that nothing is scheduled while the server switch is off', async () => {
    open('viewer', {
      [ADMIN_PATHS.scanSchedule]: ok(
        schedule({
          activeScanningEnabled: false,
          schedule: { enabled: true, profile: 'quick', intervalDays: 1 },
        }),
      ),
    });
    const c = await card();
    expect(
      await c.findByText(/Nothing will be scheduled while the server switch is off/),
    ).toBeInTheDocument();
    expect(c.getByText('Never (default settings)')).toBeInTheDocument();
  });

  it('gives admins labelled controls and confirms before turning scheduled scans on', async () => {
    const user = userEvent.setup();
    const saved = schedule({
      schedule: { enabled: true, profile: 'standard', intervalDays: 7 },
      updatedAt: '2026-10-23T10:00:00.000Z',
      updatedBy: { id: crypto.randomUUID(), email: 'admin@example.com' },
    });
    const calls = open('admin', {
      [ADMIN_PATHS.scanSchedule]: ok(schedule()),
      [ADMIN_PATHS.updateScanSchedule]: ok(saved),
    });
    const c = await card();
    const form = within(await c.findByRole('form', { name: 'Change the scan schedule' }));

    const toggle = form.getByRole('switch', { name: 'Enable scheduled scans' });
    expect(toggle).not.toBeChecked();
    expect(form.getByRole('radio', { name: 'Quick' })).toBeChecked();
    expect(form.getByRole('radio', { name: 'Standard' })).toHaveAccessibleDescription(
      /TCP port probes/,
    );
    expect(form.getByRole('group', { name: 'Profile' })).toBeInTheDocument();
    const interval = form.getByRole('spinbutton', { name: 'Interval (days)' });
    expect(form.getByRole('button', { name: 'Save schedule' })).toBeDisabled();

    await user.click(toggle);
    await user.click(form.getByRole('radio', { name: 'Standard' }));
    await user.clear(interval);
    await user.type(interval, '7');
    await user.click(form.getByRole('button', { name: 'Save schedule' }));

    // Nothing is sent until the confirmation is accepted; the dialog takes focus and is announced.
    expect(calls.some((call) => call.method === 'PUT')).toBe(false);
    const dialog = await c.findByRole('alertdialog', { name: 'Turn on scheduled active scans?' });
    expect(dialog).toHaveFocus();
    expect(dialog).toHaveAccessibleDescription(
      /This machine \(the home scanning worker\) will connect to the web servers of 4 monitored, authorised domains about every 7 days/,
    );
    expect(dialog).toHaveTextContent('Standard also probes ports, but only on approved networks.');
    expect(dialog).toHaveTextContent('You can turn it off at any time.');

    await user.click(within(dialog).getByRole('button', { name: 'Confirm and save' }));
    expect(
      await c.findByText('Saved. Scheduled scans are on: Standard, about every 7 days.'),
    ).toBeInTheDocument();
    expect(c.getByRole('status')).toHaveTextContent('Saved. Scheduled scans are on');
    const puts = calls.filter((call) => call.method === 'PUT');
    expect(puts).toEqual([
      {
        method: 'PUT',
        path: '/api/v1/settings/scan-schedule',
        body: { enabled: true, profile: 'standard', intervalDays: 7 },
      },
    ]);
    // The summary reflects the server's response.
    const summary = within(c.getByLabelText('Current schedule'));
    expect(summary.getByText('On')).toBeInTheDocument();
    expect(summary.getByText(/admin@example\.com/)).toBeInTheDocument();
  });

  it('cancelling the confirmation sends nothing', async () => {
    const user = userEvent.setup();
    const calls = open('admin', { [ADMIN_PATHS.scanSchedule]: ok(schedule()) });
    const form = within(await (await card()).findByRole('form'));
    await user.click(form.getByRole('switch', { name: 'Enable scheduled scans' }));
    await user.click(form.getByRole('button', { name: 'Save schedule' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveTextContent('about every day');
    expect(dialog).toHaveTextContent('Quick does not probe ports.');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(calls.some((call) => call.method === 'PUT')).toBe(false);
  });

  it('turning scheduled scans off or changing only the interval saves without confirmation', async () => {
    const user = userEvent.setup();
    const on = { enabled: true, profile: 'quick', intervalDays: 3 } as const;
    const calls = open('admin', {
      [ADMIN_PATHS.scanSchedule]: ok(schedule({ schedule: on })),
      [ADMIN_PATHS.updateScanSchedule]: (body) => ({
        status: 200,
        body: schedule({ schedule: body as typeof on, updatedAt: '2026-10-23T10:00:00.000Z' }),
      }),
    });
    const form = within(await (await card()).findByRole('form'));
    const interval = form.getByRole('spinbutton', { name: 'Interval (days)' });
    await user.clear(interval);
    await user.type(interval, '5');
    await user.click(form.getByRole('button', { name: 'Save schedule' }));
    expect(
      await screen.findByText(/Saved\. Scheduled scans are on: Quick, about every 5 days/),
    ).toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();

    const form2 = within(screen.getByRole('form', { name: 'Change the scan schedule' }));
    await user.click(form2.getByRole('switch', { name: 'Enable scheduled scans' }));
    await user.click(form2.getByRole('button', { name: 'Save schedule' }));
    expect(await screen.findByText('Saved. Scheduled scans are off.')).toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(calls.filter((call) => call.method === 'PUT').map((call) => call.body)).toEqual([
      { enabled: true, profile: 'quick', intervalDays: 5 },
      { enabled: false, profile: 'quick', intervalDays: 5 },
    ]);
  });

  it('rejects an out-of-range interval before sending', async () => {
    const user = userEvent.setup();
    open('admin', { [ADMIN_PATHS.scanSchedule]: ok(schedule()) });
    const form = within(await (await card()).findByRole('form'));
    const interval = form.getByRole('spinbutton', { name: 'Interval (days)' });
    await user.clear(interval);
    await user.type(interval, '31');
    expect(interval).toHaveAttribute('aria-invalid', 'true');
    expect(interval).toHaveAccessibleDescription('Enter a whole number of days from 1 to 30.');
    expect(form.getByRole('button', { name: 'Save schedule' })).toBeDisabled();
  });

  it('shows server errors with the request ID', async () => {
    const user = userEvent.setup();
    open('admin', {
      [ADMIN_PATHS.scanSchedule]: ok(schedule()),
      [ADMIN_PATHS.updateScanSchedule]: apiError(403, 'forbidden', 'You cannot change this.'),
    });
    const c = await card();
    const form = within(await c.findByRole('form'));
    await user.click(form.getByRole('switch', { name: 'Enable scheduled scans' }));
    await user.click(form.getByRole('button', { name: 'Save schedule' }));
    await user.click(await c.findByRole('button', { name: 'Confirm and save' }));
    const alert = await c.findByRole('alert');
    expect(alert).toHaveTextContent('Could not save the scan schedule');
    expect(alert).toHaveTextContent('You cannot change this.');
    expect(alert).toHaveTextContent('Request ID: req-test');
    // The form keeps the unsaved choice so the admin can retry.
    expect(form.getByRole('switch', { name: 'Enable scheduled scans' })).toBeChecked();
    expect(form.getByRole('button', { name: 'Save schedule' })).toBeEnabled();
  });

  it('shows a load error with the request ID', async () => {
    open('viewer', {
      [ADMIN_PATHS.scanSchedule]: apiError(500, 'internal_error', 'Something went wrong.'),
    });
    const alert = await (await card()).findByRole('alert');
    expect(alert).toHaveTextContent('Could not load the scan schedule');
    expect(alert).toHaveTextContent('Request ID: req-test');
  });
});
