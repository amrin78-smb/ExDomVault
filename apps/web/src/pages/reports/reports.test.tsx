import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiError, ok, renderAt, stubApi, type Handler } from '../../testing/stub-api.tsx';
import { NO_CATEGORIES, page } from '../findings/test-data.ts';
import { REPORT_PATHS, reportSummary } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const card = (name: string) => screen.findByRole('region', { name });

/** Serves the CSV export (stubApi only answers JSON) and records each request path. */
function stubCsv(body: string, headers: Record<string, string> = {}) {
  const paths: string[] = [];
  const base = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input.toString();
      if (path.startsWith('/api/v1/reports/findings.csv')) {
        paths.push(path);
        return new Response(body, {
          status: 200,
          headers: { 'Content-Type': 'text/csv; charset=utf-8', ...headers },
        });
      }
      return base(input, init);
    }),
  );
  const createObjectURL = vi.fn(() => 'blob:report');
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  return { paths, createObjectURL, click };
}

describe('Reports page', () => {
  it('shows coverage, finding breakdowns, trend, owners and expiry tables', async () => {
    stubApi('analyst', { [REPORT_PATHS.summary]: ok(reportSummary()) });
    renderAt('/reports');

    const coverage = await screen.findByRole('region', { name: 'Coverage' });
    const stat = (label: string) => within(coverage).getByText(label).parentElement!;
    expect(stat('Domains')).toHaveTextContent('339');
    expect(stat('Verified')).toHaveTextContent('41');
    expect(stat('Pending assets')).toHaveTextContent('27');

    expect(screen.getByTestId('severity-critical')).toHaveTextContent('2');
    expect(screen.getByTestId('severity-critical')).toHaveAttribute(
      'href',
      '/findings?severity=critical',
    );
    expect(screen.getByTestId('status-accepted_risk')).toHaveTextContent('3');
    expect(screen.getByText('Mean days to resolve').parentElement).toHaveTextContent('6.4');

    const chart = screen.getByRole('img', { name: /Findings created \(\d+\) and resolved/ });
    expect(chart).toBeInTheDocument();
    expect(screen.getByRole('table', { name: /created and resolved per UTC day/ })).toBeTruthy();

    const top = await card('Top domains by risk');
    expect(within(top).getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      expect.stringMatching(/^\/domains\//),
    );
    expect(within(top).getByText('540')).toBeInTheDocument();

    const owners = await card('Open findings by business owner');
    expect(within(owners).getByText('Retail')).toBeInTheDocument();
    expect(within(owners).getByText('No business owner')).toBeInTheDocument();

    const regs = await card('Expiring registrations');
    expect(within(regs).getByText('Expired 3 days ago')).toBeInTheDocument();
    expect(within(regs).getByText('39 days')).toBeInTheDocument();

    const certs = await card('Expiring certificates');
    expect(within(certs).getByRole('link', { name: 'shop.example.com' })).toBeInTheDocument();
    expect(within(certs).getByText('10 days')).toBeInTheDocument();

    const risks = await card('Accepted risks due for review');
    expect(
      within(risks).getByRole('link', { name: 'Certificate expires within 14 days' }),
    ).toHaveAttribute('href', expect.stringMatching(/^\/findings\//));
    expect(within(risks).getByText('Overdue by 2 days')).toBeInTheDocument();
  });

  it('shows honest empty states', async () => {
    stubApi('admin', {
      [REPORT_PATHS.summary]: ok(
        reportSummary({
          topDomains: [],
          expiringRegistrations: [],
          expiringCertificates: [],
          acceptedRisksDue: [],
          findings: {
            open: 0,
            bySeverity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
            byStatus: {
              open: 0,
              acknowledged: 0,
              remediation_in_progress: 0,
              resolved: 0,
              accepted_risk: 0,
            },
            byCategory: NO_CATEGORIES as never,
            meanDaysToResolve: null,
          },
        }),
      ),
    });
    renderAt('/reports');
    expect(await screen.findByText('No open findings on any domain')).toBeInTheDocument();
    expect(screen.getByText('No registrations expiring soon')).toBeInTheDocument();
    expect(screen.getByText('No certificates expiring soon')).toBeInTheDocument();
    expect(screen.getByText('No accepted risks due for review')).toBeInTheDocument();
    expect(screen.getByText('No finding was resolved in the last 90 days')).toBeInTheDocument();
  });

  it('exports findings as CSV for roles with reports:generate and reports truncation', async () => {
    stubApi('analyst', { [REPORT_PATHS.summary]: ok(reportSummary()) });
    const csv = stubCsv('finding_id\n', {
      'X-Truncated': 'true',
      'Content-Disposition': 'attachment; filename="findings-2026-10-22.csv"',
    });
    renderAt('/reports');
    await userEvent.click(await screen.findByRole('button', { name: 'Export findings (CSV)' }));
    expect(await screen.findByText(/Exported the first 5,000 matching findings/)).toBeVisible();
    expect(csv.paths).toEqual([REPORT_PATHS.csv()]);
    expect(csv.createObjectURL).toHaveBeenCalledOnce();
    expect(csv.click).toHaveBeenCalledOnce();
    csv.click.mockRestore();
  });

  it('shows an export error from the API', async () => {
    stubApi('admin', {
      [REPORT_PATHS.summary]: ok(reportSummary()),
      'GET /api/v1/reports/findings.csv': apiError(403, 'forbidden', 'Not allowed.'),
    });
    renderAt('/reports');
    await userEvent.click(await screen.findByRole('button', { name: 'Export findings (CSV)' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Export failed');
  });

  it('hides export from viewers', async () => {
    stubApi('viewer', { [REPORT_PATHS.summary]: ok(reportSummary()) });
    renderAt('/reports');
    await card('Top domains by risk');
    expect(screen.queryByRole('button', { name: /Export findings/ })).not.toBeInTheDocument();
  });

  it('omits domain-level sections for asset owners', async () => {
    stubApi('asset_owner', { [REPORT_PATHS.summary]: ok(reportSummary()) });
    renderAt('/reports');
    expect(
      await screen.findByText('Domain-level sections are not available to your role'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Coverage' })).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Top domains by risk' })).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Accepted risks due for review' })).toBeVisible();
  });

  it('shows a permission-denied state instead of a raw 403', async () => {
    stubApi('viewer', {
      [REPORT_PATHS.summary]: apiError(403, 'forbidden', 'Missing permission reports:read.'),
    });
    renderAt('/reports');
    expect(await screen.findByText('Reports are not available to your role')).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('keeps the last report visible with a stale notice when a refresh fails, then retries', async () => {
    let fail = false;
    const summary: Handler = () =>
      fail
        ? apiError(503, 'service_unavailable', 'Database unavailable.')()
        : { status: 200, body: reportSummary() };
    stubApi('admin', { [REPORT_PATHS.summary]: summary });
    renderAt('/reports');
    await card('Top domains by risk');

    fail = true;
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    const notice = await screen.findByText(/refresh failed — Database unavailable\./);
    expect(notice).toHaveTextContent(/Showing data from .* UTC/);
    expect(screen.getByRole('region', { name: 'Top domains by risk' })).toBeVisible();

    fail = false;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await vi.waitFor(() => expect(screen.queryByText(/refresh failed/)).not.toBeInTheDocument());
    expect(screen.getByRole('region', { name: 'Top domains by risk' })).toBeVisible();
  });

  it('offers a retry when the first load fails', async () => {
    let calls = 0;
    stubApi('admin', {
      [REPORT_PATHS.summary]: () =>
        ++calls === 1
          ? apiError(500, 'internal_error', 'Boom.')()
          : { status: 200, body: reportSummary() },
    });
    renderAt('/reports');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load the report');
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await card('Top domains by risk')).toBeVisible();
  });
});

describe('Findings page CSV export', () => {
  it('exports with the current filters', async () => {
    stubApi('analyst', {
      'GET /api/v1/findings?page=2&severity=high&q=shop': ok(page([])),
    });
    const csv = stubCsv('finding_id\n');
    renderAt('/findings?severity=high&q=shop&page=2');
    // page=2 changes the list request but never the export.
    await userEvent.click(await screen.findByRole('button', { name: 'Export CSV' }));
    expect(await screen.findByText('Export downloaded.')).toBeVisible();
    expect(csv.paths).toEqual([REPORT_PATHS.csv('?severity=high&q=shop')]);
    csv.click.mockRestore();
  });

  it('is hidden from viewers', async () => {
    stubApi('viewer', { 'GET /api/v1/findings': ok(page([])) });
    renderAt('/findings');
    await screen.findByText('No active findings');
    expect(screen.queryByRole('button', { name: 'Export CSV' })).not.toBeInTheDocument();
  });
});
