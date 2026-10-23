// CSV export buttons on every list page and the domain page (owner request 2026-10-24).
import type { Permission, Role } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { countCsvRows } from '../lib/api.ts';
import {
  EXPORT_PATHS,
  PERMISSIONS,
  apiError,
  ok,
  renderAt,
  stubApi,
  stubCsvDownload,
  type Handler,
} from '../testing/stub-api.tsx';
import { DOMAIN_ID, NO_CATEGORIES, domain, page } from './findings/test-data.ts';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

/** `/me` for a role with some permissions taken away. */
const meWithout = (role: Role, without: Permission[]): Handler =>
  ok({
    user: { id: crypto.randomUUID(), email: `${role}@example.com`, displayName: null, role },
    permissions: PERMISSIONS[role].filter((p) => !without.includes(p)),
    authProvider: 'cloudflare_access',
  });

const qs = (params: Record<string, string>) => `?${new URLSearchParams(params).toString()}`;

interface PageCase {
  page: string;
  /** URL with filters and paging; the export must carry the filters but never the paging. */
  url: string;
  button: string;
  permission: Permission;
  role: Role;
  expected: string;
}

const CASES: PageCase[] = [
  {
    page: 'Domains',
    url: '/domains?q=shop&criticality=high&sort=-createdAt&page=2&pageSize=50',
    button: 'Export domains (CSV)',
    permission: 'domains:read',
    role: 'viewer',
    expected: EXPORT_PATHS.csv('domains', '?q=shop&criticality=high&sort=-createdAt'),
  },
  {
    page: 'Assets',
    url: `/assets?q=www&source=ct&domainId=${DOMAIN_ID}&page=3&pageSize=50`,
    button: 'Export assets (CSV)',
    permission: 'assets:read',
    role: 'asset_owner',
    // The list's default status filter (pending) applies to the export too.
    expected: EXPORT_PATHS.csv(
      'assets',
      qs({ status: 'pending', domainId: DOMAIN_ID, source: 'ct', q: 'www' }),
    ),
  },
  {
    page: 'Advisories',
    url: '/advisories?status=all&page=2',
    button: 'Export advisories (CSV)',
    permission: 'findings:read',
    role: 'viewer',
    expected: EXPORT_PATHS.csv('advisories', '?status=all'),
  },
  {
    page: 'Software',
    url: '/software?product=nginx&status=eol&q=web&page=2&pageSize=50',
    button: 'Export software (CSV)',
    permission: 'findings:read',
    role: 'viewer',
    expected: EXPORT_PATHS.csv('software', '?product=nginx&status=eol&q=web'),
  },
  {
    page: 'Scans',
    url: `/scans?status=failed&domainId=${DOMAIN_ID}&page=2`,
    button: 'Export scans (CSV)',
    permission: 'scans:read',
    role: 'viewer',
    expected: EXPORT_PATHS.csv('scans', qs({ status: 'failed', domainId: DOMAIN_ID })),
  },
  {
    page: 'Settings → Users',
    url: '/settings?tab=users&role=analyst&q=bob&page=2',
    button: 'Export users (CSV)',
    permission: 'users:manage',
    role: 'admin',
    expected: EXPORT_PATHS.csv('users', '?q=bob&role=analyst'),
  },
  {
    page: 'Settings → Audit log',
    url: '/settings?tab=audit&action=finding.&from=2026-10-01&page=2',
    button: 'Export audit log (CSV)',
    permission: 'audit:read',
    role: 'admin',
    expected: EXPORT_PATHS.csv(
      'audit-logs',
      qs({ action: 'finding.', from: '2026-10-01T00:00:00.000Z' }),
    ),
  },
];

const CSV = 'a,b\r\n1,2\r\n3,4\r\n';

describe.each(CASES)('$page CSV export', (c) => {
  it(`exports the current filters without paging as "${c.button}"`, async () => {
    stubApi(c.role, {});
    const csv = stubCsvDownload(CSV);
    renderAt(c.url);
    await userEvent.click(await screen.findByRole('button', { name: c.button }));
    expect(await screen.findByText('Exported 2 rows.')).toBeVisible();
    expect(csv.paths).toEqual([c.expected]);
    expect(csv.paths[0]).not.toMatch(/[?&](page|pageSize)=/);
    expect(csv.createObjectURL).toHaveBeenCalledOnce();
  });

  it(`is hidden without ${c.permission}`, async () => {
    stubApi(c.role, { 'GET /api/v1/me': meWithout(c.role, [c.permission]) });
    renderAt(c.url);
    // The signed-in user is shown once the session has loaded, so the permission check has run.
    await screen.findAllByText(`${c.role}@example.com`);
    expect(screen.queryByRole('button', { name: c.button })).not.toBeInTheDocument();
  });
});

describe('Export outcomes', () => {
  it('reports truncation with the total from X-Total-Rows', async () => {
    stubApi('viewer', {});
    stubCsvDownload(`domain\r\n${'example.com\r\n'.repeat(10_000)}`, {
      'X-Truncated': 'true',
      'X-Total-Rows': '12345',
    });
    renderAt('/domains');
    await userEvent.click(await screen.findByRole('button', { name: 'Export domains (CSV)' }));
    expect(
      await screen.findByText(
        'Exported the first 10,000 of 12,345 rows (the export limit). Narrow the filters to export the rest.',
      ),
    ).toBeVisible();
  });

  it('shows an API error with its request ID', async () => {
    stubApi('viewer', {
      [`GET ${EXPORT_PATHS.csv('scans')}`]: apiError(429, 'rate_limited', 'Slow down.'),
    });
    renderAt('/scans');
    await userEvent.click(await screen.findByRole('button', { name: 'Export scans (CSV)' }));
    const alert = (await screen.findAllByRole('alert')).find((a) =>
      a.textContent?.includes('Export failed'),
    );
    expect(alert).toHaveTextContent('Too many requests');
    expect(alert).toHaveTextContent('Request ID: req-test');
    expect(screen.getByRole('button', { name: 'Export scans (CSV)' })).toBeEnabled();
  });

  it('explains an expired sign-in when the export is not a CSV file', async () => {
    stubApi('viewer', {});
    stubCsvDownload('<html>Sign in</html>', { 'Content-Type': 'text/html' });
    renderAt('/advisories');
    await userEvent.click(await screen.findByRole('button', { name: 'Export advisories (CSV)' }));
    expect(await screen.findByText(/Your sign-in may have expired/)).toBeVisible();
  });

  it('explains an expired sign-in when the export redirects', async () => {
    stubApi('viewer', {});
    stubCsvDownload('', { Location: 'https://team.cloudflareaccess.com/login' }, 302);
    renderAt('/advisories');
    await userEvent.click(await screen.findByRole('button', { name: 'Export advisories (CSV)' }));
    expect(await screen.findByText(/Your sign-in may have expired/)).toBeVisible();
  });

  it('names the file from Content-Disposition, else exdomainvault-<resource>-YYYYMMDD.csv', async () => {
    stubApi('viewer', {});
    let csv = stubCsvDownload(CSV, {
      'Content-Disposition': 'attachment; filename="exdomainvault-software-20261024.csv"',
    });
    renderAt('/software');
    await userEvent.click(await screen.findByRole('button', { name: 'Export software (CSV)' }));
    await screen.findByText('Exported 2 rows.');
    expect(csv.filenames).toEqual(['exdomainvault-software-20261024.csv']);

    vi.restoreAllMocks();
    csv = stubCsvDownload(CSV);
    await userEvent.click(screen.getByRole('button', { name: 'Export software (CSV)' }));
    await vi.waitFor(() => expect(csv.filenames).toHaveLength(1));
    expect(csv.filenames[0]).toMatch(/^exdomainvault-software-\d{8}\.csv$/);
  });

  it('shows a busy state while the export runs', async () => {
    stubApi('viewer', {});
    let release: (r: Response) => void = () => undefined;
    const base = globalThis.fetch;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        String(input).startsWith('/api/v1/exports/')
          ? new Promise<Response>((resolve) => (release = resolve))
          : base(input, init),
      ),
    );
    vi.stubGlobal(
      'URL',
      Object.assign(URL, { createObjectURL: () => 'blob:x', revokeObjectURL() {} }),
    );
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    renderAt('/scans');
    await userEvent.click(await screen.findByRole('button', { name: 'Export scans (CSV)' }));
    const busy = await screen.findByRole('button', { name: 'Exporting…' });
    expect(busy).toBeDisabled();
    release(new Response('a\r\n1\r\n', { headers: { 'Content-Type': 'text/csv' } }));
    expect(await screen.findByText('Exported 1 row.')).toBeVisible();
  });
});

describe('Domain page exports', () => {
  const summary = {
    bySeverity: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
    total: 1,
    byCategory: NO_CATEGORIES,
  };
  const stubDomain = (role: Role) =>
    stubApi(role, {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain: domain(), verification: null }),
      [`GET /api/v1/findings/summary?domainId=${DOMAIN_ID}`]: ok(summary),
      [`GET /api/v1/domains/${DOMAIN_ID}/software?pageSize=10`]: ok(page([])),
    });

  it('exports the findings and software of this domain from their cards', async () => {
    stubDomain('analyst');
    const csv = stubCsvDownload(CSV);
    renderAt(`/domains/${DOMAIN_ID}`);

    const findings = await screen.findByRole('region', { name: 'Findings' });
    await userEvent.click(within(findings).getByRole('button', { name: 'Export findings (CSV)' }));
    expect(await within(findings).findByText('Exported 2 rows.')).toBeVisible();

    const software = screen.getByRole('region', { name: 'Software' });
    await userEvent.click(within(software).getByRole('button', { name: 'Export software (CSV)' }));
    expect(await within(software).findByText('Exported 2 rows.')).toBeVisible();

    expect(csv.paths).toEqual([
      EXPORT_PATHS.findings(`?domainId=${DOMAIN_ID}`),
      EXPORT_PATHS.csv('software', `?domainId=${DOMAIN_ID}`),
    ]);
  });

  it('offers only the software export without reports:generate', async () => {
    stubDomain('viewer');
    renderAt(`/domains/${DOMAIN_ID}`);
    const software = await screen.findByRole('region', { name: 'Software' });
    expect(
      await within(software).findByRole('button', { name: 'Export software (CSV)' }),
    ).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Export findings (CSV)' })).not.toBeInTheDocument();
  });

  it('offers neither without findings:read', async () => {
    stubApi('analyst', {
      'GET /api/v1/me': meWithout('analyst', ['findings:read']),
      [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain: domain(), verification: null }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    await screen.findByText('Your role cannot view findings.');
    expect(screen.queryByRole('button', { name: /^Export / })).not.toBeInTheDocument();
  });
});

describe('countCsvRows', () => {
  it('counts data records, ignoring the BOM, blank lines and newlines inside quotes', () => {
    expect(countCsvRows('')).toBe(0);
    expect(countCsvRows('﻿a,b\r\n')).toBe(0);
    expect(countCsvRows('a,b\r\n1,2')).toBe(1);
    expect(countCsvRows('a,b\r\n"line 1\r\nline 2",x\r\n"say ""hi""",y\r\n\r\n')).toBe(2);
  });
});
