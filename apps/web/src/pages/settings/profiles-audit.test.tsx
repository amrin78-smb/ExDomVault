// Settings → Scan profiles (read-only) and Audit log (filters in the URL, metadata as text, gating).
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ADMIN_PATHS, ok, renderAt, stubApi, type Handler } from '../../testing/stub-api.tsx';
import { auditEntry, auditPage, profile } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const AUDIT_DEFAULT = ADMIN_PATHS.audit('?page=1&pageSize=50');

describe('Settings: scan profiles', () => {
  it('shows server-defined profiles read-only to any user with scans:read', async () => {
    const calls = stubApi('viewer', {
      [ADMIN_PATHS.scanProfiles]: ok({
        activeScanningEnabled: false,
        items: [
          profile(),
          profile({
            key: 'standard',
            name: 'Standard',
            description: 'Quick checks plus HTTP security headers and approved TCP ports.',
            defaultSchedule: null,
            config: {
              active: true,
              checks: ['dns', 'tls_certificate', 'http_headers', 'tcp_ports'],
              tcpPorts: [80, 443, 8443],
              timeouts: { connectMs: 3000, readMs: 500, targetSeconds: 300 },
              concurrency: 4,
              ratePerSecond: 2.5,
              maxTargets: 50,
            },
          }),
        ],
      }),
    });
    renderAt('/settings?tab=profiles');
    const card = within(await screen.findByRole('region', { name: 'Scan profiles' }));
    expect(await card.findByText(/Active scanning is disabled on the server/)).toBeInTheDocument();

    const passive = within(card.getByRole('article', { name: 'Passive' }));
    expect(passive.getByRole('heading', { name: 'Passive' })).toBeInTheDocument();
    expect(passive.getByText('Never contacts hosts')).toBeInTheDocument(); // type badge
    expect(passive.getByText(/never contacts the target hosts/)).toBeInTheDocument();
    expect(
      within(passive.getByRole('list', { name: 'Checks in Passive' }))
        .getAllByRole('listitem')
        .map((li) => li.textContent),
    ).toEqual(['DNS records', 'Registration (RDAP)']);
    expect(passive.getByText('None')).toBeInTheDocument();
    expect(passive.getByText('daily')).toBeInTheDocument();

    const standard = within(card.getByRole('article', { name: 'Standard' }));
    expect(standard.getByText('Connects to hosts')).toBeInTheDocument();
    expect(standard.getByText('3 ports')).toBeInTheDocument();
    expect(standard.getByText(/connect 3 s, read 500 ms, per target 300 s/)).toBeInTheDocument();
    expect(
      standard.getByText(/2.5 requests\/s, concurrency 4, up to 50 targets/),
    ).toBeInTheDocument();
    expect(standard.getByText('On request only')).toBeInTheDocument();

    // Read-only: no inputs or actions, and only GETs were made.
    expect(card.queryByRole('button')).not.toBeInTheDocument();
    expect(card.queryByRole('textbox')).not.toBeInTheDocument();
    expect(calls.every((c) => c.method === 'GET')).toBe(true);
  });

  it('is not offered to roles without scans:read', async () => {
    const calls = stubApi('asset_owner', {});
    renderAt('/settings?tab=profiles');
    expect(
      await screen.findByText('You do not have permission to view this section.'),
    ).toBeInTheDocument();
    expect(calls.some((c) => c.path === '/api/v1/scan-profiles')).toBe(false);
  });
});

function openAudit(path: string, handlers: Record<string, Handler>) {
  const calls = stubApi('admin', { [AUDIT_DEFAULT]: ok(auditPage([auditEntry()])), ...handlers });
  const router = renderAt(path);
  return { calls, router };
}

const auditCard = () => within(screen.getByRole('region', { name: 'Audit log' }));

describe('Settings: audit log', () => {
  it('lists entries with actor, action and resource, and metadata as escaped text', async () => {
    openAudit('/settings?tab=audit', {
      [AUDIT_DEFAULT]: ok(
        auditPage([
          auditEntry({ metadata: { note: '<img src=x onerror="alert(1)">', reason: 'ok' } }),
          auditEntry({
            id: crypto.randomUUID(),
            actorType: 'system',
            actor: null,
            action: 'verification.expired',
            resourceType: 'domain',
            resourceId: null,
            requestId: null,
            metadata: {},
          }),
        ]),
      ),
    });
    const table = within(await screen.findByRole('table', { name: /Audit log entries/ }));
    const [first, second] = table.getAllByRole('row').slice(1);
    const row = within(first!);
    expect(row.getByText('admin@example.com')).toBeInTheDocument();
    expect(row.getByText('finding.status_changed')).toBeInTheDocument();
    expect(row.getByText('finding')).toBeInTheDocument();

    const summary = row.getByText('2 fields');
    await userEvent.click(summary);
    const pre = first!.querySelector('pre')!;
    expect(pre.textContent).toContain('"note": "<img src=x onerror=\\"alert(1)\\">"');
    expect(first!.querySelector('img')).toBeNull();
    expect(row.getByText('req-audit-1')).toBeInTheDocument();

    expect(within(second!).getByText('System')).toBeInTheDocument();
    expect(within(second!).getByText('—')).toBeInTheDocument();
  });

  it('keeps filters in the URL and sends them to the API', async () => {
    const filtered = ADMIN_PATHS.audit(
      '?page=1&pageSize=50&action=finding.&resourceType=finding&actorType=user&from=2026-10-01T00%3A00%3A00.000Z&to=2026-10-22T23%3A59%3A59.999Z',
    );
    const { calls, router } = openAudit('/settings?tab=audit', {
      [filtered]: ok(auditPage([auditEntry()], 120)),
      [filtered.replace('page=1&', 'page=2&')]: ok(auditPage([auditEntry()], 120, 2)),
    });
    await screen.findByRole('table', { name: /Audit log entries/ });
    const card = auditCard();
    await userEvent.type(card.getByLabelText('Action or prefix'), 'finding.');
    await userEvent.type(card.getByLabelText('Resource type'), 'finding');
    await userEvent.selectOptions(card.getByLabelText('Actor type'), 'user');
    await userEvent.type(card.getByLabelText('From'), '2026-10-01');
    await userEvent.type(card.getByLabelText('To'), '2026-10-22');
    await userEvent.click(card.getByRole('button', { name: 'Apply filters' }));

    expect(router.state.location.search).toBe(
      '?tab=audit&action=finding.&resourceType=finding&actorType=user&from=2026-10-01&to=2026-10-22',
    );
    expect(await card.findByText('1–50 of 120')).toBeInTheDocument();
    await userEvent.click(card.getByRole('button', { name: 'Next' }));
    expect(router.state.location.search).toContain('&page=2');
    expect(await card.findByText('51–100 of 120')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain(filtered.slice(4));

    await userEvent.click(card.getByRole('button', { name: 'Clear' }));
    expect(router.state.location.search).toBe('?tab=audit');
  });

  it('reads filters from the URL on load', async () => {
    const path = ADMIN_PATHS.audit('?page=1&pageSize=50&action=user.');
    openAudit('/settings?tab=audit&action=user.', { [path]: ok(auditPage([])) });
    expect(await screen.findByText('No audit entries match these filters')).toBeInTheDocument();
    expect(auditCard().getByLabelText('Action or prefix')).toHaveValue('user.');
  });

  it('rejects invalid filters without sending them', async () => {
    const { calls, router } = openAudit('/settings?tab=audit', {});
    await screen.findByRole('table', { name: /Audit log entries/ });
    const card = auditCard();
    await userEvent.type(card.getByLabelText('Action or prefix'), 'Finding<script>');
    await userEvent.type(card.getByLabelText('From'), '2026-10-22');
    await userEvent.type(card.getByLabelText('To'), '2026-10-01');
    await userEvent.click(card.getByRole('button', { name: 'Apply filters' }));
    const action = card.getByLabelText('Action or prefix');
    expect(action).toHaveAttribute('aria-invalid', 'true');
    expect(action).toHaveAccessibleDescription(/lowercase letters, dots and underscores/);
    expect(card.getByLabelText('To')).toHaveAccessibleDescription(
      'The end date must not be before the start date.',
    );
    expect(router.state.location.search).toBe('?tab=audit');
    expect(calls.filter((c) => c.path.startsWith('/api/v1/audit-logs'))).toHaveLength(1);
  });

  it('ignores an invalid filter typed into the URL instead of sending it', async () => {
    const { calls } = openAudit('/settings?tab=audit&action=DROP%20TABLE', {});
    await screen.findByRole('table', { name: /Audit log entries/ });
    expect(calls.filter((c) => c.path.startsWith('/api/v1/audit-logs')).map((c) => c.path)).toEqual(
      ['/api/v1/audit-logs?page=1&pageSize=50'],
    );
    expect(auditCard().getByLabelText('Action or prefix')).toHaveAttribute('aria-invalid', 'true');
  });

  it('is available only with audit:read', async () => {
    const calls = stubApi('analyst', {});
    renderAt('/settings?tab=audit&action=finding.');
    expect(
      await screen.findByText('You do not have permission to view this section.'),
    ).toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith('/api/v1/audit-logs'))).toBe(false);
  });
});

describe('Settings: sections', () => {
  it('shows only the sections the user may open, marking the current one', async () => {
    stubApi('admin', { 'GET /api/v1/workers': ok({ items: [] }) });
    renderAt('/settings');
    const nav = within(await screen.findByRole('navigation', { name: 'Settings sections' }));
    expect(nav.getAllByRole('link').map((l) => l.textContent)).toEqual([
      'Workers and networks',
      'Users',
      'Scan profiles',
      'Audit log',
      'Intelligence feeds',
    ]);
    expect(nav.getByRole('link', { name: 'Workers and networks' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    expect(nav.getByRole('link', { name: 'Audit log' })).toHaveAttribute(
      'href',
      '/settings?tab=audit',
    );
  });
});
