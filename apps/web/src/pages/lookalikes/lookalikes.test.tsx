// Lookalike domains page and the domain's brand monitoring switch (Milestone 15).
import type { LookalikeItem, LookalikeListResponse } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDomainCards } from '../../testing/domain-cards.ts';
import { apiError, ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { DOMAIN_ID, domain, page } from '../findings/test-data.ts';

const FINDING_ID = '9f1e2d3c-4b5a-4968-8778-6a5b4c3d2e1f';
const LIST = 'GET /api/v1/lookalikes?registered=true';
const DOMAINS = 'GET /api/v1/domains?pageSize=100';

beforeEach(openDomainCards);
afterEach(() => vi.unstubAllGlobals());

const item = (overrides: Partial<LookalikeItem> = {}): LookalikeItem => ({
  domain: { id: DOMAIN_ID, fqdn: 'example.com' },
  candidate: 'exmple.com',
  technique: 'omission',
  state: 'registered',
  records: { A: ['192.0.2.7'], AAAA: [], MX: ['10 mx.example.org.'], NS: ['ns1.example.net.'] },
  hasMail: true,
  firstSeenAt: '2026-10-20T10:00:00.000Z',
  lastSeenAt: '2026-10-27T10:00:00.000Z',
  lastCheckedAt: '2026-10-27T10:00:00.000Z',
  finding: { id: FINDING_ID, status: 'open', severity: 'medium' },
  ...overrides,
});

const response = (
  items: LookalikeItem[],
  summary: Partial<LookalikeListResponse['summary']> = {},
): LookalikeListResponse => ({
  ...page(items),
  pageSize: 50,
  summary: {
    domainsMonitored: 1,
    candidatesChecked: 259,
    registered: items.filter((i) => i.state === 'registered').length,
    withMail: items.filter((i) => i.hasMail).length,
    newThisWeek: 1,
    lastCheckedAt: '2026-10-27T10:00:00.000Z',
    ...summary,
  },
});

const rowOf = (text: string) => {
  const row = screen.getByText(text).closest('tr');
  if (!row) throw new Error(`row for ${text} missing`);
  return within(row);
};

describe('Lookalike domains page', () => {
  it('is in the navigation right after Attack Surface', async () => {
    stubApi('viewer', { [LIST]: ok(response([])), [DOMAINS]: ok(page([domain()])) });
    renderAt('/lookalikes');
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Lookalike domains' }),
    ).toBeInTheDocument();
    const nav = within(screen.getByRole('navigation', { name: 'Primary' }));
    const links = nav.getAllByRole('link').map((a) => a.textContent);
    expect(links.indexOf('Lookalike domains')).toBe(links.indexOf('Attack Surface') + 1);
    expect(nav.getByRole('link', { name: 'Lookalike domains' })).toHaveAttribute(
      'href',
      '/lookalikes',
    );
  });

  it('shows the summary and one row per registered lookalike', async () => {
    stubApi('viewer', {
      [LIST]: ok(
        response([
          item(),
          item({
            candidate: 'exampel.com',
            technique: 'transposition',
            records: { A: [], AAAA: [], MX: [], NS: ['ns.parking.example.net.'] },
            hasMail: false,
            finding: null,
          }),
        ]),
      ),
      [DOMAINS]: ok(page([domain()])),
    });
    renderAt('/lookalikes');
    await screen.findByText('exmple.com');
    expect(screen.getByText('259')).toBeInTheDocument();
    expect(screen.getByText('Candidates checked')).toBeInTheDocument();

    const row = rowOf('exmple.com');
    expect(row.getByText('Omission')).toBeInTheDocument();
    expect(row.getByText('Mail')).toBeInTheDocument();
    expect(row.getByText('10 mx.example.org.')).toBeInTheDocument();
    expect(row.getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}`,
    );
    expect(row.getByRole('link', { name: /Finding for exmple.com/ })).toHaveAttribute(
      'href',
      `/findings/${FINDING_ID}`,
    );
    expect(row.getByText('Medium')).toBeInTheDocument();

    const parked = rowOf('exampel.com');
    expect(parked.getByText('Transposition')).toBeInTheDocument();
    expect(parked.queryByText('Mail')).not.toBeInTheDocument();
  });

  it('filters by tab, technique and search through the URL', async () => {
    const calls = stubApi('viewer', {
      [LIST]: ok(response([item()])),
      'GET /api/v1/lookalikes?registered=false': ok(
        response([item({ candidate: 'old-example.com', state: 'gone', finding: null })]),
      ),
      'GET /api/v1/lookalikes?registered=false&technique=homoglyph': ok(response([])),
      [DOMAINS]: ok(page([domain()])),
    });
    renderAt('/lookalikes');
    await screen.findByText('exmple.com');
    const tabs = within(screen.getByRole('group', { name: 'Registration state' }));
    await userEvent.click(tabs.getByRole('button', { name: 'No longer registered' }));
    await screen.findByText('old-example.com');
    expect(rowOf('old-example.com').getAllByText('No longer registered')).toHaveLength(1);

    await userEvent.selectOptions(screen.getByLabelText('Technique'), 'homoglyph');
    await screen.findByText('No lookalike domains match these filters');
    expect(calls.map((c) => c.path)).toContain(
      '/api/v1/lookalikes?registered=false&technique=homoglyph',
    );
  });

  it('explains how to turn brand monitoring on when no domain has it', async () => {
    stubApi('viewer', {
      [LIST]: ok(response([], { domainsMonitored: 0, candidatesChecked: 0, lastCheckedAt: null })),
      [DOMAINS]: ok(page([domain()])),
    });
    renderAt('/lookalikes');
    expect(
      await screen.findByText('Brand monitoring is not on for any domain'),
    ).toBeInTheDocument();
    expect(screen.getByText(/Brand monitoring \(lookalike domains\)/)).toBeInTheDocument();
  });

  it('shows the permission-denied state to roles without domain access', async () => {
    stubApi('asset_owner', { [LIST]: apiError(403, 'forbidden', 'Not allowed.') });
    renderAt('/lookalikes');
    expect(
      await screen.findByText('You do not have access to this information'),
    ).toBeInTheDocument();
  });

  it('shows other API errors', async () => {
    stubApi('viewer', {
      [LIST]: apiError(500, 'internal_error', 'Something failed.'),
      [DOMAINS]: ok(page([domain()])),
    });
    renderAt('/lookalikes');
    expect(await screen.findByText('Could not load lookalike domains')).toBeInTheDocument();
  });
});

describe('brand monitoring on the domain page', () => {
  const DETAIL = `GET /api/v1/domains/${DOMAIN_ID}`;
  const stubDomain = (role: 'admin' | 'analyst' | 'viewer', brandMonitoring: boolean, extra = {}) =>
    stubApi(role, {
      [DETAIL]: ok({ domain: domain({ brandMonitoring }), verification: null }),
      ...extra,
    });

  it('an administrator turns it on after confirming', async () => {
    const calls = stubDomain('admin', false, {
      [`PATCH /api/v1/domains/${DOMAIN_ID}`]: ok({
        domain: domain({ brandMonitoring: true, updatedAt: '2026-10-22T12:00:00.000Z' }),
        verification: null,
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(
      await screen.findByText('Brand monitoring (lookalike domains) is off'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Check lookalikes now' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Turn on brand monitoring' }));
    const dialog = within(
      screen.getByRole('alertdialog', { name: 'Confirm brand monitoring change' }),
    );
    await userEvent.click(dialog.getByRole('button', { name: 'Turn on' }));
    expect(
      await screen.findByText('Brand monitoring (lookalike domains) is on'),
    ).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ brandMonitoring: true });
  });

  it('an analyst can request a check while it is on, but not change the switch', async () => {
    const calls = stubDomain('analyst', true, {
      [`POST /api/v1/domains/${DOMAIN_ID}/lookalikes/check`]: () => ({
        status: 201,
        body: { scanJobId: '5c4b3a29-1807-4f6e-8d5c-4b3a29180765', created: true },
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    await screen.findByText('Brand monitoring (lookalike domains) is on');
    expect(screen.queryByRole('button', { name: /brand monitoring/i })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Check lookalikes now' }));
    expect(await screen.findByText('Lookalike check queued.')).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST' && c.path.endsWith('/lookalikes/check'))).toBe(
      true,
    );
    expect(screen.getByRole('link', { name: 'View lookalikes' })).toHaveAttribute(
      'href',
      `/lookalikes?domainId=${DOMAIN_ID}`,
    );
  });
});
