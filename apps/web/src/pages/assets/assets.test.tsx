// Assets list: URL filters, bulk decisions and their messages.
import type { Role } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ASSET_PATHS,
  apiError,
  ok,
  renderAt,
  stubApi,
  type Handler,
} from '../../testing/stub-api.tsx';
import { CLOUDFRONT, DOMAIN_ID, asset, page } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const SECOND_ID = '4f5a6b7c-8d9e-4f0a-9b1c-2d3e4f5a6b7c';
const APEX_ID = '5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d';
const DOMAINS = 'GET /api/v1/domains?pageSize=100';
const domainsPage = ok(
  page([
    {
      id: DOMAIN_ID,
      fqdn: 'example.com',
      unicodeFqdn: 'example.com',
      warnings: [],
      registrar: null,
      registeredAt: null,
      expiresAt: null,
      registrationDataStatus: 'unknown',
      criticality: 'medium',
      businessOwner: null,
      verificationStatus: 'verified',
      verifiedAt: '2026-10-20T00:00:00.000Z',
      verificationMethod: 'dns_txt',
      verificationExpiresAt: null,
      monitoringEnabled: true,
      createdAt: '2026-10-20T00:00:00.000Z',
      updatedAt: '2026-10-20T00:00:00.000Z',
    },
  ]),
);

const pendingRows = [
  asset({ currentIps: ['192.0.2.10', '192.0.2.11', '192.0.2.12'], activeFindings: 2 }),
  asset({
    id: SECOND_ID,
    hostname: 'cdn.example.com',
    hostingHint: CLOUDFRONT,
    wildcardOnly: true,
    currentIps: [],
  }),
];

function stubList(role: Role, handlers: Record<string, Handler> = {}) {
  return stubApi(role, {
    [DOMAINS]: domainsPage,
    [ASSET_PATHS.list('?status=pending')]: ok(page(pendingRows)),
    ...handlers,
  });
}

const table = () => screen.findByRole('table');

describe('Assets list: display and filters', () => {
  it('defaults to the review queue and shows hosting, wildcard, IPs and findings', async () => {
    const calls = stubList('viewer');
    renderAt('/assets');
    const t = await table();
    expect(calls.some((c) => c.path === '/api/v1/assets?status=pending')).toBe(true);
    expect(screen.getByLabelText('Status')).toHaveValue('pending');

    const rows = within(t).getAllByRole('row');
    const first = rows[1]!;
    expect(within(first).getByRole('link', { name: 'shop.example.com' })).toHaveAttribute(
      'href',
      `/assets/${pendingRows[0]!.id}`,
    );
    expect(within(first).getByText('192.0.2.10')).toBeInTheDocument();
    expect(within(first).getByText('192.0.2.11')).toBeInTheDocument();
    expect(within(first).queryByText('192.0.2.12')).not.toBeInTheDocument();
    expect(within(first).getByText('+1 more')).toBeInTheDocument();
    expect(within(first).getByText('Certificate logs')).toBeInTheDocument();
    expect(within(first).getByText('Pending review')).toBeInTheDocument();
    expect(
      within(first).getByRole('link', { name: '2 active findings on shop.example.com' }),
    ).toHaveAttribute('href', `/findings?q=shop.example.com&domainId=${DOMAIN_ID}`);

    const second = rows[2]!;
    expect(within(second).getByText('Amazon CloudFront')).toBeInTheDocument();
    expect(within(second).getByText('· CDN')).toBeInTheDocument();
    expect(within(second).getByText('Wildcard only')).toBeInTheDocument();
    expect(within(second).getByText('None resolved')).toBeInTheDocument();
  });

  it('keeps every filter in the URL and sends it to the API', async () => {
    const calls = stubList('viewer', {
      [ASSET_PATHS.list(
        `?domainId=${DOMAIN_ID}&source=certificate_transparency&thirdParty=true&q=shop&sort=-lastSeenAt`,
      )]: ok(page([pendingRows[1]!])),
    });
    const router = renderAt('/assets');
    await table();

    await userEvent.selectOptions(screen.getByLabelText('Status'), 'all');
    expect(router.state.location.search).toBe('?status=all');
    await userEvent.selectOptions(screen.getByLabelText('Domain'), DOMAIN_ID);
    await userEvent.selectOptions(screen.getByLabelText('Source'), 'certificate_transparency');
    await userEvent.selectOptions(screen.getByLabelText('Third-party hosting'), 'true');
    await userEvent.type(screen.getByLabelText('Search hostnames'), 'shop{Enter}');
    await userEvent.selectOptions(screen.getByLabelText('Sort'), '-lastSeenAt');

    const search = new URLSearchParams(router.state.location.search);
    expect(Object.fromEntries(search)).toEqual({
      status: 'all',
      domainId: DOMAIN_ID,
      source: 'certificate_transparency',
      thirdParty: 'true',
      q: 'shop',
      sort: '-lastSeenAt',
    });
    // "All statuses" sends no status filter.
    expect(calls.at(-1)?.path).toBe(
      `/api/v1/assets?domainId=${DOMAIN_ID}&source=certificate_transparency&thirdParty=true&q=shop&sort=-lastSeenAt`,
    );
    expect(await screen.findByRole('link', { name: 'cdn.example.com' })).toBeInTheDocument();
  });

  it('reads filters and paging from the URL', async () => {
    const calls = stubList('viewer', {
      [ASSET_PATHS.list('?page=2&status=approved&thirdParty=false')]: ok({
        ...page([asset({ status: 'approved' })], 30, 2),
      }),
    });
    renderAt('/assets?status=approved&thirdParty=false&page=2');
    await table();
    expect(calls.map((c) => c.path)).toContain(
      '/api/v1/assets?page=2&status=approved&thirdParty=false',
    );
    expect(screen.getByLabelText('Status')).toHaveValue('approved');
    expect(screen.getByLabelText('Third-party hosting')).toHaveValue('false');
    expect(screen.getByText('26–30 of 30')).toBeInTheDocument();
  });

  it('explains discovery in the empty review queue', async () => {
    stubList('viewer', { [ASSET_PATHS.list('?status=pending')]: ok(page([])) });
    renderAt('/assets');
    expect(await screen.findByText('Nothing waiting for review')).toBeInTheDocument();
    const text = screen.getByText(/Certificate Transparency logs/).textContent;
    expect(text).toMatch(/proves neither that your organisation owns it nor that the host is live/);
    expect(text).toMatch(/Nothing is scanned until it is approved/);
  });

  it('shows a filtered empty state', async () => {
    stubList('viewer', { [ASSET_PATHS.list('?status=pending&q=zzz')]: ok(page([])) });
    renderAt('/assets?q=zzz');
    expect(await screen.findByText('No assets match these filters')).toBeInTheDocument();
  });

  it('shows API errors', async () => {
    stubList('viewer', {
      [ASSET_PATHS.list('?status=pending')]: apiError(500, 'internal_error', 'Boom.'),
    });
    renderAt('/assets');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load assets');
  });
});

describe('Assets list: selection and bulk decisions', () => {
  it.each<Role>(['analyst', 'viewer', 'asset_owner'])(
    'offers no selection to %s (no assets:approve)',
    async (role) => {
      stubList(role);
      renderAt('/assets');
      await table();
      expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
      expect(screen.queryByRole('group', { name: /selected assets/ })).not.toBeInTheDocument();
    },
  );

  it('lets admins select rows and shows only decisions that apply', async () => {
    stubList('admin');
    renderAt('/assets');
    await table();
    expect(
      screen.queryByRole('group', { name: 'Decisions for selected assets' }),
    ).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select shop.example.com' }));
    const bar = screen.getByRole('group', { name: 'Decisions for selected assets' });
    expect(
      within(bar)
        .getAllByRole('button')
        .map((b) => b.textContent),
    ).toEqual(['Approve', 'Reject', 'Clear selection']);
  });

  it('never offers Reject when only the apex is selected', async () => {
    stubList('admin', {
      [ASSET_PATHS.list('?status=pending')]: ok(
        page([asset({ id: APEX_ID, hostname: 'example.com', assetType: 'apex' })]),
      ),
    });
    renderAt('/assets');
    await table();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select example.com' }));
    const bar = screen.getByRole('group', { name: 'Decisions for selected assets' });
    expect(within(bar).queryByRole('button', { name: 'Reject' })).not.toBeInTheDocument();
    expect(within(bar).getByRole('button', { name: 'Approve' })).toBeInTheDocument();
  });

  it('requires a reason and the third-party acknowledgement, then reports the result', async () => {
    const calls = stubList('admin', {
      [ASSET_PATHS.bulk]: ok({
        updated: 1,
        skipped: [{ id: SECOND_ID, code: 'third_party_not_acknowledged' }],
      }),
    });
    renderAt('/assets');
    await table();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select all assets on this page' }));
    const bar = screen.getByRole('group', { name: 'Decisions for selected assets' });
    await userEvent.click(within(bar).getByRole('button', { name: 'Approve' }));

    const form = within(bar).getByRole('form', { name: 'Approve: 2 assets' });
    const ack = within(form).getByRole('checkbox', {
      name: /Amazon CloudFront as a normal visitor/,
    });
    expect(ack).not.toBeChecked();
    expect(within(form).getByText(/port and network checks still need an approved network/));

    await userEvent.click(within(form).getByRole('button', { name: 'Approve 2 assets' }));
    expect(within(form).getByText('A reason is required.')).toBeInTheDocument();
    expect(
      within(form).getByText('Confirm the third-party hosting acknowledgement to approve.'),
    ).toBeInTheDocument();
    expect(calls.some((c) => c.path === '/api/v1/assets/bulk')).toBe(false);

    await userEvent.type(within(form).getByLabelText(/Reason/), 'ok');
    await userEvent.click(within(form).getByRole('button', { name: 'Approve 2 assets' }));
    expect(within(form).getByText('Enter at least 3 characters.')).toBeInTheDocument();

    await userEvent.type(within(form).getByLabelText(/Reason/), ' - owned shop');
    await userEvent.click(ack);
    await userEvent.click(within(form).getByRole('button', { name: 'Approve 2 assets' }));

    const post = calls.find((c) => c.path === '/api/v1/assets/bulk');
    expect(post?.body).toEqual({
      ids: [pendingRows[0]!.id, SECOND_ID],
      action: 'approve',
      reason: 'ok - owned shop',
      acknowledgeThirdPartyHosting: true,
    });
    expect(await screen.findByText(/^Updated/)).toHaveTextContent(
      'Updated 1, skipped 1 (1 third-party hosting not acknowledged). The asset was approved.',
    );
    expect(screen.queryByRole('group', { name: /selected assets/ })).not.toBeInTheDocument();
  });

  it('does not ask for the acknowledgement when no selected asset has a hosting hint', async () => {
    const calls = stubList('admin', {
      [ASSET_PATHS.bulk]: ok({
        updated: 0,
        skipped: [
          { id: pendingRows[0]!.id, code: 'invalid_transition' },
          { id: SECOND_ID, code: 'no_change' },
        ],
      }),
    });
    renderAt('/assets');
    await table();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select shop.example.com' }));
    await userEvent.click(screen.getByRole('button', { name: 'Reject' }));
    const form = screen.getByRole('form', { name: 'Reject: 1 asset' });
    expect(within(form).queryByRole('checkbox')).not.toBeInTheDocument();
    await userEvent.type(within(form).getByLabelText(/Reason/), 'Not ours');
    await userEvent.click(within(form).getByRole('button', { name: 'Reject 1 asset' }));
    expect(calls.find((c) => c.path === '/api/v1/assets/bulk')?.body).toEqual({
      ids: [pendingRows[0]!.id],
      action: 'reject',
      reason: 'Not ours',
      acknowledgeThirdPartyHosting: false,
    });
    expect(await screen.findByText(/^Updated/)).toHaveTextContent(
      'Updated 0, skipped 2 (1 decision not possible from their current status; 1 already in that state).',
    );
  });

  it('keeps the form open and shows the server error', async () => {
    stubList('admin', {
      [ASSET_PATHS.bulk]: apiError(403, 'forbidden', 'You do not have permission.'),
    });
    renderAt('/assets');
    await table();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select shop.example.com' }));
    await userEvent.click(screen.getByRole('button', { name: 'Reject' }));
    await userEvent.type(screen.getByLabelText(/Reason/), 'Not ours');
    await userEvent.click(screen.getByRole('button', { name: 'Reject 1 asset' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'You do not have permission to make this decision',
    );
    expect(screen.getByRole('form', { name: 'Reject: 1 asset' })).toBeInTheDocument();
  });

  it('clears the selection when a filter changes', async () => {
    stubList('admin', { [ASSET_PATHS.list('?status=pending&thirdParty=true')]: ok(page([])) });
    renderAt('/assets');
    await table();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select shop.example.com' }));
    expect(screen.getByRole('group', { name: /selected assets/ })).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Third-party hosting'), 'true');
    expect(screen.queryByRole('group', { name: /selected assets/ })).not.toBeInTheDocument();
  });

  it('is operable with the keyboard', async () => {
    stubList('admin');
    renderAt('/assets');
    await table();
    const box = screen.getByRole('checkbox', { name: 'Select shop.example.com' });
    box.focus();
    await userEvent.keyboard(' ');
    expect(box).toBeChecked();
    const approve = screen.getByRole('button', { name: 'Approve' });
    approve.focus();
    await userEvent.keyboard('{Enter}');
    expect(approve).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByLabelText(/Reason/)).toBeInTheDocument();
  });
});

describe('Assets list: roles (Milestone 13)', () => {
  it('shows each asset role and filters by role through the URL', async () => {
    const calls = stubList('viewer', {
      [ASSET_PATHS.list('?status=pending')]: ok(
        page([asset({ role: 'web' }), asset({ id: SECOND_ID, hostname: 'cdn.example.com' })]),
      ),
      [ASSET_PATHS.list('?status=pending&role=mail')]: ok(
        page([asset({ hostname: 'mx.example.com', role: 'mail' })]),
      ),
    });
    const router = renderAt('/assets');
    const t = await table();
    expect(within(t).getByRole('columnheader', { name: 'Role' })).toBeInTheDocument();
    const rows = within(t).getAllByRole('row');
    expect(within(rows[1]!).getByText('Web server')).toBeInTheDocument();
    expect(within(rows[2]!).getAllByText('—')).toHaveLength(2); // no role, no hosting

    await userEvent.selectOptions(screen.getByLabelText('Role'), 'mail');
    expect(router.state.location.search).toBe('?role=mail');
    expect(await screen.findByRole('link', { name: 'mx.example.com' })).toBeInTheDocument();
    expect(calls.at(-1)?.path).toBe('/api/v1/assets?status=pending&role=mail');
    expect(within(await table()).getByText('Mail server')).toBeInTheDocument();
  });
});
