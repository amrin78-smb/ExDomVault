import type { Domain, Permission, Role } from '@exdomainvault/shared';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RouterProvider, createMemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDomainCards } from '../../testing/domain-cards.ts';
import { DataModeProvider } from '../../lib/DataModeProvider.tsx';
import { routes } from '../../testing/eager-routes.ts';

const DOMAIN_ID = '0b8e3f9a-4c1d-4e5f-8a7b-1c2d3e4f5a6b';

const domain = (overrides: Partial<Domain> = {}): Domain => ({
  id: DOMAIN_ID,
  fqdn: 'example.com',
  unicodeFqdn: 'example.com',
  warnings: [],
  registrar: null,
  registeredAt: null,
  expiresAt: null,
  registrationDataStatus: 'unknown',
  criticality: 'high',
  businessOwner: 'Platform team',
  verificationStatus: 'unverified',
  verifiedAt: null,
  verificationMethod: null,
  verificationExpiresAt: null,
  monitoringEnabled: false,
  brandMonitoring: false,
  score: null,
  grade: null,
  createdAt: '2026-10-22T10:00:00.000Z',
  updatedAt: '2026-10-22T10:00:00.000Z',
  ...overrides,
});

const PERMISSIONS: Record<Role, Permission[]> = {
  admin: ['domains:read', 'domains:write', 'domains:verify'],
  analyst: ['domains:read'],
  viewer: ['domains:read'],
  asset_owner: [],
};

type Handler = (body: unknown) => { status: number; body: unknown };

interface Call {
  method: string;
  path: string;
  body: unknown;
}

/** Routes fetch calls by "METHOD path" and records every request. */
function stubApi(role: Role, handlers: Record<string, Handler>) {
  const calls: Call[] = [];
  const all: Record<string, Handler> = {
    'GET /api/v1/health': () => ({
      status: 200,
      body: {
        status: 'ok',
        service: 'exdomainvault-api',
        version: '0.1.0',
        environment: 'development',
        time: '2026-10-22T00:00:00.000Z',
        components: { database: 'ok', auth: 'ok' },
      },
    }),
    'GET /api/v1/me': () => ({
      status: 200,
      body: {
        user: { id: crypto.randomUUID(), email: `${role}@example.com`, displayName: null, role },
        permissions: PERMISSIONS[role],
        authProvider: 'cloudflare_access',
      },
    }),
    ...handlers,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined;
      calls.push({ method, path, body });
      const handler = all[`${method} ${path}`];
      const r = handler ? handler(body) : { status: 404, body: {} };
      return new Response(JSON.stringify(r.body), { status: r.status });
    }),
  );
  return calls;
}

const listOf = (items: Domain[]) => () => ({
  status: 200,
  body: { items, page: 1, pageSize: 25, total: items.length },
});
const detailOf =
  (d: Domain, verification: unknown = null) =>
  () => ({
    status: 200,
    body: { domain: d, verification },
  });

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(
    <DataModeProvider fixtures={false}>
      <RouterProvider router={router} />
    </DataModeProvider>,
  );
  return router;
}

beforeEach(openDomainCards);
afterEach(() => vi.unstubAllGlobals());

describe('Domains list', () => {
  it('lists domains with status and links to detail', async () => {
    stubApi('admin', {
      'GET /api/v1/domains': listOf([
        domain(),
        domain({
          id: crypto.randomUUID(),
          fqdn: 'xn--xample-2of.com',
          unicodeFqdn: 'еxample.com',
          warnings: ['idn', 'mixed_script'],
          verificationStatus: 'verified',
        }),
      ]),
    });
    renderAt('/domains');
    const link = await screen.findByRole('link', { name: 'example.com' });
    expect(link).toHaveAttribute('href', `/domains/${DOMAIN_ID}`);
    const table = screen.getByRole('table');
    expect(within(table).getByText('Unverified')).toBeInTheDocument();
    expect(within(table).getByText('Verified')).toBeInTheDocument();
    expect(within(table).getByLabelText(/possible homograph/)).toBeInTheDocument();
    expect(screen.getByText('1–2 of 2')).toBeInTheDocument();
  });

  it('hides add and import actions from roles without domains:write', async () => {
    stubApi('analyst', { 'GET /api/v1/domains': listOf([]) });
    renderAt('/domains');
    expect(await screen.findByText('No domains yet')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Add domain/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Import CSV/ })).not.toBeInTheDocument();
  });

  it('applies filters through the query string', async () => {
    const calls = stubApi('viewer', {
      'GET /api/v1/domains': listOf([domain()]),
      'GET /api/v1/domains?criticality=critical': listOf([]),
    });
    renderAt('/domains');
    await screen.findByRole('link', { name: 'example.com' });
    await userEvent.selectOptions(screen.getByLabelText('Criticality'), 'critical');
    expect(await screen.findByText('No domains match these filters')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/domains?criticality=critical');
  });

  it('adds a domain and opens it', async () => {
    const calls = stubApi('admin', {
      'GET /api/v1/domains': listOf([]),
      'POST /api/v1/domains': () => ({
        status: 201,
        body: { domain: domain(), verification: null },
      }),
      [`GET /api/v1/domains/${DOMAIN_ID}`]: detailOf(domain()),
    });
    const router = renderAt('/domains');
    await userEvent.click(await screen.findByRole('button', { name: 'Add domain' }));
    await userEvent.type(screen.getByLabelText('Domain'), 'Example.COM');
    await userEvent.click(
      within(screen.getByRole('region', { name: 'Add a domain' })).getByRole('button', {
        name: 'Add domain',
      }),
    );

    expect(
      await screen.findByRole('heading', { level: 1, name: 'example.com' }),
    ).toBeInTheDocument();
    expect(router.state.location.pathname).toBe(`/domains/${DOMAIN_ID}`);
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      fqdn: 'Example.COM',
      criticality: 'medium',
      businessOwner: '',
    });
  });

  it('shows the server explanation when a domain is rejected', async () => {
    stubApi('admin', {
      'GET /api/v1/domains': listOf([]),
      'POST /api/v1/domains': () => ({
        status: 400,
        body: {
          error: {
            code: 'validation_failed',
            message: 'The domain name is invalid.',
            requestId: 'req-1',
            details: [{ path: 'fqdn', message: 'www.example.com is a subdomain.' }],
          },
        },
      }),
    });
    renderAt('/domains');
    await userEvent.click(await screen.findByRole('button', { name: 'Add domain' }));
    await userEvent.type(screen.getByLabelText('Domain'), 'www.example.com');
    await userEvent.click(
      within(screen.getByRole('region', { name: 'Add a domain' })).getByRole('button', {
        name: 'Add domain',
      }),
    );
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('www.example.com is a subdomain.');
    expect(alert).toHaveTextContent('Request ID: req-1');
  });
});

describe('Bulk authorisation', () => {
  it('authorises selected domains and reloads the list', async () => {
    const second = domain({ id: crypto.randomUUID(), fqdn: 'example.org' });
    let authorised = false;
    const calls = stubApi('admin', {
      'GET /api/v1/domains': () =>
        listOf(
          authorised
            ? [
                domain({
                  verificationStatus: 'verified',
                  verifiedAt: '2026-10-22T12:00:00.000Z',
                  verificationMethod: 'admin_attestation',
                  verificationExpiresAt: '2027-10-22T23:59:59.999Z',
                }),
                second,
              ]
            : [domain(), second],
        )(),
      'POST /api/v1/domains/authorise': () => {
        authorised = true;
        return {
          status: 200,
          body: { authorised: [{ id: DOMAIN_ID, fqdn: 'example.com' }], skipped: [] },
        };
      },
    });
    renderAt('/domains');
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select example.com' }));
    const form = screen.getByRole('region', { name: /Authorise 1 selected domain/ });
    await userEvent.type(within(form).getByLabelText('Reason'), 'Group-owned; DNS managed by CSC');
    await userEvent.click(within(form).getByRole('button', { name: 'Authorise 1 domain' }));

    expect(await screen.findByText(/Authorised 1 domain/)).toBeInTheDocument();
    expect(await screen.findByText('Authorised (admin)')).toBeInTheDocument();
    expect(calls.find((c) => c.path === '/api/v1/domains/authorise')?.body).toMatchObject({
      domainIds: [DOMAIN_ID],
      reason: 'Group-owned; DNS managed by CSC',
    });
  });

  it('offers selection only to roles that can verify', async () => {
    stubApi('analyst', { 'GET /api/v1/domains': listOf([domain()]) });
    renderAt('/domains');
    await screen.findByRole('link', { name: 'example.com' });
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  });
});

describe('Domain detail', () => {
  const challenge = {
    id: crypto.randomUUID(),
    method: 'dns_txt',
    status: 'pending',
    recordName: '_exdomainvault-challenge.example.com',
    reason: null,
    reference: null,
    createdAt: '2026-10-22T10:00:00.000Z',
    expiresAt: '2026-10-25T10:00:00.000Z',
    lastCheckedAt: null,
    verifiedAt: null,
    failureReason: null,
  };

  it('starts verification and shows the record value once', async () => {
    stubApi('admin', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: detailOf(domain()),
      [`POST /api/v1/domains/${DOMAIN_ID}/verification`]: () => ({
        status: 201,
        body: {
          challenge,
          record: {
            type: 'TXT',
            name: '_exdomainvault-challenge.example.com',
            value: 'exdomainvault-verification=secret-token',
          },
        },
      }),
      [`POST /api/v1/domains/${DOMAIN_ID}/verify`]: () => ({
        status: 200,
        body: {
          outcome: 'record_not_found',
          message: 'No verification TXT record was found yet.',
          domain: domain({ verificationStatus: 'pending' }),
          verification: {
            ...challenge,
            lastCheckedAt: '2026-10-22T10:01:00.000Z',
            failureReason: 'record_not_found',
          },
        },
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    await userEvent.click(
      await screen.findByRole('button', { name: 'Verify with DNS TXT record' }),
    );

    expect(await screen.findByText('exdomainvault-verification=secret-token')).toBeInTheDocument();
    expect(screen.getByText(/shown only once/)).toBeInTheDocument();
    expect(screen.getByText('Verification pending')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Check now' }));
    expect(
      await screen.findByText('No verification TXT record was found yet.'),
    ).toBeInTheDocument();
    // The value is still visible after a failed check so it can be fixed in DNS.
    expect(screen.getByText('exdomainvault-verification=secret-token')).toBeInTheDocument();
    expect(screen.getByText('No TXT record found')).toBeInTheDocument();
  });

  it('shows verification state read-only to viewers', async () => {
    stubApi('viewer', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: detailOf(
        domain({ verificationStatus: 'pending' }),
        challenge,
      ),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(await screen.findByText('_exdomainvault-challenge.example.com')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Check now' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Generate new value/ })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Turn (on|off) monitoring/ }),
    ).not.toBeInTheDocument();
    expect(screen.getByText('Platform team')).toBeInTheDocument();
  });

  it('requires confirmation before turning monitoring on', async () => {
    const verified = domain({
      verificationStatus: 'verified',
      verifiedAt: '2026-10-22T11:00:00.000Z',
    });
    const calls = stubApi('admin', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: detailOf(verified),
      [`PATCH /api/v1/domains/${DOMAIN_ID}`]: () => ({
        status: 200,
        body: {
          domain: { ...verified, monitoringEnabled: true, updatedAt: '2026-10-22T12:00:00.000Z' },
          verification: null,
        },
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Turn on monitoring' }));
    expect(calls.filter((c) => c.method === 'PATCH')).toHaveLength(0);

    const dialog = screen.getByRole('alertdialog');
    expect(dialog).toHaveTextContent('Start monitoring example.com?');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Turn on' }));

    expect(await screen.findByText('Monitoring is on')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ monitoringEnabled: true });
  });

  it('offers passive monitoring before verification', async () => {
    stubApi('admin', { [`GET /api/v1/domains/${DOMAIN_ID}`]: detailOf(domain()) });
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(await screen.findByRole('button', { name: 'Turn on monitoring' })).toBeEnabled();
    expect(screen.getByText(/Active scanning also requires verification/)).toBeInTheDocument();
  });

  it('authorises a domain without DNS, with reason, reference and review date', async () => {
    const calls = stubApi('admin', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: detailOf(domain()),
      [`POST /api/v1/domains/${DOMAIN_ID}/authorise`]: (body) => ({
        status: 200,
        body: {
          domain: domain({
            verificationStatus: 'verified',
            verifiedAt: '2026-10-22T12:00:00.000Z',
            verificationMethod: 'admin_attestation',
            verificationExpiresAt: '2027-10-22T23:59:59.999Z',
          }),
          verification: {
            ...challenge,
            method: 'admin_attestation',
            status: 'verified',
            recordName: null,
            reason: (body as { reason: string }).reason,
            reference: 'CSC portfolio export',
            verifiedAt: '2026-10-22T12:00:00.000Z',
          },
        },
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Authorise without DNS' }));
    const form = screen.getByRole('form', { name: 'Authorise without DNS' });
    const submit = within(form).getByRole('button', { name: 'Authorise example.com' });
    expect(submit).toBeDisabled();
    await userEvent.type(
      within(form).getByLabelText('Reason'),
      'Owned by the group; DNS run by the registrar',
    );
    await userEvent.type(within(form).getByLabelText(/Reference/), 'CSC portfolio export');
    await userEvent.click(submit);

    expect(await screen.findByText(/Authorised by an administrator/)).toBeInTheDocument();
    expect(screen.getByText('Authorised (admin)')).toBeInTheDocument();
    expect(screen.getByText('CSC portfolio export')).toBeInTheDocument();
    const body = calls.find((c) => c.path.endsWith('/authorise'))?.body as Record<string, string>;
    expect(body).toMatchObject({
      reason: 'Owned by the group; DNS run by the registrar',
      reference: 'CSC portfolio export',
    });
    expect(body.reviewBy).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it('requires a reason before revoking', async () => {
    const verified = domain({
      verificationStatus: 'verified',
      verifiedAt: '2026-10-22T11:00:00.000Z',
      verificationMethod: 'dns_txt',
    });
    const calls = stubApi('admin', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: detailOf(verified),
      [`POST /api/v1/domains/${DOMAIN_ID}/revoke`]: () => ({
        status: 200,
        body: { domain: domain({ verificationStatus: 'revoked' }), verification: null },
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(await screen.findByText('Verified (DNS)')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Revoke verification' }));
    const dialog = screen.getByRole('alertdialog', { name: 'Confirm revocation' });
    const revoke = within(dialog).getByRole('button', { name: 'Revoke' });
    expect(revoke).toBeDisabled();
    await userEvent.type(within(dialog).getByRole('textbox'), 'Domain sold to a third party');
    await userEvent.click(revoke);
    expect(await screen.findByText(/Verification of this domain was revoked/)).toBeInTheDocument();
    expect(calls.find((c) => c.path.endsWith('/revoke'))?.body).toEqual({
      reason: 'Domain sold to a third party',
    });
  });

  it('warns about mixed-script names', async () => {
    stubApi('viewer', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: detailOf(
        domain({
          fqdn: 'xn--xample-2of.com',
          unicodeFqdn: 'еxample.com',
          warnings: ['idn', 'mixed_script'],
        }),
      ),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(await screen.findByRole('note')).toHaveTextContent('mixes writing systems');
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('xn--xample-2of.com');
  });

  it('reports a missing domain', async () => {
    stubApi('viewer', {
      [`GET /api/v1/domains/${DOMAIN_ID}`]: () => ({
        status: 404,
        body: {
          error: {
            code: 'not_found',
            message: 'The requested resource was not found.',
            requestId: 'r',
          },
        },
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load this domain');
  });
});

describe('Domain import', () => {
  const csv = 'domain,criticality\nalpha.com,high\nwww.bravo.com,\n';
  const preview = {
    digest: 'a'.repeat(64),
    fileErrors: [],
    rows: [
      {
        line: 2,
        input: 'alpha.com',
        fqdn: 'alpha.com',
        unicodeFqdn: 'alpha.com',
        criticality: 'high',
        businessOwner: null,
        status: 'valid',
        errors: [],
        warnings: [],
      },
      {
        line: 3,
        input: 'www.bravo.com',
        fqdn: null,
        unicodeFqdn: null,
        criticality: 'medium',
        businessOwner: null,
        status: 'invalid',
        errors: ['www.bravo.com is a subdomain.'],
        warnings: [],
      },
    ],
    summary: { total: 2, valid: 1, invalid: 1, duplicateInFile: 0, alreadyRegistered: 0 },
  };

  it('previews, then imports only after confirmation with the preview digest', async () => {
    const calls = stubApi('admin', {
      'POST /api/v1/domains/import/preview': () => ({ status: 200, body: preview }),
      'POST /api/v1/domains/import': () => ({
        status: 201,
        body: { created: [{ id: DOMAIN_ID, fqdn: 'alpha.com' }], skipped: 1, authorised: 0 },
      }),
    });
    renderAt('/domains/import');
    const textarea = await screen.findByLabelText('Or paste CSV text');
    await userEvent.click(textarea);
    await userEvent.paste(csv);
    await userEvent.click(screen.getByRole('button', { name: 'Preview import' }));

    expect(await screen.findByText('www.bravo.com is a subdomain.')).toBeInTheDocument();
    expect(screen.getByText('Will be added')).toBeInTheDocument();
    expect(calls.some((c) => c.path === '/api/v1/domains/import')).toBe(false);

    await userEvent.click(screen.getByRole('button', { name: 'Import 1 domain' }));
    expect(await screen.findByText(/Added 1 domain; skipped 1 row/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'alpha.com' })).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}`,
    );
    expect(calls.find((c) => c.path === '/api/v1/domains/import')?.body).toEqual({
      csv,
      digest: preview.digest,
    });
  });

  it('blocks import when the file has file-level errors', async () => {
    stubApi('admin', {
      'POST /api/v1/domains/import/preview': () => ({
        status: 200,
        body: {
          ...preview,
          rows: [],
          fileErrors: ['The header row must include a "domain" column.'],
          summary: { total: 0, valid: 0, invalid: 0, duplicateInFile: 0, alreadyRegistered: 0 },
        },
      }),
    });
    renderAt('/domains/import');
    await userEvent.type(await screen.findByLabelText('Or paste CSV text'), 'name');
    await userEvent.click(screen.getByRole('button', { name: 'Preview import' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('must include a "domain" column');
    expect(screen.queryByRole('button', { name: /^Import \d/ })).not.toBeInTheDocument();
  });
});
