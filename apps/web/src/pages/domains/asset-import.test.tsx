// Host import page: file → extracted hostnames → dry-run preview → confirmed import.
import type { AssetImportResponse, Role } from '@exdomainvault/shared';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { domain } from '../findings/test-data.ts';
import { DOMAIN_ID } from '../assets/test-data.ts';
import { apiError, ok, renderAt, stubApi, type Handler } from '../../testing/stub-api.tsx';

afterEach(() => vi.unstubAllGlobals());

const IMPORT = `POST /api/v1/domains/${DOMAIN_ID}/assets/import`;
const PAGE = `/domains/${DOMAIN_ID}/import-hosts`;

/** The owner's zone export layout, as CSV. */
const ZONE_CSV = [
  'zoneName,name,type,ttl,data',
  'example.com.,www,A,600,203.0.113.10',
  'example.com.,,A,600,203.0.113.11',
  'example.com.,shop,CNAME,600,shops.myshopify.com.',
  'example.com.,_dmarc,TXT,600,"v=DMARC1; p=reject"',
  'example.com.,mail,MX,600,10 mx.example.net.',
  'example.com.,_acme-challenge,CNAME,600,acme.example.net.',
  'example.com.,*,A,600,203.0.113.10',
].join('\r\n');

const EXPECTED_ENTRIES = [
  { hostname: 'www.example.com' },
  { hostname: 'example.com' },
  { hostname: 'shop.example.com', cnameTarget: 'shops.myshopify.com' },
];

const response = (dryRun: boolean): AssetImportResponse => ({
  dryRun,
  summary: {
    total: 3,
    new: 2,
    existing: 1,
    duplicate: 0,
    invalid: 0,
    outOfDomain: 0,
    thirdPartyHosted: 1,
  },
  rows: [
    { hostname: 'www.example.com', outcome: 'new', hostingHint: null },
    { hostname: 'example.com', outcome: 'existing', existingStatus: 'approved', hostingHint: null },
    {
      hostname: 'shop.example.com',
      outcome: 'new',
      hostingHint: { provider: 'Shopify', kind: 'saas', matchedName: 'shops.myshopify.com' },
    },
  ],
});

function stub(role: Role, handlers: Record<string, Handler> = {}) {
  return stubApi(role, {
    [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain: domain(), verification: null }),
    [IMPORT]: (body) => ok(response((body as { dryRun: boolean }).dryRun))(),
    ...handlers,
  });
}

const importCalls = (calls: ReturnType<typeof stub>) =>
  calls.filter((c) => c.method === 'POST' && c.path.endsWith('/assets/import'));

describe('Host import', () => {
  it('previews a zone export with a dry run, then imports after confirmation', async () => {
    const calls = stub('admin');
    renderAt(PAGE);
    const input = await screen.findByLabelText(/Choose file/);
    await userEvent.upload(
      input,
      new File([ZONE_CSV], 'example.com-records.csv', { type: 'text/csv' }),
    );

    expect(await screen.findByText(/found/)).toHaveTextContent(
      'Read as a table of DNS records: found 3 hostnames; skipped 2 records that do not name a host (TXT, MX, NS, SRV and similar), 1 service name (such as _dmarc or _domainkey), 1 wildcard.',
    );
    const preview = await screen.findByRole('region', { name: '2. Review and confirm' });
    expect(importCalls(calls)).toHaveLength(1);
    expect(importCalls(calls)[0]?.body).toEqual({
      entries: EXPECTED_ENTRIES,
      dryRun: true,
      fileName: 'example.com-records.csv',
    });

    const table = within(preview).getByRole('table');
    expect(within(table).getAllByText('New')).toHaveLength(2);
    expect(within(table).getByText('Already an asset')).toBeInTheDocument();
    expect(within(table).getByText('Approved')).toBeInTheDocument();
    expect(within(table).getByText('Shopify')).toBeInTheDocument();
    expect(within(preview).getByText(/2 new/)).toBeInTheDocument();

    // Filter by outcome.
    await userEvent.selectOptions(within(preview).getByRole('combobox'), 'existing');
    expect(within(table).queryByText('www.example.com')).not.toBeInTheDocument();
    expect(within(table).getByText('example.com')).toBeInTheDocument();

    await userEvent.click(within(preview).getByRole('button', { name: 'Add 2 hosts as pending' }));
    const done = await screen.findByRole('region', { name: 'Import complete' });
    expect(importCalls(calls)).toHaveLength(2);
    expect(importCalls(calls)[1]?.body).toEqual({
      entries: EXPECTED_ENTRIES,
      dryRun: false,
      fileName: 'example.com-records.csv',
    });
    expect(within(done).getByText(/Added 2 hostnames as pending/)).toBeInTheDocument();
    expect(within(done).getByText(/not scanned until they are approved/)).toBeInTheDocument();
    expect(within(done).getByRole('link', { name: 'Review pending hostnames' })).toHaveAttribute(
      'href',
      `/assets?domainId=${DOMAIN_ID}&status=pending`,
    );
    expect(screen.queryByRole('region', { name: '2. Review and confirm' })).not.toBeInTheDocument();
  });

  it('reads a pasted BIND zone file', async () => {
    const calls = stub('admin');
    renderAt(PAGE);
    const textarea = await screen.findByLabelText(/Or paste/);
    await userEvent.click(textarea);
    await userEvent.paste(
      '$ORIGIN example.com.\n@ 3600 IN SOA ns1 hostmaster 1 7200 900 1209600 300\nwww 600 IN A 203.0.113.10\napi IN CNAME lb.example.net.\n',
    );
    await userEvent.click(screen.getByRole('button', { name: 'Preview import' }));
    await screen.findByRole('region', { name: '2. Review and confirm' });
    expect(importCalls(calls)[0]?.body).toEqual({
      entries: [
        { hostname: 'www.example.com' },
        { hostname: 'api.example.com', cnameTarget: 'lb.example.net' },
      ],
      dryRun: true,
    });
  });

  it('refuses more than 5000 hostnames before calling the API', async () => {
    const calls = stub('admin');
    renderAt(PAGE);
    const list = Array.from({ length: 5001 }, (_, i) => `host${i}.example.com`).join('\n');
    await userEvent.upload(
      await screen.findByLabelText(/Choose file/),
      new File([list], 'hosts.txt', { type: 'text/plain' }),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The file contains 5001 hostnames; at most 5000 can be imported at once.',
    );
    expect(importCalls(calls)).toHaveLength(0);
  });

  it('shows API errors', async () => {
    stub('admin', { [IMPORT]: apiError(400, 'validation_failed', 'The request is invalid.') });
    renderAt(PAGE);
    await userEvent.upload(
      await screen.findByLabelText(/Choose file/),
      new File(['www.example.com\n'], 'hosts.txt', { type: 'text/plain' }),
    );
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('The hostnames could not be imported');
    expect(alert).toHaveTextContent('The request is invalid.');
  });

  it.each<Role>(['viewer', 'analyst'])('denies %s without domains:write', async (role) => {
    const calls = stub(role);
    renderAt(PAGE);
    expect(
      await screen.findByText('Importing hosts is not available to your role'),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/Choose file/)).not.toBeInTheDocument();
    expect(calls.some((c) => c.path === `/api/v1/domains/${DOMAIN_ID}`)).toBe(false);
  });

  it('links to the import from the domain page for users who can manage domains', async () => {
    stub('admin');
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await screen.findByRole('region', { name: 'Assets' });
    expect(within(card).getByRole('link', { name: 'Import hosts' })).toHaveAttribute('href', PAGE);
  });

  it('hides the import link from viewers', async () => {
    stub('viewer');
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await screen.findByRole('region', { name: 'Assets' });
    expect(within(card).queryByRole('link', { name: 'Import hosts' })).not.toBeInTheDocument();
  });
});
