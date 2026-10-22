// Findings card on the domain page and bulk monitoring on the domain list.
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { DOMAIN_ID, NO_CATEGORIES, domain, finding, page } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const summary = (bySeverity: Record<string, number>) => ({
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, ...bySeverity },
  total: Object.values(bySeverity).reduce((a, b) => a + b, 0),
  byCategory: NO_CATEGORIES,
});

function stubDomainPage(handlers: Parameters<typeof stubApi>[1] = {}) {
  return stubApi('viewer', {
    [`GET /api/v1/domains/${DOMAIN_ID}`]: ok({ domain: domain(), verification: null }),
    [`GET /api/v1/findings/summary?domainId=${DOMAIN_ID}`]: ok(summary({ high: 2, low: 1 })),
    [`GET /api/v1/findings?domainId=${DOMAIN_ID}&status=active&sort=-riskScore&pageSize=5`]: ok(
      page([finding()], 3),
    ),
    ...handlers,
  });
}

describe('Domain findings card', () => {
  it('summarises active findings and links to the filtered list', async () => {
    stubDomainPage();
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await screen.findByRole('region', { name: 'Findings' });
    expect(
      await within(card).findByRole('link', { name: 'Certificate expires within 14 days' }),
    ).toBeInTheDocument();
    expect(within(card).getByTestId('count-high')).toHaveTextContent('2');
    expect(within(card).getByTestId('count-low')).toHaveTextContent('1');
    expect(within(card).getByRole('link', { name: 'View all 3 active findings' })).toHaveAttribute(
      'href',
      `/findings?domainId=${DOMAIN_ID}`,
    );
  });

  it('sits after Scans and keeps the Assets placeholder', async () => {
    stubDomainPage();
    renderAt(`/domains/${DOMAIN_ID}`);
    await screen.findByRole('region', { name: 'Findings' });
    const names = screen.getAllByRole('region').map((r) => r.getAttribute('aria-label'));
    expect(names.indexOf('Findings')).toBe(names.indexOf('Scans') + 1);
    expect(names.at(-1)).toBe('Assets');
  });

  it('explains when a domain has no active findings', async () => {
    stubDomainPage({
      [`GET /api/v1/findings/summary?domainId=${DOMAIN_ID}`]: ok(summary({})),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await screen.findByRole('region', { name: 'Findings' });
    expect(await within(card).findByText(/No active findings/)).toBeInTheDocument();
  });

  it('shows an error inside the card without hiding the page', async () => {
    stubDomainPage({
      [`GET /api/v1/findings/summary?domainId=${DOMAIN_ID}`]: () => ({
        status: 500,
        body: { error: { code: 'internal_error', message: 'Boom.', requestId: 'r4' } },
      }),
    });
    renderAt(`/domains/${DOMAIN_ID}`);
    const card = await screen.findByRole('region', { name: 'Findings' });
    expect(await within(card).findByRole('alert')).toHaveTextContent('Could not load findings');
    expect(screen.getByRole('region', { name: 'Scans' })).toBeInTheDocument();
  });
});

describe('Bulk monitoring', () => {
  const second = domain({ id: crypto.randomUUID(), fqdn: 'example.org' });

  it('turns monitoring on for selected domains after confirmation', async () => {
    const calls = stubApi('admin', {
      'GET /api/v1/domains': ok(page([domain(), second])),
      'POST /api/v1/domains/monitoring': ok({ updated: 1 }),
    });
    renderAt('/domains');
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select example.com' }));
    await userEvent.click(screen.getByRole('button', { name: 'Turn on monitoring for selected' }));
    const dialog = screen.getByRole('alertdialog', {
      name: 'Turn on monitoring for 1 selected domain?',
    });
    expect(dialog).toHaveAccessibleDescription(/daily passive scan.*only for verified domains/s);
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Turn on for selected' }));
    expect(await screen.findByText(/Monitoring turned on for 1 domain\./)).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      domainIds: [DOMAIN_ID],
      enabled: true,
    });
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('turns monitoring off for selected domains', async () => {
    const calls = stubApi('admin', {
      'GET /api/v1/domains': ok(page([domain({ monitoringEnabled: true }), second])),
      'POST /api/v1/domains/monitoring': ok({ updated: 2 }),
    });
    renderAt('/domains');
    await userEvent.click(
      await screen.findByRole('checkbox', { name: 'Select all domains on this page' }),
    );
    await userEvent.click(screen.getByRole('button', { name: 'Turn off monitoring for selected' }));
    expect(await screen.findByText(/Monitoring turned off for 2 domains\./)).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      domainIds: [DOMAIN_ID, second.id],
      enabled: false,
    });
  });

  it('turns monitoring on for all domains only after confirmation, and can be cancelled', async () => {
    const calls = stubApi('admin', {
      'GET /api/v1/domains': ok(page([domain()])),
      'POST /api/v1/domains/monitoring': ok({ updated: 7 }),
    });
    renderAt('/domains');
    const open = await screen.findByRole('button', { name: 'Turn on monitoring for all domains' });
    await userEvent.click(open);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    await userEvent.click(open);
    const dialog = screen.getByRole('alertdialog', {
      name: 'Turn on monitoring for every registered domain?',
    });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Turn on for all domains' }));
    expect(await screen.findByText(/Monitoring turned on for 7 domains\./)).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ all: true, enabled: true });
  });

  it('shows the server error when the change is refused', async () => {
    stubApi('admin', {
      'GET /api/v1/domains': ok(page([domain()])),
      'POST /api/v1/domains/monitoring': () => ({
        status: 403,
        body: { error: { code: 'forbidden', message: 'Not allowed.', requestId: 'r5' } },
      }),
    });
    renderAt('/domains');
    await userEvent.click(
      await screen.findByRole('button', { name: 'Turn on monitoring for all domains' }),
    );
    await userEvent.click(screen.getByRole('button', { name: 'Turn on for all domains' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Not allowed.');
  });

  it('offers no monitoring controls or selection to viewers', async () => {
    stubApi('viewer', { 'GET /api/v1/domains': ok(page([domain()])) });
    renderAt('/domains');
    await screen.findByRole('link', { name: 'example.com' });
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Turn on monitoring/ })).not.toBeInTheDocument();
  });
});
