import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { DOMAIN_ID, FINDING_ID, detailOf, finding, page } from './test-data.ts';

afterEach(() => vi.unstubAllGlobals());

describe('Findings list', () => {
  it('lists active findings by risk with severity, rule, host, risk, status and last seen', async () => {
    const calls = stubApi('viewer', { 'GET /api/v1/findings': ok(page([finding()])) });
    renderAt('/findings');
    const row = (
      await screen.findByRole('link', { name: 'Certificate expires within 14 days' })
    ).closest('tr');
    if (!row) throw new Error('row missing');
    expect(within(row).getByText('High')).toBeInTheDocument();
    expect(within(row).getByText('TLS-003')).toBeInTheDocument();
    expect(within(row).getByText('example.com')).toBeInTheDocument();
    expect(within(row).getByText('shop.example.com')).toBeInTheDocument();
    expect(within(row).getByText('60')).toBeInTheDocument();
    expect(within(row).getByText('Open')).toBeInTheDocument();
    expect(within(row).getByText(/Oct 22, 2026/)).toBeInTheDocument();
    expect(screen.getByLabelText('Status')).toHaveValue('');
    expect(screen.getByLabelText('Sort')).toHaveValue('-riskScore');
    expect(calls.some((c) => c.path === '/api/v1/findings')).toBe(true);
  });

  it('applies filters, search and sort through the query string', async () => {
    const calls = stubApi('analyst', {
      'GET /api/v1/findings': ok(page([finding()])),
      'GET /api/v1/findings?status=all': ok(page([finding()])),
      'GET /api/v1/findings?status=all&severity=high': ok(page([finding()])),
      'GET /api/v1/findings?status=all&severity=high&category=tls': ok(page([finding()])),
      'GET /api/v1/findings?status=all&severity=high&category=tls&q=shop': ok(page([])),
      'GET /api/v1/findings?status=all&severity=high&category=tls&q=shop&sort=-lastSeenAt': ok(
        page([]),
      ),
    });
    renderAt('/findings');
    await screen.findByRole('link', { name: 'Certificate expires within 14 days' });
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'all');
    await userEvent.selectOptions(screen.getByLabelText('Severity'), 'high');
    await userEvent.selectOptions(screen.getByLabelText('Category'), 'tls');
    await userEvent.type(screen.getByLabelText('Search findings'), 'shop');
    await userEvent.click(screen.getByRole('button', { name: 'Search' }));
    expect(await screen.findByText('No findings match these filters')).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Sort'), '-lastSeenAt');
    await screen.findByText('No findings match these filters');
    expect(calls.map((c) => c.path)).toContain(
      '/api/v1/findings?status=all&severity=high&category=tls&q=shop&sort=-lastSeenAt',
    );
  });

  it('filters by domain from the URL and lets the filter be cleared', async () => {
    stubApi('viewer', {
      [`GET /api/v1/findings?domainId=${DOMAIN_ID}`]: ok(page([finding()])),
      'GET /api/v1/findings': ok(
        page([finding(), finding({ id: crypto.randomUUID(), title: 'Other' })]),
      ),
    });
    renderAt(`/findings?domainId=${DOMAIN_ID}`);
    expect(await screen.findByText('Domain: example.com')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Clear filter Domain: example.com' }));
    expect(await screen.findByRole('link', { name: 'Other' })).toBeInTheDocument();
  });

  it('paginates', async () => {
    const calls = stubApi('viewer', {
      'GET /api/v1/findings': ok(page([finding()], 30)),
      'GET /api/v1/findings?page=2': ok({ ...page([finding()], 30), page: 2 }),
    });
    renderAt('/findings');
    await userEvent.click(await screen.findByRole('button', { name: 'Next' }));
    expect(await screen.findByText('26–30 of 30')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/findings?page=2');
  });

  it('explains where findings come from when there are none', async () => {
    stubApi('viewer', { 'GET /api/v1/findings': ok(page([])) });
    renderAt('/findings');
    expect(await screen.findByText('No active findings')).toBeInTheDocument();
    expect(screen.getByText(/completed scans.*five minutes/)).toBeInTheDocument();
  });

  it('shows API errors', async () => {
    stubApi('viewer', {
      'GET /api/v1/findings': () => ({
        status: 500,
        body: {
          error: { code: 'internal_error', message: 'Something went wrong.', requestId: 'r1' },
        },
      }),
    });
    renderAt('/findings');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load findings');
  });
});

describe('Finding detail', () => {
  it('shows the observation, evidence, risk explainer, advisory, resolution and history', async () => {
    stubApi('viewer', { [`GET /api/v1/findings/${FINDING_ID}`]: ok(detailOf()) });
    renderAt(`/findings/${FINDING_ID}`);
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Certificate expires within 14 days' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('note')).toHaveTextContent(
      /not evidence that the system has been compromised/,
    );
    expect(screen.getByText('High confidence')).toBeInTheDocument();

    const observed = screen.getByRole('region', { name: 'What we observed' });
    expect(within(observed).getByText(/expires on 1 November 2026/)).toBeInTheDocument();
    expect(within(observed).getByText('Not after')).toBeInTheDocument();
    expect(within(observed).getByText('2026-11-01T00:00:00Z')).toBeInTheDocument();
    expect(within(observed).getByText('www.shop.example.com')).toBeInTheDocument();
    expect(within(observed).getByText(/"issuer": "Example CA"/)).toBeInTheDocument();

    const risk = screen.getByRole('table', { name: 'Risk score calculation' });
    expect(within(risk).getByText('75')).toBeInTheDocument();
    expect(within(risk).getByText('0.85')).toBeInTheDocument();
    expect(within(risk).getByText(/63.75, rounded/)).toBeInTheDocument();
    expect(within(risk).getByTestId('risk-total')).toHaveTextContent('60');

    const why = screen.getByRole('region', { name: 'Why this matters' });
    expect(within(why).getByText(/browser warning/)).toBeInTheDocument();
    expect(within(why).getByText('Customers may be unable to reach the shop.')).toBeInTheDocument();
    expect(within(why).getByText('Automate renewal')).toBeInTheDocument();
    expect(
      within(why).getByRole('link', { name: 'https://example.org/tls-renewal' }),
    ).toHaveAttribute('rel', 'noopener noreferrer');

    expect(
      within(screen.getByRole('region', { name: 'How it is resolved' })).getByText(
        /later TLS check sees a certificate/,
      ),
    ).toBeInTheDocument();
    const ruleCard = screen.getByRole('region', { name: 'Rule' });
    expect(within(ruleCard).getByText('TLS-003 v1')).toBeInTheDocument();
    expect(within(ruleCard).getByText(/notAfter is within 14 days/)).toBeInTheDocument();

    const history = screen.getByRole('region', { name: 'Status history' });
    expect(within(history).getByText('First detected by a scan')).toBeInTheDocument();
    expect(within(history).getByText('Resolved → Open')).toBeInTheDocument();
    expect(within(history).getByText('Observed again after being resolved')).toBeInTheDocument();
  });

  it('handles a finding without advisory or catalogue rule', async () => {
    stubApi('viewer', {
      [`GET /api/v1/findings/${FINDING_ID}`]: ok(
        detailOf({ advisory: null, rule: null, history: [] }),
      ),
    });
    renderAt(`/findings/${FINDING_ID}`);
    expect(
      await screen.findByText('No advisory has been generated for this finding.'),
    ).toBeVisible();
    expect(screen.getByText(/no longer in the catalogue/)).toBeInTheDocument();
    expect(screen.getByText('No status changes recorded.')).toBeInTheDocument();
  });

  it('reports a missing finding', async () => {
    stubApi('viewer', {
      [`GET /api/v1/findings/${FINDING_ID}`]: () => ({
        status: 404,
        body: { error: { code: 'not_found', message: 'Finding not found.', requestId: 'r2' } },
      }),
    });
    renderAt(`/findings/${FINDING_ID}`);
    expect(await screen.findByRole('alert')).toHaveTextContent('Finding not found.');
  });
});
