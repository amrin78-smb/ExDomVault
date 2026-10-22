import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, renderAt, stubApi } from '../../testing/stub-api.tsx';
import { FINDING_ID, advisory, finding, page } from '../findings/test-data.ts';

afterEach(() => vi.unstubAllGlobals());

const item = (riskScore: number, title: string, findingId = crypto.randomUUID()) => {
  const f = finding({ id: findingId, riskScore });
  return {
    ...advisory({ findingId, title }),
    finding: {
      id: f.id,
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      status: f.status,
      domain: f.domain,
      hostname: f.hostname,
      riskScore: f.riskScore,
    },
  };
};

describe('Advisories', () => {
  it('lists advisories by risk with summary, impact, actions and a link to the finding', async () => {
    stubApi('viewer', {
      'GET /api/v1/advisories': ok(
        page([item(20, 'Lower priority advisory'), item(60, 'Renew the certificate', FINDING_ID)]),
      ),
    });
    renderAt('/advisories');
    const articles = await screen.findAllByRole('article');
    expect(articles.map((a) => a.getAttribute('aria-label'))).toEqual([
      'Renew the certificate',
      'Lower priority advisory',
    ]);
    const first = articles[0]!;
    expect(within(first).getByText(/browser warning/)).toBeInTheDocument();
    expect(
      within(first).getByText('Customers may be unable to reach the shop.'),
    ).toBeInTheDocument();
    expect(
      within(first).getByText('Renew the certificate', { selector: 'li' }),
    ).toBeInTheDocument();
    expect(within(first).getByText('High')).toBeInTheDocument();
    expect(within(first).getByRole('link', { name: 'View finding and evidence' })).toHaveAttribute(
      'href',
      `/findings/${FINDING_ID}`,
    );
  });

  it('can include advisories for resolved findings', async () => {
    const calls = stubApi('viewer', {
      'GET /api/v1/advisories': ok(page([])),
      'GET /api/v1/advisories?status=all': ok(page([item(10, 'Old advisory')])),
    });
    renderAt('/advisories');
    expect(await screen.findByText('No advisories')).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Findings'), 'all');
    expect(await screen.findByRole('article', { name: 'Old advisory' })).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toContain('/api/v1/advisories?status=all');
  });

  it('shows API errors', async () => {
    stubApi('viewer', {
      'GET /api/v1/advisories': () => ({
        status: 503,
        body: { error: { code: 'unavailable', message: 'Try again later.', requestId: 'r3' } },
      }),
    });
    renderAt('/advisories');
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load advisories');
  });
});
