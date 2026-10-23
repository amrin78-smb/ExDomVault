// A 429 from the API is shown as a friendly "try again in N seconds" message and never retried.
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, renderAt, stubApi } from '../testing/stub-api.tsx';

afterEach(() => vi.unstubAllGlobals());

const rateLimited = () => ({
  status: 429,
  body: { error: { code: 'rate_limited', message: 'Rate limit exceeded.', requestId: 'req-429' } },
  headers: { 'Retry-After': '42' },
});

describe('Rate limiting in the UI', () => {
  it('shows the wait time on a refused mutation and does not resend it', async () => {
    const calls = stubApi('admin', {
      'GET /api/v1/workers': ok({ items: [] }),
      'POST /api/v1/workers': rateLimited,
    });
    renderAt('/settings');
    const form = await screen.findByRole('form', { name: 'Register a worker' });
    await userEvent.type(screen.getByLabelText('Public key (base64)'), 'AAAA');
    await userEvent.click(screen.getByRole('button', { name: /Register worker/ }));

    const alert = (await screen.findByText('Too many requests — try again in 42 seconds.')).closest(
      '[role="alert"]',
    );
    expect(alert).toHaveTextContent('Request ID: req-429');
    expect(form).toBeInTheDocument();
    // The button is usable again; the user decides when to retry.
    expect(screen.getByRole('button', { name: /Register worker/ })).toBeEnabled();
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(1);
  });

  it('shows the wait time when a page load is rate limited', async () => {
    stubApi('admin', { 'GET /api/v1/workers': rateLimited });
    renderAt('/settings');
    const message = await screen.findByText('Too many requests — try again in 42 seconds.');
    expect(message.closest('[role="alert"]')).toBeInTheDocument();
  });
});
