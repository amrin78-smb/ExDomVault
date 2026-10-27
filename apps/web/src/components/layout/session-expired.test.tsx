import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { getJson } from '../../lib/api.ts';
import { resetSessionExpiredForTests } from '../../lib/session-expiry.ts';
import { SessionExpiredBanner } from './SessionExpiredBanner.tsx';

const schema = z.object({ ok: z.boolean() });

function stubFetch(response: Partial<Response>) {
  const fetch = vi.fn().mockResolvedValue({ headers: new Headers(), ...response });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

describe('expired Cloudflare Access session', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    resetSessionExpiredForTests();
  });

  it('does not follow redirects and reports an Access login redirect as session_expired', async () => {
    const fetch = stubFetch({ type: 'opaqueredirect', status: 0, ok: false });
    render(<SessionExpiredBanner />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    await act(async () => {
      await expect(getJson('/api/v1/me', schema)).rejects.toMatchObject({
        code: 'session_expired',
        message: 'Your sign-in has expired. Sign in again to continue.',
      });
    });
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ redirect: 'manual' });
    expect(screen.getByRole('alert')).toHaveTextContent(/Your sign-in has expired/);
  });

  it('treats an HTML login page where JSON was expected as an expired session', async () => {
    stubFetch({
      type: 'basic',
      status: 200,
      ok: true,
      headers: new Headers({ 'Content-Type': 'text/html; charset=utf-8' }),
      json: () => Promise.reject(new Error('not json')),
    });
    await expect(getJson('/api/v1/me', schema)).rejects.toMatchObject({ code: 'session_expired' });
  });

  it('reloads the page to sign in again', async () => {
    const reload = vi.fn();
    vi.stubGlobal('location', { ...window.location, reload });
    stubFetch({ type: 'opaqueredirect', status: 0, ok: false });
    render(<SessionExpiredBanner />);
    await act(async () => {
      await getJson('/api/v1/me', schema).catch(() => undefined);
    });
    await userEvent.click(screen.getByRole('button', { name: 'Sign in again' }));
    expect(reload).toHaveBeenCalledOnce();
  });

  it('leaves ordinary API errors alone', async () => {
    stubFetch({
      type: 'basic',
      status: 503,
      ok: false,
      headers: new Headers({ 'Content-Type': 'application/json' }),
      json: () =>
        Promise.resolve({
          error: { code: 'service_unavailable', message: 'Down', requestId: 'r' },
        }),
    });
    render(<SessionExpiredBanner />);
    await act(async () => {
      await expect(getJson('/api/v1/me', schema)).rejects.toMatchObject({
        code: 'service_unavailable',
      });
    });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
