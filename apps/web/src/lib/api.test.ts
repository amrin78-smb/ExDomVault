import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiClientError, api } from './api.ts';

afterEach(() => vi.unstubAllGlobals());

function stubFetch(status: number, body: unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(body), { status })),
  );
}

describe('api client', () => {
  it('surfaces the server error envelope', async () => {
    stubFetch(403, { error: { code: 'forbidden', message: 'Not allowed.', requestId: 'r-1' } });
    await expect(api.health()).rejects.toMatchObject({
      name: 'ApiClientError',
      status: 403,
      code: 'forbidden',
      requestId: 'r-1',
    });
  });

  it('rejects responses that do not match the shared schema', async () => {
    stubFetch(200, { status: 'ok' });
    const err = await api.health().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiClientError);
    expect((err as ApiClientError).code).toBe('invalid_response');
  });
});
