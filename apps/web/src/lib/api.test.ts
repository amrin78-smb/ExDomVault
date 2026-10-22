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

  it('sends finding lifecycle requests to the right endpoints and validates replies', async () => {
    const id = '5c6d7e8f-9a0b-4c1d-8e2f-3a4b5c6d7e8f';
    const scanJobId = '9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f';
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const path = typeof input === 'string' ? input : input.toString();
      const body = path.endsWith('/reassess')
        ? { scanJobId, profile: 'quick', created: true }
        : path.endsWith('/bulk')
          ? { updated: 0, skipped: [{ id, code: 'no_change' }] }
          : { items: [] };
      return new Response(JSON.stringify(body), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(api.findings.reassess(id)).resolves.toEqual({
      scanJobId,
      profile: 'quick',
      created: true,
    });
    await expect(api.findings.bulkUpdate({ ids: [id], status: 'acknowledged' })).resolves.toEqual({
      updated: 0,
      skipped: [{ id, code: 'no_change' }],
    });
    await expect(api.users.assignable()).resolves.toEqual({ items: [] });
    // A PATCH whose reply is not a finding is rejected rather than trusted.
    await expect(
      api.findings.update(id, { expectedStatus: 'open', status: 'acknowledged' }),
    ).rejects.toMatchObject({ code: 'invalid_response' });

    const sent = fetchMock.mock.calls.map(([path, init]) => [init?.method ?? 'GET', path]);
    expect(sent).toEqual([
      ['POST', `/api/v1/findings/${id}/reassess`],
      ['POST', '/api/v1/findings/bulk'],
      ['GET', '/api/v1/users/assignable'],
      ['PATCH', `/api/v1/findings/${id}`],
    ]);
  });
});
