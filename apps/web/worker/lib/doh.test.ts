// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { createDohResolver, decodeTxtData } from './doh.ts';

const NAME = '_exdomainvault-challenge.example.com';

function resolverReturning(body: unknown, init: ResponseInit = { status: 200 }) {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(typeof body === 'string' ? body : JSON.stringify(body), init),
  );
  return { resolve: createDohResolver({ fetch: fetchMock as unknown as typeof fetch }), fetchMock };
}

describe('decodeTxtData', () => {
  it.each([
    ['"abc"', 'abc'],
    ['"part one" "part two"', 'part onepart two'],
    ['"say \\"hi\\""', 'say "hi"'],
    ['"semi\\059colon"', 'semi;colon'],
    ['unquoted', 'unquoted'],
  ])('%s → %s', (input, expected) => {
    expect(decodeTxtData(input)).toBe(expected);
  });
});

describe('createDohResolver', () => {
  it('queries the fixed resolver for TXT and returns matching answers', async () => {
    const { resolve, fetchMock } = resolverReturning({
      Status: 0,
      AD: true,
      Answer: [
        { name: `${NAME}.`, type: 16, data: '"exdomainvault-verification=abc"' },
        { name: `${NAME}.`, type: 5, data: 'cname.example.net.' },
        { name: 'other.example.com.', type: 16, data: '"not for us"' },
      ],
    });
    expect(await resolve(NAME)).toEqual({
      status: 'ok',
      records: ['exdomainvault-verification=abc'],
      authenticated: true,
    });
    const [url, init] = fetchMock.mock.calls[0]!;
    const u = new URL(String(url));
    expect(u.origin + u.pathname).toBe('https://cloudflare-dns.com/dns-query');
    expect(u.searchParams.get('name')).toBe(NAME);
    expect(u.searchParams.get('type')).toBe('TXT');
    expect(init?.redirect).toBe('manual');
  });

  it('maps NXDOMAIN, server failures and bad responses', async () => {
    expect(await resolverReturning({ Status: 3 }).resolve(NAME)).toEqual({ status: 'nxdomain' });
    expect(await resolverReturning({ Status: 2 }).resolve(NAME)).toEqual({
      status: 'error',
      detail: 'rcode_2',
    });
    expect(await resolverReturning('nope', { status: 502 }).resolve(NAME)).toEqual({
      status: 'error',
      detail: 'http_502',
    });
    expect(
      await resolverReturning('', {
        status: 302,
        headers: { Location: 'https://elsewhere.example/' },
      }).resolve(NAME),
    ).toEqual({
      status: 'error',
      detail: 'http_302',
    });
    expect(await resolverReturning('{not json').resolve(NAME)).toEqual({
      status: 'error',
      detail: 'invalid_json',
    });
    expect(await resolverReturning('x'.repeat(70_000)).resolve(NAME)).toEqual({
      status: 'error',
      detail: 'response_too_large',
    });
  });

  it('reports network failures as errors', async () => {
    const resolve = createDohResolver({
      fetch: (async () => {
        throw new DOMException('timed out', 'TimeoutError');
      }) as unknown as typeof fetch,
    });
    expect(await resolve(NAME)).toEqual({ status: 'error', detail: 'TimeoutError: timed out' });
  });
});
