// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { fetchFeed, FeedError, type FetchLike } from './feed-fetch.ts';

const URL_KEV =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const base = { userAgent: 'ExDomainVault/test (+https://exdomainvault.amrin78.workers.dev)' };

function mockFetch(...responses: (Response | (() => Response))[]) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn: FetchLike = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const r = responses.shift();
    if (!r) throw new Error('no more responses');
    return typeof r === 'function' ? r() : r;
  });
  return { fn, calls };
}

const json = (body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status: 200, headers });

async function errorOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    if (err instanceof FeedError) return err.errorClass;
    throw err;
  }
  throw new Error('expected a FeedError');
}

describe('fetchFeed', () => {
  it('fetches JSON with the user agent, validators and manual redirects', async () => {
    const m = mockFetch(json({ ok: 1 }, { etag: '"v2"', 'last-modified': 'Tue, 20 Oct 2026' }));
    const res = await fetchFeed(URL_KEV, {
      ...base,
      fetch: m.fn,
      timeoutMs: 1000,
      maxBytes: 1000,
      etag: '"v1"',
      lastModified: 'Mon, 19 Oct 2026',
    });
    expect(res).toEqual({
      status: 'ok',
      body: { ok: 1 },
      etag: '"v2"',
      lastModified: 'Tue, 20 Oct 2026',
    });
    const headers = m.calls[0]!.init!.headers as Record<string, string>;
    expect(headers['User-Agent']).toBe(base.userAgent);
    expect(headers['If-None-Match']).toBe('"v1"');
    expect(headers['If-Modified-Since']).toBe('Mon, 19 Oct 2026');
    expect(m.calls[0]!.init!.redirect).toBe('manual');
  });

  it('reports 304 Not Modified', async () => {
    const m = mockFetch(new Response(null, { status: 304 }));
    expect(
      await fetchFeed(URL_KEV, { ...base, fetch: m.fn, timeoutMs: 1000, maxBytes: 10 }),
    ).toEqual({ status: 'not_modified' });
  });

  it('refuses URLs that are not https on an allow-listed host', async () => {
    const m = mockFetch();
    for (const url of [
      'http://www.cisa.gov/feed.json',
      'https://evil.example/feed.json',
      'https://user:pw@www.cisa.gov/x',
      'https://www.cisa.gov:8443/x',
      'not a url',
    ]) {
      expect(
        await errorOf(fetchFeed(url, { ...base, fetch: m.fn, timeoutMs: 1000, maxBytes: 10 })),
      ).toBe('invalid_url');
    }
    expect(m.fn).not.toHaveBeenCalled();
  });

  it('follows a same-host https redirect but refuses other hosts and schemes', async () => {
    const ok = mockFetch(
      new Response(null, { status: 301, headers: { location: '/sites/feed2.json' } }),
      json([1]),
    );
    expect(
      await fetchFeed(URL_KEV, { ...base, fetch: ok.fn, timeoutMs: 1000, maxBytes: 100 }),
    ).toMatchObject({ status: 'ok', body: [1] });
    expect(ok.calls[1]!.url).toBe('https://www.cisa.gov/sites/feed2.json');

    for (const location of [
      'https://endoflife.date/api/v1/products/php', // allow-listed, but another host
      'https://attacker.example/x',
      'http://www.cisa.gov/x',
    ]) {
      const m = mockFetch(new Response(null, { status: 302, headers: { location } }));
      expect(
        await errorOf(fetchFeed(URL_KEV, { ...base, fetch: m.fn, timeoutMs: 1000, maxBytes: 100 })),
      ).toBe('redirect_refused');
      expect(m.calls).toHaveLength(1);
    }
  });

  it('stops after too many redirects', async () => {
    const loop = () => new Response(null, { status: 302, headers: { location: '/again' } });
    const m = mockFetch(loop, loop, loop, loop);
    expect(
      await errorOf(fetchFeed(URL_KEV, { ...base, fetch: m.fn, timeoutMs: 1000, maxBytes: 100 })),
    ).toBe('redirect_refused');
    expect(m.calls).toHaveLength(3);
  });

  it('caps the response size (declared and streamed)', async () => {
    const declared = mockFetch(
      new Response('{}', { status: 200, headers: { 'content-length': '5000' } }),
    );
    expect(
      await errorOf(
        fetchFeed(URL_KEV, { ...base, fetch: declared.fn, timeoutMs: 1000, maxBytes: 100 }),
      ),
    ).toBe('too_large');
    const streamed = mockFetch(new Response(JSON.stringify({ x: 'a'.repeat(500) })));
    expect(
      await errorOf(
        fetchFeed(URL_KEV, { ...base, fetch: streamed.fn, timeoutMs: 1000, maxBytes: 100 }),
      ),
    ).toBe('too_large');
  });

  it('times out', async () => {
    const hang: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      });
    expect(
      await errorOf(fetchFeed(URL_KEV, { ...base, fetch: hang, timeoutMs: 20, maxBytes: 100 })),
    ).toBe('timeout');
  });

  it('classifies network errors, HTTP errors, rate limits, 404 and bad JSON', async () => {
    const opts = { ...base, timeoutMs: 1000, maxBytes: 1000 };
    const failing: FetchLike = async () => {
      throw new TypeError('connection reset');
    };
    expect(await errorOf(fetchFeed(URL_KEV, { ...opts, fetch: failing }))).toBe('network');
    expect(
      await errorOf(
        fetchFeed(URL_KEV, {
          ...opts,
          fetch: mockFetch(new Response('<html>secret page</html>', { status: 503 })).fn,
        }),
      ),
    ).toBe('http_503');
    expect(
      await errorOf(
        fetchFeed(URL_KEV, { ...opts, fetch: mockFetch(new Response('', { status: 429 })).fn }),
      ),
    ).toBe('rate_limited');
    expect(
      await fetchFeed(URL_KEV, { ...opts, fetch: mockFetch(new Response('', { status: 404 })).fn }),
    ).toEqual({ status: 'not_found' });
    expect(
      await errorOf(
        fetchFeed(URL_KEV, { ...opts, fetch: mockFetch(new Response('<html>not json')).fn }),
      ),
    ).toBe('invalid_json');
  });
});
