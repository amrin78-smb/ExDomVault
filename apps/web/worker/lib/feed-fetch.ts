/**
 * Bounded HTTPS fetch for public intelligence feeds (Milestone 11). Feeds are untrusted input:
 *
 *  - only `https:` URLs on an allow-listed host; redirects are followed manually (at most
 *    `MAX_REDIRECTS`) and only to `https:` on the SAME host, anything else is refused;
 *  - a timeout covers the whole request including the body;
 *  - the body is read as a stream and abandoned once it exceeds `maxBytes`;
 *  - conditional requests (`If-None-Match` / `If-Modified-Since`) when validators are known;
 *  - failures become a `FeedError` with a short class (`timeout`, `http_503`, `too_large`…) —
 *    never the response body, which may echo arbitrary content.
 */

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export const FEED_HOSTS: ReadonlySet<string> = new Set([
  'endoflife.date',
  'www.cisa.gov',
  'services.nvd.nist.gov',
]);

const MAX_REDIRECTS = 2;

export class FeedError extends Error {
  override name = 'FeedError';
  /** Short, safe error class stored in `intel_feeds.last_error`. */
  readonly errorClass: string;
  constructor(errorClass: string) {
    super(errorClass);
    this.errorClass = errorClass;
  }
}

/** Short error class of any thrown value (unexpected errors are `internal`). */
export function errorClassOf(err: unknown): string {
  return err instanceof FeedError ? err.errorClass : 'internal';
}

export interface FeedFetchOptions {
  fetch: FetchLike;
  userAgent: string;
  timeoutMs: number;
  maxBytes: number;
  etag?: string | null;
  lastModified?: string | null;
  headers?: Record<string, string>;
}

export type FeedFetchResult =
  | { status: 'not_modified' }
  | { status: 'ok'; body: unknown; etag: string | null; lastModified: string | null }
  /** HTTP 404 (some feeds use it for "no such item"); the caller decides what it means. */
  | { status: 'not_found' };

function checkUrl(raw: string, host?: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new FeedError('invalid_url');
  }
  if (url.protocol !== 'https:' || !FEED_HOSTS.has(url.hostname) || url.username || url.password) {
    throw new FeedError(host ? 'redirect_refused' : 'invalid_url');
  }
  if (host && url.hostname !== host) throw new FeedError('redirect_refused');
  if (url.port && url.port !== '443')
    throw new FeedError(host ? 'redirect_refused' : 'invalid_url');
  return url;
}

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => {});
    throw new FeedError('too_large');
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new FeedError('too_large');
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    all.set(c, offset);
    offset += c.byteLength;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(all);
  } catch {
    throw new FeedError('invalid_encoding');
  }
}

export async function fetchFeed(rawUrl: string, opts: FeedFetchOptions): Promise<FeedFetchResult> {
  let url = checkUrl(rawUrl);
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, opts.timeoutMs);
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'User-Agent': opts.userAgent,
    ...opts.headers,
  };
  if (opts.etag) headers['If-None-Match'] = opts.etag;
  if (opts.lastModified) headers['If-Modified-Since'] = opts.lastModified;

  try {
    for (let hop = 0; ; hop++) {
      let res: Response;
      try {
        res = await opts.fetch(url.toString(), {
          method: 'GET',
          headers,
          redirect: 'manual',
          signal: controller.signal,
        });
      } catch {
        throw new FeedError(timedOut ? 'timeout' : 'network');
      }
      if (res.status === 304) return { status: 'not_modified' };
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => {});
        const location = res.headers.get('location');
        if (!location || hop >= MAX_REDIRECTS) throw new FeedError('redirect_refused');
        url = checkUrl(new URL(location, url).toString(), url.hostname);
        continue;
      }
      if (res.status === 404) {
        await res.body?.cancel().catch(() => {});
        return { status: 'not_found' };
      }
      if (res.status === 403 || res.status === 429) {
        await res.body?.cancel().catch(() => {});
        throw new FeedError('rate_limited');
      }
      if (res.status !== 200) {
        await res.body?.cancel().catch(() => {});
        throw new FeedError(`http_${res.status}`);
      }
      let text: string;
      try {
        text = await readCapped(res, opts.maxBytes);
      } catch (err) {
        if (err instanceof FeedError) throw err;
        throw new FeedError(timedOut ? 'timeout' : 'network');
      }
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        throw new FeedError('invalid_json');
      }
      return {
        status: 'ok',
        body,
        etag: res.headers.get('etag'),
        lastModified: res.headers.get('last-modified'),
      };
    }
  } finally {
    clearTimeout(timer);
  }
}
