/**
 * TXT lookups over DNS-over-HTTPS (RFC 8484 JSON API).
 *
 * Domain verification only ever asks a public recursive resolver for one TXT record; it never
 * connects to the customer's own infrastructure. The resolver URL is fixed in code, never user input.
 */

export type TxtLookup =
  | { status: 'ok'; records: string[]; authenticated: boolean }
  | { status: 'nxdomain' }
  | { status: 'error'; detail: string };

export type TxtResolver = (name: string) => Promise<TxtLookup>;

export const DEFAULT_DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

interface DohJson {
  Status?: number;
  AD?: boolean;
  Answer?: { name?: string; type?: number; data?: string }[];
}

const TYPE_TXT = 16;

/**
 * Joins the character-strings of one TXT record as presented by DoH JSON
 * (`"part one" "part two"` → `part onepart two`).
 */
export function decodeTxtData(data: string): string {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) =>
    (m[1] ?? '').replace(/\\(\d{3}|.)/g, (_, esc: string) =>
      /^\d{3}$/.test(esc) ? String.fromCharCode(Number(esc)) : esc,
    ),
  );
  return parts.length > 0 ? parts.join('') : data;
}

export function createDohResolver(
  opts: { endpoint?: string; fetch?: typeof fetch } = {},
): TxtResolver {
  const endpoint = opts.endpoint ?? DEFAULT_DOH_ENDPOINT;
  // Wrapped so the global is always invoked unbound (Workers rejects some detached-method calls).
  const doFetch =
    opts.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));

  return async (name) => {
    const url = new URL(endpoint);
    url.searchParams.set('name', name);
    url.searchParams.set('type', 'TXT');
    url.searchParams.set('do', 'true');

    let res: Response;
    try {
      res = await doFetch(url.toString(), {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
        // Workers' fetch supports only 'follow' | 'manual'. Manual + the status check below means a
        // redirect is treated as a failure, never followed.
        redirect: 'manual',
      });
    } catch (err) {
      return {
        status: 'error',
        detail: err instanceof Error ? `${err.name}: ${err.message}`.slice(0, 200) : 'fetch_failed',
      };
    }
    if (!res.ok) return { status: 'error', detail: `http_${res.status}` };

    const text = await res.text();
    if (text.length > MAX_RESPONSE_BYTES) return { status: 'error', detail: 'response_too_large' };

    let body: DohJson;
    try {
      body = JSON.parse(text) as DohJson;
    } catch {
      return { status: 'error', detail: 'invalid_json' };
    }

    if (body.Status === 3) return { status: 'nxdomain' };
    if (body.Status !== 0) return { status: 'error', detail: `rcode_${String(body.Status)}` };

    const wanted = name.toLowerCase().replace(/\.$/, '');
    const records = (body.Answer ?? []).flatMap((a) =>
      a.type === TYPE_TXT &&
      typeof a.data === 'string' &&
      (a.name ?? '').toLowerCase().replace(/\.$/, '') === wanted
        ? [decodeTxtData(a.data)]
        : [],
    );
    return { status: 'ok', records, authenticated: body.AD === true };
  };
}
