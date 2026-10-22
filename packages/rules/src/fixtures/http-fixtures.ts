/** Synthetic HTTP fixtures (test-only). Reserved example names and documentation addresses. */
import type { HttpObservation } from '../types.ts';
import { http } from './builders.ts';

export const HOST = 'www.example.com';
export const IP = '203.0.113.10';

export const ALL_HEADERS = {
  'strict-transport-security': 'max-age=31536000',
  'content-security-policy': "default-src 'self'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': null,
} as const;

export const NO_HEADERS = {
  'strict-transport-security': null,
  'content-security-policy': null,
  'x-content-type-options': null,
  'x-frame-options': null,
  'referrer-policy': null,
  'permissions-policy': null,
} as const;

interface HeaderOpts {
  securityHeaders?: Record<string, string | null>;
  server?: string | null;
  xPoweredBy?: string | null;
}

function headerEvidence(opts: HeaderOpts | undefined) {
  if (!opts) return {};
  return {
    securityHeaders: opts.securityHeaders ?? ALL_HEADERS,
    server: opts.server ?? null,
    xPoweredBy: opts.xPoweredBy ?? null,
  };
}

/** Successful https://<host>/ with a 200 final response. */
export function httpsOk(
  host = HOST,
  fields: Partial<HttpObservation> = {},
  headers?: HeaderOpts,
): HttpObservation {
  const url = `https://${host}/`;
  return http(
    { url, finalUrl: url, statusCode: 200, hstsEnabled: true, ...fields },
    {
      evidence: {
        hops: [{ url, ip: IP, status: fields.statusCode ?? 200, decision: 'final' }],
        ...headerEvidence(headers),
      },
    },
  );
}

/** https://<host>/ that reached an address but got no HTTP response. */
export function httpsFailed(host = HOST, status: 'error' | 'timeout' = 'timeout'): HttpObservation {
  const url = `https://${host}/`;
  return http(
    { url, finalUrl: url, statusCode: null, hstsEnabled: null, redirectCount: 0 },
    {
      status,
      evidence: {
        hops: [
          {
            url,
            ip: IP,
            status: null,
            decision: 'error',
            error: status === 'timeout' ? 'timeout' : 'ConnectionRefusedError',
          },
        ],
      },
    },
  );
}

/** http://<host>/ answering 200 directly (content over plain HTTP). */
export function plainOk(host = HOST, headers?: HeaderOpts): HttpObservation {
  const url = `http://${host}/`;
  return http(
    { url, finalUrl: url, statusCode: 200, hstsEnabled: null, redirectCount: 0 },
    {
      evidence: {
        hops: [{ url, ip: IP, status: 200, decision: 'final' }],
        ...headerEvidence(headers),
      },
    },
  );
}

/** http://<host>/ redirecting out of the domain (refused: partial observation). */
export function plainRedirectOutOfScope(host = HOST): HttpObservation {
  const url = `http://${host}/`;
  const target = 'https://parking.example.net/';
  return http(
    { url, finalUrl: target, statusCode: 301, hstsEnabled: null, redirectCount: 0 },
    {
      status: 'partial',
      evidence: {
        hops: [
          { url, ip: IP, status: 301, decision: 'followed' },
          { url: target, ip: null, status: null, decision: 'redirect_out_of_scope' },
        ],
      },
    },
  );
}

/** http://<host>/ redirecting to https on the same host (followed, final 200). */
export function plainRedirectToHttps(host = HOST): HttpObservation {
  const url = `http://${host}/`;
  const target = `https://${host}/`;
  return http(
    { url, finalUrl: target, statusCode: 200, hstsEnabled: true, redirectCount: 1 },
    {
      evidence: {
        hops: [
          { url, ip: IP, status: 301, decision: 'followed' },
          { url: target, ip: IP, status: 200, decision: 'final' },
        ],
      },
    },
  );
}
