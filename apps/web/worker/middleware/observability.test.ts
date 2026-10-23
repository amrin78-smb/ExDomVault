// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTestDatabase, type TestDatabase } from '@exdomainvault/database/testing';
import { errorResponseSchema } from '@exdomainvault/shared';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.ts';
import { generateWorkerKey, harness, userCall, workerCall } from '../testing/harness.ts';
import { API_CONTENT_SECURITY_POLICY } from './security-headers.ts';

let t: TestDatabase;
const clock = () => new Date('2026-10-23T12:00:00.000Z');
const h = harness(() => t, clock);
let lines: Record<string, unknown>[] = [];

beforeAll(async () => {
  t = await createTestDatabase();
}, 30_000);
afterAll(async () => {
  await t?.close();
});
beforeEach(() => {
  lines = [];
  const push = (line: unknown) => {
    try {
      lines.push(JSON.parse(String(line)) as Record<string, unknown>);
    } catch {
      // not structured
    }
  };
  vi.spyOn(console, 'log').mockImplementation(push);
  vi.spyOn(console, 'warn').mockImplementation(push);
  vi.spyOn(console, 'error').mockImplementation(push);
});
afterEach(() => vi.restoreAllMocks());

describe('database error monitoring', () => {
  it('answers 503 and logs db_error (class only) when the connection fails', async () => {
    const app = createApp({
      ...h.deps,
      connect: () =>
        Promise.reject(
          Object.assign(new Error('connect ECONNREFUSED 10.1.2.3:5432 postgres://u:pw@h/db'), {
            code: 'ECONNREFUSED',
          }),
        ),
    });
    const res = await app.request('/api/v1/me', {}, h.env('viewer') as unknown as Env);
    expect(res.status).toBe(503);
    expect(res.headers.get('Retry-After')).toBe('30');
    expect(errorResponseSchema.parse(await res.json()).error.code).toBe('service_unavailable');
    const dbError = lines.find((l) => l.message === 'db_error');
    expect(dbError).toMatchObject({ level: 'error', kind: 'connect', errorClass: 'econnrefused' });
    expect(JSON.stringify(lines)).not.toContain('10.1.2.3');
    expect(JSON.stringify(lines)).not.toContain('pw@');
  });

  it('answers 503 when a query fails with a connection-class error mid-request', async () => {
    const app = createApp({
      ...h.deps,
      connect: async () => ({
        db: new Proxy(t.db, {
          get(target, prop, receiver) {
            if (
              prop === 'select' ||
              prop === 'insert' ||
              prop === 'execute' ||
              prop === 'transaction'
            ) {
              return () => {
                throw Object.assign(
                  new Error('terminating connection due to administrator command'),
                  {
                    code: '57P01',
                  },
                );
              };
            }
            return Reflect.get(target, prop, receiver) as unknown;
          },
        }),
        close: async () => {},
      }),
    });
    const res = await app.request('/api/v1/me', {}, h.env('viewer') as unknown as Env);
    expect(res.status).toBe(503);
    expect(lines.find((l) => l.message === 'db_error')).toMatchObject({
      kind: 'unavailable',
      sqlState: '57P01',
    });
    // The request line still carries the request ID and the final status.
    const request = lines.find((l) => l.message === 'request');
    expect(request).toMatchObject({ status: 503 });
    expect(request?.requestId).toBe(res.headers.get('X-Request-Id'));
  });
});

describe('correlation IDs', () => {
  it('request lines carry requestId and userId', async () => {
    const res = await userCall(h, t, 'viewer', 'GET', '/me');
    expect(res.status).toBe(200);
    const request = lines.find((l) => l.message === 'request');
    expect(request).toMatchObject({
      requestId: res.headers.get('X-Request-Id'),
      path: '/api/v1/me',
      status: 200,
    });
    expect(typeof request?.userId).toBe('string');
  });

  it('worker API lines carry workerId; no header, body or signature is logged', async () => {
    const key = await generateWorkerKey();
    const reg = await userCall(h, t, 'admin', 'POST', '/workers', {
      name: `obs-${Date.now()}`,
      publicKey: key.publicKey,
    });
    const { credentialId } = (await reg.json()) as { credentialId: string };
    lines = [];
    const res = await workerCall(h, key, credentialId, 'claim', {}, { now: clock() });
    expect(res.status).toBe(200);
    const request = lines.find((l) => l.message === 'request');
    expect(typeof request?.workerId).toBe('string');
    const text = JSON.stringify(lines);
    expect(text).not.toMatch(/signature|X-ExDV|nonce-/i);
  });
});

describe('security headers', () => {
  it('API responses carry a deny-all CSP and the baseline headers', async () => {
    const res = await createApp(h.deps).request(
      '/api/v1/health',
      {},
      h.env('viewer') as unknown as Env,
    );
    expect(res.headers.get('Content-Security-Policy')).toBe(API_CONTENT_SECURITY_POLICY);
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(res.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
    expect(res.headers.get('Permissions-Policy')).toContain('camera=()');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
  });

  it('public/_headers gives the SPA a strict CSP without unsafe-inline or unsafe-eval', () => {
    const text = readFileSync(
      fileURLToPath(new URL('../../public/_headers', import.meta.url).href),
      'utf8',
    );
    const csp = /Content-Security-Policy: (.+)/.exec(text)?.[1] ?? '';
    const directives = Object.fromEntries(
      csp.split(';').map((d) => {
        const [name, ...values] = d.trim().split(/\s+/);
        return [name, values.join(' ')];
      }),
    );
    expect(directives).toMatchObject({
      'default-src': "'self'",
      'script-src': "'self'",
      'style-src': "'self'",
      'img-src': "'self' data:",
      'connect-src': "'self'",
      'frame-ancestors': "'none'",
      'base-uri': "'none'",
      'form-action': "'self'",
      'object-src': "'none'",
    });
    expect(csp).not.toContain('unsafe');
    for (const header of [
      'X-Content-Type-Options: nosniff',
      'Referrer-Policy: no-referrer',
      'Cross-Origin-Opener-Policy: same-origin',
      'Permissions-Policy:',
    ]) {
      expect(text).toContain(header);
    }
  });
});
