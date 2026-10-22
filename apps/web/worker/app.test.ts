// @vitest-environment node
import { errorResponseSchema, healthResponseSchema } from '@exdomainvault/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApp } from './app.ts';

const devEnv = { APP_ENV: 'development', APP_VERSION: '0.1.0-test' } as unknown as Env;

function request(path: string, env: Env = devEnv, init?: RequestInit) {
  return createApp().request(path, init, env);
}

describe('API application', () => {
  afterEach(() => vi.restoreAllMocks());

  it('GET /api/v1/health returns a schema-valid health report', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const res = await request('/api/v1/health');

    expect(res.status).toBe(200);
    const body = healthResponseSchema.parse(await res.json());
    expect(body.environment).toBe('development');
    expect(body.version).toBe('0.1.0-test');
    // Nothing is wired up yet, so the API must not claim full health.
    expect(body.status).toBe('degraded');
    expect(body.components).toEqual({ database: 'not_configured', auth: 'not_configured' });
  });

  it('sets a request ID and security headers on every response', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const res = await request('/api/v1/health', devEnv, {
      headers: { 'X-Request-Id': 'client-supplied' },
    });

    const requestId = res.headers.get('X-Request-Id');
    expect(requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(requestId).not.toBe('client-supplied');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
  });

  it('returns the standard error envelope for unknown API routes', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const res = await request('/api/v1/does-not-exist');

    expect(res.status).toBe(404);
    const body = errorResponseSchema.parse(await res.json());
    expect(body.error.code).toBe('not_found');
    expect(body.error.requestId).toBe(res.headers.get('X-Request-Id'));
  });

  it('fails closed with a safe 500 when configuration is invalid', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await request('/api/v1/health', { APP_ENV: 'staging' } as unknown as Env);

    expect(res.status).toBe(500);
    const text = await res.text();
    const body = errorResponseSchema.parse(JSON.parse(text));
    expect(body.error.code).toBe('internal_error');
    expect(text).not.toContain('APP_ENV');
    expect(text).not.toContain('stack');
    expect(errorLog).toHaveBeenCalled();
  });
});
