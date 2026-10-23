// @vitest-environment node
import { errorResponseSchema } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AppBindings } from '../types.ts';
import { ApiError, classifyDatabaseError, handleError, rateLimited } from './errors.ts';

afterEach(() => vi.restoreAllMocks());

function appThrowing(err: Error) {
  const app = new Hono<AppBindings>();
  app.use('*', async (c, next) => {
    c.set('requestId', 'req-test');
    await next();
  });
  app.get('/', () => {
    throw err;
  });
  app.onError(handleError);
  return app;
}

describe('handleError', () => {
  it('returns ApiError code, message and field details', async () => {
    const res = await appThrowing(
      new ApiError(422, 'validation_failed', 'Request validation failed.', [
        { path: 'fqdn', message: 'Invalid domain name' },
      ]),
    ).request('/');

    expect(res.status).toBe(422);
    expect(errorResponseSchema.parse(await res.json())).toEqual({
      error: {
        code: 'validation_failed',
        message: 'Request validation failed.',
        requestId: 'req-test',
        details: [{ path: 'fqdn', message: 'Invalid domain name' }],
      },
    });
  });

  it('maps HTTPException status codes to stable error codes', async () => {
    const res = await appThrowing(new HTTPException(401, { message: 'secret detail' })).request(
      '/',
    );
    const text = await res.text();

    expect(res.status).toBe(401);
    expect(errorResponseSchema.parse(JSON.parse(text)).error.code).toBe('unauthenticated');
    expect(text).not.toContain('secret detail');
  });
});

describe('database errors', () => {
  const pg = (code: string) =>
    Object.assign(new Error(`Failed query: select * from users where email = $1\nparams: a@b.c`), {
      name: 'DrizzleQueryError',
      cause: Object.assign(new Error('boom'), { code }),
    });

  it('classifies availability failures and query bugs', () => {
    expect(classifyDatabaseError(pg('08006'))).toMatchObject({
      kind: 'unavailable',
      sqlState: '08006',
    });
    expect(classifyDatabaseError(pg('57P01'))).toMatchObject({ kind: 'unavailable' });
    expect(classifyDatabaseError(pg('53300'))).toMatchObject({ kind: 'unavailable' });
    expect(classifyDatabaseError(pg('40001'))).toMatchObject({ kind: 'unavailable' });
    expect(classifyDatabaseError(pg('23505'))).toMatchObject({
      kind: 'query',
      errorClass: 'sqlstate_23',
    });
    expect(
      classifyDatabaseError(
        Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
      ),
    ).toMatchObject({ kind: 'unavailable', errorClass: 'econnrefused' });
    expect(classifyDatabaseError(new Error('Connection terminated unexpectedly'))).toMatchObject({
      kind: 'unavailable',
      errorClass: 'connection_lost',
    });
    expect(classifyDatabaseError(new Error('nothing to do with the database'))).toBeNull();
  });

  it('answers 503 service_unavailable with Retry-After for outages and logs db_error by class only', async () => {
    const lines: string[] = [];
    vi.spyOn(console, 'error').mockImplementation((l: unknown) => {
      lines.push(String(l));
    });
    const res = await appThrowing(pg('08006')).request('/');
    expect(res.status).toBe(503);
    expect(res.headers.get('Retry-After')).toBe('30');
    expect(errorResponseSchema.parse(await res.json()).error).toEqual({
      code: 'service_unavailable',
      message: 'The database is temporarily unavailable.',
      requestId: 'req-test',
    });
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toMatchObject({
      message: 'db_error',
      kind: 'unavailable',
      sqlState: '08006',
      errorClass: 'sqlstate_08',
    });
    expect(lines[0]).not.toContain('a@b.c');
    expect(lines[0]).not.toContain('select');
  });

  it('answers 500 for query errors without leaking the statement', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await appThrowing(pg('42703')).request('/');
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(text).toContain('internal_error');
    expect(text).not.toContain('select');
  });
});

describe('ApiError headers', () => {
  it('sends Retry-After from rateLimited()', async () => {
    const res = await appThrowing(rateLimited('Slow down.', 12.2)).request('/');
    expect(res.status).toBe(429);
    expect(res.headers.get('Retry-After')).toBe('13');
    expect(errorResponseSchema.parse(await res.json()).error.code).toBe('rate_limited');
  });
});
