// @vitest-environment node
import { errorResponseSchema } from '@exdomainvault/shared';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { describe, expect, it } from 'vitest';
import type { AppBindings } from '../types.ts';
import { ApiError, handleError } from './errors.ts';

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
