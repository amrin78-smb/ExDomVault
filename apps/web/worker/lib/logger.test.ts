// @vitest-environment node
import { afterEach, describe, expect, it, vi } from 'vitest';
import { REDACTED, createLogger, errorFields, redact, redactText } from './logger.ts';

afterEach(() => vi.restoreAllMocks());

function capture() {
  const lines: Record<string, unknown>[] = [];
  const push = (line: unknown) => lines.push(JSON.parse(String(line)) as Record<string, unknown>);
  vi.spyOn(console, 'log').mockImplementation(push);
  vi.spyOn(console, 'warn').mockImplementation(push);
  vi.spyOn(console, 'error').mockImplementation(push);
  return lines;
}

describe('redaction', () => {
  it('replaces sensitive keys at any depth, keeps identifiers', () => {
    expect(
      redact({
        authorization: 'Bearer abc',
        Cookie: 'CF_Authorization=x',
        headers: { a: 'b' },
        body: '{"x":1}',
        nested: { accessToken: 't', nvdApiKey: 'k', privateKey: 'p', signature: 's' },
        list: [{ password: 'p' }],
        keyId: '0b6e4d2a-1111-2222-3333-444455556666',
        jobId: 'j',
        requestId: 'r',
      }),
    ).toEqual({
      authorization: REDACTED,
      Cookie: REDACTED,
      headers: REDACTED,
      body: REDACTED,
      nested: {
        accessToken: REDACTED,
        nvdApiKey: REDACTED,
        privateKey: REDACTED,
        signature: REDACTED,
      },
      list: [{ password: REDACTED }],
      keyId: '0b6e4d2a-1111-2222-3333-444455556666',
      jobId: 'j',
      requestId: 'r',
    });
  });

  it('masks credentials inside free text', () => {
    expect(redactText('connect to postgres://app:s3cret@db.internal:5432/x failed')).toBe(
      'connect to postgres://[redacted]@db.internal:5432/x failed',
    );
    expect(redactText('got Bearer eyJhbGciOi.abc.def back')).toBe('got Bearer [redacted] back');
    expect(redactText('jwt eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl')).toBe(
      'jwt [redacted-jwt]',
    );
  });

  it('reduces database errors to their class, never the query or parameters', () => {
    const pgError = Object.assign(new Error('duplicate key value violates unique constraint'), {
      code: '23505',
      detail: 'Key (email)=(someone@example.com) already exists.',
    });
    const wrapped = Object.assign(new Error('Failed query: select secret\nparams: hunter2'), {
      name: 'DrizzleQueryError',
      cause: pgError,
    });
    expect(errorFields(wrapped)).toEqual({ errorName: 'DrizzleQueryError', sqlState: '23505' });
    expect(errorFields(new Error('plain'))).toEqual({ errorName: 'Error', error: 'plain' });
  });
});

describe('createLogger', () => {
  it('writes one JSON line with base fields, redacting secrets', () => {
    const lines = capture();
    createLogger({ requestId: 'r1' }).warn('x', { token: 'abc', status: 401 });
    expect(lines).toEqual([
      expect.objectContaining({
        level: 'warn',
        message: 'x',
        requestId: 'r1',
        token: REDACTED,
        status: 401,
      }),
    ]);
  });

  it('child loggers add correlation fields', () => {
    const lines = capture();
    const log = createLogger({ requestId: 'r1' }).child({ jobId: 'j1' });
    log.error('job_failed');
    log.child({ workerId: 'w1' }).info('next');
    expect(lines[0]).toMatchObject({ level: 'error', requestId: 'r1', jobId: 'j1' });
    expect(lines[1]).toMatchObject({ requestId: 'r1', jobId: 'j1', workerId: 'w1' });
  });
});
