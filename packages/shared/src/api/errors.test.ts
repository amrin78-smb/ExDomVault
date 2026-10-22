import { describe, expect, it } from 'vitest';
import { errorResponseSchema } from './errors.ts';

describe('errorResponseSchema', () => {
  it('accepts a well-formed error with field details', () => {
    const result = errorResponseSchema.safeParse({
      error: {
        code: 'validation_failed',
        message: 'Request validation failed.',
        requestId: 'req-1',
        details: [{ path: 'fqdn', message: 'Required' }],
      },
    });
    expect(result.success).toBe(true);
  });

  it('rejects unknown error codes', () => {
    const result = errorResponseSchema.safeParse({
      error: { code: 'oops', message: 'x', requestId: 'r' },
    });
    expect(result.success).toBe(false);
  });
});
