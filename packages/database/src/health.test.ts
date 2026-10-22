import { describe, expect, it, vi } from 'vitest';
import type { DatabaseConnection } from './client.ts';
import { pingDatabase } from './health.ts';

function fakeConnection(execute: () => Promise<unknown>) {
  const close = vi.fn(async () => {});
  const conn = { db: { execute }, client: {}, close } as unknown as DatabaseConnection;
  return { conn, close };
}

describe('pingDatabase', () => {
  it('reports ok and closes the connection', async () => {
    const { conn, close } = fakeConnection(async () => ({ rows: [{ '?column?': 1 }] }));
    const result = await pingDatabase('postgres://example.invalid/db', {
      connector: async () => conn,
    });
    expect(result.status).toBe('ok');
    expect(close).toHaveBeenCalledOnce();
  });

  it('reports down when the query fails, still closing the connection', async () => {
    const { conn, close } = fakeConnection(async () => {
      throw new Error('relation does not exist');
    });
    const result = await pingDatabase('postgres://example.invalid/db', {
      connector: async () => conn,
    });
    expect(result).toMatchObject({ status: 'down', error: 'relation does not exist' });
    expect(close).toHaveBeenCalledOnce();
  });

  it('reports down when the connection cannot be opened', async () => {
    const result = await pingDatabase('postgres://example.invalid/db', {
      connector: async () => {
        throw new Error('connect ECONNREFUSED');
      },
    });
    expect(result).toMatchObject({ status: 'down', error: 'connect ECONNREFUSED' });
  });
});
