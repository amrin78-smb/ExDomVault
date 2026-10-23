import { connect, type DatabaseConnection } from '@exdomainvault/database';
import { createMiddleware } from 'hono/factory';
import { ApiError, classifyDatabaseError } from '../lib/errors.ts';
import type { AppBindings } from '../types.ts';

export type Connector = (connectionString: string) => Promise<DatabaseConnection>;

/**
 * Provides `c.var.db()`: opens a connection through the Hyperdrive binding on first use and closes
 * it after the response. Requests that never touch the database never connect.
 */
export const database = (connector: Connector = (cs) => connect(cs)) =>
  createMiddleware<AppBindings>(async (c, next) => {
    let pending: Promise<DatabaseConnection> | undefined;

    c.set('db', async () => {
      if (!pending) {
        const connectionString = c.env.HYPERDRIVE?.connectionString;
        if (!connectionString) {
          throw new ApiError(503, 'service_unavailable', 'The database is not configured.');
        }
        pending = connector(connectionString).catch((err: unknown) => {
          const info = classifyDatabaseError(err);
          c.get('logger').error('db_error', {
            kind: 'connect',
            errorClass: info?.errorClass ?? (err instanceof Error ? err.name : 'unknown'),
            sqlState: info?.sqlState ?? null,
          });
          throw new ApiError(
            503,
            'service_unavailable',
            'The database is temporarily unavailable.',
            undefined,
            { 'Retry-After': '30' },
          );
        });
      }
      return (await pending).db;
    });

    try {
      await next();
    } finally {
      if (pending) {
        const closing = pending.then((conn) => conn.close()).catch(() => {});
        let ctx: { waitUntil(promise: Promise<unknown>): void } | undefined;
        try {
          ctx = c.executionCtx;
        } catch {
          // No execution context outside the Workers runtime (tests): close inline.
        }
        if (ctx) ctx.waitUntil(closing);
        else await closing;
      }
    }
  });
