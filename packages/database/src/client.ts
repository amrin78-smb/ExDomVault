import { drizzle } from 'drizzle-orm/node-postgres';
import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core';
import pg from 'pg';
import * as schema from './schema/index.ts';

export type Schema = typeof schema;

/**
 * Any Drizzle PostgreSQL database using this schema: node-postgres in the Worker, PGlite in tests.
 * Application code depends on this type, never on a specific driver.
 */
export type Database = PgDatabase<PgQueryResultHKT, Schema>;

export interface DatabaseConnection {
  db: Database;
  /** Closes the connection. Call once per request; Hyperdrive pools connections upstream. */
  close(): Promise<void>;
}

export interface ConnectOptions {
  /** Abort connection setup after this many milliseconds. */
  connectTimeoutMs?: number;
}

/**
 * Opens a single node-postgres connection and wraps it in Drizzle.
 *
 * On Cloudflare Workers pass `env.HYPERDRIVE.connectionString`; Hyperdrive pools connections
 * to Neon, so the Worker opens one short-lived client per request (Neon and Cloudflare guidance).
 */
export async function connect(
  connectionString: string,
  { connectTimeoutMs = 5_000 }: ConnectOptions = {},
): Promise<DatabaseConnection> {
  const client = new pg.Client({ connectionString, connectionTimeoutMillis: connectTimeoutMs });
  await client.connect();
  return {
    db: drizzle(client, { schema }),
    close: () => client.end(),
  };
}
