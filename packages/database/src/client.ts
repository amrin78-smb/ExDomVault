import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import pg from 'pg';

export interface DatabaseConnection {
  db: NodePgDatabase;
  client: pg.Client;
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
    db: drizzle(client),
    client,
    close: () => client.end(),
  };
}
