import { sql } from 'drizzle-orm';
import { connect } from './client.ts';

export type DatabasePingResult =
  { status: 'ok'; latencyMs: number } | { status: 'down'; latencyMs: number; error: string };

type Connector = typeof connect;

/**
 * Verifies the database answers a trivial query. Never throws; failures are returned so the
 * caller can report `down` without leaking connection details to clients.
 */
export async function pingDatabase(
  connectionString: string,
  { timeoutMs = 5_000, connector = connect }: { timeoutMs?: number; connector?: Connector } = {},
): Promise<DatabasePingResult> {
  const started = Date.now();
  let conn: Awaited<ReturnType<Connector>> | undefined;
  try {
    conn = await connector(connectionString, { connectTimeoutMs: timeoutMs });
    await conn.db.execute(sql`select 1`);
    return { status: 'ok', latencyMs: Date.now() - started };
  } catch (err) {
    return {
      status: 'down',
      latencyMs: Date.now() - started,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    await conn?.close().catch(() => {});
  }
}
