import type { Database } from '@exdomainvault/database';
import type { SQL } from 'drizzle-orm';

/** The single row an INSERT/UPDATE … RETURNING must produce. Missing it is a programming error. */
export function firstRow<T>(rows: T[]): T {
  const [row] = rows;
  if (row === undefined) throw new Error('Expected the statement to return a row');
  return row;
}

/** Rows of a raw `db.execute(sql…)` statement (node-postgres and PGlite both return `{ rows }`). */
export async function rowsOf<T>(db: Database, query: SQL): Promise<T[]> {
  const res = (await db.execute(query)) as unknown as { rows: T[] };
  return res.rows;
}
