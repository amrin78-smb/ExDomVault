import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import { migrate } from 'drizzle-orm/pglite/migrator';
import type { Database, DatabaseConnection } from './client.ts';
import * as schema from './schema/index.ts';

export const MIGRATIONS_FOLDER = fileURLToPath(new URL('../migrations', import.meta.url).href);

export interface TestDatabase extends DatabaseConnection {
  pglite: PGlite;
}

/**
 * In-process PostgreSQL (PGlite) with all migrations applied. For tests only — never import from
 * application code. Each call returns an isolated, empty database.
 */
export async function createTestDatabase(): Promise<TestDatabase> {
  const pglite = new PGlite();
  const db = drizzle(pglite, { schema });
  await migrate(db, { migrationsFolder: MIGRATIONS_FOLDER });
  return {
    db: db as unknown as Database,
    pglite,
    close: () => pglite.close(),
  };
}
