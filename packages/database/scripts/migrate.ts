/**
 * Applies pending migrations from ./migrations.
 *
 * Connection: MIGRATION_DATABASE_URL, else DATABASE_URL_UNPOOLED (migrations need a direct,
 * non-pooled connection). Values are read from the environment, then the repo-root .env.local
 * written by `neon env pull`.
 *
 * Safety: refuses to run when NEON_BRANCH is the production branch unless
 * ALLOW_PRODUCTION_MIGRATION=yes is set explicitly.
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import pg from 'pg';

const repoEnv = fileURLToPath(new URL('../../../.env.local', import.meta.url));
if (existsSync(repoEnv)) process.loadEnvFile(repoEnv);

const rawUrl = process.env.MIGRATION_DATABASE_URL ?? process.env.DATABASE_URL_UNPOOLED;
// node-postgres treats sslmode=require as verify-full; say so explicitly (full certificate checks).
const url = rawUrl?.replace(/([?&]sslmode=)(require|prefer|verify-ca)\b/, '$1verify-full');
const branch = process.env.NEON_BRANCH ?? '(unknown)';

if (!url) {
  console.error('No MIGRATION_DATABASE_URL or DATABASE_URL_UNPOOLED. Run `neon env pull` first.');
  process.exit(1);
}
if (/-pooler\./.test(url)) {
  console.error('Refusing to migrate through a pooled (-pooler) endpoint; use the direct URL.');
  process.exit(1);
}
if (branch === 'production' && process.env.ALLOW_PRODUCTION_MIGRATION !== 'yes') {
  console.error(
    'Refusing to migrate the production branch. Re-run with ALLOW_PRODUCTION_MIGRATION=yes ' +
      'only after the migration has been applied and verified on a development branch.',
  );
  process.exit(1);
}

const migrationsFolder = fileURLToPath(new URL('../migrations', import.meta.url));
const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 10_000 });

try {
  await client.connect();
  const host = new URL(url).hostname;
  console.log(`Applying migrations to Neon branch "${branch}" (${host})...`);
  await migrate(drizzle(client), { migrationsFolder });
  const { rows } = await client.query<{ count: string }>(
    'select count(*) from drizzle.__drizzle_migrations',
  );
  console.log(`Done. ${rows[0]?.count ?? '?'} migration(s) recorded.`);
} catch (err) {
  console.error('Migration failed:', err instanceof Error ? err.message : err);
  process.exitCode = 1;
} finally {
  await client.end();
}
