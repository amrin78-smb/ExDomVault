import { defineConfig } from 'drizzle-kit';

// Only `drizzle-kit generate` is used; it diffs the schema against existing migration files and
// needs no database connection. Migrations are applied with scripts/migrate.ts.
export default defineConfig({
  dialect: 'postgresql',
  schema: './src/schema/index.ts',
  out: './migrations',
  strict: true,
  verbose: true,
});
