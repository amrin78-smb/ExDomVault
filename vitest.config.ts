import { defineConfig } from 'vitest/config';

// Each DB-backed test file starts its own PGlite (Postgres in WASM, several hundred MB). On the
// 16 GB dev/scan host the default (one worker per core) exhausted memory and got other processes
// killed, so cap parallelism; CI or a bigger machine can raise it with VITEST_MAX_WORKERS.
const maxWorkers = Number(process.env.VITEST_MAX_WORKERS) || 2;

export default defineConfig({
  test: {
    maxWorkers,
    projects: [
      'apps/web/vitest.config.ts',
      'packages/shared/vitest.config.ts',
      'packages/database/vitest.config.ts',
      'packages/rules/vitest.config.ts',
    ],
  },
});
