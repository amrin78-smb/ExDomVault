import { defineProject } from 'vitest/config';

export default defineProject({
  test: {
    name: 'database',
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // Some tests build a fresh PGlite database and apply every migration, which is slow under load.
    testTimeout: 30_000,
  },
});
