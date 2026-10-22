import { defineProject } from 'vitest/config';

export default defineProject({
  test: {
    name: 'rules',
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
