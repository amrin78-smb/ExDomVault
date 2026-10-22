import react from '@vitejs/plugin-react';
import { defineProject } from 'vitest/config';

// The Cloudflare Vite plugin is deliberately omitted here: API tests exercise the Hono app
// directly with app.request(), and UI tests render components in jsdom.
export default defineProject({
  plugins: [react()],
  test: {
    name: 'web',
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}', 'worker/**/*.test.ts'],
    setupFiles: ['./src/test/setup.ts'],
  },
});
