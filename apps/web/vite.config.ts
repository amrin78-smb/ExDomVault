import { fileURLToPath } from 'node:url';
import { cloudflare } from '@cloudflare/vite-plugin';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const LOCAL_HYPERDRIVE_VAR = 'CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE';

export default defineConfig(({ command, mode }) => {
  if (command === 'serve' && !process.env[LOCAL_HYPERDRIVE_VAR]) {
    // Local dev: point the Hyperdrive binding straight at Neon using the direct (unpooled)
    // connection string that `neon env pull` writes to the repo-root .env.local (git-ignored).
    // Production uses the deployed Hyperdrive configuration instead.
    const env = loadEnv(mode, repoRoot, '');
    const local = env.DATABASE_URL_UNPOOLED || env.DATABASE_URL;
    if (local) process.env[LOCAL_HYPERDRIVE_VAR] = local;
  }

  return {
    plugins: [react(), tailwindcss(), cloudflare()],
    environments: {
      // Browser bundle only; the Worker bundle keeps its default output.
      client: {
        build: {
          rolldownOptions: {
            output: {
              // Long-lived vendor chunks: they change only on dependency upgrades, so browsers keep them
              // cached across app deploys. Pages are split per route in src/routes.tsx.
              advancedChunks: {
                groups: [
                  {
                    name: 'react',
                    test: /node_modules[\\/](react|react-dom|react-router|scheduler)[\\/]/,
                  },
                  { name: 'zod', test: /node_modules[\\/]zod[\\/]/ },
                  {
                    name: 'charts',
                    test: /node_modules[\\/](recharts|d3-[a-z-]+|victory-vendor|@reduxjs|immer|reselect|redux)[\\/]/,
                  },
                ],
              },
            },
          },
        },
      },
    },
  };
});
