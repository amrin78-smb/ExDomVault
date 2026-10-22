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
  };
});
