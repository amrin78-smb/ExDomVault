import type { AuthProvider } from './types.ts';

/**
 * Local development identity taken from server-side configuration (DEV_AUTH_EMAIL). It ignores
 * the request entirely, so no client header can choose the identity. Config loading refuses this
 * provider when APP_ENV=production.
 */
export function devAuthProvider(email: string, name: string | null): AuthProvider {
  return {
    kind: 'dev',
    authenticate: async () => ({
      ok: true,
      identity: { provider: 'dev', subject: `dev:${email}`, email, name },
    }),
  };
}
