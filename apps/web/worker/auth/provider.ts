import type { JWTVerifyGetKey } from 'jose';
import type { AuthConfig } from '../config.ts';
import { cloudflareAccessProvider } from './cloudflare-access.ts';
import { devAuthProvider } from './dev.ts';
import type { AuthProvider } from './types.ts';

export interface AuthProviderDeps {
  /** Overrides the Cloudflare Access key resolver (tests). */
  accessGetKey?: JWTVerifyGetKey;
}

/** Builds the provider for the configured mechanism; `null` when authentication is unconfigured. */
export function createAuthProvider(
  auth: AuthConfig,
  deps: AuthProviderDeps = {},
): AuthProvider | null {
  switch (auth.kind) {
    case 'cloudflare_access':
      return cloudflareAccessProvider({
        issuer: auth.issuer,
        audience: auth.audience,
        getKey: deps.accessGetKey,
      });
    case 'dev':
      return devAuthProvider(auth.email, auth.name);
    case 'unconfigured':
      return null;
  }
}
