/** An identity asserted by the configured identity provider, before mapping to an app user. */
export interface Identity {
  provider: 'cloudflare_access' | 'dev';
  /** Stable, provider-unique subject identifier. */
  subject: string;
  email: string;
  name: string | null;
}

export type AuthResult =
  | { ok: true; identity: Identity }
  | { ok: false; reason: 'missing_credentials' | 'invalid_credentials'; detail?: string };

/**
 * Replaceable authentication boundary. Implementations verify credentials cryptographically or,
 * for the development provider, return a fixed identity from server-side configuration. None of
 * them trust identity claims supplied as plain request headers.
 */
export interface AuthProvider {
  readonly kind: Identity['provider'];
  authenticate(request: Request): Promise<AuthResult>;
}
