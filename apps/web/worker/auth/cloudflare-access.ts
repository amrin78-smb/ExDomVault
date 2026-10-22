import { createRemoteJWKSet, errors, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { AuthProvider, AuthResult } from './types.ts';

export const ACCESS_JWT_HEADER = 'Cf-Access-Jwt-Assertion';
export const ACCESS_COOKIE = 'CF_Authorization';

export interface CloudflareAccessOptions {
  /** e.g. https://myteam.cloudflareaccess.com */
  issuer: string;
  /** The Access application's Audience (AUD) tag. */
  audience: string;
  /** Key resolver; defaults to the team's JWKS endpoint. Injected in tests. */
  getKey?: JWTVerifyGetKey;
}

// JWKS resolvers are cached per isolate so signing keys are fetched once and refreshed on rotation.
const jwksCache = new Map<string, JWTVerifyGetKey>();

function teamJwks(issuer: string): JWTVerifyGetKey {
  let jwks = jwksCache.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL('/cdn-cgi/access/certs', issuer));
    jwksCache.set(issuer, jwks);
  }
  return jwks;
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return undefined;
}

/**
 * Cloudflare Access: verifies the Access application token (RS256, signed by the team's keys) for
 * issuer and audience on every request. The header can be sent by anyone; only the signature
 * check makes it trustworthy. Service tokens (no email) are rejected for user sessions.
 */
export function cloudflareAccessProvider(options: CloudflareAccessOptions): AuthProvider {
  const getKey = options.getKey ?? teamJwks(options.issuer);

  return {
    kind: 'cloudflare_access',
    async authenticate(request): Promise<AuthResult> {
      const token =
        request.headers.get(ACCESS_JWT_HEADER) ??
        readCookie(request.headers.get('Cookie'), ACCESS_COOKIE);
      if (!token) return { ok: false, reason: 'missing_credentials' };

      try {
        const { payload } = await jwtVerify(token, getKey, {
          issuer: options.issuer,
          audience: options.audience,
          algorithms: ['RS256'],
          clockTolerance: 10,
          requiredClaims: ['sub', 'exp', 'iat'],
        });
        const email = typeof payload.email === 'string' ? payload.email.toLowerCase() : undefined;
        if (!payload.sub || !email) {
          return { ok: false, reason: 'invalid_credentials', detail: 'token has no user identity' };
        }
        const name = typeof payload.name === 'string' ? payload.name : null;
        return {
          ok: true,
          identity: { provider: 'cloudflare_access', subject: payload.sub, email, name },
        };
      } catch (err) {
        const detail =
          err instanceof errors.JOSEError ? err.code : err instanceof Error ? err.name : 'unknown';
        return { ok: false, reason: 'invalid_credentials', detail };
      }
    },
  };
}
