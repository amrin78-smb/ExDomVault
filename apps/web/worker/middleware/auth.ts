import { hasPermission, type Permission } from '@exdomainvault/shared';
import { createMiddleware } from 'hono/factory';
import { createAuthProvider, type AuthProviderDeps } from '../auth/provider.ts';
import type { AuthProvider } from '../auth/types.ts';
import type { AuthConfig } from '../config.ts';
import { ApiError } from '../lib/errors.ts';
import { resolveUser } from '../services/users.ts';
import type { AppBindings } from '../types.ts';

const DENIED_MESSAGES = {
  not_provisioned: 'Your account has not been granted access to ExDomainVault.',
  inactive: 'Your account has been deactivated.',
  identity_conflict: 'Your sign-in identity does not match the account on record.',
} as const;

/**
 * Authenticates the request with the configured provider and resolves the application user.
 * Fails closed: unconfigured authentication → 503, no/invalid credentials → 401, unknown or
 * inactive user → 403.
 */
export const requireAuth = (deps: AuthProviderDeps = {}) => {
  // Providers are cached per configuration so JWKS lookups are reused across requests.
  const providers = new Map<string, AuthProvider | null>();
  const providerFor = (auth: AuthConfig) => {
    const key = JSON.stringify(auth);
    if (!providers.has(key)) providers.set(key, createAuthProvider(auth, deps));
    return providers.get(key) ?? null;
  };

  return createMiddleware<AppBindings>(async (c, next) => {
    const config = c.get('config');
    const logger = c.get('logger');

    const provider = providerFor(config.auth);
    if (!provider) {
      logger.error('auth_unconfigured', {
        reason: config.auth.kind === 'unconfigured' ? config.auth.reason : undefined,
      });
      throw new ApiError(503, 'service_unavailable', 'Authentication is not configured.');
    }

    const result = await provider.authenticate(c.req.raw);
    if (!result.ok) {
      logger.warn('auth_failed', { provider: provider.kind, reason: result.reason, detail: result.detail });
      throw new ApiError(401, 'unauthenticated', 'Authentication is required.');
    }

    const db = await c.get('db')();
    const resolved = await resolveUser(db, result.identity, {
      bootstrapAdminEmails: config.bootstrapAdminEmails,
      requestId: c.get('requestId'),
    });
    if (!resolved.ok) {
      logger.warn('auth_denied', { reason: resolved.reason, email: result.identity.email });
      throw new ApiError(403, 'forbidden', DENIED_MESSAGES[resolved.reason]);
    }
    if (resolved.created) logger.info('user_bootstrapped', { userId: resolved.user.id });

    c.set('identity', result.identity);
    c.set('user', resolved.user);
    await next();
  });
};

/** Server-side permission check. Must run after requireAuth. */
export const requirePermission = (permission: Permission) =>
  createMiddleware<AppBindings>(async (c, next) => {
    const user = c.get('user');
    if (!hasPermission(user.role, permission)) {
      c.get('logger').warn('permission_denied', { userId: user.id, role: user.role, permission });
      throw new ApiError(403, 'forbidden', 'You do not have permission to perform this action.');
    }
    await next();
  });
