import { schema, type Database } from '@exdomainvault/database';
import {
  WORKER_HEADERS,
  WORKER_SIGNATURE_MAX_SKEW_SECONDS,
  workerSigningString,
} from '@exdomainvault/shared';
import { and, count, eq, gt } from 'drizzle-orm';
import { createMiddleware } from 'hono/factory';
import { sha256HexBytes, verifyEd25519 } from '../lib/ed25519.ts';
import { ApiError } from '../lib/errors.ts';
import { isUniqueViolation } from '../services/domains.ts';
import { annotateRequest } from './request-context.ts';
import type { AppBindings } from '../types.ts';

const { workerCredentials, workerRegistry, workerRequestNonces } = schema;

/** Largest signed request body (result batches). */
export const WORKER_MAX_BODY_BYTES = 1024 * 1024;
/** Requests per credential per minute. */
export const WORKER_RATE_LIMIT_PER_MINUTE = 120;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NONCE = /^[A-Za-z0-9_-]{16,64}$/;

const unauthenticated = () => new ApiError(401, 'unauthenticated', 'Worker authentication failed.');

/**
 * Authenticates the scanning worker (never a browser user): every request is signed with the
 * worker's Ed25519 private key over method, path, timestamp, nonce and body hash. Checks, in order:
 * header shape → timestamp within ±5 min → credential active, unexpired, worker enabled → signature
 * → rate limit → nonce unused (replay). Failures are logged with a reason but answered generically.
 */
export const requireWorker = (opts: { now?: () => Date } = {}) =>
  createMiddleware<AppBindings>(async (c, next) => {
    const logger = c.get('logger');
    const now = opts.now?.() ?? new Date();
    const deny = (reason: string, fields: Record<string, unknown> = {}) => {
      logger.warn('worker_auth_failed', { reason, ...fields });
      return unauthenticated();
    };

    const keyId = c.req.header(WORKER_HEADERS.keyId) ?? '';
    const timestamp = c.req.header(WORKER_HEADERS.timestamp) ?? '';
    const nonce = c.req.header(WORKER_HEADERS.nonce) ?? '';
    const signature = c.req.header(WORKER_HEADERS.signature) ?? '';
    if (!UUID.test(keyId) || !/^\d{1,12}$/.test(timestamp) || !NONCE.test(nonce) || !signature) {
      throw deny('malformed_headers');
    }
    const skew = Math.abs(now.getTime() / 1000 - Number(timestamp));
    if (skew > WORKER_SIGNATURE_MAX_SKEW_SECONDS) throw deny('timestamp_out_of_window', { skew });

    const declared = Number(c.req.header('Content-Length') ?? '0');
    if (declared > WORKER_MAX_BODY_BYTES)
      throw new ApiError(400, 'bad_request', 'The request body is too large.');
    const body = await c.req.text();
    if (new TextEncoder().encode(body).byteLength > WORKER_MAX_BODY_BYTES)
      throw new ApiError(400, 'bad_request', 'The request body is too large.');

    const db: Database = await c.get('db')();
    const [credential] = await db
      .select({
        id: workerCredentials.id,
        publicKey: workerCredentials.publicKey,
        expiresAt: workerCredentials.expiresAt,
        revokedAt: workerCredentials.revokedAt,
        workerId: workerRegistry.id,
        workerName: workerRegistry.name,
        workerStatus: workerRegistry.status,
      })
      .from(workerCredentials)
      .innerJoin(workerRegistry, eq(workerRegistry.id, workerCredentials.workerId))
      .where(eq(workerCredentials.id, keyId.toLowerCase()));
    if (!credential) throw deny('unknown_key', { keyId });
    if (credential.revokedAt) throw deny('key_revoked', { keyId });
    if (credential.expiresAt <= now) throw deny('key_expired', { keyId });
    if (credential.workerStatus !== 'active') throw deny('worker_disabled', { keyId });

    const url = new URL(c.req.url);
    const message = workerSigningString(
      c.req.method,
      url.pathname + url.search,
      timestamp,
      nonce,
      await sha256HexBytes(body),
    );
    if (!(await verifyEd25519(credential.publicKey, signature, message))) {
      throw deny('bad_signature', { keyId });
    }

    const [recent] = await db
      .select({ n: count() })
      .from(workerRequestNonces)
      .where(
        and(
          eq(workerRequestNonces.credentialId, credential.id),
          gt(workerRequestNonces.createdAt, new Date(now.getTime() - 60_000)),
        ),
      );
    if ((recent?.n ?? 0) >= WORKER_RATE_LIMIT_PER_MINUTE) {
      logger.warn('worker_rate_limited', { keyId });
      throw new ApiError(429, 'rate_limited', 'Too many requests. Slow down.');
    }

    try {
      await db
        .insert(workerRequestNonces)
        .values({ credentialId: credential.id, nonce, createdAt: now });
    } catch (err) {
      if (isUniqueViolation(err)) throw deny('replayed_nonce', { keyId });
      throw err;
    }

    const version = c.req.header(WORKER_HEADERS.version)?.slice(0, 40) ?? null;
    await db
      .update(workerCredentials)
      .set({ lastUsedAt: now })
      .where(eq(workerCredentials.id, credential.id));
    await db
      .update(workerRegistry)
      .set({ lastSeenAt: now, ...(version ? { version } : {}) })
      .where(eq(workerRegistry.id, credential.workerId));

    annotateRequest(c, { workerId: credential.workerId });
    c.set('worker', {
      id: credential.workerId,
      name: credential.workerName,
      credentialId: credential.id,
    });
    await next();
  });
