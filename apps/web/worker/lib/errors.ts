import type { ErrorCode, ErrorResponse, FieldError } from '@exdomainvault/shared';
import type { Context, ErrorHandler, NotFoundHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { AppBindings } from '../types.ts';
import { errorFields } from './logger.ts';

/** An error that is safe to return to the client as-is. */
export class ApiError extends Error {
  override name = 'ApiError';

  readonly status: ContentfulStatusCode;
  readonly code: ErrorCode;
  readonly details?: FieldError[];
  /** Extra response headers (e.g. `Retry-After` on 429). */
  readonly headers?: Record<string, string>;

  constructor(
    status: ContentfulStatusCode,
    code: ErrorCode,
    message: string,
    details?: FieldError[],
    headers?: Record<string, string>,
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.headers = headers;
  }
}

/** 429 `rate_limited` with a `Retry-After` header (whole seconds, at least 1). */
export function rateLimited(message: string, retryAfterSeconds: number): ApiError {
  const seconds = Math.max(1, Math.ceil(retryAfterSeconds));
  return new ApiError(429, 'rate_limited', message, undefined, { 'Retry-After': String(seconds) });
}

/** Network-level failures talking to PostgreSQL / Hyperdrive (no SQLSTATE). */
const DB_NETWORK_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'EPIPE',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
]);
const DB_NETWORK_MESSAGE =
  /^(Connection terminated|Client has encountered a connection error|Connection ended|timeout expired|Query read timeout)/i;

/**
 * SQLSTATE classes meaning the database is unavailable or overloaded, so retrying later is the
 * right client response: 08 connection exception, 53 insufficient resources, 57 operator
 * intervention (shutdown, statement timeout/cancel), 40 transaction rollback (serialization failure,
 * deadlock), 55P03 lock not available, 58 system error.
 */
const UNAVAILABLE_SQLSTATE = /^(08|53|57|40|58)|^55P03$/;

export interface DatabaseErrorInfo {
  /** `unavailable` → 503 service_unavailable; `query` → 500 internal_error (a bug, not an outage). */
  kind: 'unavailable' | 'query';
  sqlState: string | null;
  errorClass: string;
}

/**
 * Classifies an error thrown by the database layer (node-postgres, PGlite or Drizzle's wrapper), or
 * returns null for anything else. Only the class is reported, never the message (it can contain SQL
 * text and bound parameters).
 */
export function classifyDatabaseError(err: unknown): DatabaseErrorInfo | null {
  let drizzle = false;
  for (let e = err, i = 0; e && typeof e === 'object' && i < 4; i++) {
    const { code, name, message } = e as { code?: unknown; name?: unknown; message?: unknown };
    if (name === 'DrizzleQueryError') drizzle = true;
    if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) {
      return {
        kind: UNAVAILABLE_SQLSTATE.test(code) ? 'unavailable' : 'query',
        sqlState: code,
        errorClass: `sqlstate_${code.slice(0, 2)}`,
      };
    }
    if (typeof code === 'string' && DB_NETWORK_CODES.has(code)) {
      return { kind: 'unavailable', sqlState: null, errorClass: code.toLowerCase() };
    }
    if (typeof message === 'string' && DB_NETWORK_MESSAGE.test(message)) {
      return { kind: 'unavailable', sqlState: null, errorClass: 'connection_lost' };
    }
    e = (e as { cause?: unknown }).cause;
  }
  return drizzle ? { kind: 'query', sqlState: null, errorClass: 'query_failed' } : null;
}

export function errorBody(
  requestId: string,
  code: ErrorCode,
  message: string,
  details?: FieldError[],
): ErrorResponse {
  return { error: { code, message, requestId, ...(details ? { details } : {}) } };
}

const STATUS_CODES: Partial<Record<number, ErrorCode>> = {
  400: 'bad_request',
  401: 'unauthenticated',
  403: 'forbidden',
  404: 'not_found',
  405: 'method_not_allowed',
  409: 'conflict',
  429: 'rate_limited',
  503: 'service_unavailable',
};

function requestIdOf(c: Context<AppBindings>): string {
  return c.get('requestId') ?? 'unknown';
}

export const handleNotFound: NotFoundHandler<AppBindings> = (c) =>
  c.json(errorBody(requestIdOf(c), 'not_found', 'The requested resource was not found.'), 404);

/** Converts any thrown error into the standard envelope. Unknown errors never leak details. */
export const handleError: ErrorHandler<AppBindings> = (err, c) => {
  const requestId = requestIdOf(c);

  if (err instanceof ApiError) {
    return c.json(
      errorBody(requestId, err.code, err.message, err.details),
      err.status,
      err.headers,
    );
  }

  const db = classifyDatabaseError(err);
  if (db) {
    // Database error monitoring: one `db_error` line with the class only (alert on it in Workers
    // Logs). Outages answer 503 so clients retry; anything else is a server bug (500).
    const fields = { kind: db.kind, errorClass: db.errorClass, sqlState: db.sqlState };
    const logger = c.get('logger');
    if (logger) logger.error('db_error', fields);
    else
      console.error(JSON.stringify({ level: 'error', message: 'db_error', requestId, ...fields }));
    return db.kind === 'unavailable'
      ? c.json(
          errorBody(requestId, 'service_unavailable', 'The database is temporarily unavailable.'),
          503,
          { 'Retry-After': '30' },
        )
      : c.json(errorBody(requestId, 'internal_error', 'An internal error occurred.'), 500);
  }

  if (err instanceof HTTPException) {
    const code = STATUS_CODES[err.status] ?? (err.status >= 500 ? 'internal_error' : 'bad_request');
    const message = err.status >= 500 ? 'An internal error occurred.' : 'The request was rejected.';
    return c.json(errorBody(requestId, code, message), err.status);
  }

  const logger = c.get('logger');
  const fields = { ...errorFields(err), stack: err.stack };
  if (logger) logger.error('unhandled_error', fields);
  else
    console.error(
      JSON.stringify({ level: 'error', message: 'unhandled_error', requestId, ...fields }),
    );

  return c.json(errorBody(requestId, 'internal_error', 'An internal error occurred.'), 500);
};
