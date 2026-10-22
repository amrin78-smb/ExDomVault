import type { ErrorCode, ErrorResponse, FieldError } from '@exdomainvault/shared';
import type { Context, ErrorHandler, NotFoundHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { AppBindings } from '../types.ts';

/** An error that is safe to return to the client as-is. */
export class ApiError extends Error {
  override name = 'ApiError';

  readonly status: ContentfulStatusCode;
  readonly code: ErrorCode;
  readonly details?: FieldError[];

  constructor(
    status: ContentfulStatusCode,
    code: ErrorCode,
    message: string,
    details?: FieldError[],
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
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
    return c.json(errorBody(requestId, err.code, err.message, err.details), err.status);
  }

  if (err instanceof HTTPException) {
    const code = STATUS_CODES[err.status] ?? (err.status >= 500 ? 'internal_error' : 'bad_request');
    const message = err.status >= 500 ? 'An internal error occurred.' : 'The request was rejected.';
    return c.json(errorBody(requestId, code, message), err.status);
  }

  const logger = c.get('logger');
  const fields = { errorName: err.name, errorMessage: err.message, stack: err.stack };
  if (logger) logger.error('unhandled_error', fields);
  else
    console.error(
      JSON.stringify({ level: 'error', message: 'unhandled_error', requestId, ...fields }),
    );

  return c.json(errorBody(requestId, 'internal_error', 'An internal error occurred.'), 500);
};
