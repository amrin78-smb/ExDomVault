import type { FieldError } from '@exdomainvault/shared';
import type { Context } from 'hono';
import type { z } from 'zod';
import type { AppBindings } from '../types.ts';
import { ApiError } from './errors.ts';

/** Largest JSON body any endpoint accepts (CSV import is the biggest at 256 KB of text). */
const MAX_JSON_BYTES = 300 * 1024;

function toFieldErrors(error: z.ZodError): FieldError[] {
  return error.issues.slice(0, 20).map((issue) => ({
    path: issue.path.map(String).join('.') || '(body)',
    message: issue.message,
  }));
}

function validationFailed(error: z.ZodError): ApiError {
  return new ApiError(400, 'validation_failed', 'The request is invalid.', toFieldErrors(error));
}

/** Parses and validates a JSON request body. Rejects non-JSON and oversized bodies. */
export async function parseJsonBody<S extends z.ZodType>(
  c: Context<AppBindings>,
  schema: S,
): Promise<z.output<S>> {
  const contentType = c.req.header('Content-Type') ?? '';
  if (!/^application\/json\b/i.test(contentType)) {
    throw new ApiError(400, 'bad_request', 'Content-Type must be application/json.');
  }
  const declared = Number(c.req.header('Content-Length') ?? '0');
  if (declared > MAX_JSON_BYTES) {
    throw new ApiError(400, 'bad_request', 'The request body is too large.');
  }
  const text = await c.req.text();
  if (text.length > MAX_JSON_BYTES) {
    throw new ApiError(400, 'bad_request', 'The request body is too large.');
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new ApiError(400, 'bad_request', 'The request body is not valid JSON.');
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) throw validationFailed(parsed.error);
  return parsed.data;
}

/** Validates the query string. Repeated keys are not supported; the last value wins. */
export function parseQuery<S extends z.ZodType>(c: Context<AppBindings>, schema: S): z.output<S> {
  const parsed = schema.safeParse(c.req.query());
  if (!parsed.success) throw validationFailed(parsed.error);
  return parsed.data;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Route parameter that must be a UUID. A malformed id is reported as not found. */
export function uuidParam(c: Context<AppBindings>, name: string): string {
  const value = c.req.param(name) ?? '';
  if (!UUID.test(value))
    throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  return value.toLowerCase();
}
