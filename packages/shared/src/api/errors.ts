import { z } from 'zod';

/** Stable, machine-readable error codes returned by the API. Never rename an existing code. */
export const ERROR_CODES = [
  'bad_request',
  'validation_failed',
  'unauthenticated',
  'forbidden',
  'not_found',
  'method_not_allowed',
  'conflict',
  'rate_limited',
  'internal_error',
  'service_unavailable',
] as const;

export const errorCodeSchema = z.enum(ERROR_CODES);
export type ErrorCode = z.infer<typeof errorCodeSchema>;

export const fieldErrorSchema = z.object({
  path: z.string(),
  message: z.string(),
});
export type FieldError = z.infer<typeof fieldErrorSchema>;

/** The only error shape the API returns. Messages are safe for display; no internals or stack traces. */
export const errorResponseSchema = z.object({
  error: z.object({
    code: errorCodeSchema,
    message: z.string(),
    requestId: z.string(),
    details: z.array(fieldErrorSchema).optional(),
  }),
});
export type ErrorResponse = z.infer<typeof errorResponseSchema>;
