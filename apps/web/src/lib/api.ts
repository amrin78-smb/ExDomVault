import {
  errorResponseSchema,
  healthResponseSchema,
  type HealthResponse,
} from '@exdomainvault/shared';
import type { z } from 'zod';

export class ApiClientError extends Error {
  override name = 'ApiClientError';

  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(message: string, status: number, code: string, requestId?: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

/** Fetches a JSON endpoint and validates the response against its shared schema. */
export async function getJson<T>(
  path: string,
  schema: z.ZodType<T>,
  init?: RequestInit,
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { ...init, headers: { Accept: 'application/json', ...init?.headers } });
  } catch {
    throw new ApiClientError('The API could not be reached.', 0, 'network_error');
  }

  const body: unknown = await res.json().catch(() => null);

  if (!res.ok) {
    const parsed = errorResponseSchema.safeParse(body);
    if (parsed.success) {
      const { message, code, requestId } = parsed.data.error;
      throw new ApiClientError(message, res.status, code, requestId);
    }
    throw new ApiClientError(`Unexpected API response (${res.status}).`, res.status, 'unknown');
  }

  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new ApiClientError(
      'The API returned an unexpected response shape.',
      res.status,
      'invalid_response',
    );
  }
  return parsed.data;
}

export const api = {
  health: (init?: RequestInit): Promise<HealthResponse> =>
    getJson('/api/v1/health', healthResponseSchema, init),
};
