import {
  scanJobDetailResponseSchema,
  scanJobListResponseSchema,
  scanProfileListResponseSchema,
  workerCredentialCreatedResponseSchema,
  workerListResponseSchema,
  workerSchema,
  bulkAuthoriseResponseSchema,
  createChallengeResponseSchema,
  domainDetailResponseSchema,
  domainListResponseSchema,
  errorResponseSchema,
  healthResponseSchema,
  importConfirmResponseSchema,
  importPreviewResponseSchema,
  meResponseSchema,
  verifyDomainResponseSchema,
  type AuthorisationInput,
  type BulkAuthoriseResponse,
  type CreateChallengeResponse,
  type CreateScanRequest,
  type RegisterWorkerRequest,
  type ScanJobDetailResponse,
  type ScanJobListResponse,
  type ScanProfileListResponse,
  type Worker,
  type WorkerCredentialCreatedResponse,
  type CreateDomainRequest,
  type DomainDetailResponse,
  type DomainListResponse,
  type FieldError,
  type HealthResponse,
  type ImportConfirmResponse,
  type ImportPreviewResponse,
  type MeResponse,
  type UpdateDomainRequest,
  type VerifyDomainResponse,
} from '@exdomainvault/shared';
import { z } from 'zod';

export class ApiClientError extends Error {
  override name = 'ApiClientError';

  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  readonly details?: FieldError[];

  constructor(
    message: string,
    status: number,
    code: string,
    requestId?: string,
    details?: FieldError[],
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
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
      const { message, code, requestId, details } = parsed.data.error;
      throw new ApiClientError(message, res.status, code, requestId, details);
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

/** Sends a JSON body (POST/PATCH). Same-origin fetch carries the Origin header the API requires. */
export function sendJson<T>(
  method: 'POST' | 'PATCH',
  path: string,
  schema: z.ZodType<T>,
  body?: unknown,
): Promise<T> {
  return getJson(path, schema, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

/** Builds a query string, omitting empty values. */
export function toQuery(params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

const domainPath = (id: string) => `/api/v1/domains/${encodeURIComponent(id)}`;

export const api = {
  health: (init?: RequestInit): Promise<HealthResponse> =>
    getJson('/api/v1/health', healthResponseSchema, init),
  me: (init?: RequestInit): Promise<MeResponse> => getJson('/api/v1/me', meResponseSchema, init),

  domains: {
    list: (
      params: Record<string, string | number | undefined>,
      init?: RequestInit,
    ): Promise<DomainListResponse> =>
      getJson(`/api/v1/domains${toQuery(params)}`, domainListResponseSchema, init),
    get: (id: string, init?: RequestInit): Promise<DomainDetailResponse> =>
      getJson(domainPath(id), domainDetailResponseSchema, init),
    create: (body: CreateDomainRequest): Promise<DomainDetailResponse> =>
      sendJson('POST', '/api/v1/domains', domainDetailResponseSchema, body),
    update: (id: string, body: UpdateDomainRequest): Promise<DomainDetailResponse> =>
      sendJson('PATCH', domainPath(id), domainDetailResponseSchema, body),
    startVerification: (id: string): Promise<CreateChallengeResponse> =>
      sendJson('POST', `${domainPath(id)}/verification`, createChallengeResponseSchema),
    verify: (id: string): Promise<VerifyDomainResponse> =>
      sendJson('POST', `${domainPath(id)}/verify`, verifyDomainResponseSchema),
    previewImport: (csv: string): Promise<ImportPreviewResponse> =>
      sendJson('POST', '/api/v1/domains/import/preview', importPreviewResponseSchema, { csv }),
    confirmImport: (
      csv: string,
      digest: string,
      authorisation?: AuthorisationInput,
    ): Promise<ImportConfirmResponse> =>
      sendJson('POST', '/api/v1/domains/import', importConfirmResponseSchema, {
        csv,
        digest,
        ...(authorisation ? { authorisation } : {}),
      }),
    authorise: (id: string, body: AuthorisationInput): Promise<DomainDetailResponse> =>
      sendJson('POST', `${domainPath(id)}/authorise`, domainDetailResponseSchema, body),
    authoriseMany: (
      domainIds: string[],
      body: AuthorisationInput,
    ): Promise<BulkAuthoriseResponse> =>
      sendJson('POST', '/api/v1/domains/authorise', bulkAuthoriseResponseSchema, {
        domainIds,
        ...body,
      }),
    revoke: (id: string, reason: string): Promise<DomainDetailResponse> =>
      sendJson('POST', `${domainPath(id)}/revoke`, domainDetailResponseSchema, { reason }),
    /** Queues a scan; returns immediately (the worker runs it asynchronously). */
    requestScan: (id: string, body: CreateScanRequest): Promise<ScanJobDetailResponse> =>
      sendJson('POST', `${domainPath(id)}/scans`, scanJobDetailResponseSchema, body),
  },

  scanProfiles: (init?: RequestInit): Promise<ScanProfileListResponse> =>
    getJson('/api/v1/scan-profiles', scanProfileListResponseSchema, init),

  scans: {
    list: (
      params: Record<string, string | number | undefined>,
      init?: RequestInit,
    ): Promise<ScanJobListResponse> =>
      getJson(`/api/v1/scans${toQuery(params)}`, scanJobListResponseSchema, init),
    get: (id: string, init?: RequestInit): Promise<ScanJobDetailResponse> =>
      getJson(`/api/v1/scans/${encodeURIComponent(id)}`, scanJobDetailResponseSchema, init),
    cancel: (id: string): Promise<ScanJobDetailResponse> =>
      sendJson(
        'POST',
        `/api/v1/scans/${encodeURIComponent(id)}/cancel`,
        scanJobDetailResponseSchema,
      ),
  },

  workers: {
    list: (init?: RequestInit): Promise<{ items: Worker[] }> =>
      getJson('/api/v1/workers', workerListResponseSchema, init),
    register: (body: RegisterWorkerRequest): Promise<WorkerCredentialCreatedResponse> =>
      sendJson('POST', '/api/v1/workers', workerCredentialCreatedResponseSchema, body),
    addKey: (id: string, publicKey: string): Promise<WorkerCredentialCreatedResponse> =>
      sendJson(
        'POST',
        `/api/v1/workers/${encodeURIComponent(id)}/credentials`,
        workerCredentialCreatedResponseSchema,
        { publicKey },
      ),
    revokeKey: (id: string, credentialId: string): Promise<{ worker: Worker }> =>
      sendJson(
        'POST',
        `/api/v1/workers/${encodeURIComponent(id)}/credentials/${encodeURIComponent(credentialId)}/revoke`,
        z.object({ worker: workerSchema }),
      ),
    setStatus: (id: string, status: 'active' | 'disabled'): Promise<{ worker: Worker }> =>
      sendJson(
        'PATCH',
        `/api/v1/workers/${encodeURIComponent(id)}`,
        z.object({ worker: workerSchema }),
        {
          status,
        },
      ),
  },
};
