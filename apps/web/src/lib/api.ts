import {
  assetBulkDecisionResponseSchema,
  assetDetailResponseSchema,
  assetListResponseSchema,
  assetResponseSchema,
  discoveryRequestResponseSchema,
  type Asset,
  type AssetBulkDecisionRequest,
  type AssetBulkDecisionResponse,
  type AssetDetailResponse,
  type AssetListResponse,
  type DiscoveryRequestResponse,
  advisoryListResponseSchema,
  bulkMonitoringResponseSchema,
  type BulkMonitoringResponse,
  assignableUsersResponseSchema,
  findingBulkUpdateResponseSchema,
  findingCommentResponseSchema,
  findingDetailResponseSchema,
  findingListResponseSchema,
  findingReassessResponseSchema,
  findingUpdateResponseSchema,
  type AssignableUsersResponse,
  type Finding,
  type FindingBulkUpdateRequest,
  type FindingBulkUpdateResponse,
  type FindingComment,
  type FindingReassessResponse,
  type FindingUpdateRequest,
  findingSummaryResponseSchema,
  ruleCatalogueResponseSchema,
  type AdvisoryListResponse,
  type FindingDetailResponse,
  type FindingListResponse,
  type FindingSummaryResponse,
  type RuleCatalogueEntry,
  approvedNetworkListResponseSchema,
  approvedNetworkSchema,
  type ApprovedNetwork,
  type CreateApprovedNetworkRequest,
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
  domainObservationsResponseSchema,
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
  type DomainObservationsResponse,
  type FieldError,
  type HealthResponse,
  type ImportConfirmResponse,
  type ImportPreviewResponse,
  type MeResponse,
  type UpdateDomainRequest,
  type VerifyDomainResponse,
} from '@exdomainvault/shared';
import {
  auditListResponseSchema,
  userListResponseSchema,
  userResponseSchema,
  type AuditListResponse,
  type User,
  type UserCreateRequest,
  type UserListResponse,
  type UserUpdateRequest,
} from '@exdomainvault/shared';
import { reportSummaryResponseSchema, type ReportSummaryResponse } from '@exdomainvault/shared';
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

type QueryParams = Record<string, string | number | undefined>;

/** A downloaded file; `truncated` when the server capped the rows (`X-Truncated: true`). */
export interface CsvDownload {
  blob: Blob;
  filename: string;
  truncated: boolean;
}

const domainPath = (id: string) => `/api/v1/domains/${encodeURIComponent(id)}`;
const findingPath = (id: string) => `/api/v1/findings/${encodeURIComponent(id)}`;
const assetPath = (id: string) => `/api/v1/assets/${encodeURIComponent(id)}`;
const userPath = (id: string) => `/api/v1/users/${encodeURIComponent(id)}`;

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
    /** Latest DNS record sets and registration snapshot reported by scans (evidence only). */
    observations: (id: string, init?: RequestInit): Promise<DomainObservationsResponse> =>
      getJson(`${domainPath(id)}/observations`, domainObservationsResponseSchema, init),
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
    /** Turns passive monitoring on or off for the given domains, or for every domain. */
    setMonitoring: (
      target: { domainIds: string[] } | { all: true },
      enabled: boolean,
    ): Promise<BulkMonitoringResponse> =>
      sendJson('POST', '/api/v1/domains/monitoring', bulkMonitoringResponseSchema, {
        ...target,
        enabled,
      }),
    /** Queues a scan; returns immediately (the worker runs it asynchronously). */
    requestScan: (id: string, body: CreateScanRequest): Promise<ScanJobDetailResponse> =>
      sendJson('POST', `${domainPath(id)}/scans`, scanJobDetailResponseSchema, body),
    /** Hostnames (assets) beneath one domain, any status. */
    assets: (id: string, params: QueryParams, init?: RequestInit): Promise<AssetListResponse> =>
      getJson(`${domainPath(id)}/assets${toQuery(params)}`, assetListResponseSchema, init),
    /**
     * Queues passive discovery (Certificate Transparency). Never contacts the domain's hosts and
     * never adds scan targets; `created: false` means a discovery job was already queued.
     */
    requestDiscovery: (id: string): Promise<DiscoveryRequestResponse> =>
      sendJson('POST', `${domainPath(id)}/discovery`, discoveryRequestResponseSchema),
  },

  /** Hostname inventory. Discovered names stay `pending` until an administrator approves them. */
  assets: {
    list: (params: QueryParams, init?: RequestInit): Promise<AssetListResponse> =>
      getJson(`/api/v1/assets${toQuery(params)}`, assetListResponseSchema, init),
    get: (id: string, init?: RequestInit): Promise<AssetDetailResponse> =>
      getJson(assetPath(id), assetDetailResponseSchema, init),
    /** `acknowledgeThirdPartyHosting` is required (400 otherwise) when the asset has a hosting hint. */
    approve: (
      id: string,
      body: { reason: string; acknowledgeThirdPartyHosting: boolean },
    ): Promise<{ asset: Asset }> =>
      sendJson('POST', `${assetPath(id)}/approve`, assetResponseSchema, body),
    reject: (id: string, reason: string): Promise<{ asset: Asset }> =>
      sendJson('POST', `${assetPath(id)}/reject`, assetResponseSchema, { reason }),
    suspend: (id: string, reason: string): Promise<{ asset: Asset }> =>
      sendJson('POST', `${assetPath(id)}/suspend`, assetResponseSchema, { reason }),
    /** The same decision for many assets; each is checked individually and may be skipped. */
    bulkDecide: (body: AssetBulkDecisionRequest): Promise<AssetBulkDecisionResponse> =>
      sendJson('POST', '/api/v1/assets/bulk', assetBulkDecisionResponseSchema, body),
    /** Sets (or clears, with `null`) the asset owner; requires `assets:approve`. Audited. */
    setOwner: (id: string, ownerUserId: string | null): Promise<{ asset: Asset }> =>
      sendJson('PATCH', assetPath(id), assetResponseSchema, { ownerUserId }),
  },

  /** Networks that network-tier checks (port probes, service identification) may contact. */
  approvedNetworks: {
    list: (init?: RequestInit): Promise<{ items: ApprovedNetwork[] }> =>
      getJson('/api/v1/approved-networks', approvedNetworkListResponseSchema, init),
    create: (body: CreateApprovedNetworkRequest): Promise<ApprovedNetwork> =>
      sendJson('POST', '/api/v1/approved-networks', approvedNetworkSchema, body),
    revoke: (id: string, reason: string): Promise<ApprovedNetwork> =>
      sendJson(
        'POST',
        `/api/v1/approved-networks/${encodeURIComponent(id)}/revoke`,
        approvedNetworkSchema,
        { reason },
      ),
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

  /** Rule-engine findings: evidence-backed observations, never claims of compromise. */
  findings: {
    list: (params: QueryParams, init?: RequestInit): Promise<FindingListResponse> =>
      getJson(`/api/v1/findings${toQuery(params)}`, findingListResponseSchema, init),
    /** Active (non-resolved) findings by severity and category, optionally for one domain. */
    summary: (params: QueryParams, init?: RequestInit): Promise<FindingSummaryResponse> =>
      getJson(`/api/v1/findings/summary${toQuery(params)}`, findingSummaryResponseSchema, init),
    get: (id: string, init?: RequestInit): Promise<FindingDetailResponse> =>
      getJson(findingPath(id), findingDetailResponseSchema, init),
    /**
     * Status change and/or assignment. `expectedStatus` is the status the user saw; the server
     * answers 409 `finding_conflict` (and changes nothing) if the finding changed meanwhile.
     */
    update: (id: string, body: FindingUpdateRequest): Promise<{ finding: Finding }> =>
      sendJson('PATCH', findingPath(id), findingUpdateResponseSchema, body),
    /** The same change for many findings; each is checked individually and may be skipped. */
    bulkUpdate: (body: FindingBulkUpdateRequest): Promise<FindingBulkUpdateResponse> =>
      sendJson('POST', '/api/v1/findings/bulk', findingBulkUpdateResponseSchema, body),
    addComment: (id: string, body: string): Promise<{ comment: FindingComment }> =>
      sendJson('POST', `${findingPath(id)}/comments`, findingCommentResponseSchema, { body }),
    /** Queues a scan of the finding's domain with the profile that runs its rule's checks. */
    reassess: (id: string): Promise<FindingReassessResponse> =>
      sendJson('POST', `${findingPath(id)}/reassess`, findingReassessResponseSchema),
  },

  users: {
    /** Users a finding can be assigned to (requires `findings:assign`). */
    assignable: (init?: RequestInit): Promise<AssignableUsersResponse> =>
      getJson('/api/v1/users/assignable', assignableUsersResponseSchema, init),
    /** User administration (requires `users:manage`). */
    list: (params: QueryParams, init?: RequestInit): Promise<UserListResponse> =>
      getJson(`/api/v1/users${toQuery(params)}`, userListResponseSchema, init),
    get: (id: string, init?: RequestInit): Promise<{ user: User }> =>
      getJson(userPath(id), userResponseSchema, init),
    /** Pre-provisions a user; they must also be allowed by the Cloudflare Access policy. */
    create: (body: UserCreateRequest): Promise<{ user: User }> =>
      sendJson('POST', '/api/v1/users', userResponseSchema, body),
    /** Role / active flag / display name. 409 `conflict` for self-changes and the last admin. */
    update: (id: string, body: UserUpdateRequest): Promise<{ user: User }> =>
      sendJson('PATCH', userPath(id), userResponseSchema, body),
  },

  /** Append-only audit log (requires `audit:read`). */
  audit: {
    list: (params: QueryParams, init?: RequestInit): Promise<AuditListResponse> =>
      getJson(`/api/v1/audit-logs${toQuery(params)}`, auditListResponseSchema, init),
  },

  advisories: {
    list: (params: QueryParams, init?: RequestInit): Promise<AdvisoryListResponse> =>
      getJson(`/api/v1/advisories${toQuery(params)}`, advisoryListResponseSchema, init),
  },

  rules: (init?: RequestInit): Promise<{ items: RuleCatalogueEntry[] }> =>
    getJson('/api/v1/rules', ruleCatalogueResponseSchema, init),

  /** Portfolio reporting (design §10, §14). */
  reports: {
    /** Coverage, finding counts, trend and expiry lists (`reports:read`). */
    summary: (init?: RequestInit): Promise<ReportSummaryResponse> =>
      getJson('/api/v1/reports/summary', reportSummaryResponseSchema, init),
    /**
     * Downloads the findings CSV for the given Findings-page filters (`reports:generate`). Fetched (same-origin, so the Cloudflare Access cookie is sent)
     * rather than navigated to, so API errors show in the page and `X-Truncated` can be reported.
     */
    findingsCsv: async (params: QueryParams): Promise<CsvDownload> => {
      let res: Response;
      try {
        res = await fetch(`/api/v1/reports/findings.csv${toQuery(params)}`, {
          headers: { Accept: 'text/csv' },
        });
      } catch {
        throw new ApiClientError('The API could not be reached.', 0, 'network_error');
      }
      if (!res.ok) {
        const parsed = errorResponseSchema.safeParse(await res.json().catch(() => null));
        if (parsed.success) {
          const { message, code, requestId, details } = parsed.data.error;
          throw new ApiClientError(message, res.status, code, requestId, details);
        }
        throw new ApiClientError(`Unexpected API response (${res.status}).`, res.status, 'unknown');
      }
      const type = res.headers.get('Content-Type') ?? '';
      if (type && !type.includes('csv')) {
        // e.g. an identity-provider login page after the access session expired.
        throw new ApiClientError(
          'The export did not return a CSV file. Reload the page to sign in again.',
          res.status,
          'invalid_response',
        );
      }
      const disposition = res.headers.get('Content-Disposition') ?? '';
      const named = /filename="?([\w.-]+)"?/.exec(disposition)?.[1];
      return {
        blob: await res.blob(),
        filename: named ?? `findings-${new Date().toISOString().slice(0, 10)}.csv`,
        truncated: res.headers.get('X-Truncated') === 'true',
      };
    },
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
