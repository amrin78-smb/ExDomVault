import {
  attackSurfaceResponseSchema,
  type AttackSurfaceResponse,
  certificatesResponseSchema,
  type CertificatesResponse,
  dashboardResponseSchema,
  type DashboardResponse,
  portsResponseSchema,
  type PortsResponse,
  searchResponseSchema,
  type SearchResponse,
  vulnerabilitiesResponseSchema,
  type VulnerabilitiesResponse,
  assetImportResponseSchema,
  type AssetImportRequest,
  type AssetImportResponse,
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
import type { ExportResource } from '@exdomainvault/shared';
import {
  intelFeedsResponseSchema,
  softwareListResponseSchema,
  softwareSummaryResponseSchema,
  type IntelFeedsResponse,
  type SoftwareListResponse,
  type SoftwareSummaryResponse,
} from '@exdomainvault/shared';
import {
  scanScheduleResponseSchema,
  type ScanSchedule,
  type ScanScheduleResponse,
} from '@exdomainvault/shared';
import {
  opsAlertsResponseSchema,
  opsHealthResponseSchema,
  type OpsAlertsResponse,
  type OpsHealthResponse,
} from '@exdomainvault/shared';
import { z } from 'zod';

export class ApiClientError extends Error {
  override name = 'ApiClientError';

  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  readonly details?: FieldError[];
  /** 429 `rate_limited`: seconds until the server accepts requests again (`Retry-After`). */
  readonly retryAfterSeconds?: number;

  constructor(
    message: string,
    status: number,
    code: string,
    requestId?: string,
    details?: FieldError[],
    retryAfterSeconds?: number,
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** `Retry-After` as whole seconds (delta-seconds or an HTTP date); undefined when absent/invalid. */
export function parseRetryAfter(value: string | null, now = Date.now()): number | undefined {
  if (value === null || value.trim() === '') return undefined;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  const at = Date.parse(trimmed);
  if (Number.isNaN(at)) return undefined;
  return Math.max(0, Math.ceil((at - now) / 1000));
}

/** The message shown for a 429; the server's own text is replaced so every screen says the same. */
export function rateLimitedMessage(retryAfterSeconds: number | undefined): string {
  if (retryAfterSeconds === undefined) return 'Too many requests — try again shortly.';
  const n = Math.max(1, retryAfterSeconds);
  return `Too many requests — try again in ${n} second${n === 1 ? '' : 's'}.`;
}

/**
 * The client error for a non-2xx response. A 429 becomes `rate_limited` with the `Retry-After`
 * seconds and a friendly message; it is never retried automatically (a mutation must not repeat
 * behind the user's back), the user decides when to try again.
 */
function errorFromResponse(res: Response, body: unknown): ApiClientError {
  const parsed = errorResponseSchema.safeParse(body);
  if (res.status === 429) {
    const retryAfter = parseRetryAfter(res.headers.get('Retry-After'));
    return new ApiClientError(
      rateLimitedMessage(retryAfter),
      429,
      'rate_limited',
      parsed.success ? parsed.data.error.requestId : undefined,
      undefined,
      retryAfter,
    );
  }
  if (parsed.success) {
    const { message, code, requestId, details } = parsed.data.error;
    return new ApiClientError(message, res.status, code, requestId, details);
  }
  return new ApiClientError(`Unexpected API response (${res.status}).`, res.status, 'unknown');
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

  if (!res.ok) throw errorFromResponse(res, body);

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

/** Sends a JSON body (POST/PATCH/PUT). Same-origin fetch carries the Origin header the API requires. */
export function sendJson<T>(
  method: 'POST' | 'PATCH' | 'PUT',
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
  /** Data rows in the file (records after the header line). */
  rows: number;
  /** Rows that matched on the server (`X-Total-Rows`), or null when the header is absent. */
  totalRows: number | null;
}

/** Number of data records in a CSV text (header excluded); newlines inside quoted cells don't count. */
export function countCsvRows(text: string): number {
  let records = 0;
  let inQuotes = false;
  let pending = false; // characters seen since the last record break
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') inQuotes = !inQuotes;
    if (ch === '\n' && !inQuotes) {
      if (pending) records++; // blank lines are not records
      pending = false;
    } else if (ch !== '\r' && ch !== '\uFEFF') {
      pending = true;
    }
  }
  if (pending) records++;
  return Math.max(0, records - 1);
}

const EXPIRED_SESSION_MESSAGE =
  'The export did not return a CSV file. Your sign-in may have expired: reload the page to sign in again.';

/**
 * Downloads a CSV export. Fetched (same-origin, so the Cloudflare Access cookie is sent) rather
 * than navigated to, so API errors show in the page and truncation can be reported. Redirects are
 * not followed: a redirect (or any non-CSV body) means the access session expired.
 */
async function downloadCsv(
  path: string,
  params: QueryParams,
  resource: string,
): Promise<CsvDownload> {
  let res: Response;
  try {
    res = await fetch(`${path}${toQuery(params)}`, {
      headers: { Accept: 'text/csv' },
      redirect: 'manual',
    });
  } catch {
    throw new ApiClientError('The API could not be reached.', 0, 'network_error');
  }
  if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
    throw new ApiClientError(EXPIRED_SESSION_MESSAGE, res.status, 'session_expired');
  }
  if (!res.ok) throw errorFromResponse(res, await res.json().catch(() => null));
  const type = res.headers.get('Content-Type') ?? '';
  if (type && !type.includes('csv')) {
    // e.g. an identity-provider login page served after the access session expired.
    throw new ApiClientError(EXPIRED_SESSION_MESSAGE, res.status, 'invalid_response');
  }
  const bytes = await res.arrayBuffer();
  const disposition = res.headers.get('Content-Disposition') ?? '';
  const named = /filename="?([\w.-]+)"?/.exec(disposition)?.[1];
  const stamp = new Date().toISOString().slice(0, 10).replaceAll('-', '');
  const total = Number(res.headers.get('X-Total-Rows') ?? Number.NaN);
  return {
    blob: new Blob([bytes], { type: type || 'text/csv' }),
    filename: named ?? `exdomainvault-${resource}-${stamp}.csv`,
    truncated: res.headers.get('X-Truncated') === 'true',
    rows: countCsvRows(new TextDecoder().decode(bytes)),
    totalRows: Number.isInteger(total) && total >= 0 ? total : null,
  };
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
    /**
     * Adds known hostnames (from a zone export, CSV or list) as `pending` assets. Never approves or
     * changes an existing asset; `dryRun: true` returns the per-hostname outcome without saving.
     */
    importAssets: (id: string, body: AssetImportRequest): Promise<AssetImportResponse> =>
      sendJson('POST', `${domainPath(id)}/assets/import`, assetImportResponseSchema, body),
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

  settings: {
    /** Scheduled active scans (`scans:read` to view, `scan_policies:manage` to change). */
    scanSchedule: {
      get: (init?: RequestInit): Promise<ScanScheduleResponse> =>
        getJson('/api/v1/settings/scan-schedule', scanScheduleResponseSchema, init),
      update: (body: ScanSchedule): Promise<ScanScheduleResponse> =>
        sendJson('PUT', '/api/v1/settings/scan-schedule', scanScheduleResponseSchema, body),
    },
  },

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
    /** Downloads the findings CSV for the given Findings-page filters (`reports:generate`). */
    findingsCsv: (params: QueryParams): Promise<CsvDownload> =>
      downloadCsv('/api/v1/reports/findings.csv', params, 'findings'),
  },

  /**
   * CSV exports of the lists (`GET /exports/<resource>.csv`): same filters and sort as the list
   * endpoint, paging ignored, the list's read permission (users: `users:manage`, audit: `audit:read`).
   */
  exports: {
    csv: (resource: ExportResource, params: QueryParams): Promise<CsvDownload> =>
      downloadCsv(`/api/v1/exports/${resource}.csv`, params, resource),
  },

  /**
   * Exposed-software inventory (Milestone 11, `findings:read`; asset owners see only their own
   * assets). Versions are self-reported by hosts: matches mean "possibly affected — verify".
   */
  software: {
    list: (params: QueryParams, init?: RequestInit): Promise<SoftwareListResponse> =>
      getJson(`/api/v1/software${toQuery(params)}`, softwareListResponseSchema, init),
    summary: (init?: RequestInit): Promise<SoftwareSummaryResponse> =>
      getJson('/api/v1/software/summary', softwareSummaryResponseSchema, init),
    forDomain: (
      id: string,
      params: QueryParams,
      init?: RequestInit,
    ): Promise<SoftwareListResponse> =>
      getJson(`${domainPath(id)}/software${toQuery(params)}`, softwareListResponseSchema, init),
  },

  /** Public intelligence feeds (endoflife.date, CISA KEV, NVD) synchronised by the server. */
  intel: {
    feeds: (init?: RequestInit): Promise<IntelFeedsResponse> =>
      getJson('/api/v1/intel/feeds', intelFeedsResponseSchema, init),
    /**
     * Runs a feed sync now (`settings:manage`). The body may carry the updated feed status; callers
     * reload the status list either way.
     */
    sync: (): Promise<Partial<IntelFeedsResponse> | null> =>
      sendJson('POST', '/api/v1/intel/feeds/sync', intelFeedsResponseSchema.partial().nullable()),
  },

  /** Operations (Milestone 12): system health for administrators, alerts for everyone. */
  /** Milestone 13: overview dashboard aggregates (`range` = 7, 30 or 90 days). */
  dashboard: (range: number, init?: RequestInit): Promise<DashboardResponse> =>
    getJson(`/api/v1/dashboard${toQuery({ range })}`, dashboardResponseSchema, init),

  /** Milestone 13: global search across domains, hosts, IPs, ports, software, CVEs and findings. */
  search: (q: string, init?: RequestInit): Promise<SearchResponse> =>
    getJson(`/api/v1/search${toQuery({ q })}`, searchResponseSchema, init),

  /** Milestone 13: cross-domain inventory views. */
  inventory: {
    ports: (params: QueryParams, init?: RequestInit): Promise<PortsResponse> =>
      getJson(`/api/v1/ports${toQuery(params)}`, portsResponseSchema, init),
    certificates: (params: QueryParams, init?: RequestInit): Promise<CertificatesResponse> =>
      getJson(`/api/v1/certificates${toQuery(params)}`, certificatesResponseSchema, init),
    vulnerabilities: (params: QueryParams, init?: RequestInit): Promise<VulnerabilitiesResponse> =>
      getJson(`/api/v1/vulnerabilities${toQuery(params)}`, vulnerabilitiesResponseSchema, init),
    attackSurface: (init?: RequestInit): Promise<AttackSurfaceResponse> =>
      getJson('/api/v1/attack-surface', attackSurfaceResponseSchema, init),
  },

  ops: {
    health: (init?: RequestInit): Promise<OpsHealthResponse> =>
      getJson('/api/v1/ops/health', opsHealthResponseSchema, init),
    alerts: (init?: RequestInit): Promise<OpsAlertsResponse> =>
      getJson('/api/v1/ops/alerts', opsAlertsResponseSchema, init),
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
