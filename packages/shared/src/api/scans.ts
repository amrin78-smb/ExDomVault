import { z } from 'zod';
import { paginatedSchema } from './pagination.ts';

const isoDateTime = z.iso.datetime();

// --- Scan profiles ------------------------------------------------------------------------------

/** Checks a profile may enable. The worker maps each to fixed, server-defined code paths. */
export const SCAN_CHECKS = [
  'dns',
  'rdap',
  'tls_certificate',
  'http_availability',
  'http_headers',
  'tcp_ports',
  'service_identification',
  'tls_configuration',
  'discovery',
] as const;
export const scanCheckSchema = z.enum(SCAN_CHECKS);
export type ScanCheck = z.infer<typeof scanCheckSchema>;

/**
 * Checks that only query public infrastructure (resolvers, RDAP, Certificate Transparency logs) and
 * never contact the target. `discovery` finds candidate hostnames; it never adds scan targets.
 */
export const PASSIVE_CHECKS: readonly ScanCheck[] = ['dns', 'rdap', 'discovery'];

/**
 * Browser-like checks (one TLS handshake, one HTTP request per hop, as any visitor makes). Allowed to
 * any public address an approved hostname resolves to (owner decision, tiered policy).
 */
export const WEB_CHECKS: readonly ScanCheck[] = [
  'tls_certificate',
  'http_availability',
  'http_headers',
];

/**
 * Network checks (port probes, service identification, TLS configuration enumeration). Only to
 * addresses inside admin-approved networks: domain verification never authorises probing third-party
 * hosting, CDN or cloud infrastructure.
 */
export const NETWORK_CHECKS: readonly ScanCheck[] = [
  'tcp_ports',
  'service_identification',
  'tls_configuration',
];

/**
 * A profile's configuration (design §6). Stored in `scan_profiles.config`, copied into each job's
 * snapshot. Never contains scanner flags: only data the worker interprets with fixed code.
 */
export const scanProfileConfigSchema = z
  .strictObject({
    /** True when any check connects to target hosts. Active profiles need a verified domain. */
    active: z.boolean(),
    checks: z.array(scanCheckSchema).min(1),
    tcpPorts: z.array(z.int().min(1).max(65535)).max(1024),
    timeouts: z.strictObject({
      connectMs: z.int().min(100).max(30_000),
      readMs: z.int().min(100).max(60_000),
      targetSeconds: z.int().min(5).max(3600),
    }),
    concurrency: z.int().min(1).max(16),
    ratePerSecond: z.number().min(0.1).max(50),
    maxTargets: z.int().min(1).max(1000),
  })
  .refine((c) => c.active || c.checks.every((check) => PASSIVE_CHECKS.includes(check)), {
    message: 'A profile with non-passive checks must be marked active.',
  })
  .refine((c) => c.checks.includes('tcp_ports') || c.tcpPorts.length === 0, {
    message: 'Ports are only allowed when the tcp_ports check is enabled.',
  });
export type ScanProfileConfig = z.infer<typeof scanProfileConfigSchema>;

export const SCAN_PROFILE_KEYS = ['passive', 'quick', 'standard', 'deep'] as const;
export const scanProfileKeySchema = z.enum(SCAN_PROFILE_KEYS);
export type ScanProfileKey = z.infer<typeof scanProfileKeySchema>;

/**
 * Passive discovery runs as its own profile and job type (`scan_jobs.job_type = 'discovery'`): it is
 * requested with `POST /domains/:id/discovery` or scheduled weekly, never through
 * `POST /domains/:id/scans`, and its only check is `discovery`.
 */
export const DISCOVERY_PROFILE_KEY = 'discovery';

export const scanProfileSchema = z.object({
  key: z.string(),
  name: z.string(),
  description: z.string(),
  version: z.int(),
  defaultSchedule: z.string().nullable(),
  enabled: z.boolean(),
  config: scanProfileConfigSchema,
});
export type ScanProfile = z.infer<typeof scanProfileSchema>;

export const scanProfileListResponseSchema = z.object({
  items: z.array(scanProfileSchema),
  /** Whether the server currently accepts active-profile jobs (off until the scope validator). */
  activeScanningEnabled: z.boolean(),
});
export type ScanProfileListResponse = z.infer<typeof scanProfileListResponseSchema>;

// --- Scan jobs ----------------------------------------------------------------------------------

export const SCAN_JOB_STATUSES = [
  'queued',
  'claimed',
  'running',
  'succeeded',
  'failed',
  'cancelled',
] as const;
export const scanJobStatusSchema = z.enum(SCAN_JOB_STATUSES);
export type ScanJobStatus = z.infer<typeof scanJobStatusSchema>;
export const ACTIVE_JOB_STATUSES: readonly ScanJobStatus[] = ['queued', 'claimed', 'running'];

export const SCAN_JOB_STATUS_LABELS: Record<ScanJobStatus, string> = {
  queued: 'Queued',
  claimed: 'Claimed',
  running: 'Running',
  succeeded: 'Succeeded',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

export const SCAN_TARGET_STATUSES = [
  'pending',
  'running',
  'succeeded',
  'failed',
  'skipped',
] as const;
export const scanTargetStatusSchema = z.enum(SCAN_TARGET_STATUSES);
export type ScanTargetStatus = z.infer<typeof scanTargetStatusSchema>;

/** Immutable scope captured when a job is created. Later scope changes never enlarge it. */
export const scopeSnapshotSchema = z.object({
  version: z.literal(1),
  createdAt: isoDateTime,
  requestedBy: z.uuid().nullable(),
  trigger: z.enum(['manual', 'schedule']),
  domain: z.object({
    id: z.uuid(),
    fqdn: z.string(),
    verificationStatus: z.string(),
    verificationMethod: z.string().nullable(),
    verificationExpiresAt: isoDateTime.nullable(),
  }),
  profile: z.object({ key: z.string(), version: z.int(), config: scanProfileConfigSchema }),
  targets: z.array(z.object({ assetId: z.uuid().nullable(), hostname: z.string() })),
  /**
   * Admin-approved networks (CIDR) that network-tier checks may probe. Captured at creation and
   * intersected with the still-approved set at claim time (revocation shrinks scope; nothing enlarges it).
   */
  approvedNetworks: z.array(z.string()).default([]),
});
export type ScopeSnapshot = z.infer<typeof scopeSnapshotSchema>;

const progressSchema = z
  .object({
    completedTargets: z.int().min(0).optional(),
    totalTargets: z.int().min(0).optional(),
    message: z.string().max(200).optional(),
  })
  .nullable();

export const scanJobSchema = z.object({
  id: z.uuid(),
  jobType: z.enum(['scan', 'discovery']),
  profile: z.string(),
  domain: z.object({ id: z.uuid(), fqdn: z.string() }).nullable(),
  status: scanJobStatusSchema,
  priority: z.int(),
  reason: z.string().nullable(),
  trigger: z.enum(['manual', 'schedule']),
  requestedBy: z.object({ id: z.uuid(), email: z.string() }).nullable(),
  createdAt: isoDateTime,
  scheduledAt: isoDateTime,
  startedAt: isoDateTime.nullable(),
  completedAt: isoDateTime.nullable(),
  leaseExpiresAt: isoDateTime.nullable(),
  attempts: z.int(),
  maxAttempts: z.int(),
  worker: z.object({ id: z.uuid(), name: z.string() }).nullable(),
  progress: progressSchema,
  cancelRequestedAt: isoDateTime.nullable(),
  errorCode: z.string().nullable(),
  errorSummary: z.string().nullable(),
  targetCounts: z.record(scanTargetStatusSchema, z.int()),
});
export type ScanJob = z.infer<typeof scanJobSchema>;

export const scanJobTargetSchema = z.object({
  id: z.uuid(),
  assetId: z.uuid().nullable(),
  hostname: z.string(),
  ip: z.string().nullable(),
  status: scanTargetStatusSchema,
  startedAt: isoDateTime.nullable(),
  completedAt: isoDateTime.nullable(),
  errorCode: z.string().nullable(),
});
export type ScanJobTarget = z.infer<typeof scanJobTargetSchema>;

export const scanJobDetailResponseSchema = z.object({
  job: scanJobSchema,
  targets: z.array(scanJobTargetSchema),
  scopeSnapshot: scopeSnapshotSchema,
});
export type ScanJobDetailResponse = z.infer<typeof scanJobDetailResponseSchema>;

export const scanJobListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  status: scanJobStatusSchema.optional(),
  domainId: z.uuid().optional(),
  profile: z.string().max(40).optional(),
});
export type ScanJobListQuery = z.infer<typeof scanJobListQuerySchema>;

export const scanJobListResponseSchema = paginatedSchema(scanJobSchema);
export type ScanJobListResponse = z.infer<typeof scanJobListResponseSchema>;

export const createScanRequestSchema = z.strictObject({
  profile: z.string().min(1).max(40),
  reason: z
    .string()
    .trim()
    .max(500)
    .transform((v) => (v === '' ? null : v))
    .nullish(),
});
export type CreateScanRequest = z.input<typeof createScanRequestSchema>;
