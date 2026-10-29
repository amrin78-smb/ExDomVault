import { z } from 'zod';
import { criticalitySchema } from '../domain/severity.ts';
import { gradeSchema } from '../domain/security-score.ts';
import { paginatedSchema } from './pagination.ts';

export const DOMAIN_VERIFICATION_STATUSES = [
  'unverified',
  'pending',
  'verified',
  'revoked',
] as const;
export const domainVerificationStatusSchema = z.enum(DOMAIN_VERIFICATION_STATUSES);
export type DomainVerificationStatus = z.infer<typeof domainVerificationStatusSchema>;

export const DOMAIN_VERIFICATION_STATUS_LABELS: Record<DomainVerificationStatus, string> = {
  unverified: 'Unverified',
  pending: 'Verification pending',
  verified: 'Verified',
  revoked: 'Revoked',
};

export const VERIFICATION_METHODS = ['dns_txt', 'admin_attestation'] as const;
export const verificationMethodSchema = z.enum(VERIFICATION_METHODS);
export type VerificationMethod = z.infer<typeof verificationMethodSchema>;

export const VERIFICATION_METHOD_LABELS: Record<VerificationMethod, string> = {
  dns_txt: 'DNS TXT record',
  admin_attestation: 'Authorised by administrator',
};

export const registrationDataStatusSchema = z.enum([
  'unknown',
  'available',
  'redacted',
  'unavailable',
]);
export const domainWarningSchema = z.enum(['idn', 'mixed_script']);
export type DomainWarningCode = z.infer<typeof domainWarningSchema>;

const isoDateTime = z.iso.datetime();
const businessOwnerSchema = z
  .string()
  .trim()
  .max(200, 'Business owner must be at most 200 characters.')
  .transform((v) => (v === '' ? null : v));

export const domainSchema = z.object({
  id: z.uuid(),
  /** Canonical lowercase A-label form. Always display this; `unicodeFqdn` is supplementary. */
  fqdn: z.string(),
  unicodeFqdn: z.string(),
  warnings: z.array(domainWarningSchema),
  registrar: z.string().nullable(),
  registeredAt: isoDateTime.nullable(),
  expiresAt: isoDateTime.nullable(),
  /** Distinguishes "not collected yet" from privacy-redacted or unavailable registration data. */
  registrationDataStatus: registrationDataStatusSchema,
  criticality: criticalitySchema,
  businessOwner: z.string().nullable(),
  verificationStatus: domainVerificationStatusSchema,
  verifiedAt: isoDateTime.nullable(),
  /** How the domain was authorised for active scanning (null unless verified). */
  verificationMethod: verificationMethodSchema.nullable(),
  /** Review-by date of an administrator authorisation; it lapses then. Null for DNS proof. */
  verificationExpiresAt: isoDateTime.nullable(),
  /** Passive monitoring (public DNS, certificates, CT logs, registration data). Allowed for any domain. */
  monitoringEnabled: z.boolean(),
  /**
   * Milestone 15: weekly lookalike-domain (brand) monitoring. Passive: public resolvers only, the
   * lookalike names are never contacted. Off by default.
   */
  brandMonitoring: z.boolean().default(false),
  /** Latest security score snapshot (0–100) and grade; null until the domain has been scanned. */
  score: z.int().min(0).max(100).nullable().default(null),
  grade: gradeSchema.nullable().default(null),
  createdAt: isoDateTime,
  updatedAt: isoDateTime,
});
export type Domain = z.infer<typeof domainSchema>;

export const DOMAIN_SORTS = [
  'fqdn',
  '-fqdn',
  'createdAt',
  '-createdAt',
  'criticality',
  '-criticality',
  /** Latest security score, lowest first (unscored domains last). */
  'score',
  '-score',
] as const;

/** Query string for GET /domains. */
export const domainListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  q: z.string().trim().max(253).optional(),
  verificationStatus: domainVerificationStatusSchema.optional(),
  criticality: criticalitySchema.optional(),
  monitoring: z.enum(['true', 'false']).optional(),
  /** Latest security grade; `none` = not scored yet. */
  grade: z.union([gradeSchema, z.literal('none')]).optional(),
  sort: z.enum(DOMAIN_SORTS).default('fqdn'),
});
export type DomainListQuery = z.infer<typeof domainListQuerySchema>;

export const domainListResponseSchema = paginatedSchema(domainSchema);
export type DomainListResponse = z.infer<typeof domainListResponseSchema>;

export const createDomainRequestSchema = z.strictObject({
  fqdn: z.string().max(1024),
  criticality: criticalitySchema.default('medium'),
  businessOwner: businessOwnerSchema.nullish(),
});
export type CreateDomainRequest = z.input<typeof createDomainRequestSchema>;

export const updateDomainRequestSchema = z
  .strictObject({
    criticality: criticalitySchema.optional(),
    businessOwner: businessOwnerSchema.nullable().optional(),
    monitoringEnabled: z.boolean().optional(),
    /** Milestone 15: brand monitoring (lookalike domains); `domains:write`, audited. */
    brandMonitoring: z.boolean().optional(),
  })
  .refine((v) => Object.values(v).some((x) => x !== undefined), {
    message: 'Provide at least one field to change.',
  });
export type UpdateDomainRequest = z.input<typeof updateDomainRequestSchema>;

/** Turn passive monitoring on or off for many domains (listed ids, or every domain). */
export const BULK_MONITORING_MAX = 500;
export const bulkMonitoringRequestSchema = z.union([
  z.strictObject({
    domainIds: z
      .array(z.uuid())
      .min(1, 'Select at least one domain.')
      .max(BULK_MONITORING_MAX, `Select at most ${BULK_MONITORING_MAX} domains.`),
    enabled: z.boolean(),
  }),
  z.strictObject({ all: z.literal(true), enabled: z.boolean() }),
]);
export type BulkMonitoringRequest = z.input<typeof bulkMonitoringRequestSchema>;
export const bulkMonitoringResponseSchema = z.object({ updated: z.int().min(0) });
export type BulkMonitoringResponse = z.infer<typeof bulkMonitoringResponseSchema>;

// --- Verification -------------------------------------------------------------------------------

export const CHALLENGE_STATUSES = [
  'pending',
  'verified',
  'expired',
  'failed',
  'superseded',
  'revoked',
] as const;

/** A verification record: a DNS TXT challenge or an administrator attestation. */
export const verificationChallengeSchema = z.object({
  id: z.uuid(),
  method: verificationMethodSchema,
  status: z.enum(CHALLENGE_STATUSES),
  /** DNS name the TXT record must be published at (DNS challenges only). */
  recordName: z.string().nullable(),
  /** Attestations only: why the domain is authorised, and a supporting reference. */
  reason: z.string().nullable(),
  reference: z.string().nullable(),
  createdAt: isoDateTime,
  expiresAt: isoDateTime,
  lastCheckedAt: isoDateTime.nullable(),
  verifiedAt: isoDateTime.nullable(),
  failureReason: z.string().nullable(),
});
export type VerificationChallenge = z.infer<typeof verificationChallengeSchema>;

export const domainDetailResponseSchema = z.object({
  domain: domainSchema,
  /** The latest challenge (pending or most recent), if any. Its secret value is never returned again. */
  verification: verificationChallengeSchema.nullable(),
});
export type DomainDetailResponse = z.infer<typeof domainDetailResponseSchema>;

/** Returned once, when a challenge is created. Only a hash of the value is stored. */
export const createChallengeResponseSchema = z.object({
  challenge: verificationChallengeSchema,
  record: z.object({
    type: z.literal('TXT'),
    name: z.string(),
    value: z.string(),
  }),
});
export type CreateChallengeResponse = z.infer<typeof createChallengeResponseSchema>;

export const VERIFICATION_OUTCOMES = [
  'verified',
  'record_not_found',
  'value_mismatch',
  'expired',
  'dns_error',
  'too_soon',
] as const;
export const verificationOutcomeSchema = z.enum(VERIFICATION_OUTCOMES);
export type VerificationOutcome = z.infer<typeof verificationOutcomeSchema>;

export const verifyDomainResponseSchema = z.object({
  outcome: verificationOutcomeSchema,
  message: z.string(),
  domain: domainSchema,
  verification: verificationChallengeSchema.nullable(),
});
export type VerifyDomainResponse = z.infer<typeof verifyDomainResponseSchema>;

// --- Administrator authorisation -----------------------------------------------------------

export const ATTESTATION_MAX_MONTHS = 24;
export const ATTESTATION_DEFAULT_MONTHS = 12;

/**
 * An administrator's statement that the organisation owns the domain(s) and authorises active
 * scanning, for domains whose DNS cannot carry a TXT record. Expires on `reviewBy`.
 */
export const authorisationSchema = z.strictObject({
  reason: z
    .string()
    .trim()
    .min(10, 'Give a reason of at least 10 characters.')
    .max(500, 'The reason must be at most 500 characters.'),
  reference: z
    .string()
    .trim()
    .max(200, 'The reference must be at most 200 characters.')
    .transform((v) => (v === '' ? null : v))
    .nullish(),
  /** Calendar date (UTC) on which the authorisation lapses unless renewed. */
  reviewBy: z.iso.date('Enter the review date as YYYY-MM-DD.'),
});
export type AuthorisationInput = z.input<typeof authorisationSchema>;

export const bulkAuthoriseRequestSchema = authorisationSchema.extend({
  domainIds: z
    .array(z.uuid())
    .min(1, 'Select at least one domain.')
    .max(500, 'At most 500 domains at a time.')
    .refine((ids) => new Set(ids).size === ids.length, 'Domain ids must be unique.'),
});
export type BulkAuthoriseRequest = z.input<typeof bulkAuthoriseRequestSchema>;

export const bulkAuthoriseResponseSchema = z.object({
  authorised: z.array(z.object({ id: z.uuid(), fqdn: z.string() })),
  skipped: z.array(
    z.object({
      id: z.uuid(),
      fqdn: z.string().nullable(),
      reason: z.enum(['already_verified', 'not_found']),
    }),
  ),
});
export type BulkAuthoriseResponse = z.infer<typeof bulkAuthoriseResponseSchema>;

export const revokeRequestSchema = z.strictObject({
  reason: z
    .string()
    .trim()
    .min(10, 'Give a reason of at least 10 characters.')
    .max(500, 'The reason must be at most 500 characters.'),
});

// --- CSV import ---------------------------------------------------------------------------------

export const IMPORT_MAX_BYTES = 256 * 1024;
export const IMPORT_MAX_ROWS = 1000;

export const importPreviewRequestSchema = z.strictObject({
  csv: z
    .string()
    .min(1, 'The file is empty.')
    .max(IMPORT_MAX_BYTES, 'The file is larger than 256 KB.'),
});

export const importRowStatusSchema = z.enum([
  'valid',
  'invalid',
  'duplicate_in_file',
  'already_registered',
]);
export type ImportRowStatus = z.infer<typeof importRowStatusSchema>;

export const importPreviewRowSchema = z.object({
  /** 1-based line number in the uploaded file. */
  line: z.number().int(),
  input: z.string(),
  fqdn: z.string().nullable(),
  unicodeFqdn: z.string().nullable(),
  criticality: criticalitySchema.nullable(),
  businessOwner: z.string().nullable(),
  status: importRowStatusSchema,
  errors: z.array(z.string()),
  warnings: z.array(domainWarningSchema),
});
export type ImportPreviewRow = z.infer<typeof importPreviewRowSchema>;

export const importPreviewResponseSchema = z.object({
  /** SHA-256 of the previewed CSV; the confirm request must send it back unchanged. */
  digest: z.string(),
  rows: z.array(importPreviewRowSchema),
  /** File-level problems (missing header, too many rows). When present, nothing can be imported. */
  fileErrors: z.array(z.string()),
  summary: z.object({
    total: z.number().int(),
    valid: z.number().int(),
    invalid: z.number().int(),
    duplicateInFile: z.number().int(),
    alreadyRegistered: z.number().int(),
  }),
});
export type ImportPreviewResponse = z.infer<typeof importPreviewResponseSchema>;

export const importConfirmRequestSchema = importPreviewRequestSchema.extend({
  digest: z.string().regex(/^[0-9a-f]{64}$/),
  /** Optionally authorise every imported domain in the same transaction (needs domains:verify). */
  authorisation: authorisationSchema.optional(),
});

export const importConfirmResponseSchema = z.object({
  created: z.array(z.object({ id: z.uuid(), fqdn: z.string() })),
  skipped: z.number().int(),
  /** Number of created domains authorised by the optional administrator authorisation. */
  authorised: z.number().int(),
});
export type ImportConfirmResponse = z.infer<typeof importConfirmResponseSchema>;
