import { z } from 'zod';
import { criticalitySchema } from '../domain/severity.ts';
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
  monitoringEnabled: z.boolean(),
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
] as const;

/** Query string for GET /domains. */
export const domainListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  q: z.string().trim().max(253).optional(),
  verificationStatus: domainVerificationStatusSchema.optional(),
  criticality: criticalitySchema.optional(),
  monitoring: z.enum(['true', 'false']).optional(),
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
  })
  .refine((v) => Object.values(v).some((x) => x !== undefined), {
    message: 'Provide at least one field to change.',
  });
export type UpdateDomainRequest = z.input<typeof updateDomainRequestSchema>;

// --- Verification -------------------------------------------------------------------------------

export const CHALLENGE_STATUSES = [
  'pending',
  'verified',
  'expired',
  'failed',
  'superseded',
] as const;

export const verificationChallengeSchema = z.object({
  id: z.uuid(),
  method: z.literal('dns_txt'),
  status: z.enum(CHALLENGE_STATUSES),
  /** DNS name the TXT record must be published at. */
  recordName: z.string(),
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
});

export const importConfirmResponseSchema = z.object({
  created: z.array(z.object({ id: z.uuid(), fqdn: z.string() })),
  skipped: z.number().int(),
});
export type ImportConfirmResponse = z.infer<typeof importConfirmResponseSchema>;
