import { z } from 'zod';
import { severitySchema } from '../domain/severity.ts';
import { paginatedSchema } from './pagination.ts';

/**
 * Findings (design §5.9) produced by the deterministic rules engine, their advisories (§5.10) and the
 * rule catalogue. Findings are evidence-backed observations about configuration and exposure, not
 * claims of compromise.
 */

const isoDateTime = z.iso.datetime();

export const FINDING_STATUSES = [
  'open',
  'acknowledged',
  'remediation_in_progress',
  'resolved',
  'accepted_risk',
] as const;
export const findingStatusSchema = z.enum(FINDING_STATUSES);
export type FindingStatus = z.infer<typeof findingStatusSchema>;

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  remediation_in_progress: 'Remediation in progress',
  resolved: 'Resolved',
  accepted_risk: 'Accepted risk',
};

export const confidenceSchema = z.enum(['low', 'medium', 'high']);
export const RULE_CATEGORIES = [
  'dns',
  'email',
  'tls',
  'http',
  'exposure',
  'registration',
  'asset',
] as const;
export const ruleCategorySchema = z.enum(RULE_CATEGORIES);

export const riskInputsSchema = z.object({
  model: z.string(),
  severity: severitySchema,
  severityWeight: z.number(),
  exposure: z.enum(['public_record', 'web', 'network_service']),
  exposureFactor: z.number(),
  criticality: z.enum(['low', 'medium', 'high', 'critical']),
  criticalityFactor: z.number(),
});
export type RiskInputsDto = z.infer<typeof riskInputsSchema>;

export const findingSchema = z.object({
  id: z.uuid(),
  ruleId: z.string(),
  ruleVersion: z.int(),
  category: ruleCategorySchema,
  domain: z.object({ id: z.uuid(), fqdn: z.string() }),
  hostname: z.string(),
  component: z.string(),
  assetId: z.uuid().nullable(),
  title: z.string(),
  description: z.string(),
  severity: severitySchema,
  confidence: confidenceSchema,
  riskScore: z.int().min(0).max(100),
  riskInputs: riskInputsSchema,
  status: findingStatusSchema,
  evidence: z.record(z.string(), z.unknown()),
  firstSeenAt: isoDateTime,
  lastSeenAt: isoDateTime,
  resolvedAt: isoDateTime.nullable(),
  recurrenceCount: z.int(),
  createdAt: isoDateTime,
  updatedAt: isoDateTime,
});
export type Finding = z.infer<typeof findingSchema>;

export const advisorySchema = z.object({
  id: z.uuid(),
  findingId: z.uuid(),
  title: z.string(),
  summary: z.string(),
  businessImpact: z.string(),
  recommendedActions: z.array(z.string()),
  references: z.array(z.string()),
  createdAt: isoDateTime,
  updatedAt: isoDateTime,
});
export type AdvisoryDto = z.infer<typeof advisorySchema>;

export const findingHistoryEntrySchema = z.object({
  id: z.uuid(),
  fromStatus: findingStatusSchema.nullable(),
  toStatus: findingStatusSchema,
  changedBy: z.object({ id: z.uuid(), email: z.string() }).nullable(),
  /** `detected`, `recurrence`, `condition_absent` (system) or a user reason (Milestone 8). */
  reason: z.string(),
  note: z.string().nullable(),
  scanJobId: z.uuid().nullable(),
  createdAt: isoDateTime,
});
export type FindingHistoryEntry = z.infer<typeof findingHistoryEntrySchema>;

export const findingDetailResponseSchema = z.object({
  finding: findingSchema,
  advisory: advisorySchema.nullable(),
  history: z.array(findingHistoryEntrySchema),
  rule: z
    .object({
      id: z.string(),
      version: z.int(),
      detection: z.string(),
      resolution: z.string(),
      evidenceRequirements: z.string(),
    })
    .nullable(),
});
export type FindingDetailResponse = z.infer<typeof findingDetailResponseSchema>;

export const FINDING_SORTS = [
  '-riskScore',
  'riskScore',
  '-lastSeenAt',
  '-firstSeenAt',
  '-severity',
] as const;

export const findingListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  /** `active` = every status except resolved (default). */
  status: z.union([z.literal('active'), z.literal('all'), findingStatusSchema]).default('active'),
  severity: severitySchema.optional(),
  category: ruleCategorySchema.optional(),
  domainId: z.uuid().optional(),
  ruleId: z.string().max(20).optional(),
  q: z.string().trim().max(253).optional(),
  sort: z.enum(FINDING_SORTS).default('-riskScore'),
});
export type FindingListQuery = z.infer<typeof findingListQuerySchema>;

export const findingListResponseSchema = paginatedSchema(findingSchema);
export type FindingListResponse = z.infer<typeof findingListResponseSchema>;

/** Counts of active (non-resolved) findings by severity, optionally for one domain. */
export const findingSummaryResponseSchema = z.object({
  bySeverity: z.record(severitySchema, z.int()),
  total: z.int(),
  byCategory: z.record(ruleCategorySchema, z.int()),
});
export type FindingSummaryResponse = z.infer<typeof findingSummaryResponseSchema>;

export const advisoryListItemSchema = advisorySchema.extend({
  finding: findingSchema.pick({
    id: true,
    ruleId: true,
    title: true,
    severity: true,
    status: true,
    domain: true,
    hostname: true,
    riskScore: true,
  }),
});
export const advisoryListResponseSchema = paginatedSchema(advisoryListItemSchema);
export type AdvisoryListResponse = z.infer<typeof advisoryListResponseSchema>;

export const ruleCatalogueEntrySchema = z.object({
  id: z.string(),
  version: z.int(),
  category: ruleCategorySchema,
  title: z.string(),
  defaultSeverity: severitySchema,
  defaultConfidence: confidenceSchema,
  requires: z.array(z.string()),
  detection: z.string(),
  resolution: z.string(),
  evidenceRequirements: z.string(),
});
export const ruleCatalogueResponseSchema = z.object({ items: z.array(ruleCatalogueEntrySchema) });
export type RuleCatalogueEntry = z.infer<typeof ruleCatalogueEntrySchema>;
