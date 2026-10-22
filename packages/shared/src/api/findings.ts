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

/** A user as shown on a finding (assignee, risk approver, comment author). */
export const findingUserRefSchema = z.object({
  id: z.uuid(),
  email: z.string(),
  displayName: z.string().nullable(),
});
export type FindingUserRef = z.infer<typeof findingUserRefSchema>;

export const acceptedRiskSchema = z.object({
  reason: z.string(),
  approvedBy: findingUserRefSchema.nullable(),
  /** The acceptance lapses at this time: the finding returns to `open` (cron, audited). */
  reviewAt: isoDateTime,
});

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
  assignee: findingUserRefSchema.nullable(),
  /** Present only while `status` is `accepted_risk`. */
  acceptedRisk: acceptedRiskSchema.nullable(),
  /** The rule is a change-detection rule: a user with `findings:triage` may resolve it. */
  manualResolution: z.boolean(),
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
  /** One of FINDING_HISTORY_REASONS; the user's explanation, if any, is in `note`. */
  reason: z.string(),
  note: z.string().nullable(),
  scanJobId: z.uuid().nullable(),
  createdAt: isoDateTime,
});
export type FindingHistoryEntry = z.infer<typeof findingHistoryEntrySchema>;

export const findingCommentSchema = z.object({
  id: z.uuid(),
  author: findingUserRefSchema.nullable(),
  body: z.string(),
  createdAt: isoDateTime,
});
export type FindingComment = z.infer<typeof findingCommentSchema>;

export const findingDetailResponseSchema = z.object({
  finding: findingSchema,
  advisory: advisorySchema.nullable(),
  history: z.array(findingHistoryEntrySchema),
  /** Oldest first. */
  comments: z.array(findingCommentSchema),
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
  /** `me`, `unassigned` or a user id. */
  assignee: z.union([z.literal('me'), z.literal('unassigned'), z.uuid()]).optional(),
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

// --- Lifecycle (Milestone 8, design §9) -------------------------------------------------------

/**
 * `reason` codes in status history. System: `detected`, `recurrence`, `condition_absent`,
 * `accepted_risk_expired`. User changes are `manual` with the user's text in `note`.
 */
export const FINDING_HISTORY_REASONS = [
  'detected',
  'recurrence',
  'condition_absent',
  'accepted_risk_expired',
  'manual',
] as const;

/** Accepted risk must be reviewed within this many days (default offered in the UI: 90). */
export const ACCEPTED_RISK_MAX_DAYS = 366;
export const ACCEPTED_RISK_DEFAULT_DAYS = 90;
export const FINDING_REASON_MAX = 1000;
export const FINDING_COMMENT_MAX = 4000;

const reasonText = z.string().trim().min(3).max(FINDING_REASON_MAX);

/**
 * Status change and/or assignment of one finding. `expectedStatus` is the status the client saw:
 * if the finding changed meanwhile (another user or a scan), the server answers 409
 * `finding_conflict` and changes nothing.
 *
 * Reason rules (server-enforced, see `transitionRequirements`): accepted_risk needs `reason`
 * (min 10 chars) and `acceptedRiskReviewAt` (future, ≤ ACCEPTED_RISK_MAX_DAYS); manual `resolved`
 * and moving back to `open` need `reason`; other changes accept an optional `reason`.
 */
export const findingUpdateRequestSchema = z
  .object({
    expectedStatus: findingStatusSchema,
    status: findingStatusSchema.optional(),
    reason: reasonText.optional(),
    acceptedRiskReviewAt: isoDateTime.optional(),
    /** null unassigns. Requires `findings:assign`. */
    assigneeId: z.uuid().nullable().optional(),
  })
  .strict()
  .refine((b) => b.status !== undefined || b.assigneeId !== undefined, {
    message: 'Provide a status or an assignee.',
  });
export type FindingUpdateRequest = z.infer<typeof findingUpdateRequestSchema>;

export const findingUpdateResponseSchema = z.object({ finding: findingSchema });

export const FINDING_BULK_MAX = 500;

/** The same change applied to many findings; each finding is checked individually. */
export const findingBulkUpdateRequestSchema = z
  .object({
    ids: z.array(z.uuid()).min(1).max(FINDING_BULK_MAX),
    status: findingStatusSchema.optional(),
    reason: reasonText.optional(),
    acceptedRiskReviewAt: isoDateTime.optional(),
    assigneeId: z.uuid().nullable().optional(),
  })
  .strict()
  .refine((b) => b.status !== undefined || b.assigneeId !== undefined, {
    message: 'Provide a status or an assignee.',
  });
export type FindingBulkUpdateRequest = z.infer<typeof findingBulkUpdateRequestSchema>;

export const findingBulkUpdateResponseSchema = z.object({
  updated: z.int(),
  /** Findings left unchanged, with why (`not_found`, `transition_not_allowed`, `no_change`, …). */
  skipped: z.array(z.object({ id: z.uuid(), code: z.string() })),
});
export type FindingBulkUpdateResponse = z.infer<typeof findingBulkUpdateResponseSchema>;

export const findingCommentRequestSchema = z
  .object({ body: z.string().trim().min(1).max(FINDING_COMMENT_MAX) })
  .strict();
export const findingCommentResponseSchema = z.object({ comment: findingCommentSchema });

/** Re-check: queue a scan of the finding's domain with the profile that runs its rule's checks. */
export const findingReassessResponseSchema = z.object({
  scanJobId: z.uuid(),
  profile: z.string(),
  /** False when an identical queued/running job already existed (it is returned instead). */
  created: z.boolean(),
});
export type FindingReassessResponse = z.infer<typeof findingReassessResponseSchema>;

export const assignableUserSchema = findingUserRefSchema.extend({
  role: z.enum(['admin', 'analyst', 'asset_owner', 'viewer']),
});
export const assignableUsersResponseSchema = z.object({ items: z.array(assignableUserSchema) });
export type AssignableUsersResponse = z.infer<typeof assignableUsersResponseSchema>;
