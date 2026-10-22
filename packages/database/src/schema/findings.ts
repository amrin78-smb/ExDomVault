import { sql } from 'drizzle-orm';
import {
  check,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { assets } from './assets.ts';
import { createdAt, id, ts, updatedAt } from './common.ts';
import { domains } from './domains.ts';
import { confidence, findingStatus, severity } from './enums.ts';
import { scanJobs } from './scans.ts';
import { users } from './users.ts';

/**
 * Evidence-backed findings produced by deterministic rules. `fingerprint` identifies the logical
 * issue (rule + domain + hostname + affected component); at most one non-resolved finding per
 * fingerprint. A resolved finding that recurs is reopened (same row) rather than duplicated.
 * `asset_id` is null for domain-level findings (e.g. DMARC) and hostnames that are not assets.
 */
export const findings = pgTable(
  'findings',
  {
    id: id(),
    domainId: uuid('domain_id')
      .notNull()
      .references(() => domains.id, { onDelete: 'cascade' }),
    // Set null (not cascade) so deleting an asset keeps the finding's history; findings also carry
    // domain_id, which cascades with the domain.
    assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'set null' }),
    /** Affected hostname (the domain itself for domain-level findings). */
    hostname: text('hostname').notNull(),
    /** Stable affected-component key within the hostname (part of the fingerprint). */
    component: text('component').notNull(),
    /** Rule category at detection time (dns, email, tls, http, exposure, registration, asset). */
    category: text('category').notNull(),
    ruleId: text('rule_id').notNull(),
    ruleVersion: integer('rule_version').notNull(),
    fingerprint: text('fingerprint').notNull(),
    title: text('title').notNull(),
    description: text('description').notNull(),
    severity: severity('severity').notNull(),
    confidence: confidence('confidence').notNull(),
    /** 0-100, computed from `risk_inputs`; kept separate from severity. */
    riskScore: integer('risk_score').notNull(),
    riskInputs: jsonb('risk_inputs').$type<Record<string, unknown>>().notNull(),
    status: findingStatus('status').notNull().default('open'),
    evidence: jsonb('evidence').$type<Record<string, unknown>>().notNull(),
    firstSeenAt: ts('first_seen_at').notNull(),
    lastSeenAt: ts('last_seen_at').notNull(),
    resolvedAt: ts('resolved_at'),
    recurrenceCount: integer('recurrence_count').notNull().default(0),
    assignedTo: uuid('assigned_to').references(() => users.id, { onDelete: 'set null' }),
    acceptedRiskReason: text('accepted_risk_reason'),
    acceptedRiskApprovedBy: uuid('accepted_risk_approved_by').references(() => users.id, {
      onDelete: 'set null',
    }),
    acceptedRiskReviewAt: ts('accepted_risk_review_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('findings_active_fingerprint_key')
      .on(t.fingerprint)
      .where(sql`${t.status} <> 'resolved'`),
    index('findings_status_severity_idx').on(t.status, t.severity),
    index('findings_asset_idx').on(t.assetId),
    index('findings_domain_status_idx').on(t.domainId, t.status),
    // Recurrence lookup (latest resolved finding with a fingerprint).
    index('findings_fingerprint_idx').on(t.fingerprint),
    index('findings_assignee_idx').on(t.assignedTo),
    // Accepted-risk expiry sweep (cron).
    index('findings_accepted_risk_review_idx')
      .on(t.acceptedRiskReviewAt)
      .where(sql`${t.status} = 'accepted_risk'`),
    check(
      'findings_category_valid',
      sql`${t.category} IN ('dns', 'email', 'tls', 'http', 'exposure', 'registration', 'asset')`,
    ),
    check('findings_risk_score_range', sql`${t.riskScore} BETWEEN 0 AND 100`),
    check('findings_seen_order', sql`${t.lastSeenAt} >= ${t.firstSeenAt}`),
    check(
      'findings_resolved_at_consistent',
      sql`(${t.status} = 'resolved') = (${t.resolvedAt} IS NOT NULL)`,
    ),
    check(
      'findings_accepted_risk_complete',
      sql`${t.status} <> 'accepted_risk' OR (${t.acceptedRiskReason} IS NOT NULL AND ${t.acceptedRiskApprovedBy} IS NOT NULL AND ${t.acceptedRiskReviewAt} IS NOT NULL)`,
    ),
  ],
);

/** Append-only status history for findings. `changed_by` is null for system transitions. */
export const findingStatusHistory = pgTable(
  'finding_status_history',
  {
    id: id(),
    findingId: uuid('finding_id')
      .notNull()
      .references(() => findings.id, { onDelete: 'cascade' }),
    fromStatus: findingStatus('from_status'),
    toStatus: findingStatus('to_status').notNull(),
    changedBy: uuid('changed_by').references(() => users.id, { onDelete: 'set null' }),
    reason: text('reason').notNull(),
    note: text('note'),
    scanJobId: uuid('scan_job_id').references(() => scanJobs.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
  },
  (t) => [index('finding_status_history_finding_idx').on(t.findingId, t.createdAt)],
);

/** Remediation notes and discussion on a finding (append-only; asset owners add notes here). */
export const findingComments = pgTable(
  'finding_comments',
  {
    id: id(),
    findingId: uuid('finding_id')
      .notNull()
      .references(() => findings.id, { onDelete: 'cascade' }),
    authorUserId: uuid('author_user_id').references(() => users.id, { onDelete: 'set null' }),
    body: text('body').notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    index('finding_comments_finding_idx').on(t.findingId, t.createdAt),
    check('finding_comments_body_length', sql`char_length(${t.body}) BETWEEN 1 AND 4000`),
  ],
);

/** Remediation advisories derived from a finding and its evidence. */
export const advisories = pgTable(
  'advisories',
  {
    id: id(),
    findingId: uuid('finding_id')
      .notNull()
      .references(() => findings.id, { onDelete: 'cascade' }),
    title: text('title').notNull(),
    summary: text('summary').notNull(),
    businessImpact: text('business_impact').notNull(),
    recommendedActions: jsonb('recommended_actions').$type<string[]>().notNull(),
    /** Reference URLs ("references" is reserved in SQL). */
    referenceLinks: jsonb('reference_links').$type<string[]>().notNull().default([]),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [uniqueIndex('advisories_finding_key').on(t.findingId)],
);
