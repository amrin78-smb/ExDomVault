import { sql } from 'drizzle-orm';
import { boolean, check, index, pgTable, text, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import { createdAt, id, ts, updatedAt } from './common.ts';
import {
  challengeStatus,
  criticality,
  domainVerificationStatus,
  registrationDataStatus,
  verificationMethod,
} from './enums.ts';
import { users } from './users.ts';

/** Registered domains owned by the organisation. `fqdn` is normalised (lowercase A-label, no trailing dot). */
export const domains = pgTable(
  'domains',
  {
    id: id(),
    fqdn: text('fqdn').notNull(),
    registrar: text('registrar'),
    registeredAt: ts('registered_at'),
    expiresAt: ts('expires_at'),
    registrationDataStatus: registrationDataStatus('registration_data_status')
      .notNull()
      .default('unknown'),
    criticality: criticality('criticality').notNull().default('medium'),
    businessOwner: text('business_owner'),
    verificationStatus: domainVerificationStatus('verification_status')
      .notNull()
      .default('unverified'),
    verifiedAt: ts('verified_at'),
    /** Set while verified: how authorisation was established. */
    verificationMethod: verificationMethod('verification_method'),
    /** When an administrator attestation lapses and must be reviewed (null for DNS proof). */
    verificationExpiresAt: ts('verification_expires_at'),
    monitoringEnabled: boolean('monitoring_enabled').notNull().default(false),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('domains_fqdn_key').on(t.fqdn),
    check(
      'domains_fqdn_normalised',
      sql`${t.fqdn} = lower(${t.fqdn}) AND ${t.fqdn} NOT LIKE '%.' AND length(${t.fqdn}) <= 253`,
    ),
    check(
      'domains_verified_at_consistent',
      sql`(${t.verificationStatus} = 'verified') = (${t.verifiedAt} IS NOT NULL)`,
    ),
    check(
      'domains_verification_method_consistent',
      sql`(${t.verificationStatus} = 'verified') = (${t.verificationMethod} IS NOT NULL)`,
    ),
    check(
      'domains_attestation_has_review_date',
      // Written against 'dns_txt' so the migration that adds 'admin_attestation' can create it in the
      // same transaction (a new enum value cannot be referenced there).
      sql`COALESCE(${t.verificationMethod} <> 'dns_txt', false) = (${t.verificationExpiresAt} IS NOT NULL)`,
    ),
  ],
);

/**
 * Verification records. `dns_txt`: a challenge of which only the token hash is stored; it expires if
 * not confirmed. `admin_attestation`: an administrator's recorded authorisation (reason, reference),
 * created already `verified`; `expires_at` is its review-by date.
 */
export const domainVerifications = pgTable(
  'domain_verifications',
  {
    id: id(),
    domainId: uuid('domain_id')
      .notNull()
      .references(() => domains.id, { onDelete: 'cascade' }),
    method: verificationMethod('method').notNull(),
    challengeHash: text('challenge_hash'),
    reason: text('reason'),
    reference: text('reference'),
    status: challengeStatus('status').notNull().default('pending'),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    expiresAt: ts('expires_at').notNull(),
    lastCheckedAt: ts('last_checked_at'),
    verifiedAt: ts('verified_at'),
    failureReason: text('failure_reason'),
  },
  (t) => [
    index('domain_verifications_domain_idx').on(t.domainId, t.status),
    // At most one live challenge per domain and method.
    uniqueIndex('domain_verifications_one_pending')
      .on(t.domainId, t.method)
      .where(sql`${t.status} = 'pending'`),
    check('domain_verifications_expiry_after_creation', sql`${t.expiresAt} > ${t.createdAt}`),
    check(
      'domain_verifications_method_fields',
      sql`CASE ${t.method}
        WHEN 'dns_txt' THEN ${t.challengeHash} IS NOT NULL AND ${t.reason} IS NULL
        ELSE ${t.challengeHash} IS NULL AND ${t.reason} IS NOT NULL END`,
    ),
  ],
);
