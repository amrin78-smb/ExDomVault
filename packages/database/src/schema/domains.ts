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
  ],
);

/**
 * Domain-control challenges. Only a hash of the challenge token is stored; challenges expire.
 */
export const domainVerifications = pgTable(
  'domain_verifications',
  {
    id: id(),
    domainId: uuid('domain_id')
      .notNull()
      .references(() => domains.id, { onDelete: 'cascade' }),
    method: verificationMethod('method').notNull(),
    challengeHash: text('challenge_hash').notNull(),
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
  ],
);
