import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  cidr,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { createdAt, id, ts, updatedAt } from './common.ts';
import { confidence, severity, workerStatus } from './enums.ts';
import { users } from './users.ts';

/** Registered scanning workers. Credentials live in `worker_credentials`. */
export const workerRegistry = pgTable(
  'worker_registry',
  {
    id: id(),
    name: text('name').notNull(),
    status: workerStatus('status').notNull().default('active'),
    version: text('version'),
    lastSeenAt: ts('last_seen_at'),
    lastHealth: jsonb('last_health').$type<Record<string, unknown>>(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [uniqueIndex('worker_registry_name_key').on(t.name)],
);

/**
 * Worker credentials: Ed25519 **public** keys only. The private key never leaves the worker, so the
 * database holds nothing that could be used to impersonate it. Several keys may be valid at once
 * (rotation); each expires and can be revoked.
 */
export const workerCredentials = pgTable(
  'worker_credentials',
  {
    id: id(),
    workerId: uuid('worker_id')
      .notNull()
      .references(() => workerRegistry.id, { onDelete: 'cascade' }),
    /** Base64 of the raw 32-byte Ed25519 public key. */
    publicKey: text('public_key').notNull(),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    expiresAt: ts('expires_at').notNull(),
    revokedAt: ts('revoked_at'),
    lastUsedAt: ts('last_used_at'),
  },
  (t) => [
    index('worker_credentials_worker_idx').on(t.workerId),
    uniqueIndex('worker_credentials_public_key_key').on(t.publicKey),
    check('worker_credentials_expiry_after_creation', sql`${t.expiresAt} > ${t.createdAt}`),
  ],
);

/**
 * Nonces of accepted worker requests, for replay protection within the signature time window.
 * Also used to count requests per credential for rate limiting. Pruned after the window.
 */
export const workerRequestNonces = pgTable(
  'worker_request_nonces',
  {
    credentialId: uuid('credential_id')
      .notNull()
      .references(() => workerCredentials.id, { onDelete: 'cascade' }),
    nonce: text('nonce').notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    primaryKey({ columns: [t.credentialId, t.nonce] }),
    index('worker_request_nonces_rate_idx').on(t.credentialId, t.createdAt),
    index('worker_request_nonces_created_idx').on(t.createdAt),
  ],
);

/** Server-defined scan profiles. The UI selects a profile; it never supplies scanner flags. */
export const scanProfiles = pgTable('scan_profiles', {
  key: text('key').primaryKey(),
  name: text('name').notNull(),
  description: text('description').notNull(),
  version: integer('version').notNull().default(1),
  /** Ports, timeouts, concurrency and rate limits; validated by the application. */
  config: jsonb('config').$type<Record<string, unknown>>().notNull(),
  defaultSchedule: text('default_schedule'),
  enabled: boolean('enabled').notNull().default(true),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

/** Rule registry mirror: lets operators enable/disable rules. Logic lives in packages/rules. */
export const securityRules = pgTable('security_rules', {
  ruleId: text('rule_id').primaryKey(),
  version: integer('version').notNull(),
  category: text('category').notNull(),
  title: text('title').notNull(),
  defaultSeverity: severity('default_severity').notNull(),
  defaultConfidence: confidence('default_confidence').notNull(),
  enabled: boolean('enabled').notNull().default(true),
  config: jsonb('config').$type<Record<string, unknown>>().notNull().default({}),
  updatedAt: updatedAt(),
});

/** Non-secret operational settings. Secrets never go here. */
export const applicationSettings = pgTable('application_settings', {
  key: text('key').primaryKey(),
  value: jsonb('value').notNull(),
  updatedBy: uuid('updated_by').references(() => users.id, { onDelete: 'set null' }),
  updatedAt: updatedAt(),
});

/**
 * Admin-approved networks: the only destinations network-tier checks (port probes, service
 * identification, TLS configuration enumeration) may contact. Each approval has a reason and a
 * review date (`expires_at`), is audited, and can be revoked. An approval is active while
 * `revoked_at` is null and `expires_at` is in the future (expiry is evaluated lazily).
 */
export const approvedNetworks = pgTable(
  'approved_networks',
  {
    id: id(),
    /** Canonical network (host bits zero), validated as public unicast by the application. */
    cidr: cidr('cidr').notNull(),
    label: text('label').notNull(),
    reason: text('reason').notNull(),
    reference: text('reference'),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    expiresAt: ts('expires_at').notNull(),
    revokedAt: ts('revoked_at'),
    revokeReason: text('revoke_reason'),
    revokedBy: uuid('revoked_by').references(() => users.id, { onDelete: 'set null' }),
  },
  (t) => [
    uniqueIndex('approved_networks_cidr_active_key')
      .on(t.cidr)
      .where(sql`${t.revokedAt} is null`),
    check('approved_networks_reason_not_empty', sql`length(btrim(${t.reason})) > 0`),
    check('approved_networks_expiry_after_creation', sql`${t.expiresAt} > ${t.createdAt}`),
    check(
      'approved_networks_revoke_reason',
      sql`${t.revokedAt} is null or ${t.revokeReason} is not null`,
    ),
  ],
);
