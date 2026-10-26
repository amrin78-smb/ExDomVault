import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  index,
  inet,
  jsonb,
  pgTable,
  text,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { createdAt, id, ts, updatedAt } from './common.ts';
import { domains } from './domains.ts';
import { assetApprovalStatus, assetType, criticality, discoverySource } from './enums.ts';
import { users } from './users.ts';

/** Hostnames beneath a registered domain. Only `approved` assets may enter scan scope. */
export const assets = pgTable(
  'assets',
  {
    id: id(),
    domainId: uuid('domain_id')
      .notNull()
      .references(() => domains.id, { onDelete: 'cascade' }),
    hostname: text('hostname').notNull(),
    assetType: assetType('asset_type').notNull(),
    verificationStatus: assetApprovalStatus('verification_status').notNull().default('pending'),
    discoverySource: discoverySource('discovery_source').notNull(),
    firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
    monitoringEnabled: boolean('monitoring_enabled').notNull().default(false),
    criticalityOverride: criticality('criticality_override'),
    ownerUserId: uuid('owner_user_id').references(() => users.id, { onDelete: 'set null' }),
    approvedBy: uuid('approved_by').references(() => users.id, { onDelete: 'set null' }),
    approvedAt: ts('approved_at'),
    /** Last inventory decision (approve, reject, suspend): who, when and why (audited too). */
    decidedBy: uuid('decided_by').references(() => users.id, { onDelete: 'set null' }),
    decidedAt: ts('decided_at'),
    decisionReason: text('decision_reason'),
    /** Hosting classification from the latest DNS (`classifyHosting`), refreshed on ingestion. */
    hostingHint: jsonb('hosting_hint').$type<Record<string, unknown>>(),
    /** True while every sighting of the hostname came from a wildcard certificate name. */
    wildcardOnly: boolean('wildcard_only').notNull().default(false),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('assets_domain_hostname_key').on(t.domainId, t.hostname),
    index('assets_hostname_idx').on(t.hostname),
    index('assets_status_idx').on(t.verificationStatus),
    index('assets_owner_idx').on(t.ownerUserId),
    check(
      'assets_hostname_normalised',
      sql`${t.hostname} = lower(${t.hostname}) AND ${t.hostname} NOT LIKE '%.' AND length(${t.hostname}) <= 253`,
    ),
    check(
      'assets_approval_consistent',
      sql`${t.verificationStatus} <> 'approved' OR (${t.approvedBy} IS NOT NULL AND ${t.approvedAt} IS NOT NULL)`,
    ),
    check(
      'assets_monitoring_requires_approval',
      sql`NOT ${t.monitoringEnabled} OR ${t.verificationStatus} = 'approved'`,
    ),
  ],
);

/** IP addresses observed for an asset over time, kept separate so identity survives IP changes. */
export const assetIps = pgTable(
  'asset_ips',
  {
    id: id(),
    assetId: uuid('asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    ipAddress: inet('ip_address').notNull(),
    firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
    isCurrent: boolean('is_current').notNull().default(true),
    source: text('source').notNull(),
    /**
     * Milestone 13: ISO 3166-1 alpha-2 country from the worker's offline IP geolocation (DB-IP
     * Lite), set from DNS observations that carry `geo`. Display-only (never scope or severity);
     * null = not geolocated yet / not covered.
     */
    countryCode: text('country_code'),
  },
  (t) => [
    uniqueIndex('asset_ips_asset_ip_key').on(t.assetId, t.ipAddress),
    index('asset_ips_ip_idx').on(t.ipAddress),
    check('asset_ips_country_code_format', sql`${t.countryCode} ~ '^[A-Z]{2}$'`),
  ],
);
