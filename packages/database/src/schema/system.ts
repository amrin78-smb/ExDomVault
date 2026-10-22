import { boolean, integer, jsonb, pgTable, text, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import { createdAt, id, ts, updatedAt } from './common.ts';
import { confidence, severity, workerStatus } from './enums.ts';
import { users } from './users.ts';

/**
 * Registered scanning workers. Credentials are NOT stored here; worker authentication is
 * designed in Milestone 4 with its own table.
 */
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
