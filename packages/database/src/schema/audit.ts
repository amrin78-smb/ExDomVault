import { index, jsonb, pgTable, text, uuid } from 'drizzle-orm/pg-core';
import { createdAt, id } from './common.ts';
import { actorType } from './enums.ts';
import { users } from './users.ts';

/** Append-only audit trail of privileged actions. */
export const auditLogs = pgTable(
  'audit_logs',
  {
    id: id(),
    actorType: actorType('actor_type').notNull(),
    actorUserId: uuid('actor_user_id').references(() => users.id, { onDelete: 'set null' }),
    action: text('action').notNull(),
    resourceType: text('resource_type').notNull(),
    resourceId: text('resource_id'),
    requestId: text('request_id'),
    createdAt: createdAt(),
    metadata: jsonb('metadata').$type<Record<string, unknown>>().notNull().default({}),
  },
  (t) => [
    index('audit_logs_resource_idx').on(t.resourceType, t.resourceId),
    index('audit_logs_created_idx').on(t.createdAt),
    index('audit_logs_actor_idx').on(t.actorUserId),
  ],
);
