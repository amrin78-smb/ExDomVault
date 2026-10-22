import { sql } from 'drizzle-orm';
import { boolean, check, pgTable, text, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import { createdAt, id, ts, updatedAt } from './common.ts';
import { authProvider, userRole } from './enums.ts';

/** Application users. No passwords: identity comes from the configured identity provider. */
export const users = pgTable(
  'users',
  {
    id: id(),
    email: text('email').notNull(),
    displayName: text('display_name'),
    role: userRole('role').notNull().default('viewer'),
    authProvider: authProvider('auth_provider').notNull(),
    /** Stable subject from the identity provider; null until the user first signs in. */
    authProviderSubject: text('auth_provider_subject'),
    isActive: boolean('is_active').notNull().default(true),
    lastLoginAt: ts('last_login_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('users_email_key').on(t.email),
    uniqueIndex('users_provider_subject_key').on(t.authProvider, t.authProviderSubject),
    check('users_email_lowercase', sql`${t.email} = lower(${t.email})`),
  ],
);

/** Per-user notification opt-ins (delivery channels are implemented later). */
export const notificationPreferences = pgTable(
  'notification_preferences',
  {
    id: id(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    channel: text('channel').notNull(),
    eventType: text('event_type').notNull(),
    enabled: boolean('enabled').notNull().default(true),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [uniqueIndex('notification_preferences_key').on(t.userId, t.channel, t.eventType)],
);
