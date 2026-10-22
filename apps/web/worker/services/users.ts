import { schema, type Database } from '@exdomainvault/database';
import type { CurrentUser } from '@exdomainvault/shared';
import { and, eq, isNull } from 'drizzle-orm';
import type { Identity } from '../auth/types.ts';
import { writeAudit } from './audit.ts';

const { users } = schema;

export type ResolveUserResult =
  | { ok: true; user: CurrentUser; created: boolean }
  | { ok: false; reason: 'not_provisioned' | 'inactive' | 'identity_conflict' };

const LAST_LOGIN_REFRESH_MS = 15 * 60 * 1000;

type UserRow = typeof users.$inferSelect;

const toCurrentUser = (u: UserRow): CurrentUser => ({
  id: u.id,
  email: u.email,
  displayName: u.displayName,
  role: u.role,
});

/**
 * Maps an authenticated identity to an application user:
 *  1. existing user with the same provider + subject;
 *  2. a pre-provisioned user with the same email that has never signed in (binds the subject);
 *  3. an email listed in BOOTSTRAP_ADMIN_EMAILS (created as administrator, audited);
 *  otherwise access is denied. Authentication alone never grants access.
 */
export async function resolveUser(
  db: Database,
  identity: Identity,
  opts: { bootstrapAdminEmails: ReadonlySet<string>; requestId: string; now?: Date },
): Promise<ResolveUserResult> {
  const now = opts.now ?? new Date();

  let [user] = await db
    .select()
    .from(users)
    .where(
      and(
        eq(users.authProvider, identity.provider),
        eq(users.authProviderSubject, identity.subject),
      ),
    )
    .limit(1);
  let created = false;

  if (!user) {
    const [byEmail] = await db.select().from(users).where(eq(users.email, identity.email)).limit(1);
    if (byEmail) {
      if (byEmail.authProviderSubject !== null) {
        // Same email already bound to a different identity: never silently re-bind.
        return { ok: false, reason: 'identity_conflict' };
      }
      [user] = await db
        .update(users)
        .set({
          authProvider: identity.provider,
          authProviderSubject: identity.subject,
          displayName: byEmail.displayName ?? identity.name,
        })
        .where(and(eq(users.id, byEmail.id), isNull(users.authProviderSubject)))
        .returning();
      if (!user) return { ok: false, reason: 'identity_conflict' };
    } else if (opts.bootstrapAdminEmails.has(identity.email)) {
      user = await db.transaction(async (tx) => {
        const [inserted] = await tx
          .insert(users)
          .values({
            email: identity.email,
            displayName: identity.name,
            role: 'admin',
            authProvider: identity.provider,
            authProviderSubject: identity.subject,
          })
          .onConflictDoNothing()
          .returning();
        if (inserted) {
          await writeAudit(tx as unknown as Database, {
            actorType: 'system',
            action: 'user.bootstrap_admin',
            resourceType: 'user',
            resourceId: inserted.id,
            requestId: opts.requestId,
            metadata: { email: identity.email, provider: identity.provider },
          });
        }
        return inserted;
      });
      if (!user) return { ok: false, reason: 'identity_conflict' };
      created = true;
    } else {
      return { ok: false, reason: 'not_provisioned' };
    }
  }

  if (!user.isActive) return { ok: false, reason: 'inactive' };

  if (!user.lastLoginAt || now.getTime() - user.lastLoginAt.getTime() > LAST_LOGIN_REFRESH_MS) {
    await db.update(users).set({ lastLoginAt: now }).where(eq(users.id, user.id));
  }

  return { ok: true, user: toCurrentUser(user), created };
}
