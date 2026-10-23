import { schema, type Database } from '@exdomainvault/database';
import type {
  User,
  UserCreateRequest,
  UserListQuery,
  UserListResponse,
  UserUpdateRequest,
} from '@exdomainvault/shared';
import { and, asc, count, eq, ilike, or, type SQL } from 'drizzle-orm';
import { firstRow } from '../lib/db.ts';
import { ApiError } from '../lib/errors.ts';
import { writeAuditMany, type AuditEntry } from './audit.ts';
import { isUniqueViolation, type Actor } from './domains.ts';

const { users } = schema;

/**
 * User administration (design §4, `users:manage`). Users are pre-provisioned by email; the identity
 * provider subject is bound on first sign-in (services/users.ts `resolveUser`). Guards, enforced
 * here in one transaction: an administrator cannot change their own role or deactivate themselves,
 * and the last active administrator can never be demoted or deactivated. The active-admin rows are
 * locked (`FOR UPDATE`) before counting, so two concurrent demotions serialise and the second one
 * sees the first one's result.
 */

type UserRow = typeof users.$inferSelect;
type AuthProviderKind = UserRow['authProvider'];

const notFound = () => new ApiError(404, 'not_found', 'The requested resource was not found.');
const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

const conflict = (path: string, message: string) =>
  new ApiError(409, 'conflict', message, [{ path, message }]);

export function toUserDto(u: UserRow): User {
  return {
    id: u.id,
    email: u.email,
    displayName: u.displayName,
    role: u.role,
    isActive: u.isActive,
    signedIn: u.authProviderSubject !== null,
    lastLoginAt: u.lastLoginAt ? u.lastLoginAt.toISOString() : null,
    createdAt: u.createdAt.toISOString(),
    updatedAt: u.updatedAt.toISOString(),
  };
}

export async function listUsers(db: Database, q: UserListQuery): Promise<UserListResponse> {
  const filters: SQL[] = [];
  if (q.q) {
    const term = `%${escapeLike(q.q.toLowerCase())}%`;
    const match = or(ilike(users.email, term), ilike(users.displayName, term));
    if (match) filters.push(match);
  }
  if (q.role) filters.push(eq(users.role, q.role));
  if (q.active) filters.push(eq(users.isActive, q.active === 'true'));
  const where = filters.length > 0 ? and(...filters) : undefined;
  const [rows, [total]] = await Promise.all([
    db
      .select()
      .from(users)
      .where(where)
      .orderBy(asc(users.email))
      .limit(q.pageSize)
      .offset((q.page - 1) * q.pageSize),
    db.select({ n: count() }).from(users).where(where),
  ]);
  return { items: rows.map(toUserDto), page: q.page, pageSize: q.pageSize, total: total?.n ?? 0 };
}

export async function getUser(db: Database, id: string): Promise<User> {
  const [row] = await db.select().from(users).where(eq(users.id, id)).limit(1);
  if (!row) throw notFound();
  return toUserDto(row);
}

/**
 * Pre-provisions a user. `authProvider` is the provider currently configured; the subject stays
 * null until their first sign-in binds it (resolveUser also rewrites the provider then).
 */
export async function createUser(
  db: Database,
  input: UserCreateRequest,
  provider: AuthProviderKind,
  actor: Actor,
): Promise<User> {
  const email = input.email.toLowerCase();
  try {
    return await db.transaction(async (raw) => {
      const tx = raw as unknown as Database;
      const row = firstRow(
        await tx
          .insert(users)
          .values({
            email,
            displayName: input.displayName ?? null,
            role: input.role,
            authProvider: provider,
          })
          .returning(),
      );
      await writeAuditMany(tx, [
        {
          actorType: 'user',
          actorUserId: actor.userId,
          action: 'user.created',
          resourceType: 'user',
          resourceId: row.id,
          requestId: actor.requestId,
          metadata: { email, role: row.role, displayName: row.displayName },
        },
      ]);
      return toUserDto(row);
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw conflict('email', 'A user with this email already exists.');
    throw err;
  }
}

/**
 * Changes a user's role, active flag and/or display name. Unchanged fields are ignored; a request
 * that changes nothing returns the user without an audit entry.
 */
export async function updateUser(
  db: Database,
  id: string,
  patch: UserUpdateRequest,
  actor: Actor,
  now: Date,
): Promise<User> {
  return db.transaction(async (raw) => {
    const tx = raw as unknown as Database;

    // Lock order: every active admin first (ordered), then the target, so concurrent changes
    // cannot deadlock and the admin count below is stable until commit.
    const mayRemoveAdmin = patch.role !== undefined || patch.isActive === false;
    const activeAdmins = mayRemoveAdmin
      ? await tx
          .select({ id: users.id })
          .from(users)
          .where(and(eq(users.role, 'admin'), eq(users.isActive, true)))
          .orderBy(asc(users.id))
          .for('update')
      : [];

    const [current] = await tx.select().from(users).where(eq(users.id, id)).for('update');
    if (!current) throw notFound();

    const roleChange = patch.role !== undefined && patch.role !== current.role;
    const activeChange = patch.isActive !== undefined && patch.isActive !== current.isActive;
    const nameChange = patch.displayName !== undefined && patch.displayName !== current.displayName;

    if (id === actor.userId) {
      if (roleChange) throw conflict('role', 'You cannot change your own role.');
      if (activeChange && patch.isActive === false)
        throw conflict('isActive', 'You cannot deactivate your own account.');
    }

    const isActiveAdmin = current.role === 'admin' && current.isActive;
    const demoted = roleChange && patch.role !== 'admin';
    const deactivated = activeChange && patch.isActive === false;
    if (isActiveAdmin && (demoted || deactivated) && activeAdmins.length <= 1) {
      throw demoted
        ? conflict('role', 'The last active administrator cannot be demoted.')
        : conflict('isActive', 'The last active administrator cannot be deactivated.');
    }

    if (!roleChange && !activeChange && !nameChange) return toUserDto(current);

    const updated = firstRow(
      await tx
        .update(users)
        .set({
          ...(roleChange ? { role: patch.role } : {}),
          ...(activeChange ? { isActive: patch.isActive } : {}),
          ...(nameChange ? { displayName: patch.displayName } : {}),
          updatedAt: now,
        })
        .where(eq(users.id, id))
        .returning(),
    );

    const base = {
      actorType: 'user' as const,
      actorUserId: actor.userId,
      resourceType: 'user',
      resourceId: id,
      requestId: actor.requestId,
    };
    const audit: AuditEntry[] = [];
    if (roleChange) {
      audit.push({
        ...base,
        action: 'user.role_changed',
        metadata: { email: current.email, from: current.role, to: updated.role },
      });
    }
    if (activeChange) {
      audit.push({
        ...base,
        action: updated.isActive ? 'user.activated' : 'user.deactivated',
        metadata: { email: current.email },
      });
    }
    if (nameChange) {
      audit.push({
        ...base,
        action: 'user.updated',
        metadata: {
          email: current.email,
          displayName: { from: current.displayName, to: updated.displayName },
        },
      });
    }
    await writeAuditMany(tx, audit);
    return toUserDto(updated);
  });
}
