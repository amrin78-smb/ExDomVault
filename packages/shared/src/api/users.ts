import { z } from 'zod';
import { roleSchema } from '../domain/roles.ts';
import { paginatedSchema } from './pagination.ts';

/**
 * User administration (design §4, `users:manage`). Identity comes from Cloudflare Access: adding a
 * user here pre-provisions their email and role; they must ALSO be allowed by the Access policy to
 * reach the app. Their identity-provider subject is bound on first sign-in.
 *
 * Guards (server-enforced, 409 `conflict` with `details[0].path`): an admin cannot change their own
 * role or deactivate themselves (`role` / `isActive`), and the last active admin can never be
 * demoted or deactivated (`role` / `isActive`). Duplicate email → 409 path `email`. Every change is
 * audited (`user.created`, `user.role_changed`, `user.activated`, `user.deactivated`, `user.updated`).
 */

const isoDateTime = z.iso.datetime();

export const userSchema = z.object({
  id: z.uuid(),
  email: z.string(),
  displayName: z.string().nullable(),
  role: roleSchema,
  isActive: z.boolean(),
  /** True once the user has signed in at least once (identity bound). */
  signedIn: z.boolean(),
  lastLoginAt: isoDateTime.nullable(),
  createdAt: isoDateTime,
  updatedAt: isoDateTime,
});
export type User = z.infer<typeof userSchema>;

export const userListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(50),
  q: z.string().trim().max(254).optional(),
  role: roleSchema.optional(),
  active: z.enum(['true', 'false']).optional(),
});
export type UserListQuery = z.infer<typeof userListQuerySchema>;

export const userListResponseSchema = paginatedSchema(userSchema);
export type UserListResponse = z.infer<typeof userListResponseSchema>;

const displayName = z.string().trim().min(1).max(120);

export const userCreateRequestSchema = z
  .object({
    /** Lowercased by the server. */
    email: z.email().max(254),
    displayName: displayName.optional(),
    role: roleSchema,
  })
  .strict();
export type UserCreateRequest = z.infer<typeof userCreateRequestSchema>;

export const userUpdateRequestSchema = z
  .object({
    role: roleSchema.optional(),
    isActive: z.boolean().optional(),
    displayName: displayName.nullable().optional(),
  })
  .strict()
  .refine((b) => b.role !== undefined || b.isActive !== undefined || b.displayName !== undefined, {
    message: 'Provide a role, active flag or display name.',
  });
export type UserUpdateRequest = z.infer<typeof userUpdateRequestSchema>;

export const userResponseSchema = z.object({ user: userSchema });
