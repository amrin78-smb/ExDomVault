import { z } from 'zod';
import { permissionSchema } from '../domain/permissions.ts';
import { roleSchema } from '../domain/roles.ts';

export const currentUserSchema = z.object({
  id: z.uuid(),
  email: z.email(),
  displayName: z.string().nullable(),
  role: roleSchema,
});
export type CurrentUser = z.infer<typeof currentUserSchema>;

export const meResponseSchema = z.object({
  user: currentUserSchema,
  permissions: z.array(permissionSchema),
  authProvider: z.enum(['cloudflare_access', 'dev']),
  /** Milestone 13: organisation label from the `ORG_NAME` Worker var; null when unset. */
  organisation: z.string().nullable().optional(),
});
export type MeResponse = z.infer<typeof meResponseSchema>;
