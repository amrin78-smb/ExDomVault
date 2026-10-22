import { z } from 'zod';

/** Application roles from design §4. Authorisation is always enforced server-side. */
export const ROLES = ['admin', 'analyst', 'asset_owner', 'viewer'] as const;
export const roleSchema = z.enum(ROLES);
export type Role = z.infer<typeof roleSchema>;

export const ROLE_LABELS: Record<Role, string> = {
  admin: 'Administrator',
  analyst: 'Security analyst',
  asset_owner: 'Asset owner',
  viewer: 'Viewer',
};
