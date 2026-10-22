import { z } from 'zod';
import type { Role } from './roles.ts';

/**
 * Fine-grained permissions (design §4). The API enforces these on every request; the UI only uses
 * them to hide actions a user cannot perform.
 */
export const PERMISSIONS = [
  'users:manage',
  'audit:read',
  'settings:manage',
  'domains:read',
  'domains:write',
  'domains:verify',
  'assets:read',
  'assets:approve',
  'scans:read',
  'scans:request',
  'scan_policies:manage',
  'findings:read',
  'findings:triage',
  'findings:assign',
  'findings:accept_risk',
  'findings:remediate',
  'reports:read',
  'reports:generate',
] as const;

export const permissionSchema = z.enum(PERMISSIONS);
export type Permission = z.infer<typeof permissionSchema>;

const VIEWER: readonly Permission[] = [
  'domains:read',
  'assets:read',
  'scans:read',
  'findings:read',
  'reports:read',
];

/**
 * Role → permission matrix. Asset owners' reads and remediation updates are further restricted to
 * their assigned assets by the endpoints that serve them (object-level checks).
 */
export const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  admin: PERMISSIONS,
  analyst: [
    ...VIEWER,
    'scans:request',
    'findings:triage',
    'findings:assign',
    'findings:accept_risk',
    'findings:remediate',
    'reports:generate',
  ],
  asset_owner: ['assets:read', 'findings:read', 'findings:remediate', 'reports:read'],
  viewer: VIEWER,
};

export function hasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}
