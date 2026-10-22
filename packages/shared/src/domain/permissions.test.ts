import { describe, expect, it } from 'vitest';
import { PERMISSIONS, ROLE_PERMISSIONS, hasPermission } from './permissions.ts';
import { ROLES } from './roles.ts';

describe('role permission matrix', () => {
  it('grants administrators every permission', () => {
    for (const p of PERMISSIONS) expect(hasPermission('admin', p)).toBe(true);
  });

  it.each(['analyst', 'asset_owner', 'viewer'] as const)(
    '%s cannot manage users, settings, scan policies, approve assets or verify domains',
    (role) => {
      for (const p of [
        'users:manage',
        'settings:manage',
        'scan_policies:manage',
        'assets:approve',
        'domains:verify',
        'domains:write',
        'audit:read',
      ] as const) {
        expect(hasPermission(role, p)).toBe(false);
      }
    },
  );

  it('lets analysts request scans and triage findings', () => {
    expect(hasPermission('analyst', 'scans:request')).toBe(true);
    expect(hasPermission('analyst', 'findings:triage')).toBe(true);
  });

  it('keeps viewers read-only', () => {
    expect(ROLE_PERMISSIONS.viewer.every((p) => p.endsWith(':read'))).toBe(true);
    expect(hasPermission('viewer', 'scans:request')).toBe(false);
  });

  it('lets asset owners update remediation but not request scans', () => {
    expect(hasPermission('asset_owner', 'findings:remediate')).toBe(true);
    expect(hasPermission('asset_owner', 'scans:request')).toBe(false);
    expect(hasPermission('asset_owner', 'findings:triage')).toBe(false);
  });

  it('defines permissions for every role', () => {
    expect(Object.keys(ROLE_PERMISSIONS).sort()).toEqual([...ROLES].sort());
  });
});
