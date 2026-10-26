import { describe, expect, it } from 'vitest';
import { classifyAssetRole, type AssetRoleEvidence } from './asset-roles.ts';

const none: AssetRoleEvidence = {
  isMxTarget: false,
  isNsTarget: false,
  openPorts: [],
  respondsToHttp: false,
  hostingKind: null,
};

describe('classifyAssetRole', () => {
  it('is unclassified without evidence', () => {
    expect(classifyAssetRole(none)).toBe('unclassified');
  });
  it.each([
    [{ isMxTarget: true }, 'mail'],
    [{ openPorts: [443, 587] }, 'mail'],
    [{ isNsTarget: true, respondsToHttp: true }, 'dns'],
    [{ openPorts: [3389, 443], respondsToHttp: true }, 'remote_access'],
    [{ openPorts: [445] }, 'file_transfer'],
    [{ openPorts: [5432] }, 'database'],
    [{ respondsToHttp: true, hostingKind: 'cdn' as const }, 'web'],
    [{ hostingKind: 'saas' as const }, 'cloud_service'],
    [{ openPorts: [443] }, 'unclassified'],
  ])('%o → %s', (evidence, role) => {
    expect(classifyAssetRole({ ...none, ...evidence })).toBe(role);
  });
});
