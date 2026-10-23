// Test-only synthetic users, audit entries and scan profiles (reserved example.* names, RFC 2606).
import type { AuditEntry, ScanProfile, User } from '@exdomainvault/shared';

export const SELF_ID = '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
export const OTHER_ID = '2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e';
export const OWNER_ID = '3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e7f';

export const user = (overrides: Partial<User> = {}): User => ({
  id: OTHER_ID,
  email: 'analyst@example.com',
  displayName: 'Ana Lyst',
  role: 'analyst',
  isActive: true,
  signedIn: true,
  lastLoginAt: '2026-10-22T08:00:00.000Z',
  createdAt: '2026-10-01T08:00:00.000Z',
  updatedAt: '2026-10-22T08:00:00.000Z',
  ...overrides,
});

export const SELF = user({
  id: SELF_ID,
  email: 'admin@example.com',
  displayName: 'Ada Min',
  role: 'admin',
});

export const usersPage = (items: User[], total = items.length, page = 1) => ({
  items,
  page,
  pageSize: 25,
  total,
});

export const auditEntry = (overrides: Partial<AuditEntry> = {}): AuditEntry => ({
  id: '4d5e6f7a-8b9c-4d0e-9f1a-2b3c4d5e6f7a',
  actorType: 'user',
  actor: { id: SELF_ID, email: 'admin@example.com' },
  action: 'finding.status_changed',
  resourceType: 'finding',
  resourceId: '5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b',
  requestId: 'req-audit-1',
  metadata: { from: 'open', to: 'acknowledged' },
  createdAt: '2026-10-22T09:15:00.000Z',
  ...overrides,
});

export const auditPage = (items: AuditEntry[], total = items.length, page = 1) => ({
  items,
  page,
  pageSize: 50,
  total,
});

export const profile = (overrides: Partial<ScanProfile> = {}): ScanProfile => ({
  key: 'passive',
  name: 'Passive',
  description: 'DNS records and registration (RDAP) data from public resolvers.',
  version: 1,
  defaultSchedule: 'daily',
  enabled: true,
  config: {
    active: false,
    checks: ['dns', 'rdap'],
    tcpPorts: [],
    timeouts: { connectMs: 5000, readMs: 10000, targetSeconds: 60 },
    concurrency: 2,
    ratePerSecond: 1,
    maxTargets: 1,
  },
  ...overrides,
});
