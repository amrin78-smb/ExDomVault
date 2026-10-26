// Test-only: the authorisation route matrix shared by *.matrix.test.ts / *.hardening.test.ts.
import type { Role } from '@exdomainvault/shared';
import { expect } from 'vitest';
import { createApp } from '../app.ts';

// ------------------------------------------------------------------------------------------------
// The expectation table

export type Access =
  { kind: 'public' } | { kind: 'worker' } | { kind: 'user'; allow: readonly Role[]; note?: string };

const ALL: readonly Role[] = ['admin', 'analyst', 'asset_owner', 'viewer'];
const READERS: readonly Role[] = ['admin', 'analyst', 'viewer'];
const ANALYSTS: readonly Role[] = ['admin', 'analyst'];
const ADMIN: readonly Role[] = ['admin'];

const user = (allow: readonly Role[], note?: string): Access => ({ kind: 'user', allow, note });

/** Keyed by `METHOD /path` relative to /api/v1. Must cover every registered route. */
export const ROUTE_ACCESS: Record<string, Access> = {
  'GET /health': { kind: 'public' },

  'POST /internal/worker/claim': { kind: 'worker' },
  'POST /internal/worker/heartbeat': { kind: 'worker' },
  'POST /internal/worker/results': { kind: 'worker' },
  'POST /internal/worker/failures': { kind: 'worker' },

  'GET /me': user(ALL),

  'GET /domains': user(READERS),
  'POST /domains': user(ADMIN),
  'POST /domains/import/preview': user(ADMIN),
  'POST /domains/import': user(ADMIN),
  'POST /domains/authorise': user(ADMIN),
  'POST /domains/monitoring': user(ADMIN),
  'GET /domains/:id': user(READERS),
  'GET /domains/:id/observations': user(READERS),
  'PATCH /domains/:id': user(ADMIN),
  'POST /domains/:id/verification': user(ADMIN),
  'POST /domains/:id/authorise': user(ADMIN),
  'POST /domains/:id/revoke': user(ADMIN),
  'POST /domains/:id/scans': user(ANALYSTS),
  'POST /domains/:id/discovery': user(ANALYSTS),
  'POST /domains/:id/assets/import': user(ADMIN),
  'GET /domains/:id/assets': user(ALL, 'asset owners see only their assets (object level)'),
  'GET /domains/:id/software': user(ALL, 'asset owners see only their assets (object level)'),
  'POST /domains/:id/verify': user(ADMIN),

  'GET /assets': user(ALL, 'object-level filtering for asset owners'),
  'POST /assets/bulk': user(ADMIN),
  'GET /assets/:id': user(ALL, 'object-level filtering for asset owners'),
  'PATCH /assets/:id': user(ADMIN),
  'POST /assets/:id/approve': user(ADMIN),
  'POST /assets/:id/reject': user(ADMIN),
  'POST /assets/:id/suspend': user(ADMIN),

  'GET /scan-profiles': user(READERS),
  'GET /scans': user(READERS),
  'GET /scans/:id': user(READERS),
  'POST /scans/:id/cancel': user(ANALYSTS),

  'GET /workers': user(ADMIN),
  'POST /workers': user(ADMIN),
  'PATCH /workers/:id': user(ADMIN),
  'POST /workers/:id/credentials': user(ADMIN),
  'POST /workers/:id/credentials/:credentialId/revoke': user(ADMIN),

  'GET /approved-networks': user(ADMIN),
  'POST /approved-networks': user(ADMIN),
  'POST /approved-networks/:id/revoke': user(ADMIN),

  'GET /findings': user(ALL, 'object-level filtering for asset owners'),
  'GET /findings/summary': user(ALL),
  // Route gate is findings:read; the per-action permission (triage/assign/remediate/accept risk)
  // and asset-owner visibility are enforced in the service (finding-lifecycle.test.ts).
  'POST /findings/bulk': user(ALL, 'per-action permission checked in the service'),
  'GET /findings/:id': user(ALL),
  'PATCH /findings/:id': user(ALL, 'per-action permission checked in the service'),
  'POST /findings/:id/comments': user(ALL, 'visibility checked in the service'),
  'POST /findings/:id/reassess': user(ANALYSTS),

  'GET /advisories': user(ALL),
  'GET /rules': user(ALL),

  'GET /users/assignable': user(ANALYSTS),
  'GET /users': user(ADMIN),
  'POST /users': user(ADMIN),
  'GET /users/:id': user(ADMIN),
  'PATCH /users/:id': user(ADMIN),

  'GET /settings/scan-schedule': user(READERS),
  'PUT /settings/scan-schedule': user(ADMIN),

  'GET /audit-logs': user(ADMIN),

  'GET /reports/summary': user(ALL),
  'GET /reports/findings.csv': user(ANALYSTS),

  // CSV exports: the list's permission and visibility (exports.test.ts).
  'GET /exports/domains.csv': user(READERS),
  'GET /exports/assets.csv': user(ALL, 'object-level filtering for asset owners'),
  'GET /exports/advisories.csv': user(ALL, 'object-level filtering for asset owners'),
  'GET /exports/software.csv': user(ALL, 'object-level filtering for asset owners'),
  'GET /exports/scans.csv': user(READERS),
  'GET /exports/users.csv': user(ADMIN),
  'GET /exports/audit-logs.csv': user(ADMIN),

  'GET /software': user(ALL),
  'GET /software/summary': user(ALL),
  'GET /intel/feeds': user(ALL),
  'POST /intel/feeds/sync': user(ADMIN),

  'GET /ops/health': user(ADMIN),
  'GET /ops/alerts': user(ALL, 'content differs for admins (operational alerts)'),
};

// ------------------------------------------------------------------------------------------------
// Route enumeration

export interface RouteRef {
  method: string;
  /** Path relative to /api/v1, with Hono parameters (`/domains/:id`). */
  path: string;
  key: string;
}

/** Every concrete (non-middleware) route of the app, deduplicated. */
export function enumerateRoutes(): RouteRef[] {
  const seen = new Map<string, RouteRef>();
  for (const r of createApp().routes) {
    if (r.method === 'ALL') continue; // middleware (`use`)
    if (!r.path.startsWith('/api/v1/')) throw new Error(`route outside /api/v1: ${r.path}`);
    const path = r.path.slice('/api/v1'.length);
    const key = `${r.method} ${path}`;
    if (!seen.has(key)) seen.set(key, { method: r.method, path, key });
  }
  return [...seen.values()];
}

/** Substitutes route parameters with random (well-formed, non-existent) UUIDs. */
export const concrete = (path: string) => path.replace(/:[A-Za-z]+/g, () => crypto.randomUUID());

/** Patterns that must never appear in a client-facing error body. */
export const LEAK_PATTERNS: readonly RegExp[] = [
  /\bat .+\(.*:\d+:\d+\)/, // stack frame
  /\n\s+at /,
  /\bError:/,
  /postgres(ql)?:\/\//i,
  /\bpostgres\b/i,
  /\bneon\b/i,
  /\bpglite\b/i,
  /\bdrizzle\b/i,
  /\/home\/|\/usr\/|\/opt\/|node_modules|[A-Za-z]:\\\\/,
  /\.ts:\d+/,
  /hyperdrive/i,
  /SELECT .* FROM/i,
  /duplicate key|violates|constraint/i,
];

export function expectNoLeak(text: string, context: string) {
  for (const re of LEAK_PATTERNS) {
    expect(re.test(text), `${context}: error body matches ${re}: ${text.slice(0, 300)}`).toBe(
      false,
    );
  }
}
