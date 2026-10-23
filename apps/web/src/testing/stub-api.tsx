// Test-only: routes fetch calls to canned API responses and renders the app at a path.
import type { Permission, Role } from '@exdomainvault/shared';
import { render } from '@testing-library/react';
import { RouterProvider, createMemoryRouter } from 'react-router';
import { vi } from 'vitest';
import { DataModeProvider } from '../lib/DataModeProvider.tsx';
import { routes } from '../routes.tsx';

export type Handler = (body: unknown) => {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
};
export interface Call {
  method: string;
  path: string;
  body: unknown;
}

export const PERMISSIONS: Record<Role, Permission[]> = {
  admin: [
    'domains:read',
    'domains:write',
    'domains:verify',
    'assets:read',
    'assets:approve',
    'scans:read',
    'scans:request',
    'scan_policies:manage',
    'settings:manage',
    'findings:read',
    'findings:triage',
    'findings:assign',
    'findings:accept_risk',
    'findings:remediate',
    'users:manage',
    'audit:read',
    'reports:read',
    'reports:generate',
  ],
  analyst: [
    'domains:read',
    'assets:read',
    'scans:read',
    'scans:request',
    'findings:read',
    'findings:triage',
    'findings:assign',
    'findings:accept_risk',
    'findings:remediate',
    'reports:read',
    'reports:generate',
  ],
  viewer: ['domains:read', 'assets:read', 'scans:read', 'findings:read', 'reports:read'],
  asset_owner: ['assets:read', 'findings:read', 'findings:remediate', 'reports:read'],
};

export const ok = (body: unknown) => () => ({ status: 200, body });

/** Stubs fetch by "METHOD path" and records every request. */
export function stubApi(role: Role, handlers: Record<string, Handler>): Call[] {
  const calls: Call[] = [];
  const all: Record<string, Handler> = {
    'GET /api/v1/health': ok({
      status: 'ok',
      service: 'exdomainvault-api',
      version: '0.1.0',
      environment: 'development',
      time: '2026-10-22T00:00:00.000Z',
      components: { database: 'ok', auth: 'ok' },
    }),
    'GET /api/v1/me': ok({
      user: { id: crypto.randomUUID(), email: `${role}@example.com`, displayName: null, role },
      permissions: PERMISSIONS[role],
      authProvider: 'cloudflare_access',
    }),
    // The shell's alert banner polls this on every page; no alerts unless a test says otherwise.
    'GET /api/v1/ops/alerts': ok({ alerts: [] }),
    ...handlers,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined;
      calls.push({ method, path, body });
      const handler = all[`${method} ${path}`];
      const r: ReturnType<Handler> = handler ? handler(body) : { status: 404, body: {} };
      return new Response(JSON.stringify(r.body), { status: r.status, headers: r.headers });
    }),
  );
  return calls;
}

export function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(
    <DataModeProvider fixtures={false}>
      <RouterProvider router={router} />
    </DataModeProvider>,
  );
  return router;
}

/** An API error envelope response. */
export const apiError =
  (status: number, code: string, message: string, details?: { path: string; message: string }[]) =>
  () => ({ status, body: { error: { code, message, requestId: 'req-test', details } } });

/** Request paths of the asset endpoints, matching the server routes. */
export const ASSET_PATHS = {
  list: (query = '') => `GET /api/v1/assets${query}`,
  detail: (id: string) => `GET /api/v1/assets/${id}`,
  decide: (id: string, action: 'approve' | 'reject' | 'suspend') =>
    `POST /api/v1/assets/${id}/${action}`,
  bulk: 'POST /api/v1/assets/bulk',
  domainAssets: (domainId: string, query = '') => `GET /api/v1/domains/${domainId}/assets${query}`,
  discovery: (domainId: string) => `POST /api/v1/domains/${domainId}/discovery`,
  setOwner: (id: string) => `PATCH /api/v1/assets/${id}`,
} as const;

/** Request paths of the user administration and audit endpoints, matching the server routes. */
export const ADMIN_PATHS = {
  users: (query = '') => `GET /api/v1/users${query}`,
  createUser: 'POST /api/v1/users',
  updateUser: (id: string) => `PATCH /api/v1/users/${id}`,
  assignable: 'GET /api/v1/users/assignable',
  audit: (query = '') => `GET /api/v1/audit-logs${query}`,
  scanProfiles: 'GET /api/v1/scan-profiles',
  scanSchedule: 'GET /api/v1/settings/scan-schedule',
  updateScanSchedule: 'PUT /api/v1/settings/scan-schedule',
} as const;

/** A `/me` handler for a fixed user id, so tests can recognise the signed-in user's own rows. */
export const meAs = (role: Role, id: string, email = `${role}@example.com`) =>
  ok({
    user: { id, email, displayName: null, role },
    permissions: PERMISSIONS[role],
    authProvider: 'cloudflare_access',
  });

/** Request paths of the software inventory and intelligence-feed endpoints (Milestone 11). */
export const SOFTWARE_PATHS = {
  list: (query = '') => `GET /api/v1/software${query}`,
  summary: 'GET /api/v1/software/summary',
  domain: (domainId: string, query = '') => `GET /api/v1/domains/${domainId}/software${query}`,
  feeds: 'GET /api/v1/intel/feeds',
  sync: 'POST /api/v1/intel/feeds/sync',
} as const;

/** Request paths of the operations endpoints (Milestone 12). */
export const OPS_PATHS = {
  health: 'GET /api/v1/ops/health',
  alerts: 'GET /api/v1/ops/alerts',
} as const;

/** Request paths of the CSV exports (findings keep their reports endpoint). */
export const EXPORT_PATHS = {
  csv: (resource: string, query = '') => `/api/v1/exports/${resource}.csv${query}`,
  findings: (query = '') => `/api/v1/reports/findings.csv${query}`,
} as const;

/**
 * Serves every CSV export with `body` (stubApi only answers JSON); call after `stubApi`. Records the
 * request paths and the saved file names, and stubs the browser download.
 */
export function stubCsvDownload(
  body = 'header\r\n',
  headers: Record<string, string> = {},
  status = 200,
) {
  const paths: string[] = [];
  const filenames: string[] = [];
  const base = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input.toString();
      if (/^\/api\/v1\/(exports\/[a-z-]+|reports\/findings)\.csv(\?|$)/.test(path)) {
        paths.push(path);
        return new Response(body, {
          status,
          headers: { 'Content-Type': 'text/csv; charset=utf-8', ...headers },
        });
      }
      return base(input, init);
    }),
  );
  const createObjectURL = vi.fn(() => 'blob:export');
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    filenames.push(this.download);
  });
  return { paths, filenames, createObjectURL, click };
}
