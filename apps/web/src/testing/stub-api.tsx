// Test-only: routes fetch calls to canned API responses and renders the app at a path.
import type { Permission, Role } from '@exdomainvault/shared';
import { render } from '@testing-library/react';
import { RouterProvider, createMemoryRouter } from 'react-router';
import { vi } from 'vitest';
import { DataModeProvider } from '../lib/DataModeProvider.tsx';
import { routes } from '../routes.tsx';

export type Handler = (body: unknown) => { status: number; body: unknown };
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
    'scans:read',
    'scans:request',
    'settings:manage',
  ],
  analyst: ['domains:read', 'scans:read', 'scans:request'],
  viewer: ['domains:read', 'scans:read'],
  asset_owner: [],
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
      const r = handler ? handler(body) : { status: 404, body: {} };
      return new Response(JSON.stringify(r.body), { status: r.status });
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
