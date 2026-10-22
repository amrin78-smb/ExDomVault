# Architecture

Describes what is implemented. Planned components are marked _(planned, Milestone N)_.

## Overview

```text
                      ┌──────────────────────── Cloudflare ────────────────────────┐
  Browser ──HTTPS──▶  │  Worker "exdomainvault"                                     │
                      │   ├─ static assets: React SPA (apps/web/src → dist/client)  │
                      │   └─ /api/v1/*  → Hono app (apps/web/worker)                │
                      │        ├─ Cron Triggers / Queues        (planned, M4)       │
                      │        └─ Neon via Hyperdrive/driver    (planned, M2) ──────┼──▶ Neon PostgreSQL
                      └─────────────────────────────▲──────────────────────────────┘
                                                    │ outbound HTTPS only
                                                    │ (claim / heartbeat / results)
                                  Home Linux worker (Python, systemd)  (planned, M5–6)
```

- **One Worker** serves both the SPA and the API, using Cloudflare's Vite plugin
  (`@cloudflare/vite-plugin`). `wrangler.jsonc` sets `run_worker_first: ["/api/*"]` so API paths always
  reach the Worker, and `not_found_handling: "single-page-application"` so client-side routes like
  `/domains` load `index.html`.
- **The frontend never talks to the database.** It calls `/api/v1` and validates every response with
  the zod schemas in `packages/shared`.
- **The home worker initiates all connections** (pull model). No inbound ports are opened at home.

## API layer (`apps/web/worker`)

Request pipeline, in order (`app.ts`):

1. `requestContext` assigns a server-generated UUID request ID (client-supplied IDs are ignored), a
   request-scoped JSON logger, and logs method/path/status/duration when the request completes. The ID is
   returned in `X-Request-Id`.
2. `securityHeaders` adds `nosniff`, `no-referrer`, `DENY` framing, `no-store` and HSTS.
3. `configMiddleware` validates bindings (`APP_ENV`, `APP_VERSION`) with zod. Invalid configuration throws,
   so the request fails with a generic 500 (fail closed).
4. Route modules under `routes/`, mounted at `/api/v1`.
5. `handleNotFound` / `handleError` turn every failure into the standard envelope:

```json
{ "error": { "code": "not_found", "message": "Safe message.", "requestId": "…", "details": [] } }
```

`ApiError` carries a code and message that are safe to show. Any other error is logged with its stack
on the server and returned as `internal_error` with a generic message.

### Endpoints implemented

| Method | Path             | Notes                                                                                                                         |
| ------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/api/v1/health` | `HealthResponse` (shared schema). Reports `database` and `auth` as `not_configured` and overall `degraded` until Milestone 2. |

## Frontend (`apps/web/src`)

- `react-router` data router (`routes.tsx`), with a persistent `AppShell` (sidebar + top bar + outlet)
  and a route error boundary.
- Navigation: Overview, Domains, Assets, Scans, Findings, Advisories, Reports, Settings (`components/layout/nav.ts`).
  Sections not built yet render a placeholder that names the milestone that delivers them.
- Overview shows the panels from design §14 with empty states until real data exists.
- `ApiStatus` in the top bar polls `/api/v1/health` once on load.
- **Development fixtures**: `lib/fixtures/` holds synthetic data using RFC 2606 `example.*` names. They are
  rendered only when `import.meta.env.DEV && VITE_DEV_FIXTURES === 'true'`, always beneath a warning
  banner. The fixture data is wrapped in `import.meta.env.DEV ? … : null`, so it is removed from
  production bundles.

## Shared contracts (`packages/shared`)

Consumed as TypeScript source (no build step) through the workspace. Contains error codes and the error
envelope, the health schema, roles, severities and criticalities.

## Python worker (`worker/`)

Milestone 1 contains only validated configuration (`app/config.py`) and a `--check-config` entry
point. `active_scanning_enabled` is hard-coded to `False` and cannot be switched on from the
environment until the Milestone 6 gate.

## Testing

- Vitest projects (`vitest.config.ts`): `web` (jsdom; UI component tests, plus API tests that use
  `// @vitest-environment node` and call `createApp().request()` directly) and `shared`.
- The API is tested against the Hono app rather than inside workerd. The real Workers runtime is used
  by `npm run dev`; Milestone 2 will reconsider `@cloudflare/vitest-pool-workers` once bindings exist.
- pytest for the worker. Tests never contact real hosts.
