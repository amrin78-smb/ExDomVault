# Architecture

Describes what is implemented. Planned components are marked _(planned, Milestone N)_.

## Overview

```text
                     ┌──────────────────────── Cloudflare ─────────────────────────┐
 Browser ─(Access)─▶ │  Worker "exdomainvault"                                      │
                     │   ├─ static assets: React SPA (apps/web/src → dist/client)   │
                     │   └─ /api/v1/*  → Hono app (apps/web/worker)                 │
                     │        ├─ Cron Triggers / Queues         (planned, M4)       │
                     │        └─ HYPERDRIVE binding (pg + Drizzle) ─────────────────┼──▶ Neon PostgreSQL
                     └──────────────────────────────▲───────────────────────────────┘
                                                    │ outbound HTTPS only
                                                    │ (claim / heartbeat / results)
                                  Home Linux worker (Python, systemd)  (planned, M5–6)
```

- **One Worker** serves both the SPA and the API via Cloudflare's Vite plugin. `wrangler.jsonc` sets
  `run_worker_first: ["/api/*"]` so API paths always reach the Worker, and SPA fallback for client routes.
- **The frontend never talks to the database.** It calls `/api/v1` and validates every response with the
  zod schemas in `packages/shared`.
- **The home worker initiates all connections** (pull model). No inbound ports at home.

## API layer (`apps/web/worker`)

Request pipeline (`app.ts`):

1. `requestContext` — server-generated UUID request ID (client values ignored), request-scoped JSON
   logger, one access log line per request. ID returned in `X-Request-Id`.
2. `securityHeaders` — `nosniff`, `no-referrer`, `DENY` framing, `no-store`, HSTS.
3. `configMiddleware` — validates bindings with zod (`APP_ENV`, `APP_VERSION`, auth settings). Invalid
   configuration throws → generic 500 (fail closed).
4. `database` — `c.var.db()` lazily opens one node-postgres connection per request through the
   `HYPERDRIVE` binding and closes it after the response (`waitUntil`). Connection failures → 503.
5. Public routes: `/health`.
6. Everything else: `sameOriginWrites` (CSRF: unsafe methods need a same-origin `Origin`) → `requireAuth`
   (configured `AuthProvider`, then identity → active user) → route, which adds `requirePermission(...)`.
7. `handleNotFound` / `handleError` — standard error envelope; unknown errors are logged with stack
   server-side and returned as a generic `internal_error`.

Endpoints: `GET /health` (public), `GET /me`, domains (`routes/domains.ts`: list, create, detail, update,
DNS TXT verification, CSV import). Full contract: [`api-specification.md`](api-specification.md).

Request bodies and query strings are validated with the shared zod schemas (`lib/validation.ts`: JSON
content type and a 300 KB body limit enforced; malformed UUID params → 404).

## Domain inventory

- **Normalisation** (`packages/shared/src/hostname/normalise.ts`, subpath export
  `@exdomainvault/shared/hostname`, server-only because it bundles the Public Suffix List): ASCII
  pre-filter → WHATWG URL IDNA → strict LDH/A-label checks → PSL registrable-domain boundary (`tldts`,
  ICANN section only). `isWithinDomain()` is the exact label-boundary check later reused for scope.
- **Verification** (`services/domain-verification.ts`): random 256-bit token, SHA-256 stored, 72 h
  expiry, superseding, atomic 10 s check throttle, lookup through DoH (`lib/doh.ts`) from the Worker.
  Chosen over a home-worker job because it is a single passive query to a public resolver, needs no
  scanning infrastructure (Milestone 5) and gives immediate feedback. Expiry is applied lazily on reads
  and writes (no cron yet).
- **Import** (`services/domain-import.ts`, `lib/csv.ts`): stateless two-step preview/confirm bound by a
  SHA-256 digest of the file; confirm re-validates and inserts valid rows in one transaction.
- Every change writes its audit record in the same transaction (`domain.*` actions).

## Authentication and authorisation

- `worker/auth/types.ts` — the replaceable `AuthProvider` interface (`authenticate(request) → identity`).
- `worker/auth/cloudflare-access.ts` — production. Verifies the Access JWT (header or `CF_Authorization`
  cookie) with jose: RS256 signature against the team JWKS (cached per isolate), issuer, audience, expiry.
  Plain identity headers are never trusted.
- `worker/auth/dev.ts` — local development. Fixed identity from `DEV_AUTH_EMAIL`; config loading refuses
  it when `APP_ENV=production`.
- `worker/services/users.ts` — maps identity → user: by provider subject, else bind a pre-provisioned email,
  else bootstrap an admin from `BOOTSTRAP_ADMIN_EMAILS` (audited), else 403.
- Roles and the permission matrix live in `packages/shared` so UI and API agree; enforcement is server-side.
- `worker/services/audit.ts` — `writeAudit()`; call inside the same transaction as the audited change.

## Database (`packages/database`)

Drizzle schema (`src/schema/`), generated SQL migrations (`migrations/`), `connect()` / `pingDatabase()`,
a guarded migration runner (`scripts/migrate.ts`: refuses the production branch and pooled URLs unless
explicitly allowed), and `src/testing.ts` (PGlite with migrations applied, tests only).
Details: [`database-schema.md`](database-schema.md). Neon/Hyperdrive setup: [`deployment.md`](deployment.md).

## Frontend (`apps/web/src`)

- `react-router` data router (`routes.tsx`), persistent `AppShell` (sidebar + top bar + outlet), route
  error boundary.
- Navigation: Overview, Domains, Assets, Scans, Findings, Advisories, Reports, Settings. Unbuilt sections
  render a placeholder naming their milestone.
- Domains: list (`/domains`, filters/sort/page in the URL), detail (`/domains/:id`: verification panel,
  owner/criticality, monitoring with confirmation, registration status, honest empty states for data not
  collected yet) and CSV import (`/domains/import`).
- `SessionProvider` loads `/api/v1/me` once; `usePermission()` hides actions the user's role cannot
  perform (the API still enforces every permission).
- The top bar shows API health (`/api/v1/health`) and the signed-in user and role (`/api/v1/me`), or why
  sign-in failed (not signed in / access not granted / sign-in unavailable).
- **Development fixtures** (`lib/fixtures/`, RFC 2606 names) render only when
  `import.meta.env.DEV && VITE_DEV_FIXTURES === 'true'`, always under a warning banner, and are removed from
  production bundles.

## Python worker (`worker/`)

Validated configuration (`app/config.py`) and a `--check-config` entry point. `active_scanning_enabled` is
hard-coded `False` until the Milestone 6 gate.

## Testing

- Vitest projects: `web` (jsdom UI tests; API/service tests with `// @vitest-environment node`), `shared`,
  `database`.
- API and service tests run the Hono app in Node against **PGlite** (real PostgreSQL compiled to WASM) with
  all migrations applied, injected via `createApp({ connect })`. No network, no Neon.
- The real path (workerd + Hyperdrive local binding + Neon dev branch) is exercised with `npm run dev`.
- CI also fails if the Drizzle schema and committed migrations drift apart.
- pytest for the worker. Tests never contact real hosts.
